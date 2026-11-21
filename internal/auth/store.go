package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"quick2api/internal/netproxy"
)

// Cooldown kinds distinguish transient throttling from session/monthly quota exhaustion.
const (
	CooldownRateLimited         = "rate_limited"
	CooldownSessionQuota        = "session_quota"
	CooldownMonthlyQuota        = "monthly_quota"
	CooldownSubscriptionExpired = "subscription_expired"
	CooldownAuthFailed          = "auth_failed"
)

// Account stores one Amazon Quick social (AWS sso-oidc) account credential.
type Account struct {
	ID                    string  `json:"id"`
	Disabled              bool    `json:"disabled,omitempty"`
	ProxyURL              string  `json:"proxy_url,omitempty"`
	TenantURL             string  `json:"tenant_url"`
	IssuerURL             string  `json:"issuer_url,omitempty"`
	Region                string  `json:"region,omitempty"`
	ClientID              string  `json:"client_id"`
	ClientSecret          string  `json:"client_secret"`
	ClientSecretExpiresAt float64 `json:"client_secret_expires_at,omitempty"`
	AccessToken           string  `json:"access_token"`
	AccessTokenExpiry     float64 `json:"access_token_expiry"`
	RefreshToken          string  `json:"refresh_token"`
	RefreshTokenExpiry    float64 `json:"refresh_token_expiry,omitempty"`
	AWSAccountID          string  `json:"aws_account_id,omitempty"`
	ExternalID            string  `json:"external_id,omitempty"`
}

// QuotaInfo holds the latest parsed profile/usage snapshot for an account.
type QuotaInfo struct {
	MonthlyUsed      int    `json:"monthly_used"`
	MonthlyLimit     int    `json:"monthly_limit"`
	MonthlyPercent   int    `json:"monthly_percent"`
	MonthlyResetsAt  int64  `json:"monthly_resets_at,omitempty"`
	SessionUsed      int    `json:"session_used"`
	SessionLimit     int    `json:"session_limit"`
	SessionPercent   int    `json:"session_percent"`
	SessionResetsAt  int64  `json:"session_resets_at,omitempty"`
	SessionResumeMin int    `json:"session_resume_in_minutes,omitempty"`
	SubscriptionType string `json:"subscription_type,omitempty"`
	TrialStatus      string `json:"trial_status,omitempty"`
	UpdatedAt        int64  `json:"updated_at"`
}

// AccountStatus is a secret-free status snapshot for /healthz and /admin/status.
type AccountStatus struct {
	ID                   string     `json:"id"`
	Disabled             bool       `json:"disabled"`
	Region               string     `json:"region"`
	TenantHost           string     `json:"tenant_host"`
	Proxy                string     `json:"proxy,omitempty"`
	AccessExpiresInSec   int64      `json:"access_expires_in_sec"`
	RefreshExpiresInSec  int64      `json:"refresh_expires_in_sec,omitempty"`
	CooldownRemainingSec int64      `json:"cooldown_remaining_sec"`
	CooldownKind         string     `json:"cooldown_kind,omitempty"`
	CooldownUntil        string     `json:"cooldown_until,omitempty"`
	LastError            string     `json:"last_error,omitempty"`
	HasRefreshToken      bool       `json:"has_refresh_token"`
	Quota                *QuotaInfo `json:"quota,omitempty"`
}

// ReloadResult summarizes changes detected during an atomic accounts.json hot reload.
type ReloadResult struct {
	Total        int      `json:"total"`
	Enabled      int      `json:"enabled"`
	Added        []string `json:"added,omitempty"`
	Removed      []string `json:"removed,omitempty"`
	Disabled     []string `json:"disabled,omitempty"`
	ProxyChanged []string `json:"proxy_changed,omitempty"`
	Updated      []string `json:"updated,omitempty"`
}

type accountRuntime struct {
	mu            sync.Mutex // serializes OIDC token refresh for this account
	cooldownUntil time.Time
	cooldownKind  string
	rateStreak    int
	lastError     string
	quota         *QuotaInfo
}

// Store manages the account pool, round-robin selection, cooldowns, per-account proxies, and OIDC refresh.
type Store struct {
	path        string
	refreshLead time.Duration
	globalProxy string
	baseTr      *http.Transport
	oidcBaseURL string // optional override for unit tests; empty -> https://oidc.<region>.amazonaws.com

	clientMu    sync.Mutex
	httpClients map[string]*http.Client // keyed by effective resolved proxy URL

	mu       sync.RWMutex
	accounts []*Account
	runtime  map[string]*accountRuntime
	rr       atomic.Uint64
}

type accountsFileEnvelope struct {
	Accounts []*Account `json:"accounts"`
}

var regionInHostRe = regexp.MustCompile(`\.([a-z]{2}-[a-z]+-\d+)\.`)

// NewStore loads accounts from path and prepares per-proxy OIDC HTTP transports.
func NewStore(path string, refreshLead time.Duration, globalProxy string) (*Store, error) {
	if err := netproxy.Validate(globalProxy); err != nil {
		return nil, fmt.Errorf("global %w", err)
	}
	baseTr := &http.Transport{
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	s := &Store{
		path:        path,
		refreshLead: refreshLead,
		globalProxy: strings.TrimSpace(globalProxy),
		baseTr:      baseTr,
		httpClients: make(map[string]*http.Client),
		runtime:     make(map[string]*accountRuntime),
	}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// EffectiveProxyURL resolves an account's outbound proxy URL ("" means direct).
func (s *Store) EffectiveProxyURL(acct Account) string {
	return netproxy.Resolve(acct.ProxyURL, s.globalProxy)
}

func (s *Store) httpClientForProxy(effectiveProxy string) (*http.Client, error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if c, ok := s.httpClients[effectiveProxy]; ok {
		return c, nil
	}
	tr, err := netproxy.NewTransport(s.baseTr, effectiveProxy)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	s.httpClients[effectiveProxy] = c
	return c, nil
}

// parseAccountsFile reads, normalizes, and strictly validates an accounts JSON file.
func parseAccountsFile(path string) ([]*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read accounts file %s: %w", path, err)
	}
	trimmed := bytes.TrimSpace(data)
	var list []*Account
	switch {
	case len(trimmed) == 0:
		return nil, errors.New("accounts file is empty")
	case trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("parse accounts array: %w", err)
		}
	default:
		var env accountsFileEnvelope
		if err := json.Unmarshal(trimmed, &env); err == nil && len(env.Accounts) > 0 {
			list = env.Accounts
		} else {
			var single Account
			if err := json.Unmarshal(trimmed, &single); err != nil {
				return nil, fmt.Errorf("parse account object: %w", err)
			}
			if single.TenantURL != "" || single.ClientID != "" {
				list = []*Account{&single}
			}
		}
	}
	if len(list) == 0 {
		return nil, errors.New("no accounts configured in accounts file")
	}

	seenIDs := make(map[string]bool, len(list))
	clean := make([]*Account, 0, len(list))
	for i, a := range list {
		if a == nil {
			continue
		}
		a.ID = strings.TrimSpace(a.ID)
		if a.ID == "" {
			a.ID = fmt.Sprintf("account-%d", i+1)
		}
		if seenIDs[a.ID] {
			return nil, fmt.Errorf("duplicate account id %q in accounts file", a.ID)
		}
		seenIDs[a.ID] = true

		a.TenantURL = strings.TrimRight(strings.TrimSpace(a.TenantURL), "/")
		if a.TenantURL == "" {
			return nil, fmt.Errorf("account %s missing tenant_url", a.ID)
		}
		if a.Region == "" {
			a.Region = inferRegion(a.TenantURL, a.ClientID)
		}
		a.ProxyURL = strings.TrimSpace(a.ProxyURL)
		if err := netproxy.Validate(a.ProxyURL); err != nil {
			return nil, fmt.Errorf("account %s: %w", a.ID, err)
		}
		clean = append(clean, a)
	}
	if len(clean) == 0 {
		return nil, errors.New("no valid accounts configured in accounts file")
	}
	return clean, nil
}

// Load reads accounts from JSON on initial startup.
func (s *Store) Load() error {
	clean, err := parseAccountsFile(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = clean
	for _, a := range clean {
		if _, ok := s.runtime[a.ID]; !ok {
			s.runtime[a.ID] = &accountRuntime{}
		}
	}
	return nil
}

// Reload atomically reloads accounts.json without dropping unchanged accounts' runtime state
// or regressing freshly refreshed in-memory tokens. Invalid files are rejected without mutating live state.
func (s *Store) Reload() (ReloadResult, error) {
	incoming, err := parseAccountsFile(s.path)
	if err != nil {
		return ReloadResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldByID := make(map[string]*Account, len(s.accounts))
	for _, a := range s.accounts {
		oldByID[a.ID] = a
	}

	newByID := make(map[string]*Account, len(incoming))
	var res ReloadResult
	for _, a := range incoming {
		newByID[a.ID] = a
		old, existed := oldByID[a.ID]
		if !existed {
			res.Added = append(res.Added, a.ID)
			s.runtime[a.ID] = &accountRuntime{}
		} else {
			// Preserve newer in-memory refreshed tokens when disk still holds an older access token
			// for the exact same credential identity.
			if old.ClientID == a.ClientID && old.TenantURL == a.TenantURL &&
				old.AccessToken != "" && old.AccessTokenExpiry > a.AccessTokenExpiry {
				a.AccessToken = old.AccessToken
				a.AccessTokenExpiry = old.AccessTokenExpiry
				if old.RefreshToken != "" && old.RefreshToken != a.RefreshToken {
					a.RefreshToken = old.RefreshToken
				}
			}
			oldEffProxy := netproxy.Resolve(old.ProxyURL, s.globalProxy)
			newEffProxy := netproxy.Resolve(a.ProxyURL, s.globalProxy)
			if oldEffProxy != newEffProxy {
				res.ProxyChanged = append(res.ProxyChanged, a.ID)
			}
			if a.Disabled && !old.Disabled {
				res.Disabled = append(res.Disabled, a.ID)
			}
			if old.TenantURL != a.TenantURL || old.Disabled != a.Disabled || oldEffProxy != newEffProxy ||
				old.ClientID != a.ClientID || old.RefreshToken != a.RefreshToken {
				res.Updated = append(res.Updated, a.ID)
			}
		}
		if !a.Disabled {
			res.Enabled++
		}
	}
	for id := range oldByID {
		if _, stillPresent := newByID[id]; !stillPresent {
			res.Removed = append(res.Removed, id)
			delete(s.runtime, id)
		}
	}

	s.accounts = incoming
	res.Total = len(incoming)
	return res, nil
}

// SetAccountProxy updates and atomically persists one account's proxy_url.
// Rolls back the in-memory field if disk persistence fails. Returns whether the effective proxy changed.
func (s *Store) SetAccountProxy(id, proxyURL string) (changed bool, status AccountStatus, err error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if err := netproxy.Validate(proxyURL); err != nil {
		return false, AccountStatus{}, err
	}
	s.mu.Lock()
	var target *Account
	for _, a := range s.accounts {
		if a.ID == id {
			target = a
			break
		}
	}
	if target == nil {
		s.mu.Unlock()
		return false, AccountStatus{}, fmt.Errorf("account %q not found", id)
	}
	oldRaw := target.ProxyURL
	oldEff := netproxy.Resolve(oldRaw, s.globalProxy)
	newEff := netproxy.Resolve(proxyURL, s.globalProxy)
	target.ProxyURL = proxyURL
	if saveErr := s.saveLocked(); saveErr != nil {
		target.ProxyURL = oldRaw
		s.mu.Unlock()
		return false, AccountStatus{}, fmt.Errorf("persist account proxy: %w", saveErr)
	}
	st := s.statusLocked(target, time.Now())
	s.mu.Unlock()
	return oldEff != newEff, st, nil
}

// GetAccount returns a copy of a specific account by ID.
func (s *Store) GetAccount(id string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ID == id {
			return *a, true
		}
	}
	return Account{}, false
}

// AccountsSnapshot returns copies of all configured accounts.
func (s *Store) AccountsSnapshot() []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, *a)
	}
	return out
}

func inferRegion(tenantURL, clientID string) string {
	if m := regionInHostRe.FindStringSubmatch(tenantURL); len(m) == 2 {
		return m[1]
	}
	if clientID != "" {
		dec, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clientID, "="))
		if err == nil {
			if idx := strings.LastIndex(string(dec), ":"); idx > 0 && idx+1 < len(dec) {
				cand := string(dec[idx+1:])
				if strings.Count(cand, "-") == 2 {
					return cand
				}
			}
		}
	}
	return "us-east-1"
}

// AccountCount returns total enabled accounts.
func (s *Store) AccountCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, a := range s.accounts {
		if !a.Disabled {
			n++
		}
	}
	return n
}

func (s *Store) statusLocked(a *Account, now time.Time) AccountStatus {
	rt := s.runtime[a.ID]
	var cd int64
	var cdKind, cdUntil, lastErr string
	var quotaCopy *QuotaInfo
	if rt != nil {
		if now.Before(rt.cooldownUntil) {
			cd = int64(rt.cooldownUntil.Sub(now).Seconds())
			if cd < 1 {
				cd = 1
			}
			cdKind = rt.cooldownKind
			cdUntil = rt.cooldownUntil.UTC().Format(time.RFC3339)
		}
		lastErr = rt.lastError
		if rt.quota != nil {
			qc := *rt.quota
			quotaCopy = &qc
		}
	}
	host := ""
	if u, err := url.Parse(a.TenantURL); err == nil {
		host = u.Host
	}
	var accessIn int64
	if a.AccessTokenExpiry > 0 {
		accessIn = int64(a.AccessTokenExpiry) - now.Unix()
	}
	var refreshIn int64
	if a.RefreshTokenExpiry > 0 {
		refreshIn = int64(a.RefreshTokenExpiry) - now.Unix()
	}
	proxyDisplay := netproxy.Redact(a.ProxyURL)
	if proxyDisplay == "" && s.globalProxy != "" {
		proxyDisplay = netproxy.Redact(s.globalProxy) + " (global)"
	}
	return AccountStatus{
		ID:                   a.ID,
		Disabled:             a.Disabled,
		Region:               a.Region,
		TenantHost:           host,
		Proxy:                proxyDisplay,
		AccessExpiresInSec:   accessIn,
		RefreshExpiresInSec:  refreshIn,
		CooldownRemainingSec: cd,
		CooldownKind:         cdKind,
		CooldownUntil:        cdUntil,
		LastError:            lastErr,
		HasRefreshToken:      a.RefreshToken != "",
		Quota:                quotaCopy,
	}
}

// Statuses returns secret-free status snapshots for all accounts.
func (s *Store) Statuses() []AccountStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]AccountStatus, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, s.statusLocked(a, now))
	}
	return out
}

// PickAccount selects an available account via round-robin and ensures its access token is fresh.
func (s *Store) PickAccount(ctx context.Context) (Account, error) {
	return s.PickAccountExcluding(ctx, nil)
}

// PickAccountExcluding selects an available account not present in exclude via round-robin.
func (s *Store) PickAccountExcluding(ctx context.Context, exclude map[string]bool) (Account, error) {
	s.mu.RLock()
	enabled := make([]*Account, 0, len(s.accounts))
	now := time.Now()
	ready := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		if a.Disabled {
			continue
		}
		enabled = append(enabled, a)
		if exclude != nil && exclude[a.ID] {
			continue
		}
		rt := s.runtime[a.ID]
		if rt == nil || !now.Before(rt.cooldownUntil) {
			ready = append(ready, a)
		}
	}
	s.mu.RUnlock()

	if len(enabled) == 0 {
		return Account{}, errors.New("no enabled quick accounts")
	}
	if len(ready) == 0 {
		return Account{}, errors.New("all quick accounts are currently in cooldown")
	}

	idx := int(s.rr.Add(1)-1) % len(ready)
	chosen := ready[idx]
	return s.EnsureFresh(ctx, chosen.ID, false)
}

// EnsureFresh returns a specific account with a valid token (optionally forcing refresh).
func (s *Store) EnsureFresh(ctx context.Context, id string, force bool) (Account, error) {
	s.mu.RLock()
	var acct *Account
	var rt *accountRuntime
	for _, a := range s.accounts {
		if a.ID == id {
			acct = a
			rt = s.runtime[id]
			break
		}
	}
	if acct == nil {
		s.mu.RUnlock()
		return Account{}, fmt.Errorf("account %q not found", id)
	}
	snap := *acct
	s.mu.RUnlock()

	if !force && snap.AccessToken != "" && time.Unix(int64(snap.AccessTokenExpiry), 0).After(time.Now().Add(s.refreshLead)) {
		return snap, nil
	}

	// Serialize refresh per account.
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Re-check after acquiring per-account refresh lock.
	s.mu.RLock()
	acct = nil
	for _, a := range s.accounts {
		if a.ID == id {
			acct = a
			break
		}
	}
	if acct == nil {
		s.mu.RUnlock()
		return Account{}, fmt.Errorf("account %q removed during refresh", id)
	}
	snap = *acct
	s.mu.RUnlock()
	if !force && snap.AccessToken != "" && time.Unix(int64(snap.AccessTokenExpiry), 0).After(time.Now().Add(s.refreshLead)) {
		return snap, nil
	}

	if snap.RefreshToken == "" || snap.ClientID == "" || snap.ClientSecret == "" {
		if snap.AccessToken != "" && time.Unix(int64(snap.AccessTokenExpiry), 0).After(time.Now()) {
			return snap, nil
		}
		return Account{}, fmt.Errorf("account %s cannot refresh: missing client_id/client_secret/refresh_token", id)
	}

	refreshed, err := s.doOIDCRefresh(ctx, snap)
	if err != nil {
		s.mu.Lock()
		if curRT, ok := s.runtime[id]; ok {
			curRT.lastError = err.Error()
		}
		s.mu.Unlock()
		// If token isn't actually expired yet and this was a proactive refresh, still serve current token.
		if !force && snap.AccessToken != "" && time.Unix(int64(snap.AccessTokenExpiry), 0).After(time.Now().Add(30*time.Second)) {
			log.Printf("[auth] proactive refresh failed for %s (%v); using existing non-expired token", id, err)
			return snap, nil
		}
		return Account{}, fmt.Errorf("refresh account %s: %w", id, err)
	}

	s.mu.Lock()
	// Re-resolve pointer in case Reload replaced the slice while OIDC HTTP was in-flight.
	var liveAcct *Account
	for _, a := range s.accounts {
		if a.ID == id {
			liveAcct = a
			break
		}
	}
	out := refreshed
	var persistErr error
	if liveAcct != nil {
		liveAcct.AccessToken = refreshed.AccessToken
		liveAcct.AccessTokenExpiry = refreshed.AccessTokenExpiry
		if refreshed.RefreshToken != "" {
			liveAcct.RefreshToken = refreshed.RefreshToken
		}
		if curRT, ok := s.runtime[id]; ok {
			curRT.lastError = ""
		}
		out = *liveAcct
		persistErr = s.saveLocked()
	}
	s.mu.Unlock()

	if persistErr != nil {
		log.Printf("[auth] WARNING: refreshed %s in memory but failed to persist accounts file: %v", id, persistErr)
	} else if liveAcct != nil {
		log.Printf("[auth] refreshed access token for %s (expires_in=%ds, rotated=%v)",
			id, int64(out.AccessTokenExpiry)-time.Now().Unix(), refreshed.RefreshToken != "" && refreshed.RefreshToken != snap.RefreshToken)
	}
	return out, nil
}

// MarkCooldown puts an account on temporary cooldown with a generic reason.
func (s *Store) MarkCooldown(id string, d time.Duration, reason string) {
	s.MarkCooldownWithKind(id, CooldownAuthFailed, d, reason)
}

// MarkCooldownWithKind sets an account's cooldown with an explicit kind and duration.
func (s *Store) MarkCooldownWithKind(id, kind string, d time.Duration, reason string) {
	if d <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.runtime[id]; ok {
		until := time.Now().Add(d)
		if until.After(rt.cooldownUntil) {
			rt.cooldownUntil = until
			rt.cooldownKind = kind
		}
		if reason != "" {
			rt.lastError = reason
		}
	}
}

// MarkRateLimited applies short bounded exponential backoff (1m -> 2m -> 4m -> 8m, max 15m)
// for transient throttling without over-penalizing healthy accounts.
func (s *Store) MarkRateLimited(id, reason string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.runtime[id]
	if !ok {
		return 0
	}
	d := time.Minute << min(rt.rateStreak, 4)
	if d > 15*time.Minute {
		d = 15 * time.Minute
	}
	rt.rateStreak++
	rt.cooldownUntil = time.Now().Add(d)
	rt.cooldownKind = CooldownRateLimited
	if reason != "" {
		rt.lastError = reason
	}
	return d
}

// NoteSuccess resets transient rate-limit streaks and clears stale error labels after a clean turn.
func (s *Store) NoteSuccess(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.runtime[id]; ok {
		rt.rateStreak = 0
		rt.lastError = ""
		if !time.Now().Before(rt.cooldownUntil) {
			rt.cooldownKind = ""
		}
	}
}

// ResetCooldown clears active cooldowns for one account, or all accounts when id == "".
func (s *Store) ResetCooldown(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cleared := 0
	for acctID, rt := range s.runtime {
		if id != "" && acctID != id {
			continue
		}
		if !rt.cooldownUntil.IsZero() || rt.cooldownKind != "" || rt.rateStreak > 0 {
			cleared++
		}
		rt.cooldownUntil = time.Time{}
		rt.cooldownKind = ""
		rt.rateStreak = 0
		rt.lastError = ""
	}
	return cleared
}

// UpdateQuota records the latest Quick profile/usage snapshot and proactively applies
// quota-appropriate cooldowns when monthly, session, or free-trial limits are exhausted.
func (s *Store) UpdateQuota(id string, q *QuotaInfo) (kind string, dur time.Duration) {
	if q == nil {
		return "", 0
	}
	now := time.Now()
	qc := *q
	if qc.UpdatedAt == 0 {
		qc.UpdatedAt = now.Unix()
	}

	var reason string
	switch {
	case qc.TrialStatus != "" && !strings.EqualFold(qc.TrialStatus, "ACTIVE"):
		kind = CooldownSubscriptionExpired
		dur = 24 * time.Hour
		reason = fmt.Sprintf("subscription trial status=%s", qc.TrialStatus)

	case qc.MonthlyLimit > 0 && (qc.MonthlyUsed >= qc.MonthlyLimit || qc.MonthlyPercent >= 100):
		kind = CooldownMonthlyQuota
		dur = 6 * time.Hour
		if qc.MonthlyResetsAt > now.Unix() {
			untilReset := time.Until(time.Unix(qc.MonthlyResetsAt, 0))
			if untilReset < time.Hour {
				untilReset = time.Hour
			} else if untilReset > 72*time.Hour {
				untilReset = 72 * time.Hour
			}
			dur = untilReset
		}
		reason = fmt.Sprintf("monthly quota exhausted (%d/%d)", qc.MonthlyUsed, qc.MonthlyLimit)

	case qc.SessionLimit > 0 && (qc.SessionUsed >= qc.SessionLimit || qc.SessionPercent >= 100):
		kind = CooldownSessionQuota
		dur = 30 * time.Minute
		if qc.SessionResetsAt > now.Unix() {
			untilReset := time.Until(time.Unix(qc.SessionResetsAt, 0))
			if untilReset < 5*time.Minute {
				untilReset = 5 * time.Minute
			} else if untilReset > 6*time.Hour {
				untilReset = 6 * time.Hour
			}
			dur = untilReset
		} else if qc.SessionResumeMin > 0 {
			d := time.Duration(qc.SessionResumeMin) * time.Minute
			if d < 5*time.Minute {
				d = 5 * time.Minute
			} else if d > 6*time.Hour {
				d = 6 * time.Hour
			}
			dur = d
		}
		reason = fmt.Sprintf("session quota exhausted (%d/%d)", qc.SessionUsed, qc.SessionLimit)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.runtime[id]; ok {
		rt.quota = &qc
		if kind != "" && dur > 0 {
			until := now.Add(dur)
			if until.After(rt.cooldownUntil) || rt.cooldownKind == kind || rt.cooldownKind == CooldownRateLimited {
				rt.cooldownUntil = until
				rt.cooldownKind = kind
			}
			rt.lastError = reason
		}
	}
	return kind, dur
}

// StartBackgroundRefresher periodically refreshes tokens before expiry.
func (s *Store) StartBackgroundRefresher(ctx context.Context) {
	ticker := time.NewTicker(4 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.RLock()
				ids := make([]string, 0, len(s.accounts))
				for _, a := range s.accounts {
					if !a.Disabled {
						ids = append(ids, a.ID)
					}
				}
				s.mu.RUnlock()
				for _, id := range ids {
					rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
					if _, err := s.EnsureFresh(rctx, id, false); err != nil {
						log.Printf("[auth] background refresh error for %s: %v", id, err)
					}
					cancel()
				}
			}
		}
	}()
}

type oidcTokenRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	GrantType    string `json:"grantType"`
	RefreshToken string `json:"refreshToken"`
}

type oidcTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int64  `json:"expiresIn"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
	Message      string `json:"message"`
}

func (s *Store) doOIDCRefresh(ctx context.Context, acct Account) (Account, error) {
	effProxy := s.EffectiveProxyURL(acct)
	client, err := s.httpClientForProxy(effProxy)
	if err != nil {
		return Account{}, err
	}

	base := s.oidcBaseURL
	if base == "" {
		region := acct.Region
		if region == "" {
			region = "us-east-1"
		}
		base = fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	}
	endpoint := strings.TrimRight(base, "/") + "/token"

	bodyBytes, err := json.Marshal(oidcTokenRequest{
		ClientID:     acct.ClientID,
		ClientSecret: acct.ClientSecret,
		GrantType:    "refresh_token",
		RefreshToken: acct.RefreshToken,
	})
	if err != nil {
		return Account{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return Account{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Account{}, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Account{}, err
	}

	var parsed oidcTokenResponse
	_ = json.Unmarshal(raw, &parsed)

	if resp.StatusCode != http.StatusOK {
		msg := parsed.ErrorDesc
		if msg == "" {
			msg = parsed.Message
		}
		if msg == "" {
			msg = parsed.Error
		}
		if msg == "" {
			msg = fmt.Sprintf("http %d", resp.StatusCode)
		}
		return Account{}, fmt.Errorf("sso-oidc token refresh failed (%d): %s", resp.StatusCode, msg)
	}
	if parsed.AccessToken == "" {
		return Account{}, errors.New("sso-oidc returned empty accessToken")
	}
	expiresIn := parsed.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	out := acct
	out.AccessToken = parsed.AccessToken
	out.AccessTokenExpiry = float64(time.Now().Unix() + expiresIn)
	if parsed.RefreshToken != "" {
		out.RefreshToken = parsed.RefreshToken
	}
	return out, nil
}

// saveLocked atomically writes accounts.json (caller must hold s.mu write lock).
func (s *Store) saveLocked() error {
	return writeAccountsAtomic(s.path, s.accounts)
}

func writeAccountsAtomic(path string, accounts []*Account) error {
	env := accountsFileEnvelope{Accounts: accounts}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".accounts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// UpsertAccountsFile merges one or more accounts into path (creating it if absent) and persists atomically with 0600 permissions.
func UpsertAccountsFile(path string, incoming []Account) (added []string, updated []string, err error) {
	if len(incoming) == 0 {
		return nil, nil, errors.New("no accounts to upsert")
	}
	var existing []*Account
	if _, statErr := os.Stat(path); statErr == nil {
		existing, err = parseAccountsFile(path)
		if err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, nil, statErr
	}

	for _, cand := range incoming {
		a := cand
		a.ID = strings.TrimSpace(a.ID)
		a.TenantURL = strings.TrimRight(strings.TrimSpace(a.TenantURL), "/")
		a.ProxyURL = strings.TrimSpace(a.ProxyURL)
		if a.TenantURL == "" {
			return nil, nil, errors.New("account missing tenant_url")
		}
		if err := netproxy.Validate(a.ProxyURL); err != nil {
			return nil, nil, err
		}
		if a.Region == "" {
			a.Region = inferRegion(a.TenantURL, a.ClientID)
		}
		if a.ID == "" {
			a.ID = fmt.Sprintf("account-%d", len(existing)+1)
		}

		matched := -1
		for i, ex := range existing {
			if ex.ID == a.ID || (a.ExternalID != "" && ex.ExternalID == a.ExternalID && ex.TenantURL == a.TenantURL) {
				matched = i
				break
			}
		}
		if matched >= 0 {
			// Preserve existing proxy_url if incoming left it empty.
			if a.ProxyURL == "" && existing[matched].ProxyURL != "" {
				a.ProxyURL = existing[matched].ProxyURL
			}
			// Preserve existing ID when matched by ExternalID+TenantURL.
			if existing[matched].ID != "" {
				a.ID = existing[matched].ID
			}
			cp := a
			existing[matched] = &cp
			updated = append(updated, a.ID)
		} else {
			cp := a
			existing = append(existing, &cp)
			added = append(added, a.ID)
		}
	}

	if err := writeAccountsAtomic(path, existing); err != nil {
		return nil, nil, err
	}
	return added, updated, nil
}
