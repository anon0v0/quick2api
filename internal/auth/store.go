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
)

// Account stores one Amazon Quick social (AWS sso-oidc) account credential.
type Account struct {
	ID                    string  `json:"id"`
	Disabled              bool    `json:"disabled,omitempty"`
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

// AccountStatus is a secret-free status snapshot for /healthz and /admin/status.
type AccountStatus struct {
	ID                   string `json:"id"`
	Disabled             bool   `json:"disabled"`
	Region               string `json:"region"`
	TenantHost           string `json:"tenant_host"`
	AccessExpiresInSec   int64  `json:"access_expires_in_sec"`
	RefreshExpiresInSec  int64  `json:"refresh_expires_in_sec,omitempty"`
	CooldownRemainingSec int64  `json:"cooldown_remaining_sec"`
	LastError            string `json:"last_error,omitempty"`
	HasRefreshToken      bool   `json:"has_refresh_token"`
}

type accountRuntime struct {
	mu            sync.Mutex // serializes OIDC token refresh for this account
	cooldownUntil time.Time
	lastError     string
}

// Store manages the account pool, round-robin selection, cooldowns, and OIDC refresh.
type Store struct {
	path        string
	refreshLead time.Duration
	httpClient  *http.Client
	oidcBaseURL string // optional override for unit tests; empty -> https://oidc.<region>.amazonaws.com

	mu       sync.RWMutex
	accounts []*Account
	runtime  map[string]*accountRuntime
	rr       atomic.Uint64
}

type accountsFileEnvelope struct {
	Accounts []*Account `json:"accounts"`
}

var regionInHostRe = regexp.MustCompile(`\.([a-z]{2}-[a-z]+-\d+)\.`)

// NewStore loads accounts from path and prepares an OIDC HTTP client.
func NewStore(path string, refreshLead time.Duration, proxyURL string) (*Store, error) {
	tr := &http.Transport{
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy_url: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	s := &Store{
		path:        path,
		refreshLead: refreshLead,
		httpClient:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		runtime:     make(map[string]*accountRuntime),
	}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads accounts from JSON (supports {"accounts":[...]}, [...], or single {...}).
func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read accounts file %s: %w", s.path, err)
	}
	trimmed := bytes.TrimSpace(data)
	var list []*Account
	switch {
	case len(trimmed) == 0:
		return errors.New("accounts file is empty")
	case trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return fmt.Errorf("parse accounts array: %w", err)
		}
	default:
		var env accountsFileEnvelope
		if err := json.Unmarshal(trimmed, &env); err == nil && len(env.Accounts) > 0 {
			list = env.Accounts
		} else {
			var single Account
			if err := json.Unmarshal(trimmed, &single); err != nil {
				return fmt.Errorf("parse account object: %w", err)
			}
			if single.TenantURL != "" || single.ClientID != "" {
				list = []*Account{&single}
			}
		}
	}
	if len(list) == 0 {
		return errors.New("no accounts configured in accounts file")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = make([]*Account, 0, len(list))
	for i, a := range list {
		if a == nil {
			continue
		}
		if a.ID == "" {
			a.ID = fmt.Sprintf("account-%d", i+1)
		}
		a.TenantURL = strings.TrimRight(strings.TrimSpace(a.TenantURL), "/")
		if a.Region == "" {
			a.Region = inferRegion(a.TenantURL, a.ClientID)
		}
		if a.TenantURL == "" {
			return fmt.Errorf("account %s missing tenant_url", a.ID)
		}
		s.accounts = append(s.accounts, a)
		if _, ok := s.runtime[a.ID]; !ok {
			s.runtime[a.ID] = &accountRuntime{}
		}
	}
	return nil
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

// Statuses returns secret-free status snapshots for all accounts.
func (s *Store) Statuses() []AccountStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]AccountStatus, 0, len(s.accounts))
	for _, a := range s.accounts {
		rt := s.runtime[a.ID]
		var cd int64
		var lastErr string
		if rt != nil {
			if now.Before(rt.cooldownUntil) {
				cd = int64(time.Until(rt.cooldownUntil).Seconds())
			}
			lastErr = rt.lastError
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
		out = append(out, AccountStatus{
			ID:                   a.ID,
			Disabled:             a.Disabled,
			Region:               a.Region,
			TenantHost:           host,
			AccessExpiresInSec:   accessIn,
			RefreshExpiresInSec:  refreshIn,
			CooldownRemainingSec: cd,
			LastError:            lastErr,
			HasRefreshToken:      a.RefreshToken != "",
		})
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

// GetFreshAccount returns a specific account with a valid token (optionally forcing refresh).
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
		rt.lastError = err.Error()
		s.mu.Unlock()
		// If token isn't actually expired yet and this was a proactive refresh, still serve current token.
		if !force && snap.AccessToken != "" && time.Unix(int64(snap.AccessTokenExpiry), 0).After(time.Now().Add(30*time.Second)) {
			log.Printf("[auth] proactive refresh failed for %s (%v); using existing non-expired token", id, err)
			return snap, nil
		}
		return Account{}, fmt.Errorf("refresh account %s: %w", id, err)
	}

	s.mu.Lock()
	acct.AccessToken = refreshed.AccessToken
	acct.AccessTokenExpiry = refreshed.AccessTokenExpiry
	if refreshed.RefreshToken != "" {
		acct.RefreshToken = refreshed.RefreshToken
	}
	rt.lastError = ""
	out := *acct
	persistErr := s.saveLocked()
	s.mu.Unlock()

	if persistErr != nil {
		log.Printf("[auth] WARNING: refreshed %s in memory but failed to persist accounts file: %v", id, persistErr)
	} else {
		log.Printf("[auth] refreshed access token for %s (expires_in=%ds, rotated=%v)",
			id, int64(out.AccessTokenExpiry)-time.Now().Unix(), refreshed.RefreshToken != "" && refreshed.RefreshToken != snap.RefreshToken)
	}
	return out, nil
}

// MarkCooldown puts an account on temporary cooldown after 429/usage_blocked/auth failures.
func (s *Store) MarkCooldown(id string, d time.Duration, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rt, ok := s.runtime[id]; ok {
		rt.cooldownUntil = time.Now().Add(d)
		rt.lastError = reason
	}
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

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return Account{}, err
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
	env := accountsFileEnvelope{Accounts: s.accounts}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
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
		// Windows ignores Unix chmod bits; tolerate gracefully.
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
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
