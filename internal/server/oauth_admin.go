package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"quick2api/internal/auth"
	"quick2api/internal/cli"
	"quick2api/internal/netproxy"
	"quick2api/internal/quick"
)

const (
	oauthSessionTTL = 10 * time.Minute
	maxOAuthPending = 64
)

type pendingOAuthSession struct {
	state                 string
	accountID             string
	proxyURL              string
	effProxy              string
	region                string
	issuerURL             string
	tenantURL             string
	redirectURI           string
	oidcBase              string
	scopes                []string
	clientID              string
	clientSecret          string
	clientSecretExpiresAt int64
	codeVerifier          string
	createdAt             time.Time
	expiresAt             time.Time
	inFlight              bool
}

type oauthSessionManager struct {
	mu       sync.Mutex
	sessions map[string]*pendingOAuthSession
}

func newOAuthSessionManager() *oauthSessionManager {
	return &oauthSessionManager{
		sessions: make(map[string]*pendingOAuthSession),
	}
}

func (m *oauthSessionManager) put(sess *pendingOAuthSession, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.sessions {
		if !now.Before(v.expiresAt) {
			delete(m.sessions, k)
		}
	}
	for len(m.sessions) >= maxOAuthPending {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range m.sessions {
			if oldestKey == "" || v.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.createdAt
			}
		}
		if oldestKey != "" {
			delete(m.sessions, oldestKey)
		} else {
			break
		}
	}
	m.sessions[sess.state] = sess
}

func (m *oauthSessionManager) acquire(state string, now time.Time) (*pendingOAuthSession, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[state]
	if !ok {
		return nil, "not_found"
	}
	if !now.Before(s.expiresAt) {
		delete(m.sessions, state)
		return nil, "expired"
	}
	if s.inFlight {
		return nil, "in_flight"
	}
	s.inFlight = true
	cp := *s
	return &cp, ""
}

func (m *oauthSessionManager) release(state string, remove bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if remove {
		delete(m.sessions, state)
		return
	}
	if s, ok := m.sessions[state]; ok {
		s.inFlight = false
	}
}

func randomOAuthHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func splitOAuthScopes(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return []string{cli.DefaultOIDCScope}
	}
	return out
}

func (s *Server) handleAdminOAuthDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		CallbackPort int `json:"callback_port"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeStrictJSON(r, 4096, &req); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
			return
		}
	}
	port := req.CallbackPort
	if port == 0 {
		port = 18080
	}
	if port < 1024 || port > 65535 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_callback_port", "invalid_request_error", "callback_port must be between 1024 and 65535.")
		return
	}
	nonce := randomOAuthHex(12)
	discURL := cli.BuildDiscoveryURL(cli.DefaultSocialDiscoveryURL, nonce, port, cli.DefaultDesktopAppVersion)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"discovery_url":     discURL,
		"nonce":             nonce,
		"callback_port":     port,
		"expected_callback": fmt.Sprintf("http://127.0.0.1:%d/", port),
	})
}

func (s *Server) handleAdminOAuthStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		ID                   string `json:"id"`
		TenantURL            string `json:"tenant_url"`
		DiscoveryCallbackURL string `json:"discovery_callback_url"`
		ProxyURL             string `json:"proxy_url"`
		Region               string `json:"region"`
		IssuerURL            string `json:"issuer_url"`
		Scopes               string `json:"scopes"`
		CallbackPort         int    `json:"callback_port"`
	}
	if err := decodeStrictJSON(r, 16384, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}

	acctProxy := strings.TrimSpace(req.ProxyURL)
	if err := netproxy.Validate(acctProxy); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_proxy", "invalid_request_error", err.Error())
		return
	}
	effProxy := netproxy.Resolve(acctProxy, s.cfg.ProxyURL)

	tenantURL := strings.TrimRight(strings.TrimSpace(req.TenantURL), "/")
	region := strings.TrimSpace(req.Region)
	issuer := strings.TrimSpace(req.IssuerURL)

	if discRaw := strings.TrimSpace(req.DiscoveryCallbackURL); discRaw != "" {
		disc, err := cli.ParseDiscoveryCallback(discRaw)
		if err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_discovery_url", "invalid_request_error", err.Error())
			return
		}
		tenantURL = disc.TenantURL
		if disc.IssuerURL != "" && (issuer == "" || issuer == cli.DefaultSocialIssuerURL) {
			issuer = disc.IssuerURL
		}
		if disc.Region != "" && (region == "" || region == "us-east-1") {
			region = disc.Region
		}
	}
	if tenantURL == "" {
		// Fallback: reuse existing tenant_url from pool if available.
		for _, existing := range s.store.AccountsSnapshot() {
			if existing.TenantURL != "" {
				tenantURL = existing.TenantURL
				break
			}
		}
	}
	if parsed, err := url.Parse(tenantURL); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_tenant_url", "invalid_request_error", "A valid https:// tenant_url (or discovery_callback_url from quick.aws.com) is required.")
		return
	}

	if region == "" {
		region = "us-east-1"
	}
	if issuer == "" {
		issuer = cli.DefaultSocialIssuerURL
	}
	port := req.CallbackPort
	if port == 0 {
		port = 18080
	}
	if port < 1024 || port > 65535 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_callback_port", "invalid_request_error", "callback_port must be between 1024 and 65535.")
		return
	}
	scopes := splitOAuthScopes(req.Scopes)
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/oauth/callback", port)

	oidcBase := s.oauthBaseURL
	if oidcBase == "" {
		oidcBase = fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	}

	tr, err := netproxy.NewTransport(nil, effProxy)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_proxy", "invalid_request_error", err.Error())
		return
	}
	hc := &http.Client{Transport: tr, Timeout: 25 * time.Second}

	regCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	clientReg, err := cli.RegisterOIDCClient(regCtx, hc, oidcBase, issuer, redirectURI, scopes, effProxy)
	if err != nil {
		log.Printf("[admin] oauth client/register failed region=%s proxy=%s: %v", region, netproxy.Redact(effProxy), err)
		writeOpenAIError(w, http.StatusBadGateway, "oauth_register_failed", "api_error", err.Error())
		return
	}

	verifier, challenge := cli.GeneratePKCE()
	state := randomOAuthHex(16)
	authURL := cli.BuildAuthorizeURL(oidcBase, clientReg.ClientID, redirectURI, scopes, state, challenge)

	now := time.Now()
	sess := &pendingOAuthSession{
		state:                 state,
		accountID:             strings.TrimSpace(req.ID),
		proxyURL:              acctProxy,
		effProxy:              effProxy,
		region:                region,
		issuerURL:             issuer,
		tenantURL:             tenantURL,
		redirectURI:           redirectURI,
		oidcBase:              oidcBase,
		scopes:                scopes,
		clientID:              clientReg.ClientID,
		clientSecret:          clientReg.ClientSecret,
		clientSecretExpiresAt: clientReg.ClientSecretExpiresAt,
		codeVerifier:          verifier,
		createdAt:             now,
		expiresAt:             now.Add(oauthSessionTTL),
	}
	s.oauthSessions.put(sess, now)
	log.Printf("[admin] started web oauth flow region=%s callback_port=%d scopes=%s proxy=%s", region, port, strings.Join(scopes, ","), netproxy.Redact(effProxy))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"state":          state,
		"auth_url":       authURL,
		"redirect_uri":   redirectURI,
		"region":         region,
		"issuer_url":     issuer,
		"scopes":         scopes,
		"tenant_url":     tenantURL,
		"proxy":          netproxy.Redact(acctProxy),
		"expires_in_sec": int(oauthSessionTTL.Seconds()),
	})
}

func (s *Server) handleAdminOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		State       string `json:"state"`
		RedirectURL string `json:"redirect_url"`
		Code        string `json:"code"`
		TenantURL   string `json:"tenant_url"`
	}
	if err := decodeStrictJSON(r, 16384, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}

	state := strings.TrimSpace(req.State)
	code := strings.TrimSpace(req.Code)
	overrideTenant := strings.TrimRight(strings.TrimSpace(req.TenantURL), "/")

	if rawRedirect := strings.TrimSpace(req.RedirectURL); rawRedirect != "" {
		parseTarget := rawRedirect
		if !strings.Contains(parseTarget, "://") && strings.Contains(parseTarget, "code=") {
			parseTarget = "http://127.0.0.1/oauth/callback?" + strings.TrimPrefix(parseTarget, "?")
		}
		if strings.Contains(parseTarget, "://") {
			u, err := url.Parse(parseTarget)
			if err != nil {
				writeOpenAIError(w, http.StatusBadRequest, "invalid_callback_url", "invalid_request_error", "Malformed callback URL.")
				return
			}
			q := u.Query()
			if errCode := strings.TrimSpace(q.Get("error")); errCode != "" {
				desc := strings.TrimSpace(q.Get("error_description"))
				msg := errCode
				if desc != "" {
					msg += ": " + desc
				}
				writeOpenAIError(w, http.StatusBadRequest, "oauth_callback_error", "invalid_request_error", msg)
				return
			}
			if qState := strings.TrimSpace(q.Get("state")); qState != "" {
				if state != "" && state != qState {
					writeOpenAIError(w, http.StatusBadRequest, "oauth_state_mismatch", "invalid_request_error", "Callback URL state does not match the active login session.")
					return
				}
				state = qState
			}
			if qCode := strings.TrimSpace(q.Get("code")); qCode != "" {
				code = qCode
			}
			if qTenant := strings.TrimRight(strings.TrimSpace(q.Get("tenant_url")), "/"); qTenant != "" && overrideTenant == "" {
				overrideTenant = qTenant
			}
		} else if code == "" {
			code = rawRedirect
		}
	}

	if state == "" {
		writeOpenAIError(w, http.StatusBadRequest, "missing_state", "invalid_request_error", "OAuth session state is required.")
		return
	}
	if code == "" {
		writeOpenAIError(w, http.StatusBadRequest, "missing_code", "invalid_request_error", "Callback URL is missing the authorization `code` parameter.")
		return
	}

	sess, reason := s.oauthSessions.acquire(state, time.Now())
	if reason != "" {
		status := http.StatusNotFound
		msg := "OAuth session not found or already completed. Start a new login."
		if reason == "expired" {
			status = http.StatusGone
			msg = "OAuth login session expired (10 min limit). Generate a new login link."
		} else if reason == "in_flight" {
			status = http.StatusConflict
			msg = "OAuth token exchange is already in progress."
		}
		writeOpenAIError(w, status, "oauth_session_"+reason, "invalid_request_error", msg)
		return
	}

	consumed := false
	defer func() {
		s.oauthSessions.release(state, consumed)
	}()

	tenantURL := sess.tenantURL
	if overrideTenant != "" {
		if parsed, err := url.Parse(overrideTenant); err == nil && parsed.Scheme == "https" && parsed.Host != "" {
			tenantURL = overrideTenant
		}
	}

	tr, err := netproxy.NewTransport(nil, sess.effProxy)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_proxy", "invalid_request_error", err.Error())
		return
	}
	hc := &http.Client{Transport: tr, Timeout: 25 * time.Second}

	exCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	tok, err := cli.ExchangeAuthCode(exCtx, hc, sess.oidcBase, sess.clientID, sess.clientSecret, sess.redirectURI, code, sess.codeVerifier, sess.effProxy)
	if err != nil {
		log.Printf("[admin] oauth token exchange failed region=%s: %v", sess.region, err)
		writeOpenAIError(w, http.StatusBadGateway, "oauth_exchange_failed", "api_error", err.Error())
		return
	}

	acctID := sess.accountID
	if acctID == "" {
		acctID = "social-" + randomOAuthHex(6)
	}
	expiresIn := tok.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	now := time.Now().Unix()
	acct := auth.Account{
		ID:                    acctID,
		ProxyURL:              sess.proxyURL,
		TenantURL:             tenantURL,
		IssuerURL:             sess.issuerURL,
		Region:                sess.region,
		ClientID:              sess.clientID,
		ClientSecret:          sess.clientSecret,
		ClientSecretExpiresAt: float64(sess.clientSecretExpiresAt),
		AccessToken:           tok.AccessToken,
		AccessTokenExpiry:     float64(now + expiresIn),
		RefreshToken:          tok.RefreshToken,
	}

	added, updated, err := auth.UpsertAccountsFile(s.cfg.AccountsFile, []auth.Account{acct})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "save_account_failed", "api_error", fmt.Sprintf("Failed to persist account: %v", err))
		return
	}
	if _, err := s.ReloadAccounts(); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "reload_failed", "api_error", fmt.Sprintf("Saved account but reload failed: %v", err))
		return
	}
	consumed = true

	// Best-effort usage + identity probes to immediately populate quota & email/name on the new card.
	usageOK := false
	usageNote := ""
	uCtx, uCancel := context.WithTimeout(r.Context(), 5*time.Second)
	rawUsage, uErr := s.manager.FetchUsage(uCtx, acct)
	uCancel()
	if uErr == nil {
		if q := quick.ParseQuota(rawUsage); q != nil {
			s.store.UpdateQuota(acct.ID, q)
			usageOK = true
		}
		if acct.Email == "" {
			idCtx, idCancel := context.WithTimeout(r.Context(), 6*time.Second)
			_ = s.manager.FetchIdentity(idCtx, acct)
			idCancel()
		}
	} else {
		usageNote = uErr.Error()
	}

	var statusSnap auth.AccountStatus
	for _, st := range s.store.Statuses() {
		if st.ID == acct.ID {
			statusSnap = st
			break
		}
	}
	log.Printf("[admin] web oauth login succeeded account=%s added=%v updated=%v usage_ok=%v usage_note=%q", acct.ID, added, updated, usageOK, usageNote)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"account":    statusSnap,
		"added":      added,
		"updated":    updated,
		"usage_ok":   usageOK,
		"usage_note": usageNote,
	})
}

func (s *Server) handleAdminAccountImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		Payload  json.RawMessage `json:"payload"`
		ProxyURL string          `json:"proxy_url"`
	}
	if err := decodeStrictJSON(r, 1<<20, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}
	overrideProxy := strings.TrimSpace(req.ProxyURL)
	if err := netproxy.Validate(overrideProxy); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_proxy", "invalid_request_error", err.Error())
		return
	}
	parsedPtrs, err := auth.ParseAccountsJSONBytes(req.Payload)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_accounts_json", "invalid_request_error", err.Error())
		return
	}
	if len(parsedPtrs) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "empty_accounts", "invalid_request_error", "JSON payload contains no accounts.")
		return
	}
	incoming := make([]auth.Account, 0, len(parsedPtrs))
	for _, p := range parsedPtrs {
		a := *p
		if a.AccessToken == "" && a.RefreshToken == "" {
			writeOpenAIError(w, http.StatusBadRequest, "missing_tokens", "invalid_request_error", fmt.Sprintf("Account %s missing access_token and refresh_token.", a.ID))
			return
		}
		if overrideProxy != "" {
			a.ProxyURL = overrideProxy
		}
		incoming = append(incoming, a)
	}
	added, updated, err := auth.UpsertAccountsFile(s.cfg.AccountsFile, incoming)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "import_failed", "invalid_request_error", err.Error())
		return
	}
	if _, err := s.ReloadAccounts(); err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "reload_failed", "api_error", fmt.Sprintf("Saved accounts but reload failed: %v", err))
		return
	}
	// Best-effort identity backfill for newly imported accounts missing email (bounded to first 5).
	probed := 0
	for _, a := range incoming {
		if a.Disabled || a.Email != "" || probed >= 5 {
			continue
		}
		probed++
		if liveAcct, ok := s.store.GetAccount(a.ID); ok && liveAcct.Email == "" {
			idCtx, idCancel := context.WithTimeout(r.Context(), 4*time.Second)
			_ = s.manager.FetchIdentity(idCtx, liveAcct)
			idCancel()
		}
	}
	log.Printf("[admin] imported %d account(s) via web ui added=%v updated=%v", len(incoming), added, updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"added":    added,
		"updated":  updated,
		"accounts": s.store.Statuses(),
	})
}

func (s *Server) handleAdminAccountToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		ID       string `json:"id"`
		Disabled bool   `json:"disabled"`
	}
	if err := decodeStrictJSON(r, 4096, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", "Account `id` is required.")
		return
	}
	changed, st, err := s.store.SetAccountDisabled(req.ID, req.Disabled)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeOpenAIError(w, code, "toggle_failed", "invalid_request_error", err.Error())
		return
	}
	if changed && req.Disabled {
		s.manager.InvalidateConn(req.ID)
	}
	log.Printf("[admin] set account=%s disabled=%v", req.ID, req.Disabled)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"changed": changed,
		"account": st,
	})
}

func (s *Server) handleAdminAccountDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeStrictJSON(r, 4096, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", "Account `id` is required.")
		return
	}
	if _, err := s.store.DeleteAccount(req.ID); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeOpenAIError(w, code, "delete_failed", "invalid_request_error", err.Error())
		return
	}
	s.manager.InvalidateConn(req.ID)
	log.Printf("[admin] deleted account=%s", req.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"deleted": req.ID,
	})
}
