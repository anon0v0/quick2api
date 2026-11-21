package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"quick2api/internal/config"
)

const (
	adminSessionCookieName = "quick2api_session"
	adminCSRFHeader        = "X-Requested-With"
	adminCSRFValue         = "quick2api-ui"
	maxAdminSessions       = 256
	maxLoginFailures       = 8
	loginFailureWindow     = 5 * time.Minute
	defaultSessionTTL      = 24 * time.Hour
	rememberSessionTTL     = 14 * 24 * time.Hour
)

type adminSession struct {
	username  string
	expiresAt time.Time
	createdAt time.Time
}

type loginBucket struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type adminAuthManager struct {
	username string
	passHash [32]byte

	mu       sync.Mutex
	sessions map[string]adminSession // key = sha256 hex of raw cookie token
	attempts map[string]*loginBucket
}

func newAdminAuthManager(username, password string) *adminAuthManager {
	if strings.TrimSpace(username) == "" {
		username = config.AdminUsername
	}
	return &adminAuthManager{
		username: username,
		passHash: sha256.Sum256([]byte(password)),
		sessions: make(map[string]adminSession),
		attempts: make(map[string]*loginBucket),
	}
}

func (a *adminAuthManager) verifyCredentials(username, password string) bool {
	uOK := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(a.username)) == 1
	gotHash := sha256.Sum256([]byte(password))
	pOK := subtle.ConstantTimeCompare(gotHash[:], a.passHash[:]) == 1
	return uOK && pOK
}

func (a *adminAuthManager) checkRateLimit(ip string, now time.Time) (blocked bool, retryAfterSec int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.attempts[ip]
	if !ok {
		return false, 0
	}
	if now.Before(b.lockedUntil) {
		sec := int(b.lockedUntil.Sub(now).Seconds())
		if sec < 1 {
			sec = 1
		}
		return true, sec
	}
	if now.Sub(b.windowStart) > loginFailureWindow {
		delete(a.attempts, ip)
	}
	return false, 0
}

func (a *adminAuthManager) recordFailure(ip string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.attempts) > 1024 {
		for k, v := range a.attempts {
			if now.Sub(v.windowStart) > loginFailureWindow && !now.Before(v.lockedUntil) {
				delete(a.attempts, k)
			}
		}
	}
	b, ok := a.attempts[ip]
	if !ok || now.Sub(b.windowStart) > loginFailureWindow {
		b = &loginBucket{windowStart: now}
		a.attempts[ip] = b
	}
	b.failures++
	if b.failures >= maxLoginFailures {
		b.lockedUntil = now.Add(loginFailureWindow)
	}
}

func (a *adminAuthManager) clearFailures(ip string) {
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

func (a *adminAuthManager) createSession(ttl time.Duration, now time.Time) (rawToken string, expiresAt time.Time, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	rawToken = hex.EncodeToString(raw[:])
	key := hashSessionToken(rawToken)
	expiresAt = now.Add(ttl)

	a.mu.Lock()
	defer a.mu.Unlock()
	// Prune expired sessions first.
	for k, s := range a.sessions {
		if !now.Before(s.expiresAt) {
			delete(a.sessions, k)
		}
	}
	// Cap total sessions by evicting oldest if needed.
	for len(a.sessions) >= maxAdminSessions {
		var oldestKey string
		var oldestTime time.Time
		for k, s := range a.sessions {
			if oldestKey == "" || s.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = s.createdAt
			}
		}
		if oldestKey != "" {
			delete(a.sessions, oldestKey)
		} else {
			break
		}
	}
	a.sessions[key] = adminSession{
		username:  a.username,
		createdAt: now,
		expiresAt: expiresAt,
	}
	return rawToken, expiresAt, nil
}

func (a *adminAuthManager) validateToken(rawToken string, now time.Time) (string, bool) {
	if len(rawToken) < 32 {
		return "", false
	}
	key := hashSessionToken(rawToken)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	if !ok {
		return "", false
	}
	if !now.Before(s.expiresAt) {
		delete(a.sessions, key)
		return "", false
	}
	return s.username, true
}

func (a *adminAuthManager) revokeToken(rawToken string) {
	if rawToken == "" {
		return
	}
	key := hashSessionToken(rawToken)
	a.mu.Lock()
	delete(a.sessions, key)
	a.mu.Unlock()
}

func hashSessionToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func clientIPForRateLimit(r *http.Request) string {
	if isLoopbackRemote(r.RemoteAddr) {
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" && net.ParseIP(xri) != nil {
			return xri
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return isLoopbackRemote(r.RemoteAddr) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (s *Server) hasValidAPIKey(r *http.Request) bool {
	if len(s.cfg.APIKeys) == 0 {
		return false
	}
	got := extractBearer(r.Header.Get("Authorization"))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("x-api-key"))
	}
	if got == "" {
		return false
	}
	for _, k := range s.cfg.APIKeys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(k)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) sessionFromRequest(r *http.Request) (username string, rawToken string, ok bool) {
	c, err := r.Cookie(adminSessionCookieName)
	if err != nil || c == nil || c.Value == "" {
		return "", "", false
	}
	u, valid := s.adminAuth.validateToken(c.Value, time.Now())
	if !valid {
		return "", "", false
	}
	return u, c.Value, true
}

func (s *Server) withAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if _, _, ok := s.sessionFromRequest(r); ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(adminCSRFHeader) != adminCSRFValue {
				writeOpenAIError(w, http.StatusForbidden, "csrf_check_failed", "authentication_error", "Missing required admin request header.")
				return
			}
			next(w, r)
			return
		}
		if s.hasValidAPIKey(r) {
			next(w, r)
			return
		}
		writeOpenAIError(w, http.StatusUnauthorized, "admin_auth_required", "authentication_error", "Administrator sign-in or valid API key required.")
	}
}

func (s *Server) handleAdminAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	now := time.Now()
	ip := clientIPForRateLimit(r)
	if blocked, retrySec := s.adminAuth.checkRateLimit(ip, now); blocked {
		w.Header().Set("Retry-After", itoa(retrySec))
		writeOpenAIError(w, http.StatusTooManyRequests, "too_many_attempts", "rate_limit_error", "Too many failed sign-in attempts. Try again later.")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := decodeStrictJSON(r, 4096, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}
	if !s.adminAuth.verifyCredentials(req.Username, req.Password) {
		s.adminAuth.recordFailure(ip, now)
		log.Printf("[admin] failed login attempt ip=%s", ip)
		writeOpenAIError(w, http.StatusUnauthorized, "invalid_credentials", "authentication_error", "Invalid username or password.")
		return
	}
	s.adminAuth.clearFailures(ip)
	ttl := defaultSessionTTL
	if req.Remember {
		ttl = rememberSessionTTL
	}
	tok, exp, err := s.adminAuth.createSession(ttl, now)
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "session_error", "api_error", "Failed to create session.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    tok,
		Path:     "/admin/",
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	log.Printf("[admin] administrator signed in username=%s ip=%s", s.adminAuth.username, ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"username":   s.adminAuth.username,
		"expires_at": exp.Unix(),
	})
}

func (s *Server) handleAdminAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	if _, raw, ok := s.sessionFromRequest(r); ok {
		if r.Header.Get(adminCSRFHeader) != adminCSRFValue {
			writeOpenAIError(w, http.StatusForbidden, "csrf_check_failed", "authentication_error", "Missing required admin request header.")
			return
		}
		s.adminAuth.revokeToken(raw)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/admin/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleAdminAuthMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only GET is allowed.")
		return
	}
	if u, _, ok := s.sessionFromRequest(r); ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"username":      u,
			"mode":          "session",
		})
		return
	}
	if s.hasValidAPIKey(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"username":      s.adminAuth.username,
			"mode":          "api_key",
		})
		return
	}
	writeOpenAIError(w, http.StatusUnauthorized, "admin_auth_required", "authentication_error", "Not signed in.")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
