package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"quick2api/internal/auth"
	"quick2api/internal/config"
	"quick2api/internal/models"
	"quick2api/internal/netproxy"
	"quick2api/internal/prompt"
	"quick2api/internal/quick"
)

// Server serves OpenAI-compatible HTTP endpoints backed by Amazon Quick.
type Server struct {
	cfg      config.Config
	store    *auth.Store
	manager  *quick.Manager
	sem      chan struct{}
	mux      *http.ServeMux
	imgHTTP  *http.Client
	probeURL string // fixed HTTPS IP echo endpoint (overridable in unit tests)
}

// New creates a configured HTTP handler.
func New(cfg config.Config, store *auth.Store, manager *quick.Manager) *Server {
	s := &Server{
		cfg:      cfg,
		store:    store,
		manager:  manager,
		sem:      make(chan struct{}, cfg.MaxConcurrentTurn),
		mux:      http.NewServeMux(),
		imgHTTP:  &http.Client{Timeout: 15 * time.Second},
		probeURL: "https://api.ipify.org?format=json",
	}
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/models", s.withAuth(s.handleModels))
	s.mux.HandleFunc("/v1/models/", s.withAuth(s.handleModelGet))
	s.mux.HandleFunc("/v1/chat/completions", s.withAuth(s.handleChatCompletions))
	s.mux.HandleFunc("/admin/status", s.withAuth(s.handleAdminStatus))
	s.mux.HandleFunc("/admin/reload", s.withAuth(s.handleAdminReload))
	s.mux.HandleFunc("/admin/accounts/proxy", s.withAuth(s.handleAdminAccountProxy))
	s.mux.HandleFunc("/admin/accounts/probe-proxy", s.withAuth(s.handleAdminProbeProxy))
	s.mux.HandleFunc("/admin/accounts/reset-cooldown", s.withAuth(s.handleAdminResetCooldown))
	return s
}

// ReloadAccounts atomically reloads accounts.json and reconciles cached WebSocket connections.
func (s *Server) ReloadAccounts() (auth.ReloadResult, error) {
	res, err := s.store.Reload()
	if err != nil {
		return auth.ReloadResult{}, err
	}
	s.manager.ReconcileReload(res)
	return res, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.APIKeys) > 0 {
			got := extractBearer(r.Header.Get("Authorization"))
			if got == "" {
				got = strings.TrimSpace(r.Header.Get("x-api-key"))
			}
			ok := false
			for _, k := range s.cfg.APIKeys {
				if subtle.ConstantTimeCompare([]byte(got), []byte(k)) == 1 {
					ok = true
					break
				}
			}
			if !ok {
				writeOpenAIError(w, http.StatusUnauthorized, "invalid_api_key", "authentication_error", "Invalid or missing API key.")
				return
			}
		}
		next(w, r)
	}
}

func extractBearer(hdr string) string {
	hdr = strings.TrimSpace(hdr)
	if len(hdr) > 7 && strings.EqualFold(hdr[:7], "Bearer ") {
		return strings.TrimSpace(hdr[7:])
	}
	return hdr
}

const serviceName = "quick2api"

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	enabled := s.store.AccountCount()
	status := http.StatusOK
	label := "ok"
	if enabled == 0 {
		status = http.StatusServiceUnavailable
		label = "degraded"
	}
	w.Header().Set("X-Service", serviceName)
	writeJSON(w, status, map[string]any{
		"status":             label,
		"service":            serviceName,
		"enabled_accounts":   enabled,
		"active_connections": s.manager.ActiveConnections(),
	})
}

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	statuses := s.store.Statuses()
	resp := map[string]any{
		"status":             "ok",
		"active_connections": s.manager.ActiveConnections(),
		"accounts":           statuses,
	}
	if r.URL.Query().Get("usage") == "1" {
		usages := map[string]any{}
		for _, st := range statuses {
			if st.Disabled {
				continue
			}
			uctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			acct, err := s.store.EnsureFresh(uctx, st.ID, false)
			if err == nil {
				u, err2 := s.manager.FetchUsage(uctx, acct)
				if err2 == nil {
					usages[st.ID] = u
					if q := quick.ParseQuota(u); q != nil {
						s.store.UpdateQuota(st.ID, q)
					}
				} else {
					usages[st.ID] = map[string]string{"error": err2.Error()}
				}
			} else {
				usages[st.ID] = map[string]string{"error": err.Error()}
			}
			cancel()
		}
		resp["usage"] = usages
		resp["accounts"] = s.store.Statuses()
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodeStrictJSON(r *http.Request, maxBytes int64, dst any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return errors.New("failed to read request body")
	}
	if int64(len(body)) > maxBytes {
		return errors.New("request body too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON request body")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func (s *Server) handleAdminReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	res, err := s.ReloadAccounts()
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "reload_failed", "invalid_request_error", err.Error())
		return
	}
	log.Printf("[admin] hot reloaded accounts total=%d enabled=%d added=%v removed=%v disabled=%v proxy_changed=%v",
		res.Total, res.Enabled, res.Added, res.Removed, res.Disabled, res.ProxyChanged)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"reload": res,
	})
}

func (s *Server) handleAdminAccountProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		ID       string  `json:"id"`
		ProxyURL *string `json:"proxy_url"`
	}
	if err := decodeStrictJSON(r, 8192, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" || req.ProxyURL == nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", "Both `id` and `proxy_url` fields are required (use empty string to clear or \"direct\" to bypass global proxy).")
		return
	}
	changed, status, err := s.store.SetAccountProxy(req.ID, *req.ProxyURL)
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "not found") {
			code = http.StatusNotFound
		}
		writeOpenAIError(w, code, "proxy_update_failed", "invalid_request_error", err.Error())
		return
	}
	if changed {
		s.manager.InvalidateConn(req.ID)
		log.Printf("[admin] updated outbound proxy account=%s proxy=%s", req.ID, netproxy.Redact(*req.ProxyURL))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"changed": changed,
		"account": status,
	})
}

func (s *Server) handleAdminProbeProxy(w http.ResponseWriter, r *http.Request) {
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
	acct, ok := s.store.GetAccount(strings.TrimSpace(req.ID))
	if !ok {
		writeOpenAIError(w, http.StatusNotFound, "account_not_found", "invalid_request_error", "Account not found.")
		return
	}
	egressIP, latencyMs, err := s.manager.ProbeProxy(r.Context(), acct, s.probeURL)
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "proxy_probe_failed", "api_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"id":         acct.ID,
		"proxy":      netproxy.Redact(s.store.EffectiveProxyURL(acct)),
		"egress_ip":  egressIP,
		"latency_ms": latencyMs,
	})
}

func (s *Server) handleAdminResetCooldown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if r.ContentLength != 0 {
		if err := decodeStrictJSON(r, 4096, &req); err != nil {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", err.Error())
			return
		}
	}
	cleared := s.store.ResetCooldown(strings.TrimSpace(req.ID))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"cleared": cleared,
	})
}

func (s *Server) applyQuotaOrRateCooldown(acct auth.Account, evKind, msg string) {
	if evKind == "rate_limited" {
		d := s.store.MarkRateLimited(acct.ID, msg)
		log.Printf("[chat] rate_limited account=%s cooldown=%s", acct.ID, d.Round(time.Second))
		return
	}
	// usage_blocked: set immediate interim session cooldown so concurrent requests rotate away,
	// then query profile/usage (bounded 5s) to distinguish monthly vs session vs trial expiry.
	fallbackKind := auth.CooldownSessionQuota
	fallbackDur := 30 * time.Minute
	if strings.Contains(strings.ToLower(msg), "monthly") {
		fallbackKind = auth.CooldownMonthlyQuota
		fallbackDur = 6 * time.Hour
	}
	s.store.MarkCooldownWithKind(acct.ID, fallbackKind, fallbackDur, msg)

	if acct.TenantURL != "" && acct.AccessToken != "" {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		raw, err := s.manager.FetchUsage(uctx, acct)
		cancel()
		if err == nil {
			if q := quick.ParseQuota(raw); q != nil {
				if qKind, qDur := s.store.UpdateQuota(acct.ID, q); qKind != "" {
					log.Printf("[chat] usage_blocked classified account=%s kind=%s cooldown=%s (monthly=%d/%d session=%d/%d)",
						acct.ID, qKind, qDur.Round(time.Second), q.MonthlyUsed, q.MonthlyLimit, q.SessionUsed, q.SessionLimit)
					return
				}
			}
		}
	}
	log.Printf("[chat] usage_blocked account=%s kind=%s cooldown=%s", acct.ID, fallbackKind, fallbackDur)
}

func modelCatalogEntry(m models.ModelSpec, created int64) map[string]any {
	return map[string]any{
		"id":                 m.ID,
		"object":             "model",
		"created":            created,
		"owned_by":           m.OwnedBy,
		"context_length":     m.ContextWindow,
		"context_window":     m.ContextWindow,
		"max_output_tokens":  m.MaxOutputTokens,
		"supports_images":    m.SupportsImages,
		"supports_tool_call": m.SupportsToolCall,
		"supports_reasoning": m.SupportsReasoning,
	}
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only GET is allowed.")
		return
	}
	now := time.Now().Unix()
	data := make([]map[string]any, 0, len(models.Catalog))
	for _, m := range models.Catalog {
		data = append(data, modelCatalogEntry(m, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

func (s *Server) handleModelGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/models/")
	resolved, ok := models.Resolve(id, "")
	if !ok {
		writeOpenAIError(w, http.StatusNotFound, "model_not_found", "invalid_request_error", fmt.Sprintf("Model %q not found.", id))
		return
	}
	now := time.Now().Unix()
	if spec, found := models.LookupCatalog(resolved.CanonicalID); found {
		writeJSON(w, http.StatusOK, modelCatalogEntry(spec, now))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             resolved.CanonicalID,
		"object":         "model",
		"created":        now,
		"owned_by":       "amazon-quick",
		"context_length": 1000000,
		"context_window": 1000000,
	})
}
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "invalid_request_error", "Only POST is allowed.")
		return
	}

	chatID := "chatcmpl-" + strings.ReplaceAll(quick.NewUUID(), "-", "")[:24]
	w.Header().Set("X-Request-Id", chatID)

	maxBody := s.cfg.MaxBodyBytes()
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "invalid_request_error", "Failed to read request body.")
		return
	}
	if int64(len(rawBody)) > maxBody {
		writeOpenAIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "invalid_request_error", fmt.Sprintf("Request body exceeds %d MB limit.", maxBody>>20))
		return
	}
	var req prompt.ChatCompletionRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_json", "invalid_request_error", "Malformed JSON request body: "+err.Error())
		return
	}
	if len(req.Messages) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "missing_messages", "invalid_request_error", "`messages` must be a non-empty array.")
		return
	}

	effEffort := req.EffectiveReasoningEffort(models.BudgetToEffort)
	target, ok := models.Resolve(req.Model, effEffort)
	if !ok {
		writeOpenAIError(w, http.StatusBadRequest, "model_not_found", "invalid_request_error", fmt.Sprintf("Unsupported model %q.", req.Model))
		return
	}

	// Acquire concurrency slot.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-r.Context().Done():
		return
	}

	converted := prompt.Convert(req)
	stops := prompt.ParseStopSequences(req.Stop)
	created := time.Now().Unix()
	modelEcho := target.RequestedModel
	if modelEcho == "" {
		modelEcho = target.CanonicalID
	}
	includeUsage := req.StreamOptions != nil && req.StreamOptions.IncludeUsage

	triedAccounts := make(map[string]bool)
	maxRotate := s.store.AccountCount()
	if maxRotate < 1 {
		maxRotate = 1
	}
	retriedStale := false
	var lastRotateErr string

	for attempt := 0; attempt < maxRotate+1; attempt++ {
		turnCtx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout())
		acct, eventCh, err := s.startTurnWithRetry(turnCtx, target, converted, triedAccounts)
		if err != nil {
			cancel()
			status := http.StatusBadGateway
			errType := "api_error"
			errCode := "upstream_error"
			msg := err.Error()
			if strings.Contains(strings.ToLower(msg), "cooldown") {
				status = http.StatusTooManyRequests
				errType = "rate_limit_error"
				errCode = "rate_limit_exceeded"
				if lastRotateErr != "" {
					msg = lastRotateErr
				}
			}
			writeOpenAIError(w, status, errCode, errType, msg)
			return
		}

		canRetryStale := !retriedStale
		canRotate := len(triedAccounts)+1 < maxRotate
		var retryAction retryDirective
		if req.Stream {
			retryAction = s.serveSSE(w, cancel, acct, chatID, created, modelEcho, converted, stops, includeUsage, eventCh, canRetryStale, canRotate)
		} else {
			retryAction = s.serveNonStreaming(w, cancel, acct, chatID, created, modelEcho, converted, stops, eventCh, canRetryStale, canRotate)
		}
		cancel()

		switch retryAction.kind {
		case "stale_conn":
			retriedStale = true
			s.manager.InvalidateConn(acct.ID)
			log.Printf("[chat] stale WS closed before first output account=%s; retrying once", acct.ID)
			continue
		case "rotate_account":
			triedAccounts[acct.ID] = true
			lastRotateErr = retryAction.errMsg
			log.Printf("[chat] rotating away from rate-limited account=%s", acct.ID)
			continue
		default:
			return
		}
	}
}

type retryDirective struct {
	kind   string // "", "stale_conn", "rotate_account"
	errMsg string
}

func (s *Server) startTurnWithRetry(ctx context.Context, target models.ResolvedTarget, converted prompt.ConvertedPrompt, exclude map[string]bool) (auth.Account, <-chan quick.StreamEvent, error) {
	acct, err := s.store.PickAccountExcluding(ctx, exclude)
	if err != nil {
		return auth.Account{}, nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		attachments, attErr := s.uploadImages(ctx, acct, converted.Images)
		if attErr != nil {
			var ae *quick.AuthError
			if errors.As(attErr, &ae) && attempt == 0 {
				s.manager.InvalidateConn(acct.ID)
				if refreshed, rerr := s.store.EnsureFresh(ctx, acct.ID, true); rerr == nil {
					acct = refreshed
					continue
				}
			}
			// Non-auth image upload failure: log and proceed with text rather than hard-failing.
			log.Printf("[chat] image upload warning account=%s: %v", acct.ID, attErr)
		}

		ch, serr := s.manager.StreamTurn(ctx, acct, quick.TurnRequest{
			Text:           converted.Text,
			CustomPrompt:   converted.CustomPrompt,
			AgentMode:      target.AgentMode,
			ThinkingEffort: target.ThinkingEffort,
			Attachments:    attachments,
			SurfaceType:    s.cfg.DefaultSurface,
		})
		if serr == nil {
			return acct, ch, nil
		}

		var ae *quick.AuthError
		if errors.As(serr, &ae) && attempt == 0 {
			log.Printf("[chat] auth error on account=%s, forcing sso-oidc refresh and retrying", acct.ID)
			s.manager.InvalidateConn(acct.ID)
			refreshed, rerr := s.store.EnsureFresh(ctx, acct.ID, true)
			if rerr != nil {
				s.store.MarkCooldown(acct.ID, 2*time.Minute, rerr.Error())
				return auth.Account{}, nil, rerr
			}
			acct = refreshed
			continue
		}
		return auth.Account{}, nil, serr
	}
	return auth.Account{}, nil, errors.New("failed to start Quick turn after retry")
}

func (s *Server) uploadImages(ctx context.Context, acct auth.Account, imgs []prompt.PendingImage) ([]quick.Attachment, error) {
	if len(imgs) == 0 {
		return nil, nil
	}
	out := make([]quick.Attachment, 0, len(imgs))
	for _, img := range imgs {
		data := img.Data
		mimeType := img.MimeType
		if len(data) == 0 && img.URL != "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, img.URL, nil)
			if err != nil {
				continue
			}
			resp, err := s.imgHTTP.Do(req)
			if err != nil {
				continue
			}
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
			resp.Body.Close()
			if rerr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || len(b) == 0 {
				continue
			}
			data = b
			if mimeType == "" {
				mimeType = resp.Header.Get("Content-Type")
			}
			if mimeType == "" {
				mimeType = http.DetectContentType(data)
			}
		}
		if len(data) == 0 {
			continue
		}
		att, err := s.manager.UploadAttachment(ctx, acct, img.Name, mimeType, data)
		if err != nil {
			return out, err
		}
		out = append(out, att)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// OpenAI Streaming (SSE) & Non-Streaming response builders
// ---------------------------------------------------------------------------

type openAIUsage struct {
	PromptTokens             int                 `json:"prompt_tokens"`
	CompletionTokens         int                 `json:"completion_tokens"`
	TotalTokens              int                 `json:"total_tokens"`
	PromptTokensDetails      *promptTokenDetails `json:"prompt_tokens_details,omitempty"`
	CacheReadInputTokens     int                 `json:"cache_read_input_tokens,omitempty"`
	PromptCacheHitTokens     int                 `json:"prompt_cache_hit_tokens,omitempty"`
	CacheCreationInputTokens int                 `json:"cache_creation_input_tokens,omitempty"`
}

type promptTokenDetails struct {
	CachedTokens int `json:"cached_tokens"`
}

func toOpenAIUsage(u *quick.TurnUsage) *openAIUsage {
	if u == nil {
		return nil
	}
	promptTok := u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens
	if promptTok == 0 && u.TotalTokens > u.OutputTokens {
		promptTok = u.TotalTokens - u.OutputTokens
	}
	out := &openAIUsage{
		PromptTokens:     promptTok,
		CompletionTokens: u.OutputTokens,
		TotalTokens:      promptTok + u.OutputTokens,
	}
	if u.CacheReadTokens > 0 {
		out.PromptTokensDetails = &promptTokenDetails{CachedTokens: u.CacheReadTokens}
		out.CacheReadInputTokens = u.CacheReadTokens
		out.PromptCacheHitTokens = u.CacheReadTokens
	}
	if u.CacheWriteTokens > 0 {
		out.CacheCreationInputTokens = u.CacheWriteTokens
	}
	return out
}

func (s *Server) serveSSE(
	w http.ResponseWriter,
	cancel context.CancelFunc,
	acct auth.Account,
	chatID string,
	created int64,
	modelName string,
	converted prompt.ConvertedPrompt,
	stops []string,
	includeUsage bool,
	eventCh <-chan quick.StreamEvent,
	canRetryStale bool,
	canRotate bool,
) retryDirective {
	flusher, canFlush := w.(http.Flusher)

	headersSent := false
	sentRole := false
	emittedOutput := false
	hitStop := false

	ensureHeaders := func() {
		if headersSent {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		headersSent = true
	}

	keepAliveInterval := s.cfg.SSEKeepAliveInterval()
	var keepAliveTimer *time.Timer
	var keepAliveCh <-chan time.Time
	if keepAliveInterval > 0 {
		keepAliveTimer = time.NewTimer(keepAliveInterval)
		keepAliveCh = keepAliveTimer.C
	}
	resetKeepAlive := func() {
		if keepAliveTimer == nil {
			return
		}
		if !keepAliveTimer.Stop() {
			select {
			case <-keepAliveTimer.C:
			default:
			}
		}
		keepAliveTimer.Reset(keepAliveInterval)
	}
	defer func() {
		if keepAliveTimer != nil {
			keepAliveTimer.Stop()
		}
	}()

	writeSSEErrorAndDone := func(code, errType, message string) {
		ensureHeaders()
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": message,
				"type":    errType,
				"code":    code,
			},
		})
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", b)
		if canFlush {
			flusher.Flush()
		}
	}

	writeChunk := func(delta map[string]any, finishReason *string, usage *openAIUsage) {
		ensureHeaders()
		choices := []map[string]any{}
		if delta != nil || finishReason != nil {
			d := delta
			if d == nil {
				d = map[string]any{}
			}
			if !sentRole && finishReason == nil {
				d["role"] = "assistant"
				sentRole = true
			}
			choice := map[string]any{
				"index":         0,
				"delta":         d,
				"logprobs":      nil,
				"finish_reason": finishReason,
			}
			choices = append(choices, choice)
		}
		chunk := map[string]any{
			"id":      chatID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   modelName,
			"choices": choices,
		}
		if usage != nil {
			chunk["usage"] = usage
		} else if includeUsage {
			chunk["usage"] = nil
		}
		b, _ := json.Marshal(chunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if canFlush {
			flusher.Flush()
		}
		resetKeepAlive()
	}

	parser := prompt.NewToolStreamParser(converted.ToolMode, converted.AllowedTools)
	stopFilter := prompt.NewStopFilter(stops)
	var lastUsage *quick.TurnUsage
	finishReason := "stop"

	emitParsed := func(textOut string, calls []prompt.ParsedToolCall) bool {
		if textOut != "" {
			safe, hit := stopFilter.Feed(textOut)
			if safe != "" {
				emittedOutput = true
				writeChunk(map[string]any{"content": safe}, nil, nil)
			}
			if hit {
				hitStop = true
				cancel()
				return true
			}
		}
		for _, tc := range calls {
			emittedOutput = true
			idx := tc.Index
			writeChunk(map[string]any{
				"tool_calls": []prompt.ToolCall{{
					Index: &idx,
					ID:    tc.ID,
					Type:  "function",
					Function: prompt.ToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.ArgumentsJSON,
					},
				}},
			}, nil, nil)
		}
		return false
	}

	for {
		select {
		case <-keepAliveCh:
			ensureHeaders()
			_, _ = fmt.Fprint(w, ": keep-alive\n\n")
			if canFlush {
				flusher.Flush()
			}
			keepAliveTimer.Reset(keepAliveInterval)

		case ev, ok := <-eventCh:
			if !ok {
				goto finalize
			}
			switch ev.Kind {
			case "thinking_delta":
				if ev.Text != "" {
					emittedOutput = true
					writeChunk(map[string]any{"reasoning_content": ev.Text}, nil, nil)
				}
			case "text_delta":
				txt, calls := parser.Feed(ev.Text)
				if emitParsed(txt, calls) {
					goto finalize
				}
			case "turn_usage":
				if ev.Usage != nil {
					lastUsage = ev.Usage
				}
			case "tool_start":
				if s.cfg.Debug {
					log.Printf("[chat] upstream Quick invoked built-in tool=%s account=%s", ev.ToolName, acct.ID)
				}
			case "guardrail_blocked":
				if !headersSent {
					writeOpenAIError(w, http.StatusBadRequest, "content_filter", "invalid_request_error", ev.ErrorMsg)
					return retryDirective{}
				}
				emittedOutput = true
				finishReason = "content_filter"
				goto finalize
			case "usage_blocked", "rate_limited":
				s.applyQuotaOrRateCooldown(acct, ev.Kind, ev.ErrorMsg)
				if !headersSent && canRotate {
					return retryDirective{kind: "rotate_account", errMsg: ev.ErrorMsg}
				}
				if !headersSent {
					writeOpenAIError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "rate_limit_error", ev.ErrorMsg)
					return retryDirective{}
				}
				writeSSEErrorAndDone("rate_limit_exceeded", "rate_limit_error", ev.ErrorMsg)
				return retryDirective{}
			case "error":
				if ev.ErrorCode == "stream_closed" && !headersSent && canRetryStale {
					return retryDirective{kind: "stale_conn", errMsg: ev.ErrorMsg}
				}
				code := ev.ErrorCode
				if code == "" {
					code = "upstream_error"
				}
				if !headersSent {
					status := http.StatusBadGateway
					if code == "stream_idle_timeout" {
						status = http.StatusGatewayTimeout
					}
					writeOpenAIError(w, status, code, "api_error", ev.ErrorMsg)
					return retryDirective{}
				}
				log.Printf("[chat] mid-stream upstream error account=%s code=%s: %s", acct.ID, code, ev.ErrorMsg)
				writeSSEErrorAndDone(code, "api_error", ev.ErrorMsg)
				return retryDirective{}
			case "complete":
				goto finalize
			}
		}
	}

finalize:
	remText, remCalls := parser.Flush()
	_ = emitParsed(remText, remCalls)
	if tail := stopFilter.Flush(); tail != "" {
		emittedOutput = true
		writeChunk(map[string]any{"content": tail}, nil, nil)
	}

	if !emittedOutput && !hitStop {
		if !headersSent {
			writeOpenAIError(w, http.StatusBadGateway, "empty_stream", "api_error", "Upstream Quick completed with empty response.")
			return retryDirective{}
		}
		writeSSEErrorAndDone("empty_stream", "api_error", "Upstream Quick completed with empty response.")
		return retryDirective{}
	}

	if parser.HasToolCalls() && finishReason == "stop" {
		finishReason = "tool_calls"
	}

	if !sentRole {
		writeChunk(map[string]any{"content": ""}, nil, nil)
	}
	writeChunk(nil, &finishReason, nil)

	if includeUsage {
		if u := toOpenAIUsage(lastUsage); u != nil {
			writeChunk(nil, nil, u)
		}
	}
	ensureHeaders()
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	if canFlush {
		flusher.Flush()
	}
	s.store.NoteSuccess(acct.ID)
	return retryDirective{}
}

func (s *Server) serveNonStreaming(
	w http.ResponseWriter,
	cancel context.CancelFunc,
	acct auth.Account,
	chatID string,
	created int64,
	modelName string,
	converted prompt.ConvertedPrompt,
	stops []string,
	eventCh <-chan quick.StreamEvent,
	canRetryStale bool,
	canRotate bool,
) retryDirective {
	parser := prompt.NewToolStreamParser(converted.ToolMode, converted.AllowedTools)
	stopFilter := prompt.NewStopFilter(stops)

	var contentBuf strings.Builder
	var reasoningBuf strings.Builder
	var toolCalls []prompt.ToolCall
	var lastUsage *quick.TurnUsage
	finishReason := "stop"
	hitStop := false

	collect := func(textOut string, calls []prompt.ParsedToolCall) bool {
		if textOut != "" {
			safe, hit := stopFilter.Feed(textOut)
			if safe != "" {
				contentBuf.WriteString(safe)
			}
			if hit {
				hitStop = true
				cancel()
				return true
			}
		}
		for _, tc := range calls {
			toolCalls = append(toolCalls, prompt.ToolCall{
				ID:   tc.ID,
				Type: "function",
				Function: prompt.ToolCallFunction{
					Name:      tc.Name,
					Arguments: tc.ArgumentsJSON,
				},
			})
		}
		return false
	}

	for ev := range eventCh {
		switch ev.Kind {
		case "thinking_delta":
			reasoningBuf.WriteString(ev.Text)
		case "text_delta":
			txt, calls := parser.Feed(ev.Text)
			if collect(txt, calls) {
				goto done
			}
		case "turn_usage":
			if ev.Usage != nil {
				lastUsage = ev.Usage
			}
		case "guardrail_blocked":
			writeOpenAIError(w, http.StatusBadRequest, "content_filter", "invalid_request_error", ev.ErrorMsg)
			return retryDirective{}
		case "usage_blocked", "rate_limited":
			s.applyQuotaOrRateCooldown(acct, ev.Kind, ev.ErrorMsg)
			if canRotate {
				return retryDirective{kind: "rotate_account", errMsg: ev.ErrorMsg}
			}
			writeOpenAIError(w, http.StatusTooManyRequests, "rate_limit_exceeded", "rate_limit_error", ev.ErrorMsg)
			return retryDirective{}
		case "error":
			if ev.ErrorCode == "stream_closed" && canRetryStale && contentBuf.Len() == 0 && reasoningBuf.Len() == 0 && len(toolCalls) == 0 {
				return retryDirective{kind: "stale_conn", errMsg: ev.ErrorMsg}
			}
			code := ev.ErrorCode
			if code == "" {
				code = "upstream_error"
			}
			status := http.StatusBadGateway
			if code == "stream_idle_timeout" {
				status = http.StatusGatewayTimeout
			}
			writeOpenAIError(w, status, code, "api_error", ev.ErrorMsg)
			return retryDirective{}
		case "complete":
			goto done
		}
	}

done:
	remText, remCalls := parser.Flush()
	_ = collect(remText, remCalls)
	if tail := stopFilter.Flush(); tail != "" {
		contentBuf.WriteString(tail)
	}

	if contentBuf.Len() == 0 && reasoningBuf.Len() == 0 && len(toolCalls) == 0 && !hitStop {
		writeOpenAIError(w, http.StatusBadGateway, "empty_stream", "api_error", "Upstream Quick completed with empty response.")
		return retryDirective{}
	}

	if len(toolCalls) > 0 && finishReason == "stop" {
		finishReason = "tool_calls"
	}

	msg := map[string]any{
		"role":    "assistant",
		"refusal": nil,
	}
	contentStr := contentBuf.String()
	if len(toolCalls) > 0 && strings.TrimSpace(contentStr) == "" {
		msg["content"] = nil
	} else {
		msg["content"] = contentStr
	}
	if reasoningBuf.Len() > 0 {
		msg["reasoning_content"] = reasoningBuf.String()
	}
	if len(toolCalls) > 0 {
		msg["tool_calls"] = toolCalls
	}

	resp := map[string]any{
		"id":      chatID,
		"object":  "chat.completion",
		"created": created,
		"model":   modelName,
		"choices": []map[string]any{{
			"index":         0,
			"message":       msg,
			"logprobs":      nil,
			"finish_reason": finishReason,
		}},
	}
	if u := toOpenAIUsage(lastUsage); u != nil {
		resp["usage"] = u
	}
	writeJSON(w, http.StatusOK, resp)
	s.store.NoteSuccess(acct.ID)
	return retryDirective{}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOpenAIError(w http.ResponseWriter, status int, code, errType, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    errType,
			"code":    code,
		},
	})
}
