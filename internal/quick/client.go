package quick

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"quick2api/internal/auth"
	"quick2api/internal/netproxy"
)
// AuthError indicates an HTTP 401/403 from the Quick AIDP gateway (token rejected).
type AuthError struct {
	Status int
	Msg    string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("quick auth error (%d): %s", e.Status, e.Msg)
}

// Attachment represents a cloud attachment reference on user_message.
type Attachment struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	Size          int    `json:"size"`
	MimeType      string `json:"mimeType"`
	Path          string `json:"path,omitempty"`
	AttachmentID  string `json:"attachmentId,omitempty"`
	ContentSha256 string `json:"contentSha256,omitempty"`
	Data          string `json:"data,omitempty"`
}

// TurnRequest holds all parameters to start one Quick chat turn.
type TurnRequest struct {
	ThreadID            string
	Text                string
	CustomPrompt        string
	CompactCustomPrompt string
	StageableCustomBody string
	AgentMode           string
	ThinkingEffort      string
	Attachments         []Attachment
	SurfaceType         string
}
// TurnUsage holds token and model metadata emitted by Quick's turn_usage frame.
type TurnUsage struct {
	InputTokens      int     `json:"input_tokens"`
	OutputTokens     int     `json:"output_tokens"`
	CacheReadTokens  int     `json:"cache_read_tokens"`
	CacheWriteTokens int     `json:"cache_write_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	Model            string  `json:"model"`
	ResolvedModelID  string  `json:"resolved_model_id"`
	ServedModelID    string  `json:"served_model_id"`
	CostUSD          float64 `json:"cost_usd"`
	ContextWindow    int     `json:"context_window"`
}

// StreamEvent represents a single normalized event delivered to a turn consumer.
type StreamEvent struct {
	Kind        string // "text_delta", "thinking_delta", "turn_usage", "complete", "error", "guardrail_blocked", "usage_blocked", "rate_limited", "tool_start"
	Text        string
	Usage       *TurnUsage
	ErrorCode   string
	ErrorMsg    string
	Retryable   bool
	FailedFrame string
	ToolName    string
}
// Manager manages per-account persistent AIDP WebSocket connections and REST calls.
type Manager struct {
	store         *auth.Store
	surfaceType   string
	deleteSession bool
	proxyURL      string
	debug         bool
	idleTimeout   time.Duration
	baseTr        *http.Transport

	clientMu    sync.Mutex
	httpClients map[string]*http.Client // keyed by effective resolved proxy URL

	mu    sync.Mutex
	conns map[string]*accountConn
}

// NewManager creates a Quick transport manager.
func NewManager(store *auth.Store, surfaceType string, deleteSession bool, proxyURL string, debug bool) (*Manager, error) {
	if surfaceType == "" {
		surfaceType = "QUICK_WORK_DESKTOP_WINDOWS"
	}
	if err := netproxy.Validate(proxyURL); err != nil {
		return nil, err
	}
	baseTr := &http.Transport{
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &Manager{
		store:         store,
		surfaceType:   surfaceType,
		deleteSession: deleteSession,
		proxyURL:      strings.TrimSpace(proxyURL),
		debug:         debug,
		idleTimeout:   120 * time.Second,
		baseTr:        baseTr,
		httpClients:   make(map[string]*http.Client),
		conns:         make(map[string]*accountConn),
	}, nil
}

func (m *Manager) effectiveProxy(acct auth.Account) string {
	return netproxy.Resolve(acct.ProxyURL, m.proxyURL)
}

func (m *Manager) httpClientForProxy(effectiveProxy string) (*http.Client, error) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if c, ok := m.httpClients[effectiveProxy]; ok {
		return c, nil
	}
	tr, err := netproxy.NewTransport(m.baseTr, effectiveProxy)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Transport: tr, Timeout: 35 * time.Second}
	m.httpClients[effectiveProxy] = c
	return c, nil
}

// SetStreamIdleTimeout configures the per-turn idle watchdog duration (<=0 disables).
func (m *Manager) SetStreamIdleTimeout(d time.Duration) {
	m.mu.Lock()
	m.idleTimeout = d
	m.mu.Unlock()
}

func (m *Manager) getIdleTimeout() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.idleTimeout
}
// Close terminates all open WebSocket connections cleanly.
func (m *Manager) Close() {
	m.mu.Lock()
	conns := make([]*accountConn, 0, len(m.conns))
	for _, c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = make(map[string]*accountConn)
	m.mu.Unlock()
	for _, c := range conns {
		c.close("shutdown")
	}
}

// ActiveConnections returns the number of currently live account WebSocket connections.
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.conns {
		if c.isAlive() {
			n++
		}
	}
	return n
}

// InvalidateConn closes and removes the cached WS connection for an account (e.g. after 401/refresh/proxy change).
func (m *Manager) InvalidateConn(accountID string) {
	m.mu.Lock()
	c, ok := m.conns[accountID]
	if ok {
		delete(m.conns, accountID)
	}
	m.mu.Unlock()
	if ok && c != nil {
		c.close("invalidated")
	}
}

// ReconcileReload closes cached WebSockets only for accounts that were removed, disabled,
// or changed outbound proxy, leaving unchanged healthy accounts' connections intact.
func (m *Manager) ReconcileReload(res auth.ReloadResult) {
	seen := make(map[string]bool)
	for _, list := range [][]string{res.Removed, res.Disabled, res.ProxyChanged} {
		for _, id := range list {
			if id != "" && !seen[id] {
				seen[id] = true
				m.InvalidateConn(id)
			}
		}
	}
}

// getOrDialConn returns an existing live WS connection for acct or dials a new one.
func (m *Manager) getOrDialConn(ctx context.Context, acct auth.Account) (*accountConn, error) {
	effProxy := m.effectiveProxy(acct)
	m.mu.Lock()
	if c, ok := m.conns[acct.ID]; ok && c.isAlive() && c.token == acct.AccessToken && c.proxyURL == effProxy {
		m.mu.Unlock()
		return c, nil
	}
	if old, ok := m.conns[acct.ID]; ok {
		delete(m.conns, acct.ID)
		go old.close("replaced")
	}
	m.mu.Unlock()

	c, err := m.dialAccountConn(ctx, acct)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if existing, ok := m.conns[acct.ID]; ok && existing.isAlive() && existing.token == acct.AccessToken && existing.proxyURL == effProxy {
		m.mu.Unlock()
		c.close("superseded")
		return existing, nil
	}
	m.conns[acct.ID] = c
	m.mu.Unlock()
	return c, nil
}

// FetchIdentity opens (or reuses) an account's persistent AIDP WebSocket so the
// `connected` frame populates the account's real Email & DisplayName in the store.
func (m *Manager) FetchIdentity(ctx context.Context, acct auth.Account) error {
	_, err := m.getOrDialConn(ctx, acct)
	return err
}

// StreamTurn executes a chat turn on acct and streams normalized events to the returned channel.
// Oversized prompts (> MaxInnerUserMessageBytes) are automatically staged across multiple
// sequential turns on the same thread_id so SNCS never rejects them with FrameTooLarge.
func (m *Manager) StreamTurn(ctx context.Context, acct auth.Account, req TurnRequest) (<-chan StreamEvent, error) {
	threadID := req.ThreadID
	if threadID == "" {
		threadID = NewUUID()
	}
	surface := req.SurfaceType
	if surface == "" {
		surface = m.surfaceType
	}

	turns, rawInnerBytes, err := PlanTurnFrames(req, surface, MaxInnerUserMessageBytes)
	if err != nil {
		return nil, err
	}

	conn, err := m.getOrDialConn(ctx, acct)
	if err != nil {
		return nil, err
	}

	ch := conn.registerThread(threadID)
	if len(turns) > 1 {
		log.Printf("[quick-ws] staging oversized prompt account=%s thread=%s inner_bytes=%d parts=%d",
			acct.ID, threadID, rawInnerBytes, len(turns))
	}

	first := turns[0]
	firstFrame := buildUserMessageFrame(threadID, surface, req.AgentMode, first.ThinkingEffort, first.CustomPrompt, first.Text, first.Attachments)
	if err := conn.sendJSON(firstFrame); err != nil {
		conn.unregisterThread(threadID)
		m.InvalidateConn(acct.ID)
		return nil, fmt.Errorf("send user_message: %w", err)
	}

	out := make(chan StreamEvent, 64)
	go func() {
		defer close(out)
		defer func() {
			conn.unregisterThread(threadID)
			if m.deleteSession {
				_ = conn.sendJSON(map[string]any{
					"type": "session_delete",
					"payload": map[string]any{
						"session_id": threadID,
					},
				})
			}
		}()

		emit := func(ev StreamEvent) bool {
			select {
			case out <- ev:
				return true
			case <-ctx.Done():
				return false
			}
		}

		stageIdx := 0
		lastIdx := len(turns) - 1
		sawUsage := false
		completed := false
		var drainTimer *time.Timer
		var drainCh <-chan time.Time

		stopDrain := func() {
			if drainTimer != nil {
				if !drainTimer.Stop() {
					select {
					case <-drainTimer.C:
					default:
					}
				}
				drainTimer = nil
				drainCh = nil
			}
		}
		defer stopDrain()

		idleDur := m.getIdleTimeout()
		var idleTimer *time.Timer
		var idleCh <-chan time.Time
		if idleDur > 0 {
			idleTimer = time.NewTimer(idleDur)
			idleCh = idleTimer.C
		}
		resetIdle := func() {
			if idleTimer == nil {
				return
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleDur)
		}
		defer func() {
			if idleTimer != nil {
				idleTimer.Stop()
			}
		}()

		for {
			select {
			case <-ctx.Done():
				_ = conn.sendJSON(map[string]any{
					"type": "stop_generation",
					"payload": map[string]any{
						"thread_id": threadID,
					},
				})
				select {
				case out <- StreamEvent{Kind: "error", ErrorCode: "context_canceled", ErrorMsg: ctx.Err().Error()}:
				default:
				}
				return

			case <-idleCh:
				if completed && stageIdx == lastIdx {
					emit(StreamEvent{Kind: "complete"})
					return
				}
				_ = conn.sendJSON(map[string]any{
					"type": "stop_generation",
					"payload": map[string]any{
						"thread_id": threadID,
					},
				})
				emit(StreamEvent{
					Kind:      "error",
					ErrorCode: "stream_idle_timeout",
					ErrorMsg:  fmt.Sprintf("upstream Quick turn stalled with no events for %s", idleDur),
				})
				return

			case <-drainCh:
				emit(StreamEvent{Kind: "complete"})
				return

			case ev, ok := <-ch:
				if !ok {
					if completed && stageIdx == lastIdx {
						emit(StreamEvent{Kind: "complete"})
						return
					}
					emit(StreamEvent{Kind: "error", ErrorCode: "stream_closed", ErrorMsg: "upstream WebSocket closed before message_complete", Retryable: true})
					return
				}
				resetIdle()

				// Staging turns (0 .. lastIdx-1): consume acknowledgment internally and advance to next part.
				if stageIdx < lastIdx {
					switch ev.Kind {
					case "error", "guardrail_blocked", "usage_blocked", "rate_limited":
						emit(ev)
						return
					case "complete":
						stageIdx++
						nextTurn := turns[stageIdx]
						nextFrame := buildUserMessageFrame(threadID, surface, req.AgentMode, nextTurn.ThinkingEffort, nextTurn.CustomPrompt, nextTurn.Text, nextTurn.Attachments)
						if err := conn.sendJSON(nextFrame); err != nil {
							m.InvalidateConn(acct.ID)
							emit(StreamEvent{
								Kind:      "error",
								ErrorCode: "stream_closed",
								ErrorMsg:  fmt.Sprintf("send staged part %d/%d: %v", stageIdx+1, len(turns), err),
								Retryable: true,
							})
							return
						}
					}
					continue
				}

				switch ev.Kind {
				case "turn_usage":
					sawUsage = true
					if !emit(ev) {
						return
					}
					if completed {
						stopDrain()
						emit(StreamEvent{Kind: "complete"})
						return
					}
				case "complete":
					completed = true
					if sawUsage {
						emit(ev)
						return
					}
					drainTimer = time.NewTimer(800 * time.Millisecond)
					drainCh = drainTimer.C
				case "error", "guardrail_blocked", "usage_blocked", "rate_limited":
					emit(ev)
					return
				default:
					if !emit(ev) {
						return
					}
				}
			}
		}
	}()
	return out, nil
}

// FetchUsage calls POST {tenant_url}/integration/quick-work/qbs-event for profile/usage.
func (m *Manager) FetchUsage(ctx context.Context, acct auth.Account) (map[string]any, error) {
	env := map[string]any{
		"eventType": "invokeAgent",
		"eventBody": map[string]any{
			"invokeAgent": map[string]any{
				"path": "profile/usage",
				"queryParams": map[string]string{
					"_method":     "GET",
					"surfaceType": m.surfaceType,
				},
				"body": map[string]any{},
			},
		},
	}
	rawBody, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, acct.TenantURL+"/integration/quick-work/qbs-event", bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("x-amzn-qs-internal-trace-id", NewUUID())
	effProxy := m.effectiveProxy(acct)
	hc, err := m.httpClientForProxy(effProxy)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &AuthError{Status: resp.StatusCode, Msg: string(body)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qbs-event profile/usage failed (%d): %s", resp.StatusCode, truncate(string(body), 300))
	}

	var outer map[string]any
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, err
	}
	var inner any = outer
	if er, ok := outer["eventResponse"].(map[string]any); ok {
		if iar, ok := er["invokeAgentResponse"]; ok {
			inner = iar
		}
	}
	if s, ok := inner.(string); ok {
		var m2 map[string]any
		if err := json.Unmarshal([]byte(s), &m2); err == nil {
			inner = m2
		}
	}
	if m2, ok := inner.(map[string]any); ok {
		if m2["type"] == "api_response" {
			if bs, ok := m2["body"].(string); ok {
				var u map[string]any
				if err := json.Unmarshal([]byte(bs), &u); err == nil {
					return u, nil
				}
			}
		}
		return m2, nil
	}
	return outer, nil
}

// ParseQuota converts a raw profile/usage response map into a structured auth.QuotaInfo.
func ParseQuota(raw map[string]any) *auth.QuotaInfo {
	if len(raw) == 0 {
		return nil
	}
	q := &auth.QuotaInfo{UpdatedAt: time.Now().Unix()}
	hasAny := false
	if m, ok := raw["monthly"].(map[string]any); ok {
		q.MonthlyUsed = toInt(m["used"])
		q.MonthlyLimit = toInt(m["limit"])
		q.MonthlyPercent = toInt(m["percent"])
		q.MonthlyResetsAt = toInt64(m["resets_at"])
		hasAny = true
	}
	if s, ok := raw["session"].(map[string]any); ok {
		q.SessionUsed = toInt(s["used"])
		q.SessionLimit = toInt(s["limit"])
		q.SessionPercent = toInt(s["percent"])
		q.SessionResetsAt = toInt64(s["resets_at"])
		q.SessionResumeMin = toInt(s["resume_in_minutes"])
		hasAny = true
	}
	if sub, ok := raw["subscription"].(map[string]any); ok {
		if st, ok := sub["subscription_type"].(string); ok {
			q.SubscriptionType = st
			hasAny = true
		}
		if ft, ok := sub["free_trial_metadata"].(map[string]any); ok {
			if st, ok := ft["status"].(string); ok {
				q.TrialStatus = st
				hasAny = true
			}
		}
	}
	if !hasAny {
		return nil
	}
	return q
}

func toInt(v any) int {
	return int(toInt64(v))
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return 0
}

// ProbeProxy tests an account's resolved outbound proxy against a fixed HTTPS IP endpoint
// without sending any provider credentials.
func (m *Manager) ProbeProxy(ctx context.Context, acct auth.Account, targetURL string) (egressIP string, latencyMs int64, err error) {
	if strings.TrimSpace(targetURL) == "" {
		targetURL = "https://api.ipify.org?format=json"
	}
	effProxy := m.effectiveProxy(acct)
	hc, err := m.httpClientForProxy(effProxy)
	if err != nil {
		return "", 0, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", 0, err
	}
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("proxy probe returned HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		IP string `json:"ip"`
	}
	ipStr := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &parsed) == nil && parsed.IP != "" {
		ipStr = strings.TrimSpace(parsed.IP)
	}
	if net.ParseIP(ipStr) == nil {
		return "", 0, errors.New("proxy probe did not return a valid IP address")
	}
	return ipStr, time.Since(start).Milliseconds(), nil
}

// UploadAttachment uploads binary bytes (e.g. an image) to AIDP upload-attachment and returns an Attachment.
func (m *Manager) UploadAttachment(ctx context.Context, acct auth.Account, name, mimeType string, data []byte) (Attachment, error) {
	if name == "" {
		name = "image.png"
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	sum := sha256.Sum256(data)
	shaHex := hex.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("name", name)
	q.Set("contentType", mimeType)
	q.Set("contentLength", fmt.Sprintf("%d", len(data)))

	endpoint := fmt.Sprintf("%s/integration/quick-work/upload-attachment?%s", acct.TenantURL, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return Attachment{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("x-amzn-qs-internal-trace-id", NewUUID())
	effProxy := m.effectiveProxy(acct)
	hc, err := m.httpClientForProxy(effProxy)
	if err != nil {
		return Attachment{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Attachment{}, netproxy.SanitizeError(err, effProxy)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Attachment{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return Attachment{}, &AuthError{Status: resp.StatusCode, Msg: string(raw)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Attachment{}, fmt.Errorf("upload-attachment failed (%d): %s", resp.StatusCode, truncate(string(raw), 300))
	}

	var parsed struct {
		AttachmentID string `json:"attachmentId"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.AttachmentID == "" {
		return Attachment{}, fmt.Errorf("upload-attachment returned no attachmentId: %s", truncate(string(raw), 200))
	}

	attType := "file"
	if strings.HasPrefix(strings.ToLower(mimeType), "image/") {
		attType = "image"
	}
	return Attachment{
		Type:          attType,
		Name:          name,
		Size:          len(data),
		MimeType:      mimeType,
		AttachmentID:  parsed.AttachmentID,
		ContentSha256: shaHex,
	}, nil
}

// UploadAndDeliverAttachment runs the official 3-step Amazon Quick cloud attachment flow:
// 1. POST /integration/quick-work/upload-attachment -> attachmentId
// 2. Poll GET /integration/quick-work/attachment-dlp-status?attachmentId= -> ALLOW
// 3. POST /integration/quick-work/qbs-event (invokeAgent files/upload/{threadID}) -> server path
// Without steps 2-3, Quick's cloud agent cannot read the uploaded attachment bytes.
func (m *Manager) UploadAndDeliverAttachment(ctx context.Context, acct auth.Account, threadID, name, mimeType string, data []byte) (Attachment, error) {
	att, err := m.UploadAttachment(ctx, acct, name, mimeType, data)
	if err != nil {
		return Attachment{}, err
	}
	if err := m.waitAttachmentDLP(ctx, acct, att.AttachmentID); err != nil {
		return Attachment{}, err
	}
	if strings.TrimSpace(threadID) != "" {
		serverPath, err := m.deliverAttachmentToSession(ctx, acct, threadID, att.AttachmentID)
		if err != nil {
			return Attachment{}, err
		}
		att.Path = serverPath
	}
	return att, nil
}

func (m *Manager) waitAttachmentDLP(ctx context.Context, acct auth.Account, attachmentID string) error {
	effProxy := m.effectiveProxy(acct)
	hc, err := m.httpClientForProxy(effProxy)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("attachmentId", attachmentID)
	endpoint := fmt.Sprintf("%s/integration/quick-work/attachment-dlp-status?%s", acct.TenantURL, q.Encode())

	deadline := time.Now().Add(15 * time.Second)
	for attempt := 0; attempt < 30; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
		req.Header.Set("x-amzn-qs-internal-trace-id", NewUUID())
		resp, err := hc.Do(req)
		if err != nil {
			return netproxy.SanitizeError(err, effProxy)
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if rerr != nil {
			return rerr
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return &AuthError{Status: resp.StatusCode, Msg: string(raw)}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("attachment-dlp-status failed (%d): %s", resp.StatusCode, truncate(string(raw), 240))
		}
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return fmt.Errorf("attachment-dlp-status invalid JSON: %w", err)
		}
		status := strings.ToUpper(strField(parsed, "dlpJobStatus", "DlpJobStatus"))
		action := strings.ToUpper(strField(parsed, "policyAction", "PolicyAction"))
		switch status {
		case "COMPLETED", "SKIPPED", "NOT_APPLICABLE":
			if action == "" || action == "ALLOW" || action == "WARN" {
				return nil
			}
			policyMsg := strField(parsed, "dlpPolicyMessage", "policyMessage")
			if policyMsg == "" {
				policyMsg = "attachment blocked by AWS Quick DLP policy (" + action + ")"
			}
			return errors.New(policyMsg)
		case "FAILED", "ERROR":
			return fmt.Errorf("attachment DLP scan failed (%s)", status)
		}
		if time.Now().After(deadline) {
			return errors.New("attachment DLP scan timed out")
		}
		delay := 300 * time.Millisecond
		if attempt >= 4 {
			delay = 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return errors.New("attachment DLP scan did not complete")
}

func (m *Manager) deliverAttachmentToSession(ctx context.Context, acct auth.Account, threadID, attachmentID string) (string, error) {
	env := map[string]any{
		"eventType": "invokeAgent",
		"eventBody": map[string]any{
			"invokeAgent": map[string]any{
				"path": "files/upload/" + url.PathEscape(threadID),
				"queryParams": map[string]string{
					"_method":     "POST",
					"surfaceType": m.surfaceType,
				},
				"body": map[string]any{
					"attachmentId": attachmentID,
				},
			},
		},
	}
	rawBody, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	effProxy := m.effectiveProxy(acct)
	hc, err := m.httpClientForProxy(effProxy)
	if err != nil {
		return "", err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, acct.TenantURL+"/integration/quick-work/qbs-event", bytes.NewReader(rawBody))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
		req.Header.Set("x-amzn-qs-internal-trace-id", NewUUID())
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = netproxy.SanitizeError(err, effProxy)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &AuthError{Status: resp.StatusCode, Msg: string(body)}
		}
		if resp.StatusCode >= 500 && attempt == 0 {
			lastErr = fmt.Errorf("files/upload failed (%d): %s", resp.StatusCode, truncate(string(body), 240))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("files/upload failed (%d): %s", resp.StatusCode, truncate(string(body), 240))
		}
		serverPath, perr := parseDeliveredAttachmentPath(body)
		if perr != nil {
			return "", perr
		}
		return serverPath, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("files/upload delivery failed")
}

func parseDeliveredAttachmentPath(raw []byte) (string, error) {
	var outer map[string]any
	if err := json.Unmarshal(raw, &outer); err != nil {
		return "", fmt.Errorf("files/upload invalid JSON: %w", err)
	}
	if em := strField(outer, "errorMessage"); em != "" {
		return "", fmt.Errorf("files/upload rejected: %s", em)
	}
	var inner any = outer
	if er, ok := outer["eventResponse"].(map[string]any); ok {
		if iar, ok := er["invokeAgentResponse"]; ok && iar != nil {
			inner = iar
		}
	}
	if s, ok := inner.(string); ok {
		var m2 map[string]any
		if err := json.Unmarshal([]byte(s), &m2); err == nil {
			inner = m2
		}
	}
	if m2, ok := inner.(map[string]any); ok {
		if m2["type"] == "api_response" {
			if st := toInt(m2["status"]); st >= 400 {
				return "", fmt.Errorf("files/upload api_response error (%d): %s", st, truncate(strField(m2, "body", "error", "message"), 240))
			}
			if bs, ok := m2["body"].(string); ok {
				var m3 map[string]any
				if err := json.Unmarshal([]byte(bs), &m3); err == nil {
					m2 = m3
				}
			}
		}
		if p := strField(m2, "path"); p != "" {
			return p, nil
		}
		if files, ok := m2["files"].([]any); ok && len(files) > 0 {
			if f0, ok := files[0].(map[string]any); ok {
				if p := strField(f0, "path"); p != "" {
					return p, nil
				}
			}
		}
		if errStr := strField(m2, "error", "message"); errStr != "" {
			return "", fmt.Errorf("files/upload error: %s", errStr)
		}
	}
	return "", fmt.Errorf("files/upload did not return a path: %s", truncate(string(raw), 240))
}

// ---------------------------------------------------------------------------
// Per-account persistent WebSocket multiplexer
// ---------------------------------------------------------------------------

type threadSub struct {
	mu     sync.Mutex
	closed bool
	ch     chan StreamEvent
}

func newThreadSub() *threadSub {
	return &threadSub{ch: make(chan StreamEvent, 512)}
}

func (t *threadSub) send(ev StreamEvent, important bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if !important {
		select {
		case t.ch <- ev:
		default:
		}
		return
	}
	select {
	case t.ch <- ev:
	case <-time.After(2 * time.Second):
	}
}

func (t *threadSub) close() {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.ch)
	}
	t.mu.Unlock()
}

type accountConn struct {
	accountID   string
	token       string
	proxyURL    string
	surfaceType string
	debug       bool
	ws          *websocket.Conn
	onClose     func()
	onIdentity  func(email, displayName, awsAccountID, externalID string)

	writeMu sync.Mutex
	mu      sync.Mutex
	alive   bool
	threads map[string]*threadSub
	done    chan struct{}
}

func (m *Manager) dialAccountConn(ctx context.Context, acct auth.Account) (*accountConn, error) {
	parsed, err := url.Parse(acct.TenantURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid tenant_url for %s", acct.ID)
	}
	q := url.Values{}
	q.Set("surfaceType", m.surfaceType)
	q.Set("workingSessionId", NewUUID())
	wsURL := fmt.Sprintf("wss://%s/streaming/quickwork-chat-bidirectional-stream?%s", parsed.Host, q.Encode())

	effProxy := m.effectiveProxy(acct)
	dialer := websocket.Dialer{
		HandshakeTimeout: 25 * time.Second,
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
	}
	if err := netproxy.ConfigureWebSocketDialer(&dialer, effProxy); err != nil {
		return nil, err
	}

	hdrs := http.Header{}
	hdrs.Set("Authorization", "Bearer "+acct.AccessToken)

	ws, resp, err := dialer.DialContext(ctx, wsURL, hdrs)
	if err != nil {
		if resp != nil {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return nil, &AuthError{Status: resp.StatusCode, Msg: "websocket handshake rejected"}
			}
			return nil, fmt.Errorf("ws dial failed (http %d): %w", resp.StatusCode, netproxy.SanitizeError(err, effProxy))
		}
		return nil, fmt.Errorf("ws dial failed: %w", netproxy.SanitizeError(err, effProxy))
	}
	ws.SetReadLimit(16 * 1024 * 1024)
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})

	ac := &accountConn{
		accountID:   acct.ID,
		token:       acct.AccessToken,
		proxyURL:    effProxy,
		surfaceType: m.surfaceType,
		debug:       m.debug,
		ws:          ws,
		alive:       true,
		threads:     make(map[string]*threadSub),
		done:        make(chan struct{}),
	}
	ac.onClose = func() {
		m.mu.Lock()
		if cur, ok := m.conns[acct.ID]; ok && cur == ac {
			delete(m.conns, acct.ID)
		}
		m.mu.Unlock()
	}
	ac.onIdentity = func(email, displayName, awsAccountID, externalID string) {
		if m.store != nil {
			m.store.UpdateProfile(acct.ID, email, displayName, awsAccountID, externalID)
		}
	}
	if err := ac.sendJSON(map[string]any{
		"type": "session_connect",
		"payload": map[string]any{
			"surfaceType": m.surfaceType,
		},
	}); err != nil {
		ac.close("session_connect_send_failed")
		return nil, fmt.Errorf("send session_connect: %w", err)
	}

	connectedCh := make(chan error, 1)
	go ac.readLoop(connectedCh)

	select {
	case err := <-connectedCh:
		if err != nil {
			ac.close("handshake_error")
			return nil, err
		}
	case <-time.After(25 * time.Second):
		ac.close("connected_timeout")
		return nil, errors.New("timed out waiting for Quick connected frame")
	case <-ctx.Done():
		ac.close("ctx_canceled")
		return nil, ctx.Err()
	}

	go ac.pingLoop()
	log.Printf("[quick-ws] connected account=%s host=%s", acct.ID, parsed.Host)
	return ac, nil
}

func (c *accountConn) isAlive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.alive
}

func (c *accountConn) registerThread(threadID string) <-chan StreamEvent {
	sub := newThreadSub()
	c.mu.Lock()
	if !c.alive {
		sub.close()
		c.mu.Unlock()
		return sub.ch
	}
	c.threads[threadID] = sub
	c.mu.Unlock()
	return sub.ch
}

func (c *accountConn) unregisterThread(threadID string) {
	c.mu.Lock()
	sub, ok := c.threads[threadID]
	if ok {
		delete(c.threads, threadID)
	}
	c.mu.Unlock()
	if ok && sub != nil {
		sub.close()
	}
}

func (c *accountConn) sendJSON(v any) error {
	payload, err := EncodeAIDPFrame(v)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(20 * time.Second))
	return c.ws.WriteMessage(websocket.BinaryMessage, payload)
}

func (c *accountConn) pingLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if !c.isAlive() {
				return
			}
			c.writeMu.Lock()
			_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := c.ws.WriteMessage(websocket.PingMessage, nil)
			c.writeMu.Unlock()
			if err != nil {
				c.close("ws_ping_failed")
				return
			}
			if err := c.sendJSON(map[string]any{
				"type": "ping",
				"payload": map[string]any{
					"timestamp": time.Now().UnixMilli(),
				},
			}); err != nil {
				c.close("app_ping_failed")
				return
			}
		}
	}
}

func (c *accountConn) close(reason string) {
	c.mu.Lock()
	if !c.alive {
		c.mu.Unlock()
		return
	}
	c.alive = false
	close(c.done)
	threads := c.threads
	c.threads = make(map[string]*threadSub)
	c.mu.Unlock()

	for _, sub := range threads {
		sub.close()
	}
	if c.ws != nil {
		_ = c.ws.Close()
	}
	if c.onClose != nil {
		c.onClose()
	}
	log.Printf("[quick-ws] closed account=%s reason=%s", c.accountID, reason)
}

type quickInboundEnvelope struct {
	Type      string          `json:"type"`
	ThreadID  string          `json:"thread_id"`
	SessionID string          `json:"session_id"`
	MessageID string          `json:"message_id"`
	Payload   json.RawMessage `json:"payload"`
}

func (c *accountConn) readLoop(connectedCh chan<- error) {
	var dec EventStreamDecoder
	connectedSent := false
	notifyConnected := func(err error) {
		if !connectedSent {
			connectedSent = true
			connectedCh <- err
		}
	}

	defer func() {
		notifyConnected(errors.New("ws closed before connected"))
		c.close("read_eof")
	}()

	for {
		_ = c.ws.SetReadDeadline(time.Now().Add(120 * time.Second))
		mt, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.debug {
				log.Printf("[quick-ws] read error account=%s: %v", c.accountID, err)
			}
			notifyConnected(err)
			return
		}
		if mt != websocket.BinaryMessage || len(data) == 0 {
			continue
		}

		for _, rawMsg := range dec.Feed(data) {
			frame := DecodeAIDPEvent(rawMsg)
			if frame == nil {
				continue
			}
			if frame.IsError {
				errStr := frame.ErrorString()
				log.Printf("[quick-ws] frame error account=%s: %s", c.accountID, errStr)
				notifyConnected(errors.New(errStr))
				return
			}

			var env quickInboundEnvelope
			if err := json.Unmarshal(frame.RawJSON, &env); err != nil {
				continue
			}

			if env.Type == "connected" {
				if email, name, awsAcctID, extID := parseConnectedUserProfile(env.Payload); email != "" || name != "" || awsAcctID != "" || extID != "" {
					if c.onIdentity != nil {
						c.onIdentity(email, name, awsAcctID, extID)
					}
				}
				notifyConnected(nil)
				continue
			}
			threadID := env.ThreadID
			if threadID == "" {
				threadID = env.SessionID
			}
			var payloadMap map[string]any
			if len(env.Payload) > 0 {
				_ = json.Unmarshal(env.Payload, &payloadMap)
			}
			if threadID == "" && payloadMap != nil {
				if v, ok := payloadMap["thread_id"].(string); ok && v != "" {
					threadID = v
				} else if v, ok := payloadMap["kernel_thread_id"].(string); ok && v != "" {
					threadID = v
				} else if v, ok := payloadMap["session_id"].(string); ok && v != "" {
					threadID = v
				}
			}

			// Auto-deny any unexpected built-in tool approval so headless turns never stall.
			if env.Type == "approval_requested" && payloadMap != nil {
				if aid, ok := payloadMap["approval_id"].(string); ok && aid != "" {
					log.Printf("[quick-ws] auto-denying built-in tool approval account=%s thread=%s tool=%v",
						c.accountID, threadID, payloadMap["tool_name"])
					go func(approvalID, sid string) {
						p := map[string]any{
							"approval_id": approvalID,
							"decision":    "deny",
						}
						if sid != "" {
							p["session_id"] = sid
						}
						_ = c.sendJSON(map[string]any{
							"type":    "approval_decision",
							"payload": p,
						})
					}(aid, threadID)
				}
				continue
			}

			if env.Type == "error" {
				ev, ignore, _, summary := parseQuickErrorEvent(frame.RawJSON, payloadMap)
				if ignore {
					if c.debug {
						log.Printf("[quick-ws] ignoring background error account=%s thread=%s %s", c.accountID, threadID, summary)
					}
					continue
				}
				log.Printf("[quick-ws] upstream error account=%s thread=%s %s", c.accountID, threadID, summary)
				if threadID != "" {
					c.dispatch(threadID, ev)
				} else {
					c.dispatchUnscopedError(ev)
				}
				continue
			}

			if threadID == "" {
				continue
			}

			var ev *StreamEvent
			switch env.Type {
			case "text_delta":
				if delta, _ := payloadMap["delta"].(string); delta != "" {
					ev = &StreamEvent{Kind: "text_delta", Text: delta}
				}
			case "thinking_delta":
				delta, _ := payloadMap["delta"].(string)
				if delta == "" {
					delta, _ = payloadMap["text"].(string)
				}
				if delta != "" {
					ev = &StreamEvent{Kind: "thinking_delta", Text: delta}
				}
			case "turn_usage":
				var u TurnUsage
				if err := json.Unmarshal(env.Payload, &u); err == nil {
					ev = &StreamEvent{Kind: "turn_usage", Usage: &u}
				}
			case "message_complete":
				ev = &StreamEvent{Kind: "complete"}
			case "tool_start":
				tname, _ := payloadMap["tool_name"].(string)
				ev = &StreamEvent{Kind: "tool_start", ToolName: tname}
			case "guardrail_blocked":
				msg := strField(payloadMap, "message", "error")
				if msg == "" {
					msg = "Content blocked by AWS Quick automated guardrail."
				}
				reason := strField(payloadMap, "reason", "code")
				log.Printf("[quick-ws] guardrail_blocked account=%s thread=%s reason=%s msg=%q", c.accountID, threadID, reason, truncate(msg, 200))
				ev = &StreamEvent{Kind: "guardrail_blocked", ErrorCode: reason, ErrorMsg: msg}
			case "usage_blocked":
				msg := strField(payloadMap, "message", "error")
				if msg == "" {
					msg = "Amazon Quick usage limit reached."
				}
				log.Printf("[quick-ws] usage_blocked account=%s thread=%s msg=%q", c.accountID, threadID, truncate(msg, 200))
				ev = &StreamEvent{Kind: "usage_blocked", ErrorCode: "usage_blocked", ErrorMsg: msg}
			case "rate_limited":
				msg := strField(payloadMap, "message", "error")
				if msg == "" {
					msg = "Amazon Quick rate limit reached."
				}
				log.Printf("[quick-ws] rate_limited account=%s thread=%s msg=%q", c.accountID, threadID, truncate(msg, 200))
				ev = &StreamEvent{Kind: "rate_limited", ErrorCode: "rate_limited", ErrorMsg: msg}
			}

			if ev != nil {
				c.dispatch(threadID, *ev)
			}
		}
	}
}

func (c *accountConn) dispatch(threadID string, ev StreamEvent) {
	c.mu.Lock()
	sub, ok := c.threads[threadID]
	c.mu.Unlock()
	if !ok || sub == nil {
		return
	}
	important := ev.Kind == "complete" || ev.Kind == "error" || ev.Kind == "turn_usage" ||
		ev.Kind == "guardrail_blocked" || ev.Kind == "usage_blocked" || ev.Kind == "rate_limited"
	sub.send(ev, important)
}

// dispatchUnscopedError routes a connection-level error frame (no thread_id) to active
// turn subscribers when the error is fatal/connection-wide or only a single turn is waiting,
// preventing turns from hanging until idle timeout.
func (c *accountConn) dispatchUnscopedError(ev StreamEvent) {
	c.mu.Lock()
	subs := make([]*threadSub, 0, len(c.threads))
	for _, sub := range c.threads {
		if sub != nil {
			subs = append(subs, sub)
		}
	}
	c.mu.Unlock()
	if len(subs) == 0 {
		return
	}
	lowerCode := strings.ToLower(ev.ErrorCode)
	broadcast := len(subs) == 1 ||
		lowerCode == "auth_error" ||
		strings.Contains(lowerCode, "connection_limit") ||
		ev.Kind == "usage_blocked" ||
		ev.Kind == "rate_limited" ||
		ev.Retryable
	if !broadcast {
		return
	}
	for _, sub := range subs {
		sub.send(ev, true)
	}
}
// NewUUID generates a random RFC 4122 v4 UUID string.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// parseConnectedUserProfile extracts identity metadata from Quick's WS `connected` payload.user.
func parseConnectedUserProfile(rawPayload json.RawMessage) (email, displayName, awsAccountID, externalID string) {
	if len(rawPayload) == 0 {
		return "", "", "", ""
	}
	var p struct {
		User *struct {
			Sub          string `json:"sub"`
			Email        string `json:"email"`
			Name         string `json:"name"`
			FirstName    string `json:"first_name"`
			LastName     string `json:"last_name"`
			AWSAccountID string `json:"aws_account_id"`
			ExternalID   string `json:"external_id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rawPayload, &p); err != nil || p.User == nil {
		return "", "", "", ""
	}
	email = strings.TrimSpace(p.User.Email)
	displayName = strings.TrimSpace(p.User.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(strings.TrimSpace(p.User.FirstName) + " " + strings.TrimSpace(p.User.LastName))
	}
	awsAccountID = strings.TrimSpace(p.User.AWSAccountID)
	externalID = strings.TrimSpace(p.User.ExternalID)
	if externalID == "" {
		externalID = strings.TrimSpace(p.User.Sub)
	}
	return email, displayName, awsAccountID, externalID
}
