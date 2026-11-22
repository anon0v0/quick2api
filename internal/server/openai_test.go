package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quick2api/internal/auth"
	"quick2api/internal/cli"
	"quick2api/internal/config"
	"quick2api/internal/prompt"
	"quick2api/internal/quick"
	"quick2api/internal/telemetry"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	b := []byte(`{"accounts":[{"id":"t1","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","client_id":"c","client_secret":"s","access_token":"at","access_token_expiry":2000000000,"refresh_token":"rt"}]}`)
	if err := os.WriteFile(accPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := quick.NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.APIKeys = []string{"sk-test-secret"}
	cfg.AccountsFile = accPath
	return New(cfg, store, mgr)
}

func TestServerAuthModelsAndHealth(t *testing.T) {
	srv := newTestServer(t)

	// /healthz requires no auth and returns no secrets.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || w.Header().Get("X-Service") != "quick2api" || !strings.Contains(w.Body.String(), `"enabled_accounts":1`) {
		t.Fatalf("unexpected /healthz: %d hdr=%q %s", w.Code, w.Header().Get("X-Service"), w.Body.String())
	}

	// /v1/models without key -> 401.
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", w.Code)
	}

	// /v1/models with valid Bearer key -> 200 with canonical catalog.
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer sk-test-secret")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with key, got %d %s", w.Code, w.Body.String())
	}
	var list struct {
		Data []struct {
			ID               string `json:"id"`
			ContextLength    int    `json:"context_length"`
			MaxOutputTokens  int    `json:"max_output_tokens"`
			SupportsToolCall bool   `json:"supports_tool_call"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Data) < 5 {
		t.Fatalf("expected >=5 models, got %d", len(list.Data))
	}
	if list.Data[0].ContextLength != 1000000 || list.Data[0].MaxOutputTokens != 64000 || !list.Data[0].SupportsToolCall {
		t.Fatalf("expected rich model metadata, got %+v", list.Data[0])
	}
	// /v1/chat/completions with unsupported model -> 400.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"nope-1","messages":[{"role":"user","content":"hi"}]}`))
	req2.Header.Set("Authorization", "Bearer sk-test-secret")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req2)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported model, got %d %s", w.Code, w.Body.String())
	}
}

func TestToOpenAIUsageIncludesCacheDetails(t *testing.T) {
	u := toOpenAIUsage(&quick.TurnUsage{
		InputTokens:      10,
		CacheReadTokens:  66000,
		CacheWriteTokens: 1400,
		OutputTokens:     25,
	})
	if u.PromptTokens != 67410 || u.CompletionTokens != 25 || u.TotalTokens != 67435 {
		t.Fatalf("unexpected usage totals: %+v", u)
	}
	if u.PromptTokensDetails == nil || u.PromptTokensDetails.CachedTokens != 66000 {
		t.Fatalf("expected cached_tokens=66000, got %+v", u.PromptTokensDetails)
	}
	if u.CacheReadInputTokens != 66000 || u.PromptCacheHitTokens != 66000 || u.CacheCreationInputTokens != 1400 {
		t.Fatalf("expected cache aliases populated, got %+v", u)
	}
}

func TestServeSSEFormatIncludeUsageAndMidStreamError(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.SSEKeepAliveSec = -1

	// 1. Normal SSE stream with include_usage=true
	evCh := make(chan quick.StreamEvent, 8)
	evCh <- quick.StreamEvent{Kind: "thinking_delta", Text: "plan"}
	evCh <- quick.StreamEvent{Kind: "text_delta", Text: "Hello!"}
	evCh <- quick.StreamEvent{Kind: "turn_usage", Usage: &quick.TurnUsage{InputTokens: 5, CacheReadTokens: 100, OutputTokens: 3}}
	evCh <- quick.StreamEvent{Kind: "complete"}
	close(evCh)

	w := httptest.NewRecorder()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.serveSSE(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-1", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, true, evCh, false, false, false)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n\n")
	if len(lines) != 5 || lines[len(lines)-1] != "data: [DONE]" {
		t.Fatalf("expected 4 chunks + [DONE], got %d frames:\n%s", len(lines), w.Body.String())
	}
	// First chunk must have role=assistant, reasoning_content, logprobs=null, usage=null.
	var first map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], "data: ")), &first); err != nil {
		t.Fatal(err)
	}
	if _, hasUsage := first["usage"]; !hasUsage || first["usage"] != nil {
		t.Fatalf("expected usage:null on intermediate chunk when include_usage=true: %s", lines[0])
	}
	ch0 := first["choices"].([]any)[0].(map[string]any)
	if _, hasLP := ch0["logprobs"]; !hasLP || ch0["logprobs"] != nil {
		t.Fatalf("expected logprobs:null in choice: %s", lines[0])
	}
	// Final usage chunk must have empty choices and populated usage.
	var usageChunk map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[3], "data: ")), &usageChunk); err != nil {
		t.Fatal(err)
	}
	if len(usageChunk["choices"].([]any)) != 0 || usageChunk["usage"] == nil {
		t.Fatalf("unexpected final usage chunk: %s", lines[3])
	}

	// 2. Mid-stream error after output started must emit SSE error frame + [DONE], NOT finish_reason=stop.
	errCh := make(chan quick.StreamEvent, 4)
	errCh <- quick.StreamEvent{Kind: "text_delta", Text: "partial"}
	errCh <- quick.StreamEvent{Kind: "error", ErrorCode: "stream_idle_timeout", ErrorMsg: "stalled"}
	close(errCh)

	w2 := httptest.NewRecorder()
	srv.serveSSE(w2, cancel, auth.Account{ID: "t1"}, "chatcmpl-2", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, errCh, false, false, false)
	body2 := w2.Body.String()
	if !strings.Contains(body2, `"code":"stream_idle_timeout"`) || !strings.Contains(body2, "data: [DONE]") {
		t.Fatalf("expected SSE error frame + [DONE], got:\n%s", body2)
	}
	if strings.Contains(body2, `"finish_reason":"stop"`) {
		t.Fatalf("mid-stream error must not emit fake finish_reason=stop:\n%s", body2)
	}

	// 3. Empty upstream stream before headers must return HTTP 502 empty_stream.
	emptyCh := make(chan quick.StreamEvent, 1)
	emptyCh <- quick.StreamEvent{Kind: "complete"}
	close(emptyCh)

	w3 := httptest.NewRecorder()
	srv.serveSSE(w3, cancel, auth.Account{ID: "t1"}, "chatcmpl-3", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, emptyCh, false, false, false)
	if w3.Code != http.StatusBadGateway || !strings.Contains(w3.Body.String(), `"empty_stream"`) {
		t.Fatalf("expected 502 empty_stream, got %d %s", w3.Code, w3.Body.String())
	}

	// 4. Stale WS close before headers triggers stale_conn retry without writing response.
	staleCh := make(chan quick.StreamEvent, 1)
	staleCh <- quick.StreamEvent{Kind: "error", ErrorCode: "stream_closed", ErrorMsg: "eof"}
	close(staleCh)

	w4 := httptest.NewRecorder()
	dir := srv.serveSSE(w4, cancel, auth.Account{ID: "t1"}, "chatcmpl-4", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, staleCh, true, false, false)
	if dir.kind != "stale_conn" || w4.Body.Len() != 0 {
		t.Fatalf("expected stale_conn retry with empty body, got dir=%+v body=%q", dir, w4.Body.String())
	}
}

func TestServeNonStreamingEmptyAndToolOnlyFormat(t *testing.T) {
	srv := newTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Empty stream -> HTTP 502 empty_stream.
	emptyCh := make(chan quick.StreamEvent, 1)
	emptyCh <- quick.StreamEvent{Kind: "complete"}
	close(emptyCh)
	w := httptest.NewRecorder()
	srv.serveNonStreaming(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-ns1", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, emptyCh, false, false, false)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), `"empty_stream"`) {
		t.Fatalf("expected 502 empty_stream, got %d %s", w.Code, w.Body.String())
	}

	// 2. Tool-only reply -> content=null, refusal=null, logprobs=null, finish_reason=tool_calls, no index in tool_calls.
	tcCh := make(chan quick.StreamEvent, 3)
	tcCh <- quick.StreamEvent{Kind: "text_delta", Text: "<quick_tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.go\"}}</quick_tool_call>"}
	tcCh <- quick.StreamEvent{Kind: "complete"}
	close(tcCh)
	w2 := httptest.NewRecorder()
	conv := prompt.ConvertedPrompt{ToolMode: true, AllowedTools: map[string]bool{"read_file": true}}
	srv.serveNonStreaming(w2, cancel, auth.Account{ID: "t1"}, "chatcmpl-ns2", 1700000000, "quick-opus-5.5", conv, nil, tcCh, false, false, false)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", w2.Code, w2.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	choice := resp["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" || choice["logprobs"] != nil {
		t.Fatalf("unexpected choice: %+v", choice)
	}
	msg := choice["message"].(map[string]any)
	if msg["content"] != nil || msg["refusal"] != nil {
		t.Fatalf("expected content:null and refusal:null, got %+v", msg)
	}
	tcs := msg["tool_calls"].([]any)
	if len(tcs) != 1 {
		t.Fatalf("expected 1 tool call, got %+v", tcs)
	}
	if _, hasIndex := tcs[0].(map[string]any)["index"]; hasIndex {
		t.Fatalf("non-streaming message.tool_calls should not include index: %+v", tcs[0])
	}
}

func TestServeSSEKeepAliveAndPostHeaderEmptyStream(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.SSEKeepAliveSec = 1 // 1s keepalive
	evCh := make(chan quick.StreamEvent, 2)
	go func() {
		time.Sleep(1150 * time.Millisecond)
		evCh <- quick.StreamEvent{Kind: "complete"}
		close(evCh)
	}()
	w := httptest.NewRecorder()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.serveSSE(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-ka", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, evCh, false, false, false)
	body := w.Body.String()
	if !strings.Contains(body, ": keep-alive\n\n") {
		t.Fatalf("expected SSE keep-alive comment, got:\n%s", body)
	}
	if !strings.Contains(body, `"empty_stream"`) || !strings.Contains(body, "data: [DONE]\n\n") {
		t.Fatalf("expected post-header SSE empty_stream error + [DONE], got:\n%s", body)
	}
}

func TestAdminReloadProxyProbeAndResetCooldown(t *testing.T) {
	srv := newTestServer(t)

	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"198.51.100.9"}`))
	}))
	defer echoSrv.Close()
	srv.probeURL = echoSrv.URL

	authReq := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-test-secret")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	// 1. Update proxy with strict JSON check & redacted status response.
	w := authReq(http.MethodPost, "/admin/accounts/proxy", `{"id":"t1","proxy_url":"socks5h://u:secretpw@127.0.0.1:1080","unknown":1}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown field, got %d %s", w.Code, w.Body.String())
	}
	w = authReq(http.MethodPost, "/admin/accounts/proxy", `{"id":"t1","proxy_url":"socks5h://u:secretpw@127.0.0.1:1080"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 setting proxy, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secretpw") || !strings.Contains(w.Body.String(), "socks5h://127.0.0.1:1080") {
		t.Fatalf("expected redacted proxy in response: %s", w.Body.String())
	}

	// Reset back to direct so probe-proxy reaches local echoSrv.
	w = authReq(http.MethodPost, "/admin/accounts/proxy", `{"id":"t1","proxy_url":"direct"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 clearing proxy to direct, got %d %s", w.Code, w.Body.String())
	}
	w = authReq(http.MethodPost, "/admin/accounts/probe-proxy", `{"id":"t1"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"egress_ip":"198.51.100.9"`) {
		t.Fatalf("expected 200 probe-proxy with egress_ip, got %d %s", w.Code, w.Body.String())
	}

	// 2. Hot reload: add t2 on disk, POST /admin/reload picks it up cleanly.
	if err := os.WriteFile(srv.cfg.AccountsFile, []byte(`{"accounts":[
		{"id":"t1","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000},
		{"id":"t2","tenant_url":"https://cell2.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at2","access_token_expiry":2000000000}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w = authReq(http.MethodPost, "/admin/reload", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"t2"`) || srv.store.AccountCount() != 2 {
		t.Fatalf("expected reload to add t2, got %d count=%d body=%s", w.Code, srv.store.AccountCount(), w.Body.String())
	}

	// Invalid accounts.json on disk -> 400 and live pool untouched.
	_ = os.WriteFile(srv.cfg.AccountsFile, []byte(`{invalid`), 0o600)
	w = authReq(http.MethodPost, "/admin/reload", "")
	if w.Code != http.StatusBadRequest || srv.store.AccountCount() != 2 {
		t.Fatalf("expected 400 on malformed reload with live pool intact, got %d count=%d", w.Code, srv.store.AccountCount())
	}

	// 3. Reset cooldown clears active cooldown.
	srv.store.MarkRateLimited("t1", "rate limit test")
	w = authReq(http.MethodPost, "/admin/accounts/reset-cooldown", `{"id":"t1"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cleared":1`) {
		t.Fatalf("expected cleared:1, got %d %s", w.Code, w.Body.String())
	}
}

func TestServeDifferentiatedCooldownRateLimitVsUsageBlocked(t *testing.T) {
	// Mock Quick tenant server serving profile/usage with exhausted monthly quota.
	usageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner, _ := json.Marshal(map[string]any{
			"monthly": map[string]any{"used": 600, "limit": 600, "percent": 100, "resets_at": time.Now().Add(4 * time.Hour).Unix()},
			"session": map[string]any{"used": 5, "limit": 100, "percent": 5},
		})
		apiResp, _ := json.Marshal(map[string]any{"type": "api_response", "body": string(inner)})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"eventResponse": map[string]any{"invokeAgentResponse": string(apiResp)},
		})
	}))
	defer usageSrv.Close()

	srv := newTestServer(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. rate_limited with !canRotate -> HTTP 429 and short rate_limited cooldown (~1m).
	rlCh := make(chan quick.StreamEvent, 1)
	rlCh <- quick.StreamEvent{Kind: "rate_limited", ErrorMsg: "slow down"}
	close(rlCh)
	w1 := httptest.NewRecorder()
	srv.serveNonStreaming(w1, cancel, auth.Account{ID: "t1"}, "chatcmpl-rl", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, rlCh, false, false, false)
	if w1.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on non-streaming rate_limited without rotation, got %d %s", w1.Code, w1.Body.String())
	}
	st := srv.store.Statuses()[0]
	if st.CooldownKind != auth.CooldownRateLimited || st.CooldownRemainingSec > 70 {
		t.Fatalf("expected short rate_limited cooldown, got %+v", st)
	}

	// 2. usage_blocked queries profile/usage -> classifies monthly_quota (~4h) and rotates when canRotate=true.
	ubCh := make(chan quick.StreamEvent, 1)
	ubCh <- quick.StreamEvent{Kind: "usage_blocked", ErrorMsg: "limit reached"}
	close(ubCh)
	w2 := httptest.NewRecorder()
	dir := srv.serveNonStreaming(w2, cancel, auth.Account{ID: "t1", TenantURL: usageSrv.URL, AccessToken: "at"}, "chatcmpl-ub", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, ubCh, false, false, true)
	if dir.kind != "rotate_account" {
		t.Fatalf("expected rotate_account directive, got %+v", dir)
	}
	st = srv.store.Statuses()[0]
	if st.CooldownKind != auth.CooldownMonthlyQuota || st.CooldownRemainingSec < 3*3600 {
		t.Fatalf("expected monthly_quota cooldown >=3h, got %+v", st)
	}
}

func TestWebUIRoutesAndTelemetryEndpoints(t *testing.T) {
	srv := newTestServer(t)
	buf := telemetry.NewLogBuffer(100)
	_, _ = buf.Write([]byte("2026/11/22 03:30:00 [chat] sample info line\n"))
	_, _ = buf.Write([]byte("2026/11/22 03:30:01 [auth] refresh failed error\n"))
	srv.SetLogBuffer(buf)

	// 1. Root & /admin redirect to /admin/; unknown path stays 404.
	for _, p := range []string{"/", "/admin"} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/" {
			t.Fatalf("expected 302 -> /admin/ for %s, got %d loc=%q", p, w.Code, w.Header().Get("Location"))
		}
	}
	w404 := httptest.NewRecorder()
	srv.ServeHTTP(w404, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if w404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown path, got %d", w404.Code)
	}

	// 2. Embedded WebUI index + CSS + JS with security headers.
	wUI := httptest.NewRecorder()
	srv.ServeHTTP(wUI, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if wUI.Code != http.StatusOK || !strings.Contains(wUI.Body.String(), "quick2api") {
		t.Fatalf("unexpected /admin/ response: %d", wUI.Code)
	}
	if wUI.Header().Get("X-Frame-Options") != "DENY" || wUI.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers on /admin/: %v", wUI.Header())
	}
	for _, asset := range []string{"/admin/assets/style.css", "/admin/assets/app.js"} {
		wa := httptest.NewRecorder()
		srv.ServeHTTP(wa, httptest.NewRequest(http.MethodGet, asset, nil))
		if wa.Code != http.StatusOK || wa.Body.Len() < 100 {
			t.Fatalf("expected embedded asset %s to load, got %d len=%d", asset, wa.Code, wa.Body.Len())
		}
	}

	// 3. /admin/metrics & /admin/logs require auth.
	for _, ep := range []string{"/admin/metrics", "/admin/logs"} {
		wu := httptest.NewRecorder()
		srv.ServeHTTP(wu, httptest.NewRequest(http.MethodGet, ep, nil))
		if wu.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without auth on %s, got %d", ep, wu.Code)
		}
	}

	// Record one chat completion metric and verify /admin/metrics + reset.
	srv.recordChatMetrics("chatcmpl-m1", "quick-opus-5.5", "t1", true, time.Now().Add(-250*time.Millisecond), "ok", http.StatusOK, &quick.TurnUsage{
		InputTokens:     500,
		CacheReadTokens: 66000,
		OutputTokens:    120,
		CostUSD:         0.01,
	}, 1)

	authReq := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer sk-test-secret")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	wm := authReq(http.MethodGet, "/admin/metrics")
	if wm.Code != http.StatusOK || wm.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected /admin/metrics: %d cc=%q", wm.Code, wm.Header().Get("Cache-Control"))
	}
	var snap telemetry.MetricsSnapshot
	if err := json.Unmarshal(wm.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Totals.Requests != 1 || snap.Totals.ToolCallRequests != 1 || len(snap.ByModel) != 1 || snap.ByModel[0].Model != "quick-opus-5.5" {
		t.Fatalf("unexpected metrics snapshot: %+v", snap)
	}

	// Verify /admin/logs filtering + clear.
	wl := authReq(http.MethodGet, "/admin/logs?level=error")
	if wl.Code != http.StatusOK {
		t.Fatalf("unexpected /admin/logs: %d %s", wl.Code, wl.Body.String())
	}
	var logPage telemetry.LogPage
	if err := json.Unmarshal(wl.Body.Bytes(), &logPage); err != nil {
		t.Fatal(err)
	}
	if len(logPage.Entries) != 1 || logPage.Entries[0].Tag != "auth" {
		t.Fatalf("expected 1 error log entry from auth, got %+v", logPage.Entries)
	}

	if wr := authReq(http.MethodPost, "/admin/metrics/reset"); wr.Code != http.StatusOK {
		t.Fatalf("metrics reset failed: %d", wr.Code)
	}
	if wc := authReq(http.MethodPost, "/admin/logs/clear"); wc.Code != http.StatusOK {
		t.Fatalf("logs clear failed: %d", wc.Code)
	}
}

func TestAdminPasswordLoginSessionCSRFAndRateLimit(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.AdminPassword = "TestStrongPass!99"
	srv.adminAuth = newAdminAuthManager(config.AdminUsername, srv.cfg.AdminPassword)

	// 1. Unauthenticated /admin/auth/me -> 401.
	wMe := httptest.NewRecorder()
	srv.ServeHTTP(wMe, httptest.NewRequest(http.MethodGet, "/admin/auth/me", nil))
	if wMe.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated /admin/auth/me, got %d", wMe.Code)
	}

	// 2. Wrong username or password -> 401.
	badLogin := func(user, pass, xri string) *httptest.ResponseRecorder {
		body := `{"username":"` + user + `","password":"` + pass + `"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/auth/login", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Real-IP", xri)
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	if w := badLogin("admin", "TestStrongPass!99", "203.0.113.10"); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-root username, got %d", w.Code)
	}

	// 3. Valid root login via loopback proxy with X-Forwarded-Proto: https -> 200 + HttpOnly/Secure/SameSite=Strict cookie.
	wOK := badLogin("root", "TestStrongPass!99", "203.0.113.10")
	if wOK.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid login, got %d %s", wOK.Code, wOK.Body.String())
	}
	cookies := wOK.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminSessionCookieName || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie attributes: %+v", cookies)
	}
	sessionCookie := cookies[0]

	// 4. GET /admin/status with session cookie -> 200.
	reqSt := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	reqSt.AddCookie(sessionCookie)
	wSt := httptest.NewRecorder()
	srv.ServeHTTP(wSt, reqSt)
	if wSt.Code != http.StatusOK {
		t.Fatalf("expected 200 on cookie-authed GET /admin/status, got %d", wSt.Code)
	}

	// 5. POST /admin/logs/clear with session cookie WITHOUT CSRF header -> 403; WITH CSRF header -> 200.
	reqNoCSRF := httptest.NewRequest(http.MethodPost, "/admin/logs/clear", nil)
	reqNoCSRF.AddCookie(sessionCookie)
	wNoCSRF := httptest.NewRecorder()
	srv.ServeHTTP(wNoCSRF, reqNoCSRF)
	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 missing CSRF header, got %d", wNoCSRF.Code)
	}
	reqCSRF := httptest.NewRequest(http.MethodPost, "/admin/logs/clear", nil)
	reqCSRF.AddCookie(sessionCookie)
	reqCSRF.Header.Set(adminCSRFHeader, adminCSRFValue)
	wCSRF := httptest.NewRecorder()
	srv.ServeHTTP(wCSRF, reqCSRF)
	if wCSRF.Code != http.StatusOK {
		t.Fatalf("expected 200 with CSRF header, got %d", wCSRF.Code)
	}

	// 6. Logout revokes session so subsequent GET -> 401.
	reqOut := httptest.NewRequest(http.MethodPost, "/admin/auth/logout", nil)
	reqOut.AddCookie(sessionCookie)
	reqOut.Header.Set(adminCSRFHeader, adminCSRFValue)
	wOut := httptest.NewRecorder()
	srv.ServeHTTP(wOut, reqOut)
	if wOut.Code != http.StatusOK {
		t.Fatalf("logout failed: %d", wOut.Code)
	}
	reqAfter := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	reqAfter.AddCookie(sessionCookie)
	wAfter := httptest.NewRecorder()
	srv.ServeHTTP(wAfter, reqAfter)
	if wAfter.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", wAfter.Code)
	}

	// 7. Brute-force IP rate limit kicks in after maxLoginFailures -> 429.
	for i := 0; i < maxLoginFailures; i++ {
		if w := badLogin("root", "wrong", "203.0.113.99"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}
	if w := badLogin("root", "TestStrongPass!99", "203.0.113.99"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after brute-force lockout, got %d", w.Code)
	}
}

func TestAdminWebOAuthFlowAndAccountManagement(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.APIKeys = []string{"admin-secret"}

	// Mock AWS sso-oidc endpoints (/client/register and /token).
	var gotVerifier string
	var gotRedirect string
	var gotClientName string
	var gotScopes []any
	oidcMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/client/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotClientName, _ = body["clientName"].(string)
			gotScopes, _ = body["scopes"].([]any)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId":              "mock-client-id",
				"clientSecret":          "mock-client-secret",
				"clientSecretExpiresAt": time.Now().Add(24 * time.Hour).Unix(),
			})
		case "/token":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if body["clientId"] != "mock-client-id" || body["clientSecret"] != "mock-client-secret" || body["code"] != "auth-code-xyz" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			gotVerifier, _ = body["codeVerifier"].(string)
			gotRedirect, _ = body["redirectUri"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":  "aoa_mock_access",
				"refreshToken": "aor_mock_refresh",
				"expiresIn":    3600,
				"tokenType":    "Bearer",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer oidcMock.Close()
	srv.oauthBaseURL = oidcMock.URL

	postJSON := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-secret")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}

	// 0. /admin/oauth/discover returns official quick.aws.com qwSurface discovery link.
	wDisc := postJSON("/admin/oauth/discover", `{"callback_port":19090}`)
	if wDisc.Code != http.StatusOK {
		t.Fatalf("oauth/discover failed: %d %s", wDisc.Code, wDisc.Body.String())
	}
	var discResp struct {
		DiscoveryURL string `json:"discovery_url"`
		CallbackPort int    `json:"callback_port"`
	}
	if err := json.Unmarshal(wDisc.Body.Bytes(), &discResp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(discResp.DiscoveryURL, "https://quick.aws.com/sn?qwSurface=desktop%3A") || discResp.CallbackPort != 19090 {
		t.Fatalf("unexpected discovery response: %+v", discResp)
	}

	// 1. Validation checks on /admin/oauth/start.
	if w := postJSON("/admin/oauth/start", `{"proxy_url":"ftp://bad:21"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid proxy_url, got %d: %s", w.Code, w.Body.String())
	}
	if w := postJSON("/admin/oauth/start", `{"callback_port":80}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid callback_port, got %d: %s", w.Code, w.Body.String())
	}
	if w := postJSON("/admin/oauth/start", `{"discovery_callback_url":"http://127.0.0.1:19090/?foo=bar"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on discovery URL missing tenant_url, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Start OAuth flow via discovery_callback_url (uses fast-fail local tenant_url so best-effort usage probe finishes immediately).
	wStart := postJSON("/admin/oauth/start", `{"id":"web-oauth-1","discovery_callback_url":"http://127.0.0.1:19090/?tenantUrl=https%3A%2F%2F127.0.0.1%3A1&idcRegion=us-east-1","proxy_url":"direct","callback_port":19090}`)
	if wStart.Code != http.StatusOK {
		t.Fatalf("oauth/start failed: %d %s", wStart.Code, wStart.Body.String())
	}
	var startResp struct {
		State       string   `json:"state"`
		AuthURL     string   `json:"auth_url"`
		RedirectURI string   `json:"redirect_uri"`
		Scopes      []string `json:"scopes"`
	}
	if err := json.Unmarshal(wStart.Body.Bytes(), &startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.State == "" || startResp.RedirectURI != "http://127.0.0.1:19090/oauth/callback" {
		t.Fatalf("unexpected startResp: %+v", startResp)
	}
	if gotClientName != "AmazonQuick-Desktop" || len(gotScopes) != 1 || gotScopes[0] != "quicksight:read_write" {
		t.Fatalf("expected official clientName & quicksight:read_write scope, got name=%q scopes=%v", gotClientName, gotScopes)
	}
	parsedAuth, err := url.Parse(startResp.AuthURL)
	if err != nil || parsedAuth.Query().Get("state") != startResp.State || parsedAuth.Query().Get("code_challenge") == "" || parsedAuth.Query().Get("scopes") != "quicksight:read_write" {
		t.Fatalf("invalid auth_url: %q", startResp.AuthURL)
	}
	// 3. State mismatch and upstream callback error are rejected without consuming the session.
	wMismatch := postJSON("/admin/oauth/callback", `{"state":"`+startResp.State+`","redirect_url":"http://127.0.0.1:19090/oauth/callback?code=auth-code-xyz&state=wrongstate"}`)
	if wMismatch.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on state mismatch, got %d", wMismatch.Code)
	}
	wOAuthErr := postJSON("/admin/oauth/callback", `{"state":"`+startResp.State+`","redirect_url":"http://127.0.0.1:19090/oauth/callback?error=access_denied&error_description=user_cancelled"}`)
	if wOAuthErr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on oauth error param, got %d", wOAuthErr.Code)
	}

	// 4. Valid CPA-style pasted callback URL completes token exchange, persists, and hot-reloads.
	cbURL := "http://127.0.0.1:19090/oauth/callback?code=auth-code-xyz&state=" + startResp.State
	wCB := postJSON("/admin/oauth/callback", `{"redirect_url":"`+cbURL+`"}`)
	if wCB.Code != http.StatusOK {
		t.Fatalf("oauth/callback failed: %d %s", wCB.Code, wCB.Body.String())
	}
	if gotVerifier == "" || gotRedirect != "http://127.0.0.1:19090/oauth/callback" {
		t.Fatalf("unexpected token exchange params: verifier=%q redirect=%q", gotVerifier, gotRedirect)
	}
	acct, ok := srv.store.GetAccount("web-oauth-1")
	if !ok || acct.AccessToken != "aoa_mock_access" || acct.RefreshToken != "aor_mock_refresh" || acct.ProxyURL != "direct" {
		t.Fatalf("expected persisted oauth account, got ok=%v acct=%+v", ok, acct)
	}

	// 5. Replaying consumed state fails with 404.
	if wReplay := postJSON("/admin/oauth/callback", `{"redirect_url":"`+cbURL+`"}`); wReplay.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on callback replay, got %d", wReplay.Code)
	}

	// 6. Manual JSON import adds account with proxy override and rejects missing tokens.
	wBadImp := postJSON("/admin/accounts/import", `{"payload":{"id":"no-tok","tenant_url":"https://127.0.0.1:1"}}`)
	if wBadImp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on import missing tokens, got %d", wBadImp.Code)
	}
	wImp := postJSON("/admin/accounts/import", `{"payload":{"id":"imp-1","tenant_url":"https://127.0.0.1:1","access_token":"at_imp","access_token_expiry":2000000000},"proxy_url":"socks5h://127.0.0.1:1080"}`)
	if wImp.Code != http.StatusOK {
		t.Fatalf("accounts/import failed: %d %s", wImp.Code, wImp.Body.String())
	}
	if impAcct, ok := srv.store.GetAccount("imp-1"); !ok || impAcct.ProxyURL != "socks5h://127.0.0.1:1080" {
		t.Fatalf("expected imported account with proxy override, got ok=%v acct=%+v", ok, impAcct)
	}

	// 7. Toggle disable/enable and delete via admin API.
	if wTog := postJSON("/admin/accounts/toggle", `{"id":"imp-1","disabled":true}`); wTog.Code != http.StatusOK {
		t.Fatalf("toggle disable failed: %d %s", wTog.Code, wTog.Body.String())
	}
	if impAcct, _ := srv.store.GetAccount("imp-1"); !impAcct.Disabled {
		t.Fatalf("expected imp-1 to be disabled")
	}
	if wDel := postJSON("/admin/accounts/delete", `{"id":"imp-1"}`); wDel.Code != http.StatusOK {
		t.Fatalf("delete failed: %d %s", wDel.Code, wDel.Body.String())
	}
	if _, ok := srv.store.GetAccount("imp-1"); ok {
		t.Fatalf("expected imp-1 removed from store")
	}
	if wDel404 := postJSON("/admin/accounts/delete", `{"id":"imp-1"}`); wDel404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting missing account, got %d", wDel404.Code)
	}
}

func TestServeRetryableTransientAuthOverflowAndImageDedup(t *testing.T) {
	srv := newTestServer(t)
	srv.cfg.SSEKeepAliveSec = -1
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Transient InternalFailure before headers triggers stale_conn + invalidateConn.
	trCh := make(chan quick.StreamEvent, 1)
	trCh <- quick.StreamEvent{Kind: "error", ErrorCode: "InternalFailure", ErrorMsg: "Failed to deliver message", Retryable: true}
	close(trCh)
	w1 := httptest.NewRecorder()
	dir := srv.serveSSE(w1, cancel, auth.Account{ID: "t1"}, "chatcmpl-tr", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, trCh, true, true, false)
	if dir.kind != "stale_conn" || !dir.invalidateConn || w1.Body.Len() != 0 {
		t.Fatalf("expected stale_conn+invalidateConn for InternalFailure, got dir=%+v body=%q", dir, w1.Body.String())
	}

	// 2. Mid-WS auth_error before headers triggers auth_refresh retry.
	authCh := make(chan quick.StreamEvent, 1)
	authCh <- quick.StreamEvent{Kind: "error", ErrorCode: "auth_error", ErrorMsg: "ExpiredToken"}
	close(authCh)
	w2 := httptest.NewRecorder()
	dir = srv.serveNonStreaming(w2, cancel, auth.Account{ID: "t1"}, "chatcmpl-auth", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, authCh, true, true, false)
	if dir.kind != "auth_refresh" || w2.Body.Len() != 0 {
		t.Fatalf("expected auth_refresh directive, got dir=%+v body=%q", dir, w2.Body.String())
	}

	// 3. Upstream context_overflow maps cleanly to HTTP 400 context_length_exceeded.
	ovCh := make(chan quick.StreamEvent, 1)
	ovCh <- quick.StreamEvent{Kind: "error", ErrorCode: "context_overflow", ErrorMsg: "context window exceeded"}
	close(ovCh)
	w3 := httptest.NewRecorder()
	dir = srv.serveSSE(w3, cancel, auth.Account{ID: "t1"}, "chatcmpl-ov", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, ovCh, true, true, false)
	if w3.Code != http.StatusBadRequest || !strings.Contains(w3.Body.String(), `"context_length_exceeded"`) || dir.kind != "" {
		t.Fatalf("expected 400 context_length_exceeded, got code=%d dir=%+v body=%s", w3.Code, dir, w3.Body.String())
	}

	// 4. uploadImages deduplicates identical SHA-256 images and delivers with thread path.
	uploadCount := 0
	attSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/integration/quick-work/upload-attachment":
			uploadCount++
			_, _ = w.Write([]byte(`{"attachmentId":"att-dedup-1"}`))
		case "/integration/quick-work/attachment-dlp-status":
			_, _ = w.Write([]byte(`{"dlpJobStatus":"COMPLETED","policyAction":"ALLOW"}`))
		case "/integration/quick-work/qbs-event":
			inner, _ := json.Marshal(map[string]any{"path": "/data/s3files/sessions/tid-dedup/workspace/attached_files/img.jpg"})
			apiResp, _ := json.Marshal(map[string]any{"type": "api_response", "status": 200, "body": string(inner)})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"eventResponse": map[string]any{"invokeAgentResponse": string(apiResp)},
			})
		}
	}))
	defer attSrv.Close()

	dupBytes := []byte("same-jpeg-payload-bytes")
	atts, err := srv.uploadImages(context.Background(), auth.Account{ID: "t1", TenantURL: attSrv.URL, AccessToken: "at"}, "tid-dedup", []prompt.PendingImage{
		{Name: "image-1.jpg", MimeType: "image/jpeg", Data: dupBytes},
		{Name: "image-2.jpg", MimeType: "image/jpeg", Data: dupBytes},
	})
	if err != nil {
		t.Fatalf("uploadImages failed: %v", err)
	}
	if uploadCount != 1 || len(atts) != 1 || atts[0].Path != "/data/s3files/sessions/tid-dedup/workspace/attached_files/img.jpg" {
		t.Fatalf("expected 1 deduplicated delivered attachment, got uploads=%d atts=%+v", uploadCount, atts)
	}
}

func TestAdminOAuthStartIssuerAndRegionResolution(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	quickworkDir := filepath.Join(home, ".quickwork")
	if err := os.MkdirAll(quickworkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilesBody := `{"version":1,"entries":[
		{"provider":"social","login_metadata":{
			"tenant_url":"https://cell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev",
			"issuer_url":"https://identitycenter.amazonaws.com/ssoins-desktop-shadowed"
		}},
		{"provider":"social","login_metadata":{
			"tenant_url":"https://cell-desktop.dp.appintegrations.eu-west-1.prod.plato.ai.aws.dev/",
			"issuer_url":"https://identitycenter.amazonaws.com/ssoins-desktop-only/"
		}},
		{"provider":"social","login_metadata":{
			"tenant_url":"https://cell-conflict.dp.appintegrations.ap-northeast-1.prod.plato.ai.aws.dev",
			"issuer_url":"https://identitycenter.amazonaws.com/ssoins-desktop-fallback"
		}}
	]}`
	if err := os.WriteFile(filepath.Join(quickworkDir, "profiles.json"), []byte(profilesBody), 0o600); err != nil {
		t.Fatal(err)
	}

	accPath := filepath.Join(dir, "accounts.json")
	acctsBody := `{"accounts":[
		{"id":"p1","tenant_url":"https://cell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-pool-primary","region":"us-west-2","access_token":"at1","access_token_expiry":2000000000},
		{"id":"c1","tenant_url":"https://cell-conflict.dp.appintegrations.ap-northeast-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-conflict-1","region":"ap-northeast-1","access_token":"at2","access_token_expiry":2000000000},
		{"id":"c2","tenant_url":"https://cell-conflict.dp.appintegrations.ap-northeast-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-conflict-2","region":"ap-northeast-1","access_token":"at3","access_token_expiry":2000000000}
	]}`
	if err := os.WriteFile(accPath, []byte(acctsBody), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := quick.NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.APIKeys = []string{"admin-secret"}
	cfg.AccountsFile = accPath
	srv := New(cfg, store, mgr)

	var lastRegisteredIssuer string
	oidcMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/client/register" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastRegisteredIssuer, _ = body["issuerUrl"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"clientId":              "cid",
				"clientSecret":          "csec",
				"clientSecretExpiresAt": time.Now().Add(time.Hour).Unix(),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer oidcMock.Close()
	srv.oauthBaseURL = oidcMock.URL

	start := func(body string) (int, map[string]any) {
		lastRegisteredIssuer = ""
		req := httptest.NewRequest(http.MethodPost, "/admin/oauth/start", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer admin-secret")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		var resp map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}

	// 0. Non-HTTPS explicit issuer_url is rejected with 400.
	if code, _ := start(`{"tenant_url":"https://cell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev","issuer_url":"http://bad.example/ssoins"}`); code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-HTTPS issuer_url, got %d", code)
	}

	// 1. Explicit issuer_url overrides both pool and desktop profile.
	code, resp := start(`{"tenant_url":"https://cell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-explicit/"}`)
	if code != http.StatusOK || lastRegisteredIssuer != "https://identitycenter.amazonaws.com/ssoins-explicit" || resp["region"] != "us-west-2" {
		t.Fatalf("explicit override failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}

	// 2. Discovery callback issuer/region overrides legacy default values.
	code, resp = start(`{"discovery_callback_url":"http://127.0.0.1:18080/?tenantUrl=https%3A%2F%2Fcell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev&idcInstanceId=ssoins-from-disc&idcRegion=us-west-2","issuer_url":"` + cli.DefaultSocialIssuerURL + `","region":"us-east-1"}`)
	if code != http.StatusOK || lastRegisteredIssuer != "https://identitycenter.amazonaws.com/ssoins-from-disc" || resp["region"] != "us-west-2" {
		t.Fatalf("discovery override failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}

	// 3. Matching pool account wins over desktop profile and inherits region.
	code, resp = start(`{"tenant_url":"https://cell-pool.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev"}`)
	if code != http.StatusOK || lastRegisteredIssuer != "https://identitycenter.amazonaws.com/ssoins-pool-primary" || resp["region"] != "us-west-2" {
		t.Fatalf("pool issuer resolution failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}

	// 4. Conflicting pool issuers do not guess and fall through to desktop profile.
	code, resp = start(`{"tenant_url":"https://cell-conflict.dp.appintegrations.ap-northeast-1.prod.plato.ai.aws.dev"}`)
	if code != http.StatusOK || lastRegisteredIssuer != "https://identitycenter.amazonaws.com/ssoins-desktop-fallback" || resp["region"] != "ap-northeast-1" {
		t.Fatalf("conflict fallthrough to desktop failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}

	// 5. Desktop profile discovery applies when pool has no match, and region is inferred from tenant_url.
	code, resp = start(`{"tenant_url":"https://cell-desktop.dp.appintegrations.eu-west-1.prod.plato.ai.aws.dev"}`)
	if code != http.StatusOK || lastRegisteredIssuer != "https://identitycenter.amazonaws.com/ssoins-desktop-only" || resp["region"] != "eu-west-1" {
		t.Fatalf("desktop issuer + region inference failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}

	// 6. Unknown tenant falls back to DefaultSocialIssuerURL and inferred region (or us-east-1).
	code, resp = start(`{"tenant_url":"https://cell-unknown.dp.appintegrations.ca-central-1.prod.plato.ai.aws.dev"}`)
	if code != http.StatusOK || lastRegisteredIssuer != cli.DefaultSocialIssuerURL || resp["region"] != "ca-central-1" {
		t.Fatalf("fallback resolution failed: code=%d registered=%q resp=%+v", code, lastRegisteredIssuer, resp)
	}
}
