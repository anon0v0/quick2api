package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quick2api/internal/auth"
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
	srv.serveSSE(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-1", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, true, evCh, false, false)

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
	srv.serveSSE(w2, cancel, auth.Account{ID: "t1"}, "chatcmpl-2", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, errCh, false, false)
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
	srv.serveSSE(w3, cancel, auth.Account{ID: "t1"}, "chatcmpl-3", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, emptyCh, false, false)
	if w3.Code != http.StatusBadGateway || !strings.Contains(w3.Body.String(), `"empty_stream"`) {
		t.Fatalf("expected 502 empty_stream, got %d %s", w3.Code, w3.Body.String())
	}

	// 4. Stale WS close before headers triggers stale_conn retry without writing response.
	staleCh := make(chan quick.StreamEvent, 1)
	staleCh <- quick.StreamEvent{Kind: "error", ErrorCode: "stream_closed", ErrorMsg: "eof"}
	close(staleCh)

	w4 := httptest.NewRecorder()
	dir := srv.serveSSE(w4, cancel, auth.Account{ID: "t1"}, "chatcmpl-4", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, staleCh, true, false)
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
	srv.serveNonStreaming(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-ns1", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, emptyCh, false, false)
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
	srv.serveNonStreaming(w2, cancel, auth.Account{ID: "t1"}, "chatcmpl-ns2", 1700000000, "quick-opus-5.5", conv, nil, tcCh, false, false)
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
	srv.serveSSE(w, cancel, auth.Account{ID: "t1"}, "chatcmpl-ka", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, false, evCh, false, false)
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
	srv.serveNonStreaming(w1, cancel, auth.Account{ID: "t1"}, "chatcmpl-rl", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, rlCh, false, false)
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
	dir := srv.serveNonStreaming(w2, cancel, auth.Account{ID: "t1", TenantURL: usageSrv.URL, AccessToken: "at"}, "chatcmpl-ub", 1700000000, "quick-opus-5.5", prompt.ConvertedPrompt{}, nil, ubCh, false, true)
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
