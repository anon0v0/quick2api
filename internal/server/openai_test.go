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
