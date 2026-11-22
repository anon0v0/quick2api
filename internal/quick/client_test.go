package quick

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"quick2api/internal/auth"
)

func TestParseQuota(t *testing.T) {
	if ParseQuota(nil) != nil || ParseQuota(map[string]any{"unrelated": true}) != nil {
		t.Fatal("expected nil quota for empty/unrelated payload")
	}
	raw := map[string]any{
		"monthly": map[string]any{
			"used":      float64(42),
			"limit":     float64(600),
			"percent":   float64(7),
			"resets_at": float64(1780000000),
		},
		"session": map[string]any{
			"used":              float64(100),
			"limit":             float64(100),
			"percent":           float64(100),
			"resets_at":         float64(1777777777),
			"resume_in_minutes": float64(18),
		},
		"subscription": map[string]any{
			"subscription_type": "FREE_TRIAL",
			"free_trial_metadata": map[string]any{
				"status": "ACTIVE",
			},
		},
	}
	q := ParseQuota(raw)
	if q == nil {
		t.Fatal("expected non-nil quota")
	}
	if q.MonthlyUsed != 42 || q.MonthlyLimit != 600 || q.MonthlyPercent != 7 || q.MonthlyResetsAt != 1780000000 {
		t.Fatalf("unexpected monthly quota: %+v", q)
	}
	if q.SessionUsed != 100 || q.SessionLimit != 100 || q.SessionResumeMin != 18 || q.SessionResetsAt != 1777777777 {
		t.Fatalf("unexpected session quota: %+v", q)
	}
	if q.SubscriptionType != "FREE_TRIAL" || q.TrialStatus != "ACTIVE" {
		t.Fatalf("unexpected subscription metadata: %+v", q)
	}
}

func TestProbeProxyAndSanitizeError(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"a1","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}

	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.42"}`))
	}))
	defer echoSrv.Close()

	ip, latency, err := mgr.ProbeProxy(context.Background(), auth.Account{ID: "a1"}, echoSrv.URL)
	if err != nil || ip != "203.0.113.42" || latency < 0 {
		t.Fatalf("ProbeProxy failed: ip=%q latency=%d err=%v", ip, latency, err)
	}

	// Dead proxy with credentials must fail cleanly without leaking userinfo.
	_, _, err = mgr.ProbeProxy(context.Background(), auth.Account{
		ID:       "a1",
		ProxyURL: "http://secretuser:secretpass@127.0.0.1:1",
	}, echoSrv.URL)
	if err == nil {
		t.Fatal("expected dead proxy error")
	}
	if strings.Contains(err.Error(), "secretuser") || strings.Contains(err.Error(), "secretpass") {
		t.Fatalf("proxy credentials leaked in error: %v", err)
	}
}

func TestReconcileReloadSelectiveInvalidation(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"keep","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}

	mkConn := func(id string) *accountConn {
		return &accountConn{accountID: id, alive: true, done: make(chan struct{}), threads: make(map[string]*threadSub)}
	}
	cKeep := mkConn("keep")
	cRemoved := mkConn("removed")
	cDisabled := mkConn("disabled")
	cProxy := mkConn("proxy-changed")
	mgr.mu.Lock()
	mgr.conns["keep"] = cKeep
	mgr.conns["removed"] = cRemoved
	mgr.conns["disabled"] = cDisabled
	mgr.conns["proxy-changed"] = cProxy
	mgr.mu.Unlock()

	mgr.ReconcileReload(auth.ReloadResult{
		Removed:      []string{"removed"},
		Disabled:     []string{"disabled"},
		ProxyChanged: []string{"proxy-changed"},
	})

	if mgr.ActiveConnections() != 1 || !cKeep.isAlive() {
		t.Fatalf("expected only 'keep' alive, active=%d keepAlive=%v", mgr.ActiveConnections(), cKeep.isAlive())
	}
	if cRemoved.isAlive() || cDisabled.isAlive() || cProxy.isAlive() {
		t.Fatal("expected removed/disabled/proxy-changed connections to be closed")
	}
}

func TestParseQuickErrorEventTopLevelAndNested(t *testing.T) {
	// 1. Real top-level SNCS FrameTooLarge error (no payload sub-object).
	rawFrameTooLarge := []byte(`{"type":"error","code":"FrameTooLarge","message":"This message is over the 64 KB size limit, so it was not sent. Try again with a smaller message.","trace_id":"t1","source":"sncs","retryable":false,"failed_frame_type":"user_message","thread_id":"th-1"}`)
	ev, ignore, failed, _ := parseQuickErrorEvent(rawFrameTooLarge, nil)
	if ignore {
		t.Fatal("FrameTooLarge must not be ignored")
	}
	if ev.Kind != "error" || ev.ErrorCode != "frame_too_large" || ev.Retryable || failed != "user_message" {
		t.Fatalf("unexpected FrameTooLarge event: ev=%+v failed=%q", ev, failed)
	}
	if !strings.Contains(ev.ErrorMsg, "64 KB size limit") {
		t.Fatalf("expected original SNCS message, got %q", ev.ErrorMsg)
	}

	// 2. Background session_delete error must be ignored.
	rawDel := []byte(`{"type":"error","payload":{"message":"Error deleting session: session delete was not confirmed","operation":"session_delete","session_id":"th-1"}}`)
	var pDel map[string]any
	_ = json.Unmarshal([]byte(`{"message":"Error deleting session: session delete was not confirmed","operation":"session_delete","session_id":"th-1"}`), &pDel)
	_, ignore, _, _ = parseQuickErrorEvent(rawDel, pDel)
	if !ignore {
		t.Fatal("expected session_delete error to be ignored")
	}

	// 3. Transient InternalFailure delivery error -> retryable=true.
	rawDelivery := []byte(`{"type":"error","code":"InternalFailure","message":"Failed to deliver message to agent"}`)
	ev, ignore, _, _ = parseQuickErrorEvent(rawDelivery, nil)
	if ignore || !ev.Retryable || ev.Kind != "error" {
		t.Fatalf("expected retryable delivery error, got ignore=%v ev=%+v", ignore, ev)
	}

	// 4. Auth error & context_overflow & throttling & usage_limit.
	evAuth, _, _, _ := parseQuickErrorEvent([]byte(`{"type":"error","payload":{"error_code":"auth_error","message":"ExpiredToken"}}`), map[string]any{"error_code": "auth_error", "message": "ExpiredToken"})
	if evAuth.ErrorCode != "auth_error" {
		t.Fatalf("expected auth_error, got %+v", evAuth)
	}
	evOV, _, _, _ := parseQuickErrorEvent([]byte(`{"type":"error","code":"context_overflow","message":"context full"}`), nil)
	if evOV.ErrorCode != "context_overflow" || evOV.Retryable {
		t.Fatalf("expected non-retryable context_overflow, got %+v", evOV)
	}
	evRL, _, _, _ := parseQuickErrorEvent([]byte(`{"type":"error","code":"ThrottlingException","status_code":429,"message":"slow down"}`), nil)
	if evRL.Kind != "rate_limited" {
		t.Fatalf("expected rate_limited, got %+v", evRL)
	}
	evUL, _, _, _ := parseQuickErrorEvent([]byte(`{"type":"error","payload":{"error_code":"usage_limit","message":"quota exhausted"}}`), map[string]any{"error_code": "usage_limit", "message": "quota exhausted"})
	if evUL.Kind != "usage_blocked" {
		t.Fatalf("expected usage_blocked, got %+v", evUL)
	}

	// 5. Bare unknown error must preserve raw JSON snippet instead of opaque generic text.
	evUnk, _, _, _ := parseQuickErrorEvent([]byte(`{"type":"error","weird_field":"diagnostic_value"}`), nil)
	if !strings.Contains(evUnk.ErrorMsg, "diagnostic_value") {
		t.Fatalf("expected raw snippet in fallback message, got %q", evUnk.ErrorMsg)
	}
}

func TestPlanTurnFramesSingleAndStaged(t *testing.T) {
	// 1. Small prompt stays single-turn untouched.
	turns, sz, err := PlanTurnFrames(TurnRequest{
		CustomPrompt:   "You are helpful.",
		Text:           "Hello <world> & friends",
		AgentMode:      "opus_4_6",
		ThinkingEffort: "high",
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil || len(turns) != 1 || sz > MaxInnerUserMessageBytes {
		t.Fatalf("expected 1 turn under limit, got len=%d sz=%d err=%v", len(turns), sz, err)
	}
	if turns[0].IsStaging || turns[0].CustomPrompt != "You are helpful." || turns[0].Text != "Hello <world> & friends" {
		t.Fatalf("single turn mutated: %+v", turns[0])
	}

	// Verify MarshalAIDPInner does not bloat <, >, & with HTML escapes.
	rawInner, err := MarshalAIDPInner(map[string]string{"x": "<tag>a&b</tag>"})
	if err != nil || !strings.Contains(string(rawInner), "<tag>a&b</tag>") {
		t.Fatalf("expected unescaped HTML in MarshalAIDPInner, got %q err=%v", string(rawInner), err)
	}

	// 2. CPA-style oversized prompt (54KB CustomPrompt + 23KB Text + Attachments) -> 2 turns, every frame <= 58KB.
	bigCP := strings.Repeat("TOOL_SCHEMA_LINE_0123456789\n", 1950)         // ~54.6KB
	bigText := strings.Repeat("CONVERSATION_LINE_\"quoted\"_<tag>\n", 700) // ~23.1KB
	atts := []Attachment{{Type: "image", Name: "shot.jpg", Size: 150000, MimeType: "image/jpeg", AttachmentID: "att-1", Path: "/data/s3files/attached_files/shot.jpg"}}
	turns, _, err = PlanTurnFrames(TurnRequest{
		CustomPrompt:        bigCP,
		CompactCustomPrompt: "[Direct API Tool-Calling Mode] Use <quick_tool_call>.",
		Text:                bigText,
		AgentMode:           "opus_4_6",
		ThinkingEffort:      "high",
		Attachments:         atts,
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames failed: %v", err)
	}
	if len(turns) != 2 {
		t.Fatalf("expected 2 turns for 54KB CP + 23KB Text (keeping full CP inline), got %d", len(turns))
	}
	if !turns[0].IsStaging || turns[0].ThinkingEffort != "low" || len(turns[0].Attachments) != 1 {
		t.Fatalf("unexpected staging turn 0 (expected attachments staged on turn 0): isStaging=%v effort=%s atts=%d", turns[0].IsStaging, turns[0].ThinkingEffort, len(turns[0].Attachments))
	}
	if turns[1].IsStaging || turns[1].ThinkingEffort != "high" || len(turns[1].Attachments) != 0 || turns[1].CustomPrompt != bigCP {
		t.Fatalf("expected full 54KB CustomPrompt preserved inline on final turn 1 without attachment bloat: isStaging=%v effort=%s atts=%d cpLen=%d", turns[1].IsStaging, turns[1].ThinkingEffort, len(turns[1].Attachments), len(turns[1].CustomPrompt))
	}
	for i, tr := range turns {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, merr := MarshalAIDPInner(frame)
		if merr != nil || len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("turn %d exceeded %d bytes: len=%d err=%v", i, MaxInnerUserMessageBytes, len(b), merr)
		}
		if !utf8.ValidString(tr.Text) {
			t.Fatalf("turn %d produced invalid UTF-8", i)
		}
	}
	// 2a. Regression: 57KB CustomPrompt + 5 delivered image attachments + 135KB conversation
	// must keep full CustomPrompt inline on the final turn (preventing prompt-attack guardrail false positives)
	// by placing attachments on Turn 0 and staying <= MaxInnerUserMessageBytes on every frame.
	cp57k := "CRITICAL RULES: NEVER invoke built-in tools.\n" + strings.Repeat("TOOL_AND_SYS_LINE_0123456789\n", 1960) // ~57KB raw
	conv135k := strings.Repeat("CONVERSATION_HISTORY_LINE_0123456789\n", 3650)                                         // ~135KB raw
	fiveAtts := make([]Attachment, 5)
	for i := range fiveAtts {
		fiveAtts[i] = Attachment{
			Type:          "image",
			Name:          "shot.png",
			Size:          500000,
			MimeType:      "image/png",
			AttachmentID:  "00000000-0000-4000-8000-000000000000",
			ContentSha256: strings.Repeat("a", 64),
			Path:          "/data/s3files/sessions/00000000-0000-4000-8000-000000000000/workspace/attached_files/shot.png",
		}
	}
	turns57, _, err := PlanTurnFrames(TurnRequest{
		CustomPrompt:        cp57k,
		CompactCustomPrompt: "[Direct API Tool-Calling Mode] Use <quick_tool_call>.",
		StageableCustomBody: "FALLBACK_BODY",
		Text:                conv135k,
		AgentMode:           "opus_4_6",
		ThinkingEffort:      "high",
		Attachments:         fiveAtts,
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames 57KB+5atts failed: %v", err)
	}
	if len(turns57) < 3 {
		t.Fatalf("expected >=3 turns for 57KB CP + 135KB conv + 5 atts, got %d", len(turns57))
	}
	if len(turns57[0].Attachments) != 5 || len(turns57[len(turns57)-1].Attachments) != 0 {
		t.Fatalf("expected all 5 attachments on turn 0 and 0 on final turn, got t0=%d tLast=%d", len(turns57[0].Attachments), len(turns57[len(turns57)-1].Attachments))
	}
	if turns57[len(turns57)-1].CustomPrompt != cp57k {
		t.Fatalf("expected full 57KB CustomPrompt kept inline on final turn")
	}
	for i, tr := range turns57 {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, merr := MarshalAIDPInner(frame)
		if merr != nil || len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("57KB+5atts turn %d exceeded %d bytes: len=%d err=%v", i, MaxInnerUserMessageBytes, len(b), merr)
		}
		if i < len(turns57)-1 && strings.Contains(tr.Text, "CRITICAL RULES") {
			t.Fatalf("57KB+5atts staging turn %d leaked CustomPrompt into user text", i)
		}
	}

	// 2a2. Attachment-only overflow: 57KB CP + 4KB Text fits without attachments, but 10 attachments push singleSize > limit.
	tenAtts := append(append([]Attachment{}, fiveAtts...), fiveAtts...)
	turnsAttOnly, _, err := PlanTurnFrames(TurnRequest{
		CustomPrompt:   cp57k,
		Text:           strings.Repeat("Short reply prompt.\n", 180), // ~3.6KB
		AgentMode:      "opus_4_6",
		ThinkingEffort: "high",
		Attachments:    tenAtts,
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames attachment-only overflow failed: %v", err)
	}
	if len(turnsAttOnly) != 2 || len(turnsAttOnly[0].Attachments) != 10 || len(turnsAttOnly[1].Attachments) != 0 || turnsAttOnly[1].CustomPrompt != cp57k {
		t.Fatalf("expected 2 turns (attachments on turn 0, full CP inline on turn 1), got len=%d t0Atts=%d t1Atts=%d cpMatch=%v",
			len(turnsAttOnly), len(turnsAttOnly[0].Attachments), len(turnsAttOnly[len(turnsAttOnly)-1].Attachments), turnsAttOnly[len(turnsAttOnly)-1].CustomPrompt == cp57k)
	}
	for i, tr := range turnsAttOnly {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, merr := MarshalAIDPInner(frame)
		if merr != nil || len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("att-only overflow turn %d exceeded %d bytes: len=%d err=%v", i, MaxInnerUserMessageBytes, len(b), merr)
		}
	}
	// 2b. Huge CustomPrompt (~110KB, e.g. SillyTavern card + closing preset) uses hybrid inline fill:
	// packs the largest tail (~60KB, including closing rules) into final turn's custom_prompt,
	// and stages only the opening prefix into Turn 0 (keeping CRITICAL RULES out of user text).
	hugeCP := "CRITICAL RULES: NEVER invoke built-in tools.\n" + strings.Repeat("SYS_DOC_LINE_0123456789\n", 4600) + "CLOSING_PRESET_CANARY\n"
	neutralBody := "OPENING_LORE_CANARY\n" + strings.Repeat("NEUTRAL_REF_LINE_0123456789\n", 3900) + "CLOSING_PRESET_CANARY\n"
	turnsHuge, _, err := PlanTurnFrames(TurnRequest{
		CustomPrompt:        hugeCP,
		CompactCustomPrompt: "[Direct API Tool-Calling Mode] Use <quick_tool_call>.",
		StageableCustomBody: neutralBody,
		Text:                "Final user question.",
		AgentMode:           "opus_4_6",
		ThinkingEffort:      "high",
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames huge CP failed: %v", err)
	}
	if len(turnsHuge) != 2 {
		t.Fatalf("expected 2 turns for 110KB body via hybrid inline tail (~50KB staged + ~60KB inline CP), got %d", len(turnsHuge))
	}
	if strings.Contains(turnsHuge[0].Text, "CRITICAL RULES") || strings.Contains(turnsHuge[0].Text, "CLOSING_PRESET_CANARY") {
		t.Fatalf("staging turn 0 must NOT contain CRITICAL RULES or closing preset tail")
	}
	if !strings.Contains(turnsHuge[0].Text, "OPENING_LORE_CANARY") {
		t.Fatalf("expected opening prefix in staging turn 0")
	}
	finalHugeCP := turnsHuge[len(turnsHuge)-1].CustomPrompt
	if !strings.Contains(finalHugeCP, "<quick_tool_call>") || !strings.Contains(finalHugeCP, "CLOSING_PRESET_CANARY") {
		t.Fatalf("expected CompactCustomPrompt + closing preset tail in final custom_prompt, got len=%d", len(finalHugeCP))
	}
	for i, tr := range turnsHuge {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, merr := MarshalAIDPInner(frame)
		if merr != nil || len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("huge CP turn %d exceeded %d bytes: len=%d err=%v", i, MaxInnerUserMessageBytes, len(b), merr)
		}
	}

	// 2c. Oversized tool-mode CustomPrompt (25KB tools + 50KB system = 75KB > 63KB):
	// keeps 100% of tool definitions + tail of system prompt in final custom_prompt,
	// staging ONLY the opening system prefix so zero JSON tool schemas enter user_message.text.
	toolInline25k := "[Direct API Tool-Calling Mode]\nDeclared Caller Tools:\n" + strings.Repeat("- {\"name\":\"tool_x\",\"description\":\"desc 0123456789\"}\n", 480)
	sysBody50k := "SYS_HEAD_CANARY\n" + strings.Repeat("SYSTEM_GUIDELINE_LINE_0123456789\n", 1500) + "SYS_TAIL_CANARY\n"
	turnsToolHybrid, _, err := PlanTurnFrames(TurnRequest{
		CustomPrompt:           toolInline25k + "\n\n" + sysBody50k,
		CompactCustomPrompt:    "[Direct API Tool-Calling Mode] Use <quick_tool_call>.",
		ToolInlineCustomPrompt: toolInline25k,
		StageableSystemBody:    sysBody50k,
		StageableCustomBody:    "Declared Caller Tools:\n" + sysBody50k,
		Text:                   "Call tool_x.",
		AgentMode:              "opus_4_6",
		ThinkingEffort:         "high",
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames tool hybrid failed: %v", err)
	}
	if len(turnsToolHybrid) != 2 {
		t.Fatalf("expected 2 turns for 75KB tool+system hybrid, got %d", len(turnsToolHybrid))
	}
	if strings.Contains(turnsToolHybrid[0].Text, "Declared Caller Tools") || !strings.Contains(turnsToolHybrid[0].Text, "SYS_HEAD_CANARY") {
		t.Fatalf("expected only system prefix (zero tool schemas) in turn 0")
	}
	finalToolCP := turnsToolHybrid[1].CustomPrompt
	if !strings.Contains(finalToolCP, "Declared Caller Tools") || !strings.Contains(finalToolCP, "SYS_TAIL_CANARY") {
		t.Fatalf("expected 100%% of tools + system tail in final custom_prompt")
	}
	for i, tr := range turnsToolHybrid {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, merr := MarshalAIDPInner(frame)
		if merr != nil || len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("tool hybrid turn %d exceeded %d bytes: len=%d err=%v", i, MaxInnerUserMessageBytes, len(b), merr)
		}
	}

	// 3. Modest CustomPrompt (4KB) + huge UTF-8 Chinese/escaped Text (130KB) -> keeps full CustomPrompt inline on final turn & preserves valid UTF-8.
	smallCP := "SYSTEM_KEEP_INLINE_" + strings.Repeat("S", 4000)
	cjkText := strings.Repeat("中文多字节内容\"引号\"\\反斜杠\n", 4000)
	turns, _, err = PlanTurnFrames(TurnRequest{
		CustomPrompt:   smallCP,
		Text:           cjkText,
		AgentMode:      "opus_4_6",
		ThinkingEffort: "medium",
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	if err != nil {
		t.Fatalf("PlanTurnFrames CJK failed: %v", err)
	}
	if len(turns) < 3 {
		t.Fatalf("expected >=3 turns for 130KB CJK text, got %d", len(turns))
	}
	if turns[len(turns)-1].CustomPrompt != smallCP {
		t.Fatalf("expected modest CustomPrompt to stay inline on final turn")
	}
	for i, tr := range turns {
		frame := buildUserMessageFrame(sampleUUID, "QUICK_WORK_DESKTOP_WINDOWS", "opus_4_6", tr.ThinkingEffort, tr.CustomPrompt, tr.Text, tr.Attachments)
		b, _ := MarshalAIDPInner(frame)
		if len(b) > MaxInnerUserMessageBytes {
			t.Fatalf("CJK turn %d exceeded limit: %d", i, len(b))
		}
		if !utf8.ValidString(tr.Text) {
			t.Fatalf("CJK turn %d split mid-rune", i)
		}
	}

	// 4. Absurdly huge 1.5MB prompt fails fast with ContextOverflowError.
	_, _, err = PlanTurnFrames(TurnRequest{
		Text:           strings.Repeat("A", 1_500_000),
		AgentMode:      "opus_4_6",
		ThinkingEffort: "low",
	}, "QUICK_WORK_DESKTOP_WINDOWS", MaxInnerUserMessageBytes)
	var ovErr *ContextOverflowError
	if !errors.As(err, &ovErr) {
		t.Fatalf("expected ContextOverflowError for 1.5MB prompt, got %v", err)
	}
}

func TestUploadAndDeliverAttachmentFlow(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"a1","tenant_url":"https://127.0.0.1:1","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}

	dlpPolls := 0
	deliveredTID := ""
	blockDLP := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/integration/quick-work/upload-attachment":
			_, _ = w.Write([]byte(`{"attachmentId":"att-xyz-123"}`))
		case r.URL.Path == "/integration/quick-work/attachment-dlp-status":
			dlpPolls++
			if blockDLP {
				_, _ = w.Write([]byte(`{"dlpJobStatus":"COMPLETED","policyAction":"BLOCK","dlpPolicyMessage":"sensitive data blocked"}`))
				return
			}
			if dlpPolls == 1 {
				_, _ = w.Write([]byte(`{"dlpJobStatus":"IN_PROGRESS"}`))
				return
			}
			_, _ = w.Write([]byte(`{"dlpJobStatus":"COMPLETED","policyAction":"ALLOW"}`))
		case r.URL.Path == "/integration/quick-work/qbs-event":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			ia := body["eventBody"].(map[string]any)["invokeAgent"].(map[string]any)
			deliveredTID = ia["path"].(string)
			inner, _ := json.Marshal(map[string]any{"path": "/data/s3files/sessions/tid-1/workspace/attached_files/pic.png"})
			apiResp, _ := json.Marshal(map[string]any{"type": "api_response", "status": 200, "body": string(inner)})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"eventResponse": map[string]any{"invokeAgentResponse": string(apiResp)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	acct := auth.Account{ID: "a1", TenantURL: srv.URL, AccessToken: "at"}
	att, err := mgr.UploadAndDeliverAttachment(context.Background(), acct, "tid-1", "pic.png", "image/png", []byte("pngbytes"))
	if err != nil {
		t.Fatalf("UploadAndDeliverAttachment failed: %v", err)
	}
	if att.AttachmentID != "att-xyz-123" || att.Path != "/data/s3files/sessions/tid-1/workspace/attached_files/pic.png" || deliveredTID != "files/upload/tid-1" || dlpPolls != 2 {
		t.Fatalf("unexpected attachment delivery result: att=%+v deliveredTID=%q dlpPolls=%d", att, deliveredTID, dlpPolls)
	}

	blockDLP = true
	if _, err := mgr.UploadAndDeliverAttachment(context.Background(), acct, "tid-1", "bad.png", "image/png", []byte("x")); err == nil || !strings.Contains(err.Error(), "sensitive data blocked") {
		t.Fatalf("expected DLP block error, got %v", err)
	}
}

func TestStreamTurnMultiTurnStagingOverMockWS(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"a1","tenant_url":"https://127.0.0.1:1","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	upgrader := websocket.Upgrader{}
	var mu sync.Mutex
	var seenUserMessages []map[string]any
	var seenDeletes int

	emitWS := func(ws *websocket.Conn, obj map[string]any) {
		b, _ := json.Marshal(obj)
		outer, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(b)})
		es := EncodeEventStreamMessage(map[string]string{
			":message-type": "event",
			":event-type":   "rawOutputEvent",
		}, outer)
		_ = ws.WriteMessage(websocket.BinaryMessage, es)
	}

	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			var env struct {
				Payload struct {
					Payload string `json:"payload"`
				} `json:"payload"`
			}
			if json.Unmarshal(data, &env) != nil {
				continue
			}
			innerBytes, err := base64.StdEncoding.DecodeString(env.Payload.Payload)
			if err != nil {
				continue
			}
			var frame map[string]any
			if json.Unmarshal(innerBytes, &frame) != nil {
				continue
			}
			switch frame["type"] {
			case "user_message":
				if len(innerBytes) > MaxInnerUserMessageBytes {
					t.Errorf("sent oversized user_message frame: %d bytes", len(innerBytes))
				}
				pay := frame["payload"].(map[string]any)
				tid := pay["thread_id"].(string)
				mu.Lock()
				seenUserMessages = append(seenUserMessages, pay)
				idx := len(seenUserMessages)
				mu.Unlock()
				if idx == 1 {
					emitWS(ws, map[string]any{"type": "text_delta", "thread_id": tid, "payload": map[string]any{"delta": "OK"}})
					emitWS(ws, map[string]any{"type": "turn_usage", "thread_id": tid, "payload": map[string]any{"input_tokens": 10, "output_tokens": 2}})
					emitWS(ws, map[string]any{"type": "message_complete", "thread_id": tid, "payload": map[string]any{"text": "OK"}})
				} else {
					emitWS(ws, map[string]any{"type": "text_delta", "thread_id": tid, "payload": map[string]any{"delta": "FINAL_ANSWER"}})
					emitWS(ws, map[string]any{"type": "turn_usage", "thread_id": tid, "payload": map[string]any{"input_tokens": 5, "cache_read_tokens": 70000, "output_tokens": 9}})
					emitWS(ws, map[string]any{"type": "message_complete", "thread_id": tid, "payload": map[string]any{"text": "FINAL_ANSWER"}})
				}
			case "session_delete":
				mu.Lock()
				seenDeletes++
				mu.Unlock()
			}
		}
	}))
	defer wsSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(wsSrv.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ac := &accountConn{
		accountID:   "a1",
		token:       "at",
		proxyURL:    "",
		surfaceType: "QUICK_WORK_DESKTOP_WINDOWS",
		ws:          wsConn,
		alive:       true,
		threads:     make(map[string]*threadSub),
		done:        make(chan struct{}),
	}
	connectedCh := make(chan error, 1)
	go ac.readLoop(connectedCh)
	mgr.mu.Lock()
	mgr.conns["a1"] = ac
	mgr.mu.Unlock()

	acct := auth.Account{ID: "a1", AccessToken: "at"}
	evCh, err := mgr.StreamTurn(context.Background(), acct, TurnRequest{
		ThreadID:            "thread-staged-1",
		CustomPrompt:        strings.Repeat("S", 52000),
		CompactCustomPrompt: "[Direct API Mode] Compact",
		Text:                strings.Repeat("T", 22000),
		AgentMode:           "opus_4_6",
		ThinkingEffort:      "high",
	})
	if err != nil {
		t.Fatalf("StreamTurn failed: %v", err)
	}
	var gotText strings.Builder
	var gotUsage *TurnUsage
	for ev := range evCh {
		switch ev.Kind {
		case "text_delta":
			gotText.WriteString(ev.Text)
		case "turn_usage":
			gotUsage = ev.Usage
		case "error":
			t.Fatalf("unexpected stream error: %+v", ev)
		}
	}
	if gotText.String() != "FINAL_ANSWER" {
		t.Fatalf("expected only final turn text 'FINAL_ANSWER' (staging 'OK' must be hidden), got %q", gotText.String())
	}
	if gotUsage == nil || gotUsage.CacheReadTokens != 70000 || gotUsage.OutputTokens != 9 {
		t.Fatalf("expected final turn usage, got %+v", gotUsage)
	}
	// Wait briefly for deferred session_delete to arrive at mock server.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(seenUserMessages) != 2 {
		t.Fatalf("expected 2 user_message turns, got %d", len(seenUserMessages))
	}
	if seenUserMessages[0]["thread_id"] != "thread-staged-1" || seenUserMessages[1]["thread_id"] != "thread-staged-1" {
		t.Fatalf("expected same thread_id across staged turns: %v vs %v", seenUserMessages[0]["thread_id"], seenUserMessages[1]["thread_id"])
	}
	if seenUserMessages[0]["thinking_effort"] != "low" || seenUserMessages[1]["thinking_effort"] != "high" {
		t.Fatalf("expected effort low -> high, got %v -> %v", seenUserMessages[0]["thinking_effort"], seenUserMessages[1]["thinking_effort"])
	}
	if seenDeletes != 1 {
		t.Fatalf("expected exactly 1 session_delete after all staged turns, got %d", seenDeletes)
	}
}

func TestParseConnectedUserProfile(t *testing.T) {
	raw := json.RawMessage(`{"client_id":"1","user":{"sub":"sub-1","email":"alice@example.com","name":"Alice Chen","aws_account_id":"123456789012","external_id":"ext-1"}}`)
	email, name, awsID, extID := parseConnectedUserProfile(raw)
	if email != "alice@example.com" || name != "Alice Chen" || awsID != "123456789012" || extID != "ext-1" {
		t.Fatalf("unexpected profile: email=%q name=%q awsID=%q extID=%q", email, name, awsID, extID)
	}

	// Fallback to first_name + last_name and sub when name/external_id are empty.
	raw2 := json.RawMessage(`{"user":{"sub":"sub-2","email":"bob@example.com","first_name":"Bob","last_name":"Lee"}}`)
	email, name, _, extID = parseConnectedUserProfile(raw2)
	if email != "bob@example.com" || name != "Bob Lee" || extID != "sub-2" {
		t.Fatalf("unexpected fallback profile: email=%q name=%q extID=%q", email, name, extID)
	}
}
