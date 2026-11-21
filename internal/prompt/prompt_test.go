package prompt

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToolStreamParserChunkedAndParallel(t *testing.T) {
	allowed := map[string]bool{"read_file": true, "run_cmd": true}
	p := NewToolStreamParser(true, allowed)

	full := "I will inspect both files now.\n" +
		"<quick_tool_call>\n" +
		`{"name": "read_file", "arguments": {"path": "main.go"}}` +
		"\n</quick_tool_call>\n" +
		"<quick_tool_call>\n" +
		"```json\n" +
		`{"name": "run_cmd", "arguments": "{\"cmd\":\"go test ./...\"}"}` +
		"\n```\n" +
		"</quick_tool_call>"

	var outText strings.Builder
	var calls []ParsedToolCall
	// Feed 3 bytes at a time to stress tag-boundary splitting.
	for i := 0; i < len(full); i += 3 {
		end := i + 3
		if end > len(full) {
			end = len(full)
		}
		txt, c := p.Feed(full[i:end])
		outText.WriteString(txt)
		calls = append(calls, c...)
	}
	remTxt, remCalls := p.Flush()
	outText.WriteString(remTxt)
	calls = append(calls, remCalls...)

	if strings.TrimSpace(outText.String()) != "I will inspect both files now." {
		t.Fatalf("unexpected text output: %q", outText.String())
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d: %+v", len(calls), calls)
	}
	if calls[0].Index != 0 || calls[0].Name != "read_file" || calls[0].ArgumentsJSON != `{"path":"main.go"}` {
		t.Fatalf("unexpected call 0: %+v", calls[0])
	}
	if calls[1].Index != 1 || calls[1].Name != "run_cmd" || calls[1].ArgumentsJSON != `{"cmd":"go test ./..."}` {
		t.Fatalf("unexpected call 1: %+v", calls[1])
	}
	if !p.HasToolCalls() {
		t.Fatalf("expected HasToolCalls() == true")
	}
}

func TestToolStreamParserPlainTextWithAngleBrackets(t *testing.T) {
	p := NewToolStreamParser(true, map[string]bool{"foo": true})
	txt, calls := p.Feed("x < y && <quick_not_a_tool> hello <qu")
	rem, remCalls := p.Flush()
	got := txt + rem
	if len(calls) != 0 || len(remCalls) != 0 {
		t.Fatalf("expected 0 tool calls, got %d/%d", len(calls), len(remCalls))
	}
	if got != "x < y && <quick_not_a_tool> hello <qu" {
		t.Fatalf("text mutated: %q", got)
	}
}

func TestConvertSillyTavernPrefillAndMidSystem(t *testing.T) {
	req := ChatCompletionRequest{
		Model: "quick-opus-5.5",
		Messages: []Message{
			{Role: "system", Content: json.RawMessage(`"You are Alice, a concise narrator."`)},
			{Role: "user", Content: json.RawMessage(`"Enter the tavern."`)},
			{Role: "system", Content: json.RawMessage(`"[Author's Note: keep tone atmospheric]"`)},
			{Role: "assistant", Content: json.RawMessage(`"The oak door creaked open"`)},
		},
	}
	conv := Convert(req)
	if conv.ToolMode {
		t.Fatalf("expected ToolMode=false")
	}
	if !strings.Contains(conv.CustomPrompt, "You are Alice") {
		t.Fatalf("missing leading system in custom_prompt: %s", conv.CustomPrompt)
	}
	if !strings.Contains(conv.Text, "<system_note>\n[Author's Note: keep tone atmospheric]\n</system_note>") {
		t.Fatalf("missing mid-conversation system_note: %s", conv.Text)
	}
	if !strings.Contains(conv.Text, "Continue seamlessly from the end of the final assistant turn") {
		t.Fatalf("missing prefill continuation instruction: %s", conv.Text)
	}
}

func TestStopFilter(t *testing.T) {
	sf := NewStopFilter([]string{"\nUser:", "STOP!"})
	var out strings.Builder
	chunks := []string{"Hello ", "world\nUs", "er: ignored"}
	hitAny := false
	for _, c := range chunks {
		emit, hit := sf.Feed(c)
		out.WriteString(emit)
		if hit {
			hitAny = true
			break
		}
	}
	out.WriteString(sf.Flush())
	if !hitAny {
		t.Fatalf("expected stop sequence hit")
	}
	if out.String() != "Hello world" {
		t.Fatalf("got %q, want %q", out.String(), "Hello world")
	}
}

func TestEffectiveReasoningEffortShapes(t *testing.T) {
	budgetFn := func(b int) string {
		if b <= 4096 {
			return "low"
		}
		if b <= 16384 {
			return "medium"
		}
		return "high"
	}
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"snake", `{"model":"m","reasoning_effort":"medium"}`, "medium"},
		{"camel", `{"model":"m","reasoningEffort":"low"}`, "low"},
		{"reasoning_obj", `{"model":"m","reasoning":{"effort":"max"}}`, "max"},
		{"reasoning_disabled", `{"model":"m","reasoning":{"enabled":false}}`, "off"},
		{"thinking_budget", `{"model":"m","thinking":{"type":"enabled","budget_tokens":10000}}`, "medium"},
		{"thinking_disabled", `{"model":"m","thinking":{"type":"disabled"}}`, "off"},
		{"extra_body", `{"model":"m","extra_body":{"thinking":{"type":"enabled","budget_tokens":2000}}}`, "low"},
	}
	for _, tc := range cases {
		var req ChatCompletionRequest
		if err := json.Unmarshal([]byte(tc.raw), &req); err != nil {
			t.Fatalf("%s unmarshal: %v", tc.name, err)
		}
		if got := req.EffectiveReasoningEffort(budgetFn); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestExtractMessageContentStringImageURL(t *testing.T) {
	raw := json.RawMessage(`[
		{"type":"text","text":"Describe this"},
		{"type":"image_url","image_url":"data:image/png;base64,aGVsbG8="},
		{"type":"input_image","image_url":{"url":"https://example.com/a.png"}}
	]`)
	counter := 0
	txt, imgs := ExtractMessageContent(raw, &counter)
	if txt != "Describe this" {
		t.Fatalf("unexpected text: %q", txt)
	}
	if len(imgs) != 2 {
		t.Fatalf("expected 2 images, got %d: %+v", len(imgs), imgs)
	}
	if string(imgs[0].Data) != "hello" || imgs[0].MimeType != "image/png" {
		t.Fatalf("unexpected first image: %+v", imgs[0])
	}
	if imgs[1].URL != "https://example.com/a.png" {
		t.Fatalf("unexpected second image: %+v", imgs[1])
	}
}

func TestConvertToolChoiceRepackAndCacheOrder(t *testing.T) {
	// 1. Object tool_choice {"type":"none"} must disable tool mode.
	var reqNone ChatCompletionRequest
	if err := json.Unmarshal([]byte(`{
		"model":"quick-opus-5.5",
		"tools":[{"type":"function","name":"read_file","description":"Read file"}],
		"tool_choice":{"type":"none"},
		"messages":[{"role":"user","content":"hi"}]
	}`), &reqNone); err != nil {
		t.Fatal(err)
	}
	if conv := Convert(reqNone); conv.ToolMode {
		t.Fatalf("expected ToolMode=false for tool_choice={type:none}")
	}

	// 2. allowed_tools subset + flat tool + repacked interleaved developer notice + backfilled tool name + cache order.
	var req ChatCompletionRequest
	if err := json.Unmarshal([]byte(`{
		"model":"quick-opus-5.5",
		"tools":[
			{"type":"function","name":"read_file","description":"Read file"},
			{"type":"function","function":{"name":"run_cmd","description":"Run cmd"}}
		],
		"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"required","tools":[{"type":"function","function":{"name":"read_file"}}]}},
		"response_format":{"type":"json_object"},
		"messages":[
			{"role":"system","content":"BASE_SYSTEM_PROMPT"},
			{"role":"user","content":"check"},
			{"role":"assistant","content":null,"tool_calls":[
				{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"p\":\"a\"}"}},
				{"id":"c2","type":"function","function":{"name":"read_file","arguments":"{\"p\":\"b\"}"}}
			]},
			{"role":"tool","tool_call_id":"c1","content":"content-a"},
			{"role":"developer","content":"<image_resize_notice>resized</image_resize_notice>"},
			{"role":"tool","tool_call_id":"c2","content":"content-b"}
		]
	}`), &req); err != nil {
		t.Fatal(err)
	}
	conv := Convert(req)
	if !conv.ToolMode || !conv.AllowedTools["read_file"] || conv.AllowedTools["run_cmd"] {
		t.Fatalf("unexpected allowed tools: %+v", conv.AllowedTools)
	}
	// Cache-friendly prefix: Declared Caller Tools & BASE_SYSTEM_PROMPT must appear BEFORE [Tool Choice = REQUIRED] and [Output Format].
	idxTools := strings.Index(conv.CustomPrompt, "Declared Caller Tools:")
	idxSys := strings.Index(conv.CustomPrompt, "BASE_SYSTEM_PROMPT")
	idxChoice := strings.Index(conv.CustomPrompt, "[Tool Choice = REQUIRED]")
	idxFmt := strings.Index(conv.CustomPrompt, "[Output Format]")
	if !(idxTools >= 0 && idxTools < idxSys && idxSys < idxChoice && idxChoice < idxFmt) {
		t.Fatalf("non-cache-friendly custom_prompt order: tools=%d sys=%d choice=%d fmt=%d", idxTools, idxSys, idxChoice, idxFmt)
	}
	// Repack + backfilled tool name: c1 and c2 must both appear before <image_resize_notice> with name="read_file".
	idxC1 := strings.Index(conv.Text, `<tool_result tool_call_id="c1" name="read_file">`)
	idxC2 := strings.Index(conv.Text, `<tool_result tool_call_id="c2" name="read_file">`)
	idxNotice := strings.Index(conv.Text, `<image_resize_notice>`)
	if !(idxC1 >= 0 && idxC1 < idxC2 && idxC2 < idxNotice) {
		t.Fatalf("expected repacked contiguous tool results with backfilled names, got:\n%s", conv.Text)
	}
	if !strings.Contains(conv.CompactCustomPrompt, "<quick_tool_call>") || !strings.Contains(conv.CompactCustomPrompt, "[Tool Choice = REQUIRED]") || !strings.Contains(conv.CompactCustomPrompt, "[Output Format]") {
		t.Fatalf("CompactCustomPrompt missing required directives: %s", conv.CompactCustomPrompt)
	}
	if strings.Contains(conv.CompactCustomPrompt, "BASE_SYSTEM_PROMPT") {
		t.Fatalf("CompactCustomPrompt should stay compact and omit full leading system prompt: %s", conv.CompactCustomPrompt)
	}
}

func TestToolStreamParserToolOnlyNoStrayWhitespaceAndParamsFallback(t *testing.T) {
	p := NewToolStreamParser(true, map[string]bool{"read_file": true})
	in := "<quick_tool_call>\n{\"name\":\"read_file\",\"parameters\":{\"path\":\"a.go\"}}\n</quick_tool_call>\n\n<quick_tool_call>\n{\"name\":\"read_file\",\"arguments\":{\"path\":\"b.go\"}}\n</quick_tool_call>\n"
	txt, calls := p.Feed(in)
	remTxt, remCalls := p.Flush()
	calls = append(calls, remCalls...)
	if txt+remTxt != "" {
		t.Fatalf("expected empty text for tool-only parallel calls, got %q", txt+remTxt)
	}
	if len(calls) != 2 || calls[0].ArgumentsJSON != `{"path":"a.go"}` || calls[1].ArgumentsJSON != `{"path":"b.go"}` {
		t.Fatalf("unexpected parsed calls: %+v", calls)
	}
}
