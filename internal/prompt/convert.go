package prompt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	ToolCallOpenTag  = "<quick_tool_call>"
	ToolCallCloseTag = "</quick_tool_call>"
)

// PendingImage is an image extracted from OpenAI content parts ready to upload as a Quick attachment.
type PendingImage struct {
	Name     string
	MimeType string
	Data     []byte // populated for data: URIs
	URL      string // populated for remote http(s) URLs
}

// ConvertedPrompt is the rendered Quick payload derived from an OpenAI ChatCompletionRequest.
type ConvertedPrompt struct {
	CustomPrompt        string
	CompactCustomPrompt string
	StageableCustomBody string
	Text                string
	Images              []PendingImage
	ToolMode            bool
	AllowedTools        map[string]bool
}

type contentPart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	URL      string          `json:"url,omitempty"`
	ImageURL json.RawMessage `json:"image_url,omitempty"`
}

func extractImageURLValue(raw json.RawMessage, fallbackURL string) string {
	if len(raw) > 0 && string(raw) != "null" {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
		var obj struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil && strings.TrimSpace(obj.URL) != "" {
			return strings.TrimSpace(obj.URL)
		}
	}
	return strings.TrimSpace(fallbackURL)
}

// ExtractMessageContent extracts text and any image attachments from OpenAI message content.
func ExtractMessageContent(raw json.RawMessage, imgCounter *int) (string, []PendingImage) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err == nil {
		var texts []string
		var imgs []PendingImage
		for _, p := range parts {
			switch p.Type {
			case "text", "input_text", "output_text":
				if p.Text != "" {
					texts = append(texts, p.Text)
				}
			case "image_url", "input_image":
				if u := extractImageURLValue(p.ImageURL, p.URL); u != "" {
					if img, ok := parseImageURL(u, imgCounter); ok {
						imgs = append(imgs, img)
					}
				}
			}
		}
		return strings.Join(texts, "\n"), imgs
	}
	return strings.TrimSpace(string(raw)), nil
}

func parseImageURL(rawURL string, counter *int) (PendingImage, bool) {
	*counter++
	idx := *counter
	if strings.HasPrefix(rawURL, "data:") {
		comma := strings.IndexByte(rawURL, ',')
		if comma < 0 {
			return PendingImage{}, false
		}
		meta := rawURL[5:comma]
		dataPart := rawURL[comma+1:]
		mime := "image/png"
		if semi := strings.IndexByte(meta, ';'); semi > 0 {
			mime = meta[:semi]
		} else if meta != "" && !strings.Contains(meta, "base64") {
			mime = meta
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataPart))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(dataPart))
			if err != nil {
				return PendingImage{}, false
			}
		}
		ext := "png"
		switch strings.ToLower(mime) {
		case "image/jpeg", "image/jpg":
			ext = "jpg"
		case "image/webp":
			ext = "webp"
		case "image/gif":
			ext = "gif"
		}
		return PendingImage{
			Name:     fmt.Sprintf("image-%d.%s", idx, ext),
			MimeType: mime,
			Data:     decoded,
		}, true
	}
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		return PendingImage{
			Name: fmt.Sprintf("image-%d.png", idx),
			URL:  rawURL,
		}, true
	}
	return PendingImage{}, false
}

// Convert transforms an OpenAI ChatCompletionRequest into Quick custom_prompt + text + attachments.
func Convert(req ChatCompletionRequest) ConvertedPrompt {
	tools := collectTools(req)
	toolChoiceMode, forcedToolName, allowedSubset := parseToolChoice(req.ToolChoice, req.FunctionCall)
	if len(allowedSubset) > 0 {
		filtered := make([]FunctionDef, 0, len(tools))
		for _, t := range tools {
			if allowedSubset[t.Name] {
				filtered = append(filtered, t)
			}
		}
		tools = filtered
	}
	toolMode := len(tools) > 0 && toolChoiceMode != "none"

	allowed := make(map[string]bool, len(tools))
	for _, t := range tools {
		allowed[t.Name] = true
	}

	// Collect leading system/developer messages into custom_prompt.
	// Any later system messages (e.g. SillyTavern depth-0/depth-4 worldbook/author's note) stay in-order in the transcript.
	var leadingSystems []string
	idx := 0
	for idx < len(req.Messages) {
		r := strings.ToLower(strings.TrimSpace(req.Messages[idx].Role))
		if r == "system" || r == "developer" {
			dummy := 0
			txt, _ := ExtractMessageContent(req.Messages[idx].Content, &dummy)
			if strings.TrimSpace(txt) != "" {
				leadingSystems = append(leadingSystems, txt)
			}
			idx++
			continue
		}
		break
	}
	rest := repackMessagesForTranscript(req.Messages[idx:])

	// Cache-friendly ordering: keep static directives (tool catalog + leading system) first,
	// and put per-turn dynamic directives (tool_choice required/forced + response_format) last.
	var cpParts []string
	var compactParts []string
	var stageableParts []string
	if toolMode {
		cpParts = append(cpParts, buildToolSystemDirective(tools))
		compactParts = append(compactParts, buildCompactToolReminder())
		stageableParts = append(stageableParts, buildToolCatalogOnly(tools))
	} else {
		cpParts = append(cpParts, "[Direct API Mode] Respond directly as the assistant defined below. Do NOT invoke any built-in AWS Quick workspace, file, code, browser, memory, search, or connector tools; reply directly with text only.")
		compactParts = append(compactParts, "[Direct API Mode] Use the reference notes and context from earlier parts of this conversation. Do NOT invoke any built-in AWS Quick workspace, file, code, browser, memory, search, or connector tools; reply directly with text only.")
	}

	if len(leadingSystems) > 0 {
		joinedSys := strings.Join(leadingSystems, "\n\n")
		cpParts = append(cpParts, joinedSys)
		stageableParts = append(stageableParts, joinedSys)
	}

	if toolMode {
		switch toolChoiceMode {
		case "required":
			d := "[Tool Choice = REQUIRED] You MUST call at least one of the declared caller tools in this turn."
			cpParts = append(cpParts, d)
			compactParts = append(compactParts, d)
		case "function":
			d := fmt.Sprintf("[Tool Choice = FORCED] You MUST call the declared tool named %q in this turn.", forcedToolName)
			cpParts = append(cpParts, d)
			compactParts = append(compactParts, d)
		}
	}

	if rf := parseResponseFormatDirective(req.ResponseFormat); rf != "" {
		cpParts = append(cpParts, rf)
		if len(rf) <= 4000 {
			compactParts = append(compactParts, rf)
		} else {
			stageableParts = append(stageableParts, rf)
			compactParts = append(compactParts, "[Output Format] Follow the JSON Schema output format from the reference notes above, returning valid JSON only with no markdown fences.")
		}
	}
	compactCustomPrompt := strings.Join(compactParts, "\n\n")
	stageableCustomBody := strings.Join(stageableParts, "\n\n")
	imgCounter := 0
	var allImages []PendingImage

	// Fast path: single plain user turn (no history, no tool results, no prefill).
	if len(rest) == 1 && strings.EqualFold(rest[0].Role, "user") && len(rest[0].ToolCalls) == 0 && rest[0].FunctionCall == nil {
		txt, imgs := ExtractMessageContent(rest[0].Content, &imgCounter)
		allImages = append(allImages, imgs...)
		if strings.TrimSpace(txt) == "" && len(allImages) == 0 {
			txt = "Continue."
		}
		return ConvertedPrompt{
			CustomPrompt:        strings.Join(cpParts, "\n\n"),
			CompactCustomPrompt: compactCustomPrompt,
			StageableCustomBody: stageableCustomBody,
			Text:                txt,
			Images:              allImages,
			ToolMode:            toolMode,
			AllowedTools:        allowed,
		}
	}
	// Build tool_call_id -> function name index so role:tool results without `name` stay labeled clearly.
	toolCallIDToName := make(map[string]string)
	for _, m := range rest {
		if !strings.EqualFold(strings.TrimSpace(m.Role), "assistant") {
			continue
		}
		for _, tc := range m.ToolCalls {
			if tc.ID != "" && strings.TrimSpace(tc.Function.Name) != "" {
				toolCallIDToName[tc.ID] = strings.TrimSpace(tc.Function.Name)
			}
		}
	}

	// Multi-turn / agent loop / SillyTavern transcript path.
	var sb strings.Builder
	sb.WriteString("Below is the full conversation transcript so far. Respond ONLY as the assistant for the next turn without echoing wrapper tags.\n\n")
	sb.WriteString("<conversation>\n")

	for _, m := range rest {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		txt, imgs := ExtractMessageContent(m.Content, &imgCounter)
		allImages = append(allImages, imgs...)

		switch role {
		case "system", "developer":
			sb.WriteString("<system_note>\n")
			sb.WriteString(txt)
			sb.WriteString("\n</system_note>\n")

		case "user":
			if m.Name != "" {
				fmt.Fprintf(&sb, "<turn role=\"user\" name=%q>\n", m.Name)
			} else {
				sb.WriteString("<turn role=\"user\">\n")
			}
			sb.WriteString(txt)
			sb.WriteString("\n</turn>\n")

		case "assistant":
			if m.Name != "" {
				fmt.Fprintf(&sb, "<turn role=\"assistant\" name=%q>\n", m.Name)
			} else {
				sb.WriteString("<turn role=\"assistant\">\n")
			}
			if txt != "" {
				sb.WriteString(txt)
				sb.WriteString("\n")
			}
			for _, tc := range m.ToolCalls {
				name := strings.TrimSpace(tc.Function.Name)
				if name == "" {
					continue
				}
				argsRaw := json.RawMessage(tc.Function.Arguments)
				if !json.Valid(argsRaw) {
					quoted, _ := json.Marshal(tc.Function.Arguments)
					argsRaw = quoted
				}
				callObj := map[string]any{
					"id":        tc.ID,
					"name":      name,
					"arguments": argsRaw,
				}
				b, _ := json.Marshal(callObj)
				sb.WriteString(ToolCallOpenTag)
				sb.Write(b)
				sb.WriteString(ToolCallCloseTag)
				sb.WriteString("\n")
			}
			if m.FunctionCall != nil && strings.TrimSpace(m.FunctionCall.Name) != "" {
				argsRaw := json.RawMessage(m.FunctionCall.Arguments)
				if !json.Valid(argsRaw) {
					quoted, _ := json.Marshal(m.FunctionCall.Arguments)
					argsRaw = quoted
				}
				callObj := map[string]any{
					"name":      strings.TrimSpace(m.FunctionCall.Name),
					"arguments": argsRaw,
				}
				b, _ := json.Marshal(callObj)
				sb.WriteString(ToolCallOpenTag)
				sb.Write(b)
				sb.WriteString(ToolCallCloseTag)
				sb.WriteString("\n")
			}
			sb.WriteString("</turn>\n")

		case "tool", "function":
			fnName := strings.TrimSpace(m.Name)
			if fnName == "" && m.ToolCallID != "" {
				fnName = toolCallIDToName[m.ToolCallID]
			}
			if m.ToolCallID != "" && fnName != "" {
				fmt.Fprintf(&sb, "<tool_result tool_call_id=%q name=%q>\n", m.ToolCallID, fnName)
			} else if m.ToolCallID != "" {
				fmt.Fprintf(&sb, "<tool_result tool_call_id=%q>\n", m.ToolCallID)
			} else if fnName != "" {
				fmt.Fprintf(&sb, "<tool_result name=%q>\n", fnName)
			} else {
				sb.WriteString("<tool_result>\n")
			}
			sb.WriteString(txt)
			sb.WriteString("\n</tool_result>\n")

		default:
			fmt.Fprintf(&sb, "<turn role=%q>\n%s\n</turn>\n", role, txt)
		}
	}
	sb.WriteString("</conversation>\n")
	// Handle assistant prefill (common in SillyTavern) vs normal next-turn cue.
	if len(rest) > 0 && strings.EqualFold(rest[len(rest)-1].Role, "assistant") && len(rest[len(rest)-1].ToolCalls) == 0 && rest[len(rest)-1].FunctionCall == nil {
		sb.WriteString("\nContinue seamlessly from the end of the final assistant turn above. Do NOT repeat text already written in that final assistant turn, and do NOT wrap your reply in <turn> tags.")
	} else if toolMode {
		sb.WriteString("\nRespond now as the assistant. Either provide your final response directly OR emit one or more ")
		sb.WriteString(ToolCallOpenTag)
		sb.WriteString("...")
		sb.WriteString(ToolCallCloseTag)
		sb.WriteString(" blocks to invoke caller tools.")
	} else {
		sb.WriteString("\nRespond now as the assistant. Do NOT wrap your reply in <turn> tags.")
	}

	return ConvertedPrompt{
		CustomPrompt:        strings.Join(cpParts, "\n\n"),
		CompactCustomPrompt: compactCustomPrompt,
		StageableCustomBody: stageableCustomBody,
		Text:                sb.String(),
		Images:              allImages,
		ToolMode:            toolMode,
		AllowedTools:        allowed,
	}
}

// repackMessagesForTranscript keeps each batch of role:tool results contiguous right after
// its triggering assistant.tool_calls message, moving interleaved non-tool notices (such as
// developer/system image-resize notes inserted between parallel tool results) right after the batch.
func repackMessagesForTranscript(msgs []Message) []Message {
	if len(msgs) < 3 {
		return msgs
	}
	out := make([]Message, 0, len(msgs))
	changed := false
	i := 0
	for i < len(msgs) {
		m := msgs[i]
		if !strings.EqualFold(strings.TrimSpace(m.Role), "assistant") || len(m.ToolCalls) == 0 {
			out = append(out, m)
			i++
			continue
		}
		want := make(map[string]bool, len(m.ToolCalls))
		for _, tc := range m.ToolCalls {
			if tc.ID != "" {
				want[tc.ID] = true
			}
		}
		out = append(out, m)
		i++
		if len(want) == 0 {
			continue
		}
		var results []Message
		var between []Message
		sawNonTool := false
		for i < len(msgs) {
			role := strings.ToLower(strings.TrimSpace(msgs[i].Role))
			if role == "tool" {
				if !want[msgs[i].ToolCallID] {
					break
				}
				results = append(results, msgs[i])
				if sawNonTool {
					changed = true
				}
				i++
				continue
			}
			if len(results) == 0 {
				break
			}
			if role == "assistant" && len(msgs[i].ToolCalls) > 0 {
				break
			}
			between = append(between, msgs[i])
			sawNonTool = true
			i++
		}
		out = append(out, results...)
		out = append(out, between...)
	}
	if !changed {
		return msgs
	}
	return out
}

func collectTools(req ChatCompletionRequest) []FunctionDef {
	out := make([]FunctionDef, 0, len(req.Tools)+len(req.Functions))
	seen := make(map[string]bool, len(req.Tools)+len(req.Functions))
	add := func(fd FunctionDef) {
		fd.Name = strings.TrimSpace(fd.Name)
		if fd.Name == "" || seen[fd.Name] {
			return
		}
		seen[fd.Name] = true
		out = append(out, fd)
	}
	for _, t := range req.Tools {
		if t.Function != nil && strings.TrimSpace(t.Function.Name) != "" {
			add(*t.Function)
			continue
		}
		if strings.TrimSpace(t.Name) != "" {
			add(FunctionDef{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			})
		}
	}
	for _, f := range req.Functions {
		if strings.TrimSpace(f.Name) != "" {
			add(f)
		}
	}
	return out
}

func parseToolChoice(raw, legacyRaw json.RawMessage) (mode string, forcedName string, allowedSubset map[string]bool) {
	src := raw
	if len(src) == 0 || string(src) == "null" {
		src = legacyRaw
	}
	if len(src) == 0 || string(src) == "null" {
		return "auto", "", nil
	}
	var s string
	if err := json.Unmarshal(src, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "none":
			return "none", "", nil
		case "required", "any":
			return "required", "", nil
		default:
			return "auto", "", nil
		}
	}
	var obj struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Function *struct {
			Name string `json:"name"`
		} `json:"function"`
		AllowedTools *struct {
			Mode  string `json:"mode"`
			Tools []struct {
				Type     string `json:"type"`
				Name     string `json:"name"`
				Function *struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		} `json:"allowed_tools"`
	}
	if err := json.Unmarshal(src, &obj); err == nil {
		switch strings.ToLower(strings.TrimSpace(obj.Type)) {
		case "none":
			return "none", "", nil
		case "auto":
			return "auto", "", nil
		case "required", "any":
			return "required", "", nil
		case "allowed_tools":
			if obj.AllowedTools != nil {
				subset := make(map[string]bool, len(obj.AllowedTools.Tools))
				for _, sel := range obj.AllowedTools.Tools {
					name := strings.TrimSpace(sel.Name)
					if sel.Function != nil && strings.TrimSpace(sel.Function.Name) != "" {
						name = strings.TrimSpace(sel.Function.Name)
					}
					if name != "" {
						subset[name] = true
					}
				}
				m := strings.ToLower(strings.TrimSpace(obj.AllowedTools.Mode))
				if len(subset) == 0 && m != "required" {
					return "none", "", nil
				}
				if m == "required" {
					return "required", "", subset
				}
				return "auto", "", subset
			}
		}
		if obj.Function != nil && strings.TrimSpace(obj.Function.Name) != "" {
			return "function", strings.TrimSpace(obj.Function.Name), nil
		}
		if strings.TrimSpace(obj.Name) != "" {
			return "function", strings.TrimSpace(obj.Name), nil
		}
	}
	return "auto", "", nil
}

func buildToolSystemDirective(tools []FunctionDef) string {
	var sb strings.Builder
	sb.WriteString("[Direct API Tool-Calling Mode]\n")
	sb.WriteString("CRITICAL RULES:\n")
	sb.WriteString("1. NEVER invoke any AWS Quick built-in tools (such as run_python, file_read, file_write, file_matches, web_search, kg_search, memory_*, browser_*, acp_*, etc.). Those host tools are DISABLED for this API caller.\n")
	sb.WriteString("2. You may ONLY invoke the caller-declared tools listed below by emitting EXACT XML-delimited JSON blocks:\n")
	sb.WriteString(ToolCallOpenTag)
	sb.WriteString("\n{\"name\": \"<exact_tool_name>\", \"arguments\": {<JSON object matching parameters schema>}}\n")
	sb.WriteString(ToolCallCloseTag)
	sb.WriteString("\n")
	sb.WriteString("3. You may emit multiple ")
	sb.WriteString(ToolCallOpenTag)
	sb.WriteString(" blocks in one turn for parallel tool calls. When calling tools, STOP IMMEDIATELY after the final ")
	sb.WriteString(ToolCallCloseTag)
	sb.WriteString(" and NEVER fabricate tool outputs.\n")
	sb.WriteString("4. Arguments MUST be valid JSON strictly following the tool's parameter schema.\n")

	sb.WriteString("\nDeclared Caller Tools:\n")
	for _, t := range tools {
		entry := map[string]any{
			"name": t.Name,
		}
		if t.Description != "" {
			entry["description"] = t.Description
		}
		if len(t.Parameters) > 0 && string(t.Parameters) != "null" {
			entry["parameters"] = t.Parameters
		}
		b, _ := json.Marshal(entry)
		sb.WriteString("- ")
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func buildToolCatalogOnly(tools []FunctionDef) string {
	var sb strings.Builder
	sb.WriteString("Declared Caller Tools:\n")
	for _, t := range tools {
		entry := map[string]any{
			"name": t.Name,
		}
		if t.Description != "" {
			entry["description"] = t.Description
		}
		if len(t.Parameters) > 0 && string(t.Parameters) != "null" {
			entry["parameters"] = t.Parameters
		}
		b, _ := json.Marshal(entry)
		sb.WriteString("- ")
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func buildCompactToolReminder() string {
	var sb strings.Builder
	sb.WriteString("[Direct API Tool-Calling Mode]\n")
	sb.WriteString("Use the reference notes and declared caller tools provided in earlier parts of this conversation.\n")
	sb.WriteString("CRITICAL RULES:\n")
	sb.WriteString("1. NEVER invoke any AWS Quick built-in tools (run_python, file_read, file_write, file_matches, web_search, kg_search, memory_*, browser_*, acp_*, etc.).\n")
	sb.WriteString("2. Invoke ONLY caller-declared tools using exact XML-delimited JSON blocks:\n")
	sb.WriteString(ToolCallOpenTag)
	sb.WriteString("\n{\"name\": \"<exact_tool_name>\", \"arguments\": {<JSON object matching parameters schema>}}\n")
	sb.WriteString(ToolCallCloseTag)
	sb.WriteString("\n3. You may emit multiple ")
	sb.WriteString(ToolCallOpenTag)
	sb.WriteString(" blocks for parallel calls; stop immediately after the final ")
	sb.WriteString(ToolCallCloseTag)
	sb.WriteString(" and NEVER fabricate tool outputs.")
	return sb.String()
}
func parseResponseFormatDirective(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var rf struct {
		Type       string          `json:"type"`
		JSONSchema json.RawMessage `json:"json_schema,omitempty"`
	}
	if err := json.Unmarshal(raw, &rf); err != nil {
		return ""
	}
	switch rf.Type {
	case "json_object":
		return "[Output Format] Respond with a single valid JSON object only, with no surrounding markdown code fences or extra commentary."
	case "json_schema":
		return fmt.Sprintf("[Output Format] Respond with a single valid JSON value strictly conforming to this JSON Schema, with no surrounding markdown fences or extra commentary:\n%s", string(rf.JSONSchema))
	default:
		return ""
	}
}
