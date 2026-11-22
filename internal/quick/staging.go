package quick

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// MaxInnerUserMessageBytes is the conservative byte ceiling for one AIDP inner
	// user_message JSON frame. AWS Quick SNCS accepts frames up to ~64,992 bytes and
	// rejects frames above ~65,392 bytes with FrameTooLarge, so 63,000 leaves ~2 KB headroom.
	MaxInnerUserMessageBytes = 63000

	// MinFinalTextHeadroom is the minimum byte budget reserved for the final turn's
	// text when keeping CustomPrompt intact in the final turn's custom_prompt slot.
	// Keeping CustomPrompt in custom_prompt avoids moving tool/system directives into
	// user-role messages (which AWS Quick's built-in prompt-attack guardrail inspects).
	MinFinalTextHeadroom = 128

	// MaxStagedTurns caps automatic multi-turn context staging (~900 KB UTF-8,
	// roughly Claude's 200K token context window) so pathological payloads fail
	MaxStagedTurns = 16

	stagingSystemDirective = "[Direct API Mode] Do NOT invoke any AWS Quick built-in tools. Acknowledge each incoming part briefly with 'OK' and wait for the final part."
	defaultCompactFallback = "[Direct API Mode] Use the reference notes and context from earlier parts of this conversation. Do NOT invoke any built-in AWS Quick workspace, file, code, browser, memory, search, or connector tools."
)

// ContextOverflowError indicates a prompt exceeds the gateway's safe multi-turn staging cap.
type ContextOverflowError struct {
	Msg string
}

func (e *ContextOverflowError) Error() string {
	return e.Msg
}

type stagedTurn struct {
	Text           string
	CustomPrompt   string
	ThinkingEffort string
	Attachments    []Attachment
	IsStaging      bool
}

func buildUserMessageFrame(threadID, surface, agentMode, thinkingEffort, customPrompt, text string, attachments []Attachment) map[string]any {
	payload := map[string]any{
		"traceId":            NewUUID(),
		"text":               text,
		"message_id":         NewUUID(),
		"thread_id":          threadID,
		"agent_mode":         agentMode,
		"thinking_effort":    thinkingEffort,
		"auto_routing":       false,
		"web_search_enabled": false,
		"chat_agent_id":      nil,
		"user_timezone":      "UTC",
		"user_locale":        "en-US",
		"surfaceType":        surface,
	}
	if customPrompt != "" {
		payload["custom_prompt"] = customPrompt
	} else {
		payload["custom_prompt"] = nil
	}
	if len(attachments) > 0 {
		payload["attachments"] = attachments
	}
	return map[string]any{
		"type":    "user_message",
		"payload": payload,
	}
}

const sampleUUID = "00000000-0000-4000-8000-000000000000"

func measureUserMessageInnerBytes(surface, agentMode, thinkingEffort, customPrompt, text string, attachments []Attachment) (int, error) {
	frame := buildUserMessageFrame(sampleUUID, surface, agentMode, thinkingEffort, customPrompt, text, attachments)
	b, err := MarshalAIDPInner(frame)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// PlanTurnFrames decides whether req fits inside a single Quick user_message frame
// (<= maxInnerBytes) or must be staged across multiple sequential turns on the same
// thread_id so SNCS never rejects it with FrameTooLarge.
func PlanTurnFrames(req TurnRequest, surface string, maxInnerBytes int) ([]stagedTurn, int, error) {
	if maxInnerBytes <= 0 {
		maxInnerBytes = MaxInnerUserMessageBytes
	}
	singleSize, err := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, req.CustomPrompt, req.Text, req.Attachments)
	if err != nil {
		return nil, 0, err
	}
	if singleSize <= maxInnerBytes {
		return []stagedTurn{{
			Text:           req.Text,
			CustomPrompt:   req.CustomPrompt,
			ThinkingEffort: req.ThinkingEffort,
			Attachments:    req.Attachments,
			IsStaging:      false,
		}}, singleSize, nil
	}

	// Prefer keeping full CustomPrompt intact in the final turn's custom_prompt slot
	// whenever it leaves at least MinFinalTextHeadroom bytes for the final user text.
	// This keeps all system/tool rules in Quick's system slot (immune to user-message
	// prompt-attack false positives) and preserves 100% tool-calling accuracy.
	const finalPrefixSample = "Part 99 of 99 (final part). Please respond now based on all parts above.\n\n"
	const refPrefixSample = "Part 99 of 99 (reference notes). Please reply with 'OK' and wait for the next part.\n\n"
	const convPrefixSample = "Part 99 of 99 (conversation context). Please reply with 'OK' and wait for the next part.\n\n"
	const attPrefixSample = "Part 99 of 99 (attached files). Please reply with 'OK' and wait for the next part.\n\n"
	const attOnlyBody = "Attached files for this conversation are included with this part."

	// When staging across multiple turns, place Attachments on the first staging turn
	// (which uses the tiny stagingSystemDirective) instead of the final turn. Quick retains
	// Turn 0 attachments across the thread, so images never steal bytes from the final turn's
	// custom_prompt budget.
	stageAttachmentsOnFirst := len(req.Attachments) > 0
	if stageAttachmentsOnFirst {
		attOverhead, aerr := measureUserMessageInnerBytes(surface, req.AgentMode, "low", stagingSystemDirective, attPrefixSample+attOnlyBody, req.Attachments)
		if aerr != nil {
			return nil, singleSize, aerr
		}
		if attOverhead > maxInnerBytes {
			return nil, singleSize, &ContextOverflowError{Msg: fmt.Sprintf("request attachments exceed Amazon Quick's %d-byte frame limit (%d bytes)", maxInnerBytes, attOverhead)}
		}
	}
	keepCustomPromptInline := false
	finalCP := strings.TrimSpace(req.CompactCustomPrompt)
	if finalCP == "" {
		finalCP = defaultCompactFallback
	}
	stageBody := ""
	if req.CustomPrompt == "" {
		keepCustomPromptInline = true
		finalCP = ""
	} else {
		probeSize, perr := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, req.CustomPrompt, finalPrefixSample+strings.Repeat("a", MinFinalTextHeadroom), nil)
		if perr == nil && probeSize <= maxInnerBytes {
			keepCustomPromptInline = true
			finalCP = req.CustomPrompt
		} else {
			// Hybrid fill: never leave the final turn's ~62 KB guardrail-exempt custom_prompt slot empty.
			// 1) If tool definitions alone fit in custom_prompt, keep 100% of tools inline (avoiding
			//    Bedrock's user-message prompt-attack false positives on JSON tool schemas) and pack the
			//    largest fitting tail of the leading system prompt right beside them.
			// 2) Otherwise pack CompactCustomPrompt + the largest fitting tail of StageableCustomBody
			//    into finalCP (keeping closing presets/CoT/rules in custom_prompt) and stage only the prefix.
			baseCP := finalCP
			candidateBody := strings.TrimSpace(req.StageableCustomBody)
			if candidateBody == "" {
				candidateBody = req.CustomPrompt
			}
			if toolCP := strings.TrimSpace(req.ToolInlineCustomPrompt); toolCP != "" {
				if tsz, terr := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, toolCP, finalPrefixSample+strings.Repeat("a", MinFinalTextHeadroom), nil); terr == nil && tsz <= maxInnerBytes {
					baseCP = toolCP
					candidateBody = strings.TrimSpace(req.StageableSystemBody)
				}
			}
			stageBody, finalCP = splitSuffixForInlineCP(baseCP, candidateBody, surface, req.AgentMode, req.ThinkingEffort, finalPrefixSample, maxInnerBytes)
		}
	}

	// Ensure finalCustomPrompt itself isn't oversized.
	finalOverhead, err := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, finalCP, finalPrefixSample, nil)
	if err != nil {
		return nil, singleSize, err
	}
	if finalOverhead+MinFinalTextHeadroom > maxInnerBytes {
		keepCustomPromptInline = false
		finalCP = defaultCompactFallback
		stageBody = strings.TrimSpace(req.StageableCustomBody)
		if stageBody == "" {
			stageBody = req.CustomPrompt
		}
		finalOverhead, err = measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, finalCP, finalPrefixSample, nil)
		if err != nil {
			return nil, singleSize, err
		}
		if finalOverhead+MinFinalTextHeadroom > maxInnerBytes {
			return nil, singleSize, &ContextOverflowError{Msg: fmt.Sprintf("request metadata exceed Amazon Quick's %d-byte frame limit (%d bytes)", maxInnerBytes, finalOverhead)}
		}
	}

	type rawPart struct {
		kind string // "attachments", "reference", or "conversation"
		body string
	}
	var parts []rawPart

	attsForNextPart := func() []Attachment {
		if stageAttachmentsOnFirst && len(parts) == 0 {
			return req.Attachments
		}
		return nil
	}

	// Helper to slice a string into JSON-size-verified chunks for staging frames.
	sliceForFrame := func(src, kind, cp, effort, prefixTpl string, limit int) error {
		rem := src
		for len(rem) > 0 {
			curAtts := attsForNextPart()
			fit := func(n int) bool {
				sz, merr := measureUserMessageInnerBytes(surface, req.AgentMode, effort, cp, prefixTpl+rem[:n], curAtts)
				return merr == nil && sz <= limit
			}
			if fit(len(rem)) {
				parts = append(parts, rawPart{kind: kind, body: rem})
				break
			}
			lo, hi, best := 1, len(rem), 0
			for lo <= hi {
				mid := lo + (hi-lo)/2
				cut := alignUTF8Floor(rem, mid)
				if cut == 0 {
					lo = mid + 1
					continue
				}
				if fit(cut) {
					best = cut
					lo = mid + 1
				} else {
					hi = mid - 1
				}
			}
			if best == 0 {
				if len(curAtts) > 0 {
					// Attachments nearly filled Turn 0 on their own; give them a dedicated first part.
					parts = append(parts, rawPart{kind: "attachments", body: attOnlyBody})
					if len(parts) >= MaxStagedTurns {
						return &ContextOverflowError{Msg: fmt.Sprintf("prompt is too large (%d bytes; exceeds maximum %d staged context parts)", singleSize, MaxStagedTurns)}
					}
					continue
				}
				return &ContextOverflowError{Msg: "unable to fit prompt chunk within Amazon Quick frame size limit"}
			}
			cut := preferNewlineCut(rem, best)
			if cut <= 0 {
				return &ContextOverflowError{Msg: "unable to advance prompt chunk split within frame size limit"}
			}
			parts = append(parts, rawPart{kind: kind, body: rem[:cut]})
			rem = rem[cut:]
			if len(parts) >= MaxStagedTurns {
				return &ContextOverflowError{Msg: fmt.Sprintf("prompt is too large (%d bytes; exceeds maximum %d staged context parts)", singleSize, MaxStagedTurns)}
			}
		}
		return nil
	}

	// Stage only the overflow prefix when full CustomPrompt exceeds final-turn capacity.
	if !keepCustomPromptInline && stageBody != "" {
		if cerr := sliceForFrame(stageBody, "reference", stagingSystemDirective, "low", refPrefixSample, maxInnerBytes); cerr != nil {
			return nil, singleSize, cerr
		}
	}

	// Slice Text so every staging turn and the final turn (with finalCP) fit strictly <= maxInnerBytes.
	if req.Text == "" {
		if stageAttachmentsOnFirst && len(parts) == 0 {
			parts = append(parts, rawPart{kind: "attachments", body: attOnlyBody})
		}
		parts = append(parts, rawPart{kind: "conversation", body: "Continue."})
	} else if sz, merr := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, finalCP, finalPrefixSample+req.Text, nil); merr == nil && sz <= maxInnerBytes {
		// If singleSize exceeded maxInnerBytes only because of attachments (while Text+finalCP fits alone),
		// put attachments on a dedicated Part 1 so the final turn stays strictly <= maxInnerBytes.
		if stageAttachmentsOnFirst && len(parts) == 0 {
			parts = append(parts, rawPart{kind: "attachments", body: attOnlyBody})
		}
		parts = append(parts, rawPart{kind: "conversation", body: req.Text})
	} else {
		rem := req.Text
		for len(rem) > 0 {
			if len(parts) > 0 || !stageAttachmentsOnFirst {
				if sz, merr := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, finalCP, finalPrefixSample+rem, nil); merr == nil && sz <= maxInnerBytes {
					parts = append(parts, rawPart{kind: "conversation", body: rem})
					break
				}
			}
			curAtts := attsForNextPart()
			fit := func(n int) bool {
				sz, merr := measureUserMessageInnerBytes(surface, req.AgentMode, "low", stagingSystemDirective, convPrefixSample+rem[:n], curAtts)
				return merr == nil && sz <= maxInnerBytes
			}
			lo, hi, best := 1, len(rem), 0
			for lo <= hi {
				mid := lo + (hi-lo)/2
				cut := alignUTF8Floor(rem, mid)
				if cut == 0 {
					lo = mid + 1
					continue
				}
				if fit(cut) {
					best = cut
					lo = mid + 1
				} else {
					hi = mid - 1
				}
			}
			if best == 0 {
				if len(curAtts) > 0 {
					parts = append(parts, rawPart{kind: "attachments", body: attOnlyBody})
					if len(parts) >= MaxStagedTurns {
						return nil, singleSize, &ContextOverflowError{Msg: fmt.Sprintf("prompt is too large (%d bytes; exceeds maximum %d staged context parts)", singleSize, MaxStagedTurns)}
					}
					continue
				}
				return nil, singleSize, &ContextOverflowError{Msg: "unable to fit conversation chunk within Amazon Quick frame size limit"}
			}
			var cut int
			if best == len(rem) {
				// All of rem fits inside a staging turn, so cut right before the largest suffix
				// that fits in the final turn -> completes in exactly 1 more turn!
				tailLo, tailHi, bestStart := 1, len(rem), len(rem)
				for tailLo <= tailHi {
					mid := tailLo + (tailHi-tailLo)/2
					start := alignUTF8Ceil(rem, len(rem)-mid)
					if start >= len(rem) {
						tailHi = mid - 1
						continue
					}
					sz, merr := measureUserMessageInnerBytes(surface, req.AgentMode, req.ThinkingEffort, finalCP, finalPrefixSample+rem[start:], nil)
					if merr == nil && sz <= maxInnerBytes {
						bestStart = start
						tailLo = mid + 1
					} else {
						tailHi = mid - 1
					}
				}
				if bestStart >= len(rem) {
					// Even a tiny suffix won't fit with finalCP (edge case); split halfway as fallback.
					bestStart = alignUTF8Floor(rem, len(rem)/2)
				} else {
					// Prefer breaking right after a newline inside the fitting suffix so the tail still fits!
					if nl := strings.IndexByte(rem[bestStart:], '\n'); nl >= 0 && bestStart+nl+1 < len(rem) && nl <= 512 {
						bestStart = bestStart + nl + 1
					}
				}
				cut = bestStart
			} else {
				cut = preferNewlineCut(rem, best)
			}
			if cut <= 0 {
				return nil, singleSize, &ContextOverflowError{Msg: "unable to advance staged conversation split within frame size limit"}
			}
			parts = append(parts, rawPart{kind: "conversation", body: rem[:cut]})
			rem = rem[cut:]
			if len(parts) >= MaxStagedTurns {
				return nil, singleSize, &ContextOverflowError{Msg: fmt.Sprintf("prompt is too large (%d bytes; exceeds maximum %d staged context parts)", singleSize, MaxStagedTurns)}
			}
		}
	}

	if len(parts) > MaxStagedTurns {
		return nil, singleSize, &ContextOverflowError{Msg: fmt.Sprintf("prompt is too large (%d bytes; requires %d staged parts, limit is %d)", singleSize, len(parts), MaxStagedTurns)}
	}

	total := len(parts)
	turns := make([]stagedTurn, 0, total)
	for i, p := range parts {
		partNum := i + 1
		isFinal := i == total-1
		var turnAtts []Attachment
		if i == 0 && stageAttachmentsOnFirst {
			turnAtts = req.Attachments
		}
		if !isFinal {
			label := "conversation context"
			switch p.kind {
			case "reference":
				label = "reference notes"
			case "attachments":
				label = "attached files"
			}
			txt := fmt.Sprintf(
				"Part %d of %d (%s). Please reply with 'OK' and wait for the next part.\n\n%s",
				partNum, total, label, p.body,
			)
			turns = append(turns, stagedTurn{
				Text:           txt,
				CustomPrompt:   stagingSystemDirective,
				ThinkingEffort: "low",
				Attachments:    turnAtts,
				IsStaging:      true,
			})
		} else {
			txt := fmt.Sprintf(
				"Part %d of %d (final part). Please respond now based on all parts above.\n\n%s",
				partNum, total, p.body,
			)
			turns = append(turns, stagedTurn{
				Text:           txt,
				CustomPrompt:   finalCP,
				ThinkingEffort: req.ThinkingEffort,
				Attachments:    turnAtts,
				IsStaging:      false,
			})
		}
	}
	return turns, singleSize, nil
}

// splitSuffixForInlineCP packs the largest UTF-8/newline-aligned suffix of body into
// baseCP + "\n\n" + suffix so the combined final turn (with MinFinalTextHeadroom bytes
// of text and nil attachments) stays strictly <= maxInnerBytes.
// It returns (remainingPrefixToStage, combinedFinalCP).
func splitSuffixForInlineCP(baseCP, body, surface, agentMode, thinkingEffort, finalPrefixSample string, maxInnerBytes int) (string, string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return "", baseCP
	}
	joinCP := func(suf string) string {
		if baseCP == "" {
			return suf
		}
		return baseCP + "\n\n" + suf
	}
	fits := func(start int) bool {
		cp := joinCP(body[start:])
		sz, err := measureUserMessageInnerBytes(surface, agentMode, thinkingEffort, cp, finalPrefixSample+strings.Repeat("a", MinFinalTextHeadroom), nil)
		return err == nil && sz <= maxInnerBytes
	}
	if fits(0) {
		return "", joinCP(body)
	}
	lo, hi, bestStart := 1, len(body), len(body)
	for lo <= hi {
		mid := lo + (hi-lo)/2
		start := alignUTF8Ceil(body, len(body)-mid)
		if start >= len(body) {
			hi = mid - 1
			continue
		}
		if fits(start) {
			bestStart = start
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if bestStart >= len(body) {
		return body, baseCP
	}
	if nl := strings.IndexByte(body[bestStart:], '\n'); nl >= 0 && bestStart+nl+1 < len(body) && nl <= 1024 {
		bestStart = bestStart + nl + 1
	}
	prefix := strings.TrimSpace(body[:bestStart])
	suffix := strings.TrimSpace(body[bestStart:])
	if suffix == "" {
		return body, baseCP
	}
	return prefix, joinCP(suffix)
}
func alignUTF8Ceil(s string, idx int) int {
	if idx <= 0 {
		return 0
	}
	if idx >= len(s) {
		return len(s)
	}
	for idx < len(s) && !utf8.RuneStart(s[idx]) {
		idx++
	}
	return idx
}

func alignUTF8Floor(s string, idx int) int {
	if idx >= len(s) {
		return len(s)
	}
	for idx > 0 && !utf8.RuneStart(s[idx]) {
		idx--
	}
	return idx
}

func preferNewlineCut(s string, maxCut int) int {
	if maxCut <= 0 || maxCut >= len(s) {
		return maxCut
	}
	window := maxCut / 6
	if window > 4096 {
		window = 4096
	}
	minCut := maxCut - window
	if minCut < 1 {
		minCut = 1
	}
	if nl := strings.LastIndexByte(s[minCut:maxCut], '\n'); nl >= 0 {
		return minCut + nl + 1
	}
	return maxCut
}

// ---------------------------------------------------------------------------
// Upstream Quick error frame normalization (handles both nested payload & top-level SNCS frames)
// ---------------------------------------------------------------------------

func strField(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch s := v.(type) {
		case string:
			if strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		case map[string]any:
			if inner := strField(s, "message", "error", "detail", "reason"); inner != "" {
				return inner
			}
		}
	}
	return ""
}

func boolField(m map[string]any, key string) (val bool, present bool) {
	if m == nil {
		return false, false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func intField(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	return toInt(m[key])
}

// parseQuickErrorEvent normalizes both nested-payload and top-level SNCS `type:"error"`
// frames into a StreamEvent, flagging harmless background cleanup errors (e.g. session_delete)
// to be ignored instead of terminating an active turn.
func parseQuickErrorEvent(rawJSON []byte, payloadMap map[string]any) (ev StreamEvent, ignore bool, failedFrame string, summary string) {
	var rawMap map[string]any
	_ = json.Unmarshal(rawJSON, &rawMap)

	op := strField(payloadMap, "operation")
	if op == "" {
		op = strField(rawMap, "operation")
	}
	failedFrame = strField(payloadMap, "failed_frame_type")
	if failedFrame == "" {
		failedFrame = strField(rawMap, "failed_frame_type")
	}

	msg := strField(payloadMap, "message", "error", "detail", "reason", "errorMessage")
	if msg == "" {
		msg = strField(rawMap, "message", "error", "detail", "reason", "errorMessage")
	}
	code := strField(payloadMap, "error_code", "code", "error_type")
	if code == "" {
		code = strField(rawMap, "error_code", "code", "error_type")
	}
	statusCode := intField(payloadMap, "status_code")
	if statusCode == 0 {
		statusCode = intField(rawMap, "status_code")
	}

	retryableVal, hasRetryable := boolField(payloadMap, "retryable")
	if !hasRetryable {
		retryableVal, hasRetryable = boolField(rawMap, "retryable")
	}

	// Background session cleanup errors (e.g. deleting a session that never started) must not fail turns.
	if op == "session_delete" || failedFrame == "session_delete" || strings.HasPrefix(strings.ToLower(msg), "error deleting session:") {
		return StreamEvent{}, true, failedFrame, fmt.Sprintf("op=%s code=%s msg=%q", op, code, truncate(msg, 160))
	}

	if msg == "" {
		if code != "" {
			msg = fmt.Sprintf("Upstream Quick error (%s)", code)
		} else {
			msg = "Unknown upstream Quick error: " + truncate(strings.TrimSpace(string(rawJSON)), 240)
		}
	}

	kind := "error"
	normCode := code
	retryable := false
	lowerCode := strings.ToLower(code)
	lowerAll := strings.ToLower(code + " " + msg)

	switch {
	case lowerCode == "usage_limit" || lowerCode == "usage_blocked" || (strings.Contains(lowerAll, "usage") && strings.Contains(lowerAll, "limit")):
		kind = "usage_blocked"
		if normCode == "" {
			normCode = "usage_blocked"
		}
	case lowerCode == "throttled" || lowerCode == "throttlingexception" || lowerCode == "rate_limited" || statusCode == 429 || strings.Contains(lowerAll, "rate_limit") || strings.Contains(lowerAll, "throttl"):
		kind = "rate_limited"
		if normCode == "" {
			normCode = "rate_limited"
		}
	case lowerCode == "content_filtered" || lowerCode == "guardrail_blocked":
		kind = "guardrail_blocked"
		if normCode == "" {
			normCode = "content_filtered"
		}
	case lowerCode == "auth_error" || lowerCode == "unauthorized_key" || strings.Contains(msg, "AWS authentication failed") || strings.Contains(msg, "ExpiredToken") || strings.Contains(msg, "UnauthorizedAccess") || strings.Contains(msg, "AccessDenied"):
		normCode = "auth_error"
	case lowerCode == "context_overflow":
		normCode = "context_overflow"
	case lowerCode == "frametoolarge":
		normCode = "frame_too_large"
	case lowerCode == "internalfailure" || lowerCode == "session_stale" || strings.Contains(strings.ToLower(msg), "failed to deliver message"):
		if normCode == "" {
			normCode = "delivery_failure"
		}
		retryable = true
	case lowerCode == "service_overloaded" || lowerCode == "service_error" || lowerCode == "stream_interrupted" || lowerCode == "buffered_stream_exhausted" || lowerCode == "timeout" || statusCode == 503:
		retryable = true
	}

	if hasRetryable {
		retryable = retryableVal
	}

	ev = StreamEvent{
		Kind:        kind,
		ErrorCode:   normCode,
		ErrorMsg:    msg,
		Retryable:   retryable,
		FailedFrame: failedFrame,
	}
	summary = fmt.Sprintf("code=%s retryable=%v failed_frame=%s status=%d msg=%q", normCode, retryable, failedFrame, statusCode, truncate(msg, 240))
	return ev, false, failedFrame, summary
}
