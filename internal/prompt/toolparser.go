package prompt

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// ParsedToolCall is one tool call extracted from the model's output stream.
type ParsedToolCall struct {
	Index         int
	ID            string
	Name          string
	ArgumentsJSON string
}

// maxToolBlockBytes caps buffering inside an unclosed <quick_tool_call> tag so a model
// discussing the tag in prose without closing it cannot buffer unbounded memory.
const maxToolBlockBytes = 512 * 1024

// ToolStreamParser incrementally separates normal assistant text from <quick_tool_call>...</quick_tool_call> blocks.
type ToolStreamParser struct {
	enabled      bool
	allowedTools map[string]bool

	buf          string
	inToolCall   bool
	nextIndex    int
	emittedAny   bool
	emittedNonWS bool
}
// NewToolStreamParser creates a streaming parser; when enabled is false, all text passes through untouched.
func NewToolStreamParser(enabled bool, allowedTools map[string]bool) *ToolStreamParser {
	return &ToolStreamParser{
		enabled:      enabled,
		allowedTools: allowedTools,
	}
}

// Feed consumes a text delta and returns safe-to-emit plain content plus any completed tool calls.
func (p *ToolStreamParser) Feed(delta string) (textOut string, calls []ParsedToolCall) {
	if delta == "" {
		return "", nil
	}
	if !p.enabled {
		return delta, nil
	}

	p.buf += delta
	var out strings.Builder
	writeText := func(seg string) {
		if seg == "" {
			return
		}
		if strings.TrimSpace(seg) == "" {
			if p.emittedAny && !p.emittedNonWS {
				return
			}
			out.WriteString(seg)
			return
		}
		p.emittedNonWS = true
		out.WriteString(seg)
	}

	for {
		if !p.inToolCall {
			idx := strings.Index(p.buf, ToolCallOpenTag)
			if idx >= 0 {
				if idx > 0 {
					writeText(p.buf[:idx])
				}
				p.buf = p.buf[idx+len(ToolCallOpenTag):]
				p.inToolCall = true
				continue
			}

			// Hold back only a trailing prefix that could still become ToolCallOpenTag.
			hold := partialSuffixMatch(p.buf, ToolCallOpenTag)
			emitLen := len(p.buf) - hold
			if emitLen > 0 {
				writeText(p.buf[:emitLen])
				p.buf = p.buf[emitLen:]
			}
			break
		}

		// Inside <quick_tool_call> ... look for closing tag.
		endIdx := strings.Index(p.buf, ToolCallCloseTag)
		if endIdx < 0 {
			if len(p.buf) > maxToolBlockBytes {
				// Unclosed block exceeded safety cap: treat as literal text.
				writeText(ToolCallOpenTag + p.buf)
				p.buf = ""
				p.inToolCall = false
			}
			break
		}
		rawBody := p.buf[:endIdx]
		p.buf = p.buf[endIdx+len(ToolCallCloseTag):]
		p.inToolCall = false

		if tc, ok := p.parseToolCallBody(rawBody); ok {
			calls = append(calls, tc)
			p.emittedAny = true
		} else {
			// Malformed payload: do not silently discard output.
			writeText(ToolCallOpenTag + rawBody + ToolCallCloseTag)
		}
	}

	return out.String(), calls
}

// Flush drains any remaining buffered text at end-of-stream.
func (p *ToolStreamParser) Flush() (textOut string, calls []ParsedToolCall) {
	if !p.enabled || p.buf == "" {
		return "", nil
	}
	rem := p.buf
	p.buf = ""
	if p.inToolCall {
		p.inToolCall = false
		if tc, ok := p.parseToolCallBody(rem); ok {
			p.emittedAny = true
			return "", []ParsedToolCall{tc}
		}
		return ToolCallOpenTag + rem, nil
	}
	// If tool calls were emitted and only trailing whitespace remains, suppress noisy whitespace.
	if p.emittedAny && strings.TrimSpace(rem) == "" {
		return "", nil
	}
	return rem, nil
}

// HasToolCalls reports whether at least one valid tool call was parsed.
func (p *ToolStreamParser) HasToolCalls() bool {
	return p.emittedAny
}

func (p *ToolStreamParser) parseToolCallBody(raw string) (ParsedToolCall, bool) {
	body := strings.TrimSpace(raw)
	// Strip accidental markdown fences if the model wrapped the JSON inside the XML tag.
	if strings.HasPrefix(body, "```") {
		if nl := strings.IndexByte(body, '\n'); nl >= 0 {
			body = body[nl+1:]
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), "```")
		body = strings.TrimSpace(body)
	}
	// Extract outermost JSON object if stray text crept around it.
	if start := strings.IndexByte(body, '{'); start > 0 {
		if end := strings.LastIndexByte(body, '}'); end > start {
			body = body[start : end+1]
		}
	}

	var parsed struct {
		ID         string          `json:"id"`
		Name       string          `json:"name"`
		Arguments  json.RawMessage `json:"arguments"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return ParsedToolCall{}, false
	}
	name := strings.TrimSpace(parsed.Name)
	if name == "" {
		return ParsedToolCall{}, false
	}
	if len(p.allowedTools) > 0 && !p.allowedTools[name] {
		return ParsedToolCall{}, false
	}

	rawArgs := parsed.Arguments
	if len(rawArgs) == 0 || string(rawArgs) == "null" {
		rawArgs = parsed.Parameters
	}

	argsJSON := "{}"
	if len(rawArgs) > 0 && string(rawArgs) != "null" {
		// If arguments was already encoded as a JSON string, unwrap if valid JSON; otherwise marshal compactly.
		var asStr string
		if err := json.Unmarshal(rawArgs, &asStr); err == nil {
			trimmed := strings.TrimSpace(asStr)
			if trimmed == "" {
				argsJSON = "{}"
			} else if json.Valid([]byte(trimmed)) {
				argsJSON = trimmed
			} else {
				argsJSON = string(rawArgs)
			}
		} else {
			var compacted strings.Builder
			var tmp any
			if err := json.Unmarshal(rawArgs, &tmp); err == nil {
				if b, err := json.Marshal(tmp); err == nil {
					compacted.Write(b)
					argsJSON = compacted.String()
				}
			} else {
				argsJSON = string(rawArgs)
			}
		}
	}

	id := strings.TrimSpace(parsed.ID)
	if id == "" {
		id = newCallID()
	}
	idx := p.nextIndex
	p.nextIndex++
	return ParsedToolCall{
		Index:         idx,
		ID:            id,
		Name:          name,
		ArgumentsJSON: argsJSON,
	}, true
}

// partialSuffixMatch returns the longest k (0 < k < len(target)) such that s ends with target[:k].
func partialSuffixMatch(s, target string) int {
	maxK := len(target) - 1
	if len(s) < maxK {
		maxK = len(s)
	}
	for k := maxK; k > 0; k-- {
		if strings.HasSuffix(s, target[:k]) {
			return k
		}
	}
	return 0
}

func newCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "call_" + hex.EncodeToString(b[:])
}

// StopFilter enforces OpenAI `stop` sequences during streaming.
type StopFilter struct {
	stops   []string
	maxLen  int
	buf     string
	stopped bool
}

func NewStopFilter(stops []string) *StopFilter {
	maxL := 0
	clean := make([]string, 0, len(stops))
	for _, s := range stops {
		if s != "" {
			clean = append(clean, s)
			if len(s) > maxL {
				maxL = len(s)
			}
		}
	}
	return &StopFilter{stops: clean, maxLen: maxL}
}

// Feed returns safe text to emit and whether a stop sequence was hit.
func (f *StopFilter) Feed(delta string) (emit string, hit bool) {
	if f.stopped {
		return "", true
	}
	if len(f.stops) == 0 || delta == "" {
		return delta, false
	}
	f.buf += delta
	earliest := -1
	for _, st := range f.stops {
		if idx := strings.Index(f.buf, st); idx >= 0 {
			if earliest < 0 || idx < earliest {
				earliest = idx
			}
		}
	}
	if earliest >= 0 {
		out := f.buf[:earliest]
		f.buf = ""
		f.stopped = true
		return out, true
	}
	hold := 0
	for _, st := range f.stops {
		if k := partialSuffixMatch(f.buf, st); k > hold {
			hold = k
		}
	}
	emitLen := len(f.buf) - hold
	if emitLen > 0 {
		out := f.buf[:emitLen]
		f.buf = f.buf[emitLen:]
		return out, false
	}
	return "", false
}

func (f *StopFilter) Flush() string {
	if f.stopped || f.buf == "" {
		return ""
	}
	out := f.buf
	f.buf = ""
	return out
}
