package prompt

import (
	"encoding/json"
	"strings"
)

// ChatCompletionRequest models an OpenAI /v1/chat/completions request.
type ChatCompletionRequest struct {
	Model                string                     `json:"model"`
	Messages             []Message                  `json:"messages"`
	Stream               bool                       `json:"stream,omitempty"`
	StreamOptions        *StreamOptions             `json:"stream_options,omitempty"`
	Tools                []Tool                     `json:"tools,omitempty"`
	ToolChoice           json.RawMessage            `json:"tool_choice,omitempty"`
	Functions            []FunctionDef              `json:"functions,omitempty"` // legacy OpenAI functions
	FunctionCall         json.RawMessage            `json:"function_call,omitempty"`
	ReasoningEffort      string                     `json:"reasoning_effort,omitempty"`
	ReasoningEffortCamel string                     `json:"reasoningEffort,omitempty"`
	Reasoning            json.RawMessage            `json:"reasoning,omitempty"`
	Thinking             json.RawMessage            `json:"thinking,omitempty"`
	ExtraBody            map[string]json.RawMessage `json:"extra_body,omitempty"`
	MaxTokens            *int                       `json:"max_tokens,omitempty"`
	MaxCompletionTokens  *int                       `json:"max_completion_tokens,omitempty"`
	Temperature          *float64                   `json:"temperature,omitempty"`
	TopP                 *float64                   `json:"top_p,omitempty"`
	Stop                 json.RawMessage            `json:"stop,omitempty"`
	ResponseFormat       json.RawMessage            `json:"response_format,omitempty"`
	User                 string                     `json:"user,omitempty"`
}

// ReasoningConfig captures OpenRouter/Responses-style `reasoning: {effort, enabled, max_tokens}`.
type ReasoningConfig struct {
	Effort    string `json:"effort,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
	MaxTokens *int   `json:"max_tokens,omitempty"`
}

// ThinkingConfig captures Anthropic/DeepSeek-style `thinking: {type, budget_tokens}`.
type ThinkingConfig struct {
	Type         string `json:"type,omitempty"`
	BudgetTokens *int   `json:"budget_tokens,omitempty"`
}

func parseReasoningRaw(raw json.RawMessage, budgetToEffort func(int) string) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if !b {
			return "off"
		}
		return "high"
	}
	var rc ReasoningConfig
	if json.Unmarshal(raw, &rc) == nil {
		if s := strings.TrimSpace(rc.Effort); s != "" {
			return s
		}
		if rc.Enabled != nil {
			if !*rc.Enabled {
				return "off"
			}
			if rc.MaxTokens != nil && budgetToEffort != nil {
				return budgetToEffort(*rc.MaxTokens)
			}
			return "high"
		}
		if rc.MaxTokens != nil && budgetToEffort != nil {
			return budgetToEffort(*rc.MaxTokens)
		}
	}
	return ""
}

func parseThinkingRaw(raw json.RawMessage, budgetToEffort func(int) string) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		if !b {
			return "off"
		}
		return "high"
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "disabled", "none", "off", "false":
			return "off"
		case "enabled", "adaptive", "true":
			return "high"
		default:
			return strings.TrimSpace(s)
		}
	}
	var tc ThinkingConfig
	if json.Unmarshal(raw, &tc) == nil {
		switch strings.ToLower(strings.TrimSpace(tc.Type)) {
		case "disabled", "none", "off":
			return "off"
		case "enabled", "adaptive":
			if tc.BudgetTokens != nil && budgetToEffort != nil {
				return budgetToEffort(*tc.BudgetTokens)
			}
			return "high"
		}
	}
	return ""
}

// EffectiveReasoningEffort extracts a normalized reasoning/thinking directive from
// reasoning_effort, reasoningEffort, reasoning, thinking, and extra_body fields.
func (r ChatCompletionRequest) EffectiveReasoningEffort(budgetToEffort func(int) string) string {
	if s := strings.TrimSpace(r.ReasoningEffort); s != "" {
		return s
	}
	if s := strings.TrimSpace(r.ReasoningEffortCamel); s != "" {
		return s
	}
	if eff := parseReasoningRaw(r.Reasoning, budgetToEffort); eff != "" {
		return eff
	}
	if eff := parseThinkingRaw(r.Thinking, budgetToEffort); eff != "" {
		return eff
	}
	if len(r.ExtraBody) > 0 {
		for _, k := range []string{"reasoning_effort", "reasoningEffort"} {
			if raw, ok := r.ExtraBody[k]; ok {
				var s string
				if json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
		if raw, ok := r.ExtraBody["reasoning"]; ok {
			if eff := parseReasoningRaw(raw, budgetToEffort); eff != "" {
				return eff
			}
		}
		if raw, ok := r.ExtraBody["thinking"]; ok {
			if eff := parseThinkingRaw(raw, budgetToEffort); eff != "" {
				return eff
			}
		}
	}
	return ""
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

type Message struct {
	Role             string            `json:"role"`
	Content          json.RawMessage   `json:"content,omitempty"`
	Name             string            `json:"name,omitempty"`
	ToolCallID       string            `json:"tool_call_id,omitempty"`
	ToolCalls        []ToolCall        `json:"tool_calls,omitempty"`
	FunctionCall     *ToolCallFunction `json:"function_call,omitempty"`
	ReasoningContent string            `json:"reasoning_content,omitempty"`
}

type Tool struct {
	Type        string          `json:"type"`
	Function    *FunctionDef    `json:"function,omitempty"`
	Name        string          `json:"name,omitempty"`        // Responses-style flat tool
	Description string          `json:"description,omitempty"` // Responses-style flat tool
	Parameters  json.RawMessage `json:"parameters,omitempty"`  // Responses-style flat tool
}

type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type ToolCall struct {
	Index    *int             `json:"index,omitempty"`
	ID       string           `json:"id,omitempty"`
	Type     string           `json:"type,omitempty"`
	Function ToolCallFunction `json:"function"`
}

type ToolCallFunction struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments"`
}

// UnmarshalJSON tolerates both OpenAI string `arguments` and raw JSON object/null
// arguments occasionally forwarded by third-party proxies.
func (f *ToolCallFunction) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.Name = raw.Name
	trimmed := strings.TrimSpace(string(raw.Arguments))
	if trimmed == "" || trimmed == "null" {
		f.Arguments = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(raw.Arguments, &s); err == nil {
		f.Arguments = s
		return nil
	}
	f.Arguments = trimmed
	return nil
}
// ParseStopSequences parses OpenAI `stop` which can be a single string or []string.
func ParseStopSequences(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single != "" {
			return []string{single}
		}
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		out := make([]string, 0, len(list))
		for _, s := range list {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
