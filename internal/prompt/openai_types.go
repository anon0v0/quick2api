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
	Reasoning            *ReasoningConfig           `json:"reasoning,omitempty"`
	Thinking             *ThinkingConfig            `json:"thinking,omitempty"`
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

// EffectiveReasoningEffort extracts a normalized reasoning/thinking directive from
// reasoning_effort, reasoningEffort, reasoning, thinking, and extra_body fields.
func (r ChatCompletionRequest) EffectiveReasoningEffort(budgetToEffort func(int) string) string {
	if s := strings.TrimSpace(r.ReasoningEffort); s != "" {
		return s
	}
	if s := strings.TrimSpace(r.ReasoningEffortCamel); s != "" {
		return s
	}
	if r.Reasoning != nil {
		if s := strings.TrimSpace(r.Reasoning.Effort); s != "" {
			return s
		}
		if r.Reasoning.Enabled != nil {
			if !*r.Reasoning.Enabled {
				return "off"
			}
			if r.Reasoning.MaxTokens != nil && budgetToEffort != nil {
				return budgetToEffort(*r.Reasoning.MaxTokens)
			}
			return "high"
		}
		if r.Reasoning.MaxTokens != nil && budgetToEffort != nil {
			return budgetToEffort(*r.Reasoning.MaxTokens)
		}
	}
	if r.Thinking != nil {
		switch strings.ToLower(strings.TrimSpace(r.Thinking.Type)) {
		case "disabled", "none", "off":
			return "off"
		case "enabled", "adaptive":
			if r.Thinking.BudgetTokens != nil && budgetToEffort != nil {
				return budgetToEffort(*r.Thinking.BudgetTokens)
			}
			return "high"
		}
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
			var rc ReasoningConfig
			if json.Unmarshal(raw, &rc) == nil {
				sub := ChatCompletionRequest{Reasoning: &rc}
				if eff := sub.EffectiveReasoningEffort(budgetToEffort); eff != "" {
					return eff
				}
			}
		}
		if raw, ok := r.ExtraBody["thinking"]; ok {
			var tc ThinkingConfig
			if json.Unmarshal(raw, &tc) == nil {
				sub := ChatCompletionRequest{Thinking: &tc}
				if eff := sub.EffectiveReasoningEffort(budgetToEffort); eff != "" {
					return eff
				}
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
