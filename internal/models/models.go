package models

import "strings"

// ModelSpec defines a canonical model exposed on /v1/models and its Quick routing target.
type ModelSpec struct {
	ID                string `json:"id"`
	AgentMode         string `json:"-"`
	ThinkingEffort    string `json:"-"`
	UpstreamModelID   string `json:"-"`
	OwnedBy           string `json:"owned_by"`
	ContextWindow     int    `json:"context_window"`
	MaxOutputTokens   int    `json:"max_output_tokens"`
	SupportsImages    bool   `json:"supports_images"`
	SupportsToolCall  bool   `json:"supports_tool_call"`
	SupportsReasoning bool   `json:"supports_reasoning"`
}

// Catalog lists the canonical models verified on Amazon Quick.
var Catalog = []ModelSpec{
	{
		ID:                "quick-haiku-5.5",
		AgentMode:         "fast",
		ThinkingEffort:    "off",
		UpstreamModelID:   "us.anthropic.claude-haiku-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: false,
	},
	{
		ID:                "quick-sonnet-5.5",
		AgentMode:         "balanced",
		ThinkingEffort:    "off",
		UpstreamModelID:   "us.anthropic.claude-sonnet-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: true,
	},
	{
		ID:                "quick-sonnet-5.5-thinking",
		AgentMode:         "balanced",
		ThinkingEffort:    "high",
		UpstreamModelID:   "us.anthropic.claude-sonnet-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: true,
	},
	{
		ID:                "quick-opus-5.5",
		AgentMode:         "smart",
		ThinkingEffort:    "off",
		UpstreamModelID:   "us.anthropic.claude-opus-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: true,
	},
	{
		ID:                "quick-opus-5.5-thinking",
		AgentMode:         "smart",
		ThinkingEffort:    "high",
		UpstreamModelID:   "us.anthropic.claude-opus-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: true,
	},
	{
		ID:                "quick-opus-5.5-max",
		AgentMode:         "smart",
		ThinkingEffort:    "max",
		UpstreamModelID:   "us.anthropic.claude-opus-5-5",
		OwnedBy:           "amazon-quick",
		ContextWindow:     1000000,
		MaxOutputTokens:   64000,
		SupportsImages:    true,
		SupportsToolCall:  true,
		SupportsReasoning: true,
	},
}

// LookupCatalog returns the ModelSpec matching a canonical ID.
func LookupCatalog(canonicalID string) (ModelSpec, bool) {
	for _, m := range Catalog {
		if strings.EqualFold(m.ID, canonicalID) {
			return m, true
		}
	}
	return ModelSpec{}, false
}

// ResolvedTarget is the effective Quick agent_mode and thinking_effort for a request.
type ResolvedTarget struct {
	RequestedModel string
	CanonicalID    string
	AgentMode      string
	ThinkingEffort string
}

// NormalizeReasoningEffort maps OpenAI reasoning_effort values onto Quick's thinking_effort.
func NormalizeReasoningEffort(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", false
	case "none", "off", "disabled", "false", "0":
		return "off", true
	case "minimal", "low":
		return "low", true
	case "medium", "med":
		return "medium", true
	case "high":
		return "high", true
	case "max", "xhigh", "very_high":
		return "max", true
	default:
		return "", false
	}
}

// BudgetToEffort maps Anthropic/Gemini thinking budget_tokens onto Quick's thinking_effort.
func BudgetToEffort(budget int) string {
	switch {
	case budget <= 0:
		return "off"
	case budget <= 4096:
		return "low"
	case budget <= 16384:
		return "medium"
	case budget <= 32768:
		return "high"
	default:
		return "max"
	}
}

// Resolve maps an incoming OpenAI model name and optional reasoning_effort onto Quick parameters.
func Resolve(modelName, reasoningEffort string) (ResolvedTarget, bool) {
	raw := strings.TrimSpace(modelName)
	if raw == "" {
		raw = "quick-sonnet-5.5"
	}
	norm := strings.ToLower(raw)

	// Strip common provider prefixes (e.g. "quick/", "[quick]-", "amazon-quick/")
	for _, pfx := range []string{"amazon-quick/", "quick/", "[quick]-", "[aws]-"} {
		norm = strings.TrimPrefix(norm, pfx)
	}

	// Exact match against catalog first.
	for _, m := range Catalog {
		if norm == strings.ToLower(m.ID) {
			t := ResolvedTarget{
				RequestedModel: raw,
				CanonicalID:    m.ID,
				AgentMode:      m.AgentMode,
				ThinkingEffort: m.ThinkingEffort,
			}
			if eff, ok := NormalizeReasoningEffort(reasoningEffort); ok {
				t.ThinkingEffort = eff
			}
			return t, true
		}
	}

	// Extract optional thinking suffix (-thinking, -low, -medium, -high, -max, -off, or parenthesized "(high)").
	effort := "off"
	hasSuffixEffort := false
	if strings.HasSuffix(norm, ")") {
		if open := strings.LastIndexByte(norm, '('); open > 0 {
			inner := norm[open+1 : len(norm)-1]
			if eff, ok := NormalizeReasoningEffort(inner); ok {
				norm = strings.TrimSpace(norm[:open])
				effort = eff
				hasSuffixEffort = true
			}
		}
	}
	if !hasSuffixEffort {
		for _, suf := range []struct {
			s   string
			eff string
		}{
			{"-thinking", "high"},
			{"-xhigh", "max"},
			{"-max", "max"},
			{"-high", "high"},
			{"-medium", "medium"},
			{"-med", "medium"},
			{"-low", "low"},
			{"-minimal", "low"},
			{"-none", "off"},
			{"-off", "off"},
		} {
			if strings.HasSuffix(norm, suf.s) {
				norm = strings.TrimSuffix(norm, suf.s)
				effort = suf.eff
				hasSuffixEffort = true
				break
			}
		}
	}

	var mode, canonical string
	switch {
	case norm == "fast" || norm == "quick-fast" || strings.Contains(norm, "haiku"):
		mode = "fast"
		canonical = "quick-haiku-5.5"
	case norm == "balanced" || norm == "quick-balanced" || strings.Contains(norm, "sonnet"):
		mode = "balanced"
		if hasSuffixEffort && effort != "off" {
			canonical = "quick-sonnet-5.5-thinking"
		} else {
			canonical = "quick-sonnet-5.5"
		}
	case norm == "smart" || norm == "quick-smart" || strings.Contains(norm, "opus"):
		mode = "smart"
		switch effort {
		case "max":
			canonical = "quick-opus-5.5-max"
		case "off":
			canonical = "quick-opus-5.5"
		default:
			canonical = "quick-opus-5.5-thinking"
		}
	case norm == "advanced" || norm == "quick-advanced":
		mode = "advanced"
		canonical = "quick-advanced"
		if !hasSuffixEffort {
			effort = "high"
		}
	default:
		return ResolvedTarget{}, false
	}

	if eff, ok := NormalizeReasoningEffort(reasoningEffort); ok {
		effort = eff
	}

	return ResolvedTarget{
		RequestedModel: raw,
		CanonicalID:    canonical,
		AgentMode:      mode,
		ThinkingEffort: effort,
	}, true
}
