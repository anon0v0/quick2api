package models

import "testing"

func TestResolveModels(t *testing.T) {
	cases := []struct {
		model     string
		effort    string
		wantOK    bool
		wantMode  string
		wantThink string
	}{
		{"quick-haiku-5.5", "", true, "fast", "off"},
		{"quick-sonnet-5.5", "", true, "balanced", "off"},
		{"quick-sonnet-5.5-thinking", "", true, "balanced", "high"},
		{"quick-opus-5.5", "", true, "smart", "off"},
		{"quick-opus-5.5-thinking", "", true, "smart", "high"},
		{"quick-opus-5.5-max", "", true, "smart", "max"},
		{"[quick]-claude-opus-5-5", "medium", true, "smart", "medium"},
		{"claude-sonnet-5-5-high", "", true, "balanced", "high"},
		{"quick-opus-5.5-thinking", "none", true, "smart", "off"},
		{"quick-opus-5.5(high)", "", true, "smart", "high"},
		{"[quick]-claude-opus-5.5(max)", "", true, "smart", "max"},
		{"unknown-gpt-99", "", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := Resolve(tc.model, tc.effort)
		if ok != tc.wantOK {
			t.Errorf("Resolve(%q, %q) ok=%v, want %v", tc.model, tc.effort, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.AgentMode != tc.wantMode || got.ThinkingEffort != tc.wantThink {
			t.Errorf("Resolve(%q, %q) = (%s, %s), want (%s, %s)",
				tc.model, tc.effort, got.AgentMode, got.ThinkingEffort, tc.wantMode, tc.wantThink)
		}
	}
}

func TestBudgetToEffortAndCatalogLookup(t *testing.T) {
	if got := BudgetToEffort(0); got != "off" {
		t.Fatalf("BudgetToEffort(0)=%q, want off", got)
	}
	if got := BudgetToEffort(2048); got != "low" {
		t.Fatalf("BudgetToEffort(2048)=%q, want low", got)
	}
	if got := BudgetToEffort(12000); got != "medium" {
		t.Fatalf("BudgetToEffort(12000)=%q, want medium", got)
	}
	if got := BudgetToEffort(24000); got != "high" {
		t.Fatalf("BudgetToEffort(24000)=%q, want high", got)
	}
	if got := BudgetToEffort(64000); got != "max" {
		t.Fatalf("BudgetToEffort(64000)=%q, want max", got)
	}
	spec, ok := LookupCatalog("quick-opus-5.5-thinking")
	if !ok || spec.ContextWindow != 1000000 || spec.MaxOutputTokens != 64000 || !spec.SupportsReasoning {
		t.Fatalf("unexpected catalog spec: %+v ok=%v", spec, ok)
	}
}
