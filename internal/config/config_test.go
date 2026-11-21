package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminPasswordEnvAndStrongGeneration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"admin_password":"from-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("QUICK2API_ADMIN_PASSWORD", "")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	p, gen := cfg.EnsureAdminPassword()
	if gen || p != "from-file" {
		t.Fatalf("expected from-file password without generation, got p=%q gen=%v", p, gen)
	}

	// Env var overrides config file.
	t.Setenv("QUICK2API_ADMIN_PASSWORD", "from-env-strong")
	cfg2, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	p2, gen2 := cfg2.EnsureAdminPassword()
	if gen2 || p2 != "from-env-strong" {
		t.Fatalf("expected env override, got p=%q gen=%v", p2, gen2)
	}

	// Empty in both file and env -> generates unique strong password.
	t.Setenv("QUICK2API_ADMIN_PASSWORD", "")
	cfg3 := Default()
	p3, gen3 := cfg3.EnsureAdminPassword()
	if !gen3 || len(p3) < 20 {
		t.Fatalf("expected generated >=20 char password, got len=%d gen=%v", len(p3), gen3)
	}
	hasUpper := strings.ContainsAny(p3, "ABCDEFGHJKLMNPQRSTUVWXYZ")
	hasLower := strings.ContainsAny(p3, "abcdefghijkmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(p3, "23456789")
	hasSym := strings.ContainsAny(p3, "!@#%+=._-")
	if !hasUpper || !hasLower || !hasDigit || !hasSym {
		t.Fatalf("generated password missing required character classes: %q", p3)
	}
	cfg4 := Default()
	p4, _ := cfg4.EnsureAdminPassword()
	if p4 == p3 {
		t.Fatal("two generated passwords collided")
	}
}
