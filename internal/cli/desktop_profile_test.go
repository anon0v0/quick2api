package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func writeDesktopProfiles(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".quickwork")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "profiles.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write profiles: %v", err)
	}
}

const twoProfileIndex = `{
  "version": 1,
  "entries": [
    {"id": "social-a", "provider": "social", "login_metadata": {
      "issuer_url": "https://identitycenter.amazonaws.com/ssoins-aaaa",
      "tenant_url": "https://cell-a.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
      "client_id": "cid-a"}},
    {"id": "social-b", "provider": "social", "login_metadata": {
      "issuer_url": "https://identitycenter.amazonaws.com/ssoins-bbbb",
      "tenant_url": "https://cell-b.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev/",
      "client_id": "cid-b"}}
  ]
}`

func TestDesktopProfileForTenant(t *testing.T) {
	writeDesktopProfiles(t, twoProfileIndex)

	got, ok := desktopProfileForTenant("https://cell-b.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev/")
	if !ok {
		t.Fatal("expected match for tenant b")
	}
	if got.LoginMetadata.IssuerURL != "https://identitycenter.amazonaws.com/ssoins-bbbb" {
		t.Fatalf("unexpected issuer: %s", got.LoginMetadata.IssuerURL)
	}

	if _, ok := desktopProfileForTenant("https://unknown.example"); ok {
		t.Fatal("expected no match for unknown tenant")
	}
}

func TestSingleDesktopProfileRequiresUnambiguousIndex(t *testing.T) {
	writeDesktopProfiles(t, twoProfileIndex)
	if _, ok := singleDesktopProfile(); ok {
		t.Fatal("expected ambiguous index to be rejected")
	}

	writeDesktopProfiles(t, `{"entries":[{"login_metadata":{
      "issuer_url":"https://identitycenter.amazonaws.com/ssoins-cccc",
      "tenant_url":"https://cell-c.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}}]}`)
	got, ok := singleDesktopProfile()
	if !ok {
		t.Fatal("expected single profile to be accepted")
	}
	if got.LoginMetadata.ClientID != "" || got.LoginMetadata.IssuerURL == "" {
		t.Fatalf("unexpected profile: %+v", got)
	}
}

func TestLoadDesktopProfilesSkipsIncompleteEntries(t *testing.T) {
	writeDesktopProfiles(t, `{"entries":[
      {"login_metadata":{"tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}},
      {"login_metadata":{"issuer_url":"https://identitycenter.amazonaws.com/ssoins-dddd","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}}
    ]}`)
	profiles, err := loadDesktopProfiles()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 usable profile, got %d", len(profiles))
	}
}

func TestLoadDesktopProfilesMissingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if _, err := loadDesktopProfiles(); err == nil {
		t.Fatal("expected error when profiles.json is absent")
	}
	if _, ok := desktopProfileForTenant("https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); ok {
		t.Fatal("expected no discovery without profiles.json")
	}
}

func TestDesktopProfileForTenantRejectsConflictingIssuers(t *testing.T) {
	writeDesktopProfiles(t, `{"entries":[
      {"login_metadata":{"issuer_url":"https://identitycenter.amazonaws.com/ssoins-one","tenant_url":"https://same.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}},
      {"login_metadata":{"issuer_url":"https://identitycenter.amazonaws.com/ssoins-two","tenant_url":"https://same.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}}
    ]}`)
	if _, ok := desktopProfileForTenant("https://same.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); ok {
		t.Fatal("expected conflicting issuers to be rejected")
	}
}
