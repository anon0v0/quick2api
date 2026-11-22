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

func TestLoadDesktopProfilesNormalizesSlashValidatesHTTPSAndFiltersProvider(t *testing.T) {
	writeDesktopProfiles(t, `{"entries":[
      {"provider":"enterprise","login_metadata":{"issuer_url":"https://corp.awsapps.com/start","tenant_url":"https://corp.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"}},
      {"provider":"social","login_metadata":{"issuer_url":"http://insecure.example/ssoins-bad","tenant_url":"https://cell-ok.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev"}},
      {"provider":"social","login_metadata":{"issuer_url":"https://identitycenter.amazonaws.com/ssoins-norm/","tenant_url":"https://cell-ok.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev"}},
      {"provider":"social","login_metadata":{"issuer_url":"https://identitycenter.amazonaws.com/ssoins-norm","tenant_url":"https://cell-ok.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev/"}}
    ]}`)

	got, ok := singleDesktopProfile()
	if !ok {
		t.Fatal("expected single unambiguous social profile after filtering enterprise/http and normalizing trailing slashes")
	}
	if got.LoginMetadata.IssuerURL != "https://identitycenter.amazonaws.com/ssoins-norm" {
		t.Fatalf("expected trimmed issuer_url, got %q", got.LoginMetadata.IssuerURL)
	}
	if iss, ok := DiscoverIssuerForTenant("https://cell-ok.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev"); !ok || iss != "https://identitycenter.amazonaws.com/ssoins-norm" {
		t.Fatalf("DiscoverIssuerForTenant mismatch: ok=%v iss=%q", ok, iss)
	}
}

func TestInferRegionFromTenantURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://cell-1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev", "us-east-1"},
		{"https://cell-2.dp.appintegrations.us-west-2.prod.plato.ai.aws.dev/", "us-west-2"},
		{"https://cell-3.dp.appintegrations.eu-west-1.prod.plato.ai.aws.dev/extra", "eu-west-1"},
		{"https://cell-4.dp.appintegrations.ap-northeast-1.prod.plato.ai.aws.dev", "ap-northeast-1"},
		{"https://127.0.0.1:8443", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := InferRegionFromTenantURL(tc.in); got != tc.want {
			t.Fatalf("InferRegionFromTenantURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDiscoverIssuerFromAccountsFile(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	body := `{"accounts":[
		{"id":"a1","tenant_url":"https://cell-a.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev/","issuer_url":"https://identitycenter.amazonaws.com/ssoins-pool-a/"},
		{"id":"a2","tenant_url":"https://cell-a.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-pool-a"},
		{"id":"b1","tenant_url":"https://cell-conflict.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-one"},
		{"id":"b2","tenant_url":"https://cell-conflict.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","issuer_url":"https://identitycenter.amazonaws.com/ssoins-two"},
		{"id":"c1","tenant_url":"https://cell-bad.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","issuer_url":"http://insecure.example/ssoins-bad"}
	]}`
	if err := os.WriteFile(accPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, ok := discoverIssuerFromAccountsFile(accPath, "https://cell-a.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); !ok || got != "https://identitycenter.amazonaws.com/ssoins-pool-a" {
		t.Fatalf("expected pool issuer match, got ok=%v issuer=%q", ok, got)
	}
	if _, ok := discoverIssuerFromAccountsFile(accPath, "https://cell-conflict.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); ok {
		t.Fatal("expected conflicting issuers in accounts.json to be rejected")
	}
	if _, ok := discoverIssuerFromAccountsFile(accPath, "https://cell-bad.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); ok {
		t.Fatal("expected non-HTTPS issuer in accounts.json to be ignored")
	}
	if _, ok := discoverIssuerFromAccountsFile(filepath.Join(dir, "missing.json"), "https://cell-a.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev"); ok {
		t.Fatal("expected missing accounts file to return false")
	}
}
