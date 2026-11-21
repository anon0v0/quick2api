package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// desktopProfile is one account recorded by Amazon Quick Desktop in ~/.quickwork/profiles.json.
type desktopProfile struct {
	Provider      string `json:"provider"`
	LoginMetadata struct {
		IssuerURL string `json:"issuer_url"`
		TenantURL string `json:"tenant_url"`
		ClientID  string `json:"client_id"`
	} `json:"login_metadata"`
}

type desktopProfilesFile struct {
	Entries []desktopProfile `json:"entries"`
}

// desktopProfilesPath returns the Amazon Quick Desktop profile index for the current user.
func desktopProfilesPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".quickwork", "profiles.json"), nil
}

// loadDesktopProfiles reads the Amazon Quick Desktop profile index, dropping entries that
// carry no issuer. A missing file is not an error: login still works with an explicit issuer.
func loadDesktopProfiles() ([]desktopProfile, error) {
	path, err := desktopProfilesPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f desktopProfilesFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	out := make([]desktopProfile, 0, len(f.Entries))
	for _, e := range f.Entries {
		e.LoginMetadata.IssuerURL = strings.TrimSpace(e.LoginMetadata.IssuerURL)
		e.LoginMetadata.TenantURL = strings.TrimRight(strings.TrimSpace(e.LoginMetadata.TenantURL), "/")
		if e.LoginMetadata.IssuerURL == "" || e.LoginMetadata.TenantURL == "" {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// desktopProfileForTenant returns the single desktop account whose tenant matches tenant.
// It reports false when the file is absent, has no match, or holds conflicting issuers.
func desktopProfileForTenant(tenant string) (desktopProfile, bool) {
	profiles, err := loadDesktopProfiles()
	if err != nil {
		return desktopProfile{}, false
	}
	tenant = strings.TrimRight(strings.TrimSpace(tenant), "/")
	var found *desktopProfile
	for i := range profiles {
		if !strings.EqualFold(profiles[i].LoginMetadata.TenantURL, tenant) {
			continue
		}
		if found != nil && !strings.EqualFold(found.LoginMetadata.IssuerURL, profiles[i].LoginMetadata.IssuerURL) {
			return desktopProfile{}, false
		}
		found = &profiles[i]
	}
	if found == nil {
		return desktopProfile{}, false
	}
	return *found, true
}

// singleDesktopProfile returns the only desktop account. It reports false unless exactly one
// issuer is present, so an ambiguous profile index never silently picks an identity store.
func singleDesktopProfile() (desktopProfile, bool) {
	profiles, err := loadDesktopProfiles()
	if err != nil || len(profiles) == 0 {
		return desktopProfile{}, false
	}
	first := profiles[0]
	for _, p := range profiles[1:] {
		if !strings.EqualFold(p.LoginMetadata.IssuerURL, first.LoginMetadata.IssuerURL) ||
			!strings.EqualFold(p.LoginMetadata.TenantURL, first.LoginMetadata.TenantURL) {
			return desktopProfile{}, false
		}
	}
	return first, true
}

// DiscoverIssuerForTenant exposes the issuer Amazon Quick Desktop recorded for tenantURL so
// callers outside this package (for example the admin OAuth endpoint) can reuse it.
func DiscoverIssuerForTenant(tenantURL string) (string, bool) {
	profile, ok := desktopProfileForTenant(tenantURL)
	if !ok {
		return "", false
	}
	return profile.LoginMetadata.IssuerURL, true
}
