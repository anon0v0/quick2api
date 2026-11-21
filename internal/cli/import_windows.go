//go:build windows

package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"quick2api/internal/auth"
	"quick2api/internal/config"
	"quick2api/internal/netproxy"
)

var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	procCredEnumW  = advapi32.NewProc("CredEnumerateW")
	procCredFree   = advapi32.NewProc("CredFree")
)

type winCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// RunImportDesktop reads logged-in Amazon Quick social credentials from Windows Credential Manager
// and upserts them atomically (0600) into accounts.json without printing secrets.
func RunImportDesktop(args []string) error {
	fs := flag.NewFlagSet("import-desktop", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "Optional config.json path to resolve accounts_file")
	accountsPath := fs.String("accounts", "", "Target accounts.json path")
	proxyURL := fs.String("proxy", "", "Optional per-account outbound proxy URL to assign to imported accounts")
	filter := fs.String("filter", "quickwork-social-*", "Windows Credential Manager target filter")
	if err := fs.Parse(args); err != nil {
		return err
	}

	targetAccounts := strings.TrimSpace(*accountsPath)
	if targetAccounts == "" && strings.TrimSpace(*cfgPath) != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		targetAccounts = cfg.AccountsFile
	}
	if targetAccounts == "" {
		targetAccounts = "accounts.json"
	}

	acctProxy := strings.TrimSpace(*proxyURL)
	if err := netproxy.Validate(acctProxy); err != nil {
		return err
	}

	creds, err := enumerateWindowsCredentials(*filter)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		return fmt.Errorf("no Windows credentials matched %q (sign in with Amazon Quick Desktop first)", *filter)
	}

	imported := reassembleDesktopCredentials(creds, acctProxy)
	if len(imported) == 0 {
		return errors.New("matched credentials did not contain valid Amazon Quick OIDC account payloads")
	}

	added, updated, err := auth.UpsertAccountsFile(targetAccounts, imported)
	if err != nil {
		return err
	}
	fmt.Printf("Imported %d account(s) into %s (added=%v updated=%v)\n", len(imported), targetAccounts, added, updated)
	return nil
}

func enumerateWindowsCredentials(filter string) (map[string][]byte, error) {
	filterPtr, err := syscall.UTF16PtrFromString(filter)
	if err != nil {
		return nil, err
	}
	var count uint32
	var credsPtr **winCredential
	r1, _, callErr := procCredEnumW.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credsPtr)),
	)
	if r1 == 0 {
		if errors.Is(callErr, syscall.ERROR_NOT_FOUND) {
			return nil, nil
		}
		return nil, fmt.Errorf("CredEnumerateW failed: %w", callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credsPtr)))

	list := unsafe.Slice(credsPtr, count)
	out := make(map[string][]byte, len(list))
	for _, c := range list {
		if c == nil || c.TargetName == nil || c.CredentialBlob == nil || c.CredentialBlobSize == 0 {
			continue
		}
		target := utf16PtrToString(c.TargetName)
		raw := unsafe.Slice(c.CredentialBlob, c.CredentialBlobSize)
		cp := make([]byte, len(raw))
		copy(cp, raw)
		out[target] = cp
	}
	return out, nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var units []uint16
	for ptr := p; *ptr != 0; ptr = (*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2)) {
		units = append(units, *ptr)
		if len(units) > 4096 {
			break
		}
	}
	return string(utf16.Decode(units))
}

