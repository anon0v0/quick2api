//go:build !windows

package cli

import "errors"

// RunImportDesktop is only supported on Windows where Amazon Quick Desktop stores credentials in Windows Credential Manager.
func RunImportDesktop(args []string) error {
	_ = args
	return errors.New("import-desktop reads Windows Credential Manager and is only supported on Windows; use `quick2api login -headless` on Linux/macOS")
}
