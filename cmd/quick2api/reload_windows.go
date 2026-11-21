//go:build windows

package main

import (
	"context"

	"quick2api/internal/auth"
)

func watchReloadSignal(ctx context.Context, reloadFn func() (auth.ReloadResult, error)) {
	// Windows has no SIGHUP; use POST /admin/reload for zero-downtime reloads.
	_ = ctx
	_ = reloadFn
}
