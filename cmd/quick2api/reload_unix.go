//go:build !windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"quick2api/internal/auth"
)

func watchReloadSignal(ctx context.Context, reloadFn func() (auth.ReloadResult, error)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				res, err := reloadFn()
				if err != nil {
					log.Printf("[quick2api] SIGHUP reload failed (kept existing accounts): %v", err)
					continue
				}
				log.Printf("[quick2api] SIGHUP reloaded accounts total=%d enabled=%d added=%v removed=%v disabled=%v proxy_changed=%v",
					res.Total, res.Enabled, res.Added, res.Removed, res.Disabled, res.ProxyChanged)
			}
		}
	}()
}
