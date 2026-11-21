package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"quick2api/internal/auth"
	"quick2api/internal/cli"
	"quick2api/internal/config"
	"quick2api/internal/quick"
	"quick2api/internal/server"
	"quick2api/internal/telemetry"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "login":
			if err := cli.RunLogin(os.Args[2:]); err != nil {
				log.Fatalf("[quick2api] login: %v", err)
			}
			return
		case "import-desktop":
			if err := cli.RunImportDesktop(os.Args[2:]); err != nil {
				log.Fatalf("[quick2api] import-desktop: %v", err)
			}
			return
		}
	}

	configPath := flag.String("config", "", "Path to JSON config file")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = out.Write([]byte("Usage:\n  quick2api [-config path]\n  quick2api login [flags]\n  quick2api import-desktop [flags]\n\nServer flags:\n"))
		flag.PrintDefaults()
	}
	flag.Parse()
	logBuf := telemetry.NewLogBuffer(1000)
	log.SetOutput(io.MultiWriter(os.Stderr, logBuf))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[quick2api] load config: %v", err)
	}

	store, err := auth.NewStore(cfg.AccountsFile, cfg.RefreshLead(), cfg.ProxyURL)
	if err != nil {
		log.Fatalf("[quick2api] init account store: %v", err)
	}
	log.Printf("[quick2api] loaded %d enabled account(s) from %s", store.AccountCount(), cfg.AccountsFile)

	manager, err := quick.NewManager(store, cfg.DefaultSurface, cfg.ShouldDeleteSession(), cfg.ProxyURL, cfg.Debug)
	if err != nil {
		log.Fatalf("[quick2api] init quick manager: %v", err)
	}
	manager.SetStreamIdleTimeout(cfg.StreamIdleTimeout())
	defer manager.Close()

	bgCtx, bgCancel := context.WithCancel(context.Background())
	store.StartBackgroundRefresher(bgCtx)

	handler := server.New(cfg, store, manager)
	handler.SetLogBuffer(logBuf)
	watchReloadSignal(bgCtx, handler.ReloadAccounts)
	httpServers := make([]*http.Server, 0, len(cfg.ListenAddrs))
	var wg sync.WaitGroup

	for _, addr := range cfg.ListenAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("[quick2api] listen %s failed: %v", addr, err)
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		httpServers = append(httpServers, srv)
		log.Printf("[quick2api] listening on http://%s (admin console: http://%s/admin/)", addr, addr)
		wg.Add(1)
		go func(a string, l net.Listener, s *http.Server) {
			defer wg.Done()
			if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[quick2api] server on %s stopped with error: %v", a, err)
			}
		}(addr, ln, srv)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[quick2api] received signal %s, shutting down...", sig)
	bgCancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	for _, srv := range httpServers {
		_ = srv.Shutdown(shutdownCtx)
	}
	manager.Close()
	wg.Wait()
	log.Printf("[quick2api] shutdown complete")
}
