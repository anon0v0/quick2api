package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds runtime settings for quick2api.
type Config struct {
	ListenAddrs       []string `json:"listen_addrs"`
	APIKeys           []string `json:"api_keys"`
	AccountsFile      string   `json:"accounts_file"`
	ProxyURL          string   `json:"proxy_url,omitempty"`
	DefaultSurface    string   `json:"default_surface,omitempty"`
	DeleteSession     *bool    `json:"delete_session,omitempty"`
	RequestTimeoutSec    int      `json:"request_timeout_sec,omitempty"`
	StreamIdleTimeoutSec int      `json:"stream_idle_timeout_sec,omitempty"`
	SSEKeepAliveSec      int      `json:"sse_keepalive_sec,omitempty"`
	MaxBodyMB            int      `json:"max_body_mb,omitempty"`
	RefreshLeadSec       int      `json:"refresh_lead_sec,omitempty"`
	MaxConcurrentTurn    int      `json:"max_concurrent_turns,omitempty"`
	Debug                bool     `json:"debug,omitempty"`
}

func boolPtr(b bool) *bool { return &b }

// Default returns safe loopback-only defaults.
func Default() Config {
	return Config{
		ListenAddrs:          []string{"127.0.0.1:18082"},
		AccountsFile:         "accounts.json",
		DefaultSurface:       "QUICK_WORK_DESKTOP_WINDOWS",
		DeleteSession:        boolPtr(true),
		RequestTimeoutSec:    600,
		StreamIdleTimeoutSec: 120,
		SSEKeepAliveSec:      15,
		MaxBodyMB:            64,
		RefreshLeadSec:       600,
		MaxConcurrentTurn:    8,
	}
}

// Load reads optional JSON config file and overlays environment variables.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if v := strings.TrimSpace(os.Getenv("QUICK2API_LISTEN")); v != "" {
		cfg.ListenAddrs = splitCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("QUICK2API_API_KEYS")); v != "" {
		cfg.APIKeys = splitCSV(v)
	}
	if v := strings.TrimSpace(os.Getenv("QUICK2API_ACCOUNTS_FILE")); v != "" {
		cfg.AccountsFile = v
	}
	if v := strings.TrimSpace(os.Getenv("QUICK2API_PROXY_URL")); v != "" {
		cfg.ProxyURL = v
	}
	if strings.EqualFold(os.Getenv("QUICK2API_DEBUG"), "true") || os.Getenv("QUICK2API_DEBUG") == "1" {
		cfg.Debug = true
	}

	if len(cfg.ListenAddrs) == 0 {
		cfg.ListenAddrs = []string{"127.0.0.1:18082"}
	}
	if cfg.DefaultSurface == "" {
		cfg.DefaultSurface = "QUICK_WORK_DESKTOP_WINDOWS"
	}
	if cfg.DeleteSession == nil {
		cfg.DeleteSession = boolPtr(true)
	}
	if cfg.RequestTimeoutSec <= 0 {
		cfg.RequestTimeoutSec = 600
	}
	if cfg.StreamIdleTimeoutSec == 0 {
		cfg.StreamIdleTimeoutSec = 120
	}
	if cfg.SSEKeepAliveSec == 0 {
		cfg.SSEKeepAliveSec = 15
	}
	if cfg.MaxBodyMB <= 0 {
		cfg.MaxBodyMB = 64
	}
	if cfg.RefreshLeadSec <= 0 {
		cfg.RefreshLeadSec = 600
	}
	if cfg.MaxConcurrentTurn <= 0 {
		cfg.MaxConcurrentTurn = 8
	}
	return cfg, nil
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutSec) * time.Second
}

func (c Config) StreamIdleTimeout() time.Duration {
	if c.StreamIdleTimeoutSec < 0 {
		return 0
	}
	return time.Duration(c.StreamIdleTimeoutSec) * time.Second
}

func (c Config) SSEKeepAliveInterval() time.Duration {
	if c.SSEKeepAliveSec < 0 {
		return 0
	}
	return time.Duration(c.SSEKeepAliveSec) * time.Second
}

func (c Config) MaxBodyBytes() int64 {
	mb := c.MaxBodyMB
	if mb <= 0 {
		mb = 64
	}
	return int64(mb) << 20
}

func (c Config) RefreshLead() time.Duration {
	return time.Duration(c.RefreshLeadSec) * time.Second
}

func (c Config) ShouldDeleteSession() bool {
	return c.DeleteSession == nil || *c.DeleteSession
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
