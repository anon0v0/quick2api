package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// AdminUsername is the fixed administrator login name for the embedded web console.
const AdminUsername = "root"

// Config holds runtime settings for quick2api.
type Config struct {
	ListenAddrs          []string `json:"listen_addrs"`
	APIKeys              []string `json:"api_keys"`
	AdminPassword        string   `json:"admin_password,omitempty"`
	AccountsFile         string   `json:"accounts_file"`
	ProxyURL             string   `json:"proxy_url,omitempty"`
	DefaultSurface       string   `json:"default_surface,omitempty"`
	DeleteSession        *bool    `json:"delete_session,omitempty"`
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
	if v := strings.TrimSpace(os.Getenv("QUICK2API_ADMIN_PASSWORD")); v != "" {
		cfg.AdminPassword = v
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

// EnsureAdminPassword guarantees cfg.AdminPassword is non-empty, generating a
// cryptographically random strong password when neither env nor config supplied one.
func (c *Config) EnsureAdminPassword() (password string, generated bool) {
	c.AdminPassword = strings.TrimSpace(c.AdminPassword)
	if c.AdminPassword != "" {
		return c.AdminPassword, false
	}
	c.AdminPassword = GenerateStrongPassword(20)
	return c.AdminPassword, true
}

// GenerateStrongPassword creates a random strong password containing uppercase,
// lowercase, digits, and safe punctuation using crypto/rand.
func GenerateStrongPassword(length int) string {
	if length < 16 {
		length = 16
	}
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnopqrstuvwxyz"
		digits  = "23456789"
		symbols = "!@#%+=._-"
		all     = upper + lower + digits + symbols
	)
	pick := func(set string) byte {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			panic(fmt.Errorf("crypto/rand failed: %w", err))
		}
		return set[n.Int64()]
	}
	buf := make([]byte, length)
	buf[0] = pick(upper)
	buf[1] = pick(lower)
	buf[2] = pick(digits)
	buf[3] = pick(symbols)
	for i := 4; i < length; i++ {
		buf[i] = pick(all)
	}
	for i := length - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			panic(fmt.Errorf("crypto/rand failed: %w", err))
		}
		j := int(jBig.Int64())
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
