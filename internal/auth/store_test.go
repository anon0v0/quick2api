package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreConcurrentRefreshAndPersist(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken":  "aoa_new_access_token",
			"refreshToken": "aor_rotated_refresh_token",
			"expiresIn":    3600,
			"tokenType":    "Bearer",
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	initial := map[string]any{
		"accounts": []map[string]any{{
			"id":                  "acc-1",
			"tenant_url":          "https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
			"client_id":           "cid",
			"client_secret":       "csec",
			"access_token":        "aoa_expired",
			"access_token_expiry": float64(time.Now().Unix() - 10),
			"refresh_token":       "aor_old",
		}},
	}
	b, _ := json.Marshal(initial)
	if err := os.WriteFile(accPath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(accPath, 10*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	store.oidcBaseURL = srv.URL

	// Fire 8 concurrent EnsureFresh calls; only 1 OIDC HTTP call should execute.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acct, err := store.EnsureFresh(context.Background(), "acc-1", false)
			if err != nil {
				errs <- err
				return
			}
			if acct.AccessToken != "aoa_new_access_token" {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected single-flight 1 refresh call, got %d", calls.Load())
	}

	// Verify rotated refresh token was atomically persisted to disk.
	store2, err := NewStore(accPath, 10*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	acct2, err := store2.PickAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if acct2.AccessToken != "aoa_new_access_token" || acct2.RefreshToken != "aor_rotated_refresh_token" {
		t.Fatalf("persisted tokens mismatch: access=%q refresh=%q", acct2.AccessToken, acct2.RefreshToken)
	}
}

func TestStorePerAccountProxyIsolationAndValidation(t *testing.T) {
	dir := t.TempDir()

	// 1. Invalid proxy_url on disk must fail NewStore (no silent fallback to direct).
	badPath := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(badPath, []byte(`{"accounts":[{"id":"bad","proxy_url":"ftp://127.0.0.1:21","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	if _, err := NewStore(badPath, 5*time.Minute, ""); err == nil {
		t.Fatal("expected NewStore to reject unsupported proxy scheme on disk")
	}

	// 2. Per-account HTTP proxy isolation during OIDC refresh (account A -> proxyA, account B -> direct).
	var proxyAHits atomic.Int32
	var directHits atomic.Int32
	oidcSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "direct-tok", "expiresIn": 3600})
	}))
	defer oidcSrv.Close()

	proxyASrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyAHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "proxied-tok", "expiresIn": 3600})
	}))
	defer proxyASrv.Close()

	accPath := filepath.Join(dir, "accounts.json")
	payload := map[string]any{
		"accounts": []map[string]any{
			{
				"id":                  "acc-proxied",
				"proxy_url":           proxyASrv.URL,
				"tenant_url":          "https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
				"client_id":           "cid",
				"client_secret":       "csec",
				"access_token":        "old-a",
				"access_token_expiry": 1,
				"refresh_token":       "rt-a",
			},
			{
				"id":                  "acc-direct",
				"proxy_url":           "direct",
				"tenant_url":          "https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev",
				"client_id":           "cid",
				"client_secret":       "csec",
				"access_token":        "old-b",
				"access_token_expiry": 1,
				"refresh_token":       "rt-b",
			},
		},
	}
	b, _ := json.Marshal(payload)
	if err := os.WriteFile(accPath, b, 0o600); err != nil {
		t.Fatal(err)
	}

	// Global proxy points to proxyA, yet acc-direct explicitly sets "direct" and must bypass it.
	store, err := NewStore(accPath, 5*time.Minute, proxyASrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	store.oidcBaseURL = oidcSrv.URL

	a1, err := store.EnsureFresh(context.Background(), "acc-proxied", true)
	if err != nil || a1.AccessToken != "proxied-tok" {
		t.Fatalf("expected proxied refresh, got acct=%+v err=%v", a1, err)
	}
	a2, err := store.EnsureFresh(context.Background(), "acc-direct", true)
	if err != nil || a2.AccessToken != "direct-tok" {
		t.Fatalf("expected direct refresh, got acct=%+v err=%v", a2, err)
	}
	if proxyAHits.Load() != 1 || directHits.Load() != 1 {
		t.Fatalf("expected proxyA=1 direct=1, got proxyA=%d direct=%d", proxyAHits.Load(), directHits.Load())
	}

	// 3. SetAccountProxy updates, persists, and redacts credentials in returned status.
	changed, st, err := store.SetAccountProxy("acc-direct", "socks5h://alice:supersecret@127.0.0.1:1080")
	if err != nil || !changed {
		t.Fatalf("SetAccountProxy failed: changed=%v err=%v", changed, err)
	}
	if strings.Contains(st.Proxy, "supersecret") || !strings.Contains(st.Proxy, "socks5h://127.0.0.1:1080") {
		t.Fatalf("expected redacted proxy in status, got %q", st.Proxy)
	}
	if _, _, err := store.SetAccountProxy("acc-direct", "bad://host"); err == nil {
		t.Fatal("expected SetAccountProxy to reject invalid scheme")
	}
}

func TestStoreDifferentiatedCooldownsAndQuota(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[
		{"id":"a1","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at1","access_token_expiry":2000000000},
		{"id":"a2","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at2","access_token_expiry":2000000000}
	]}`), 0o600)
	store, err := NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}

	// Exponential rate-limit backoff: 1m -> 2m -> 4m -> 8m -> 15m -> 15m
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range want {
		got := store.MarkRateLimited("a1", "throttled")
		if got != w {
			t.Fatalf("step %d: want backoff %v, got %v", i, w, got)
		}
	}
	store.NoteSuccess("a1")
	if got := store.MarkRateLimited("a1", "throttled"); got != time.Minute {
		t.Fatalf("after NoteSuccess expected backoff reset to 1m, got %v", got)
	}

	// Interim 30m session cooldown refined by exact resume_in_minutes=12 -> 12m.
	store.MarkCooldownWithKind("a1", CooldownSessionQuota, 30*time.Minute, "interim")
	kind, dur := store.UpdateQuota("a1", &QuotaInfo{
		MonthlyUsed:      50,
		MonthlyLimit:     600,
		SessionUsed:      100,
		SessionLimit:     100,
		SessionPercent:   100,
		SessionResumeMin: 12,
	})
	if kind != CooldownSessionQuota || dur != 12*time.Minute {
		t.Fatalf("expected session_quota 12m, got kind=%q dur=%v", kind, dur)
	}
	for _, st := range store.Statuses() {
		if st.ID == "a1" {
			if st.CooldownKind != CooldownSessionQuota || st.CooldownRemainingSec > 12*60+5 || st.CooldownRemainingSec < 11*60 {
				t.Fatalf("expected refined ~12m session cooldown in status, got %+v", st)
			}
		}
	}

	// Monthly quota exhausted -> monthly_quota clamped up to 72h.
	kind, dur = store.UpdateQuota("a2", &QuotaInfo{
		MonthlyUsed:     600,
		MonthlyLimit:    600,
		MonthlyPercent:  100,
		MonthlyResetsAt: time.Now().Add(200 * time.Hour).Unix(),
	})
	if kind != CooldownMonthlyQuota || dur != 72*time.Hour {
		t.Fatalf("expected monthly_quota clamped to 72h, got kind=%q dur=%v", kind, dur)
	}

	// Expired free trial -> subscription_expired 24h.
	kind, dur = store.UpdateQuota("a2", &QuotaInfo{TrialStatus: "EXPIRED"})
	if kind != CooldownSubscriptionExpired || dur != 24*time.Hour {
		t.Fatalf("expected subscription_expired 24h, got kind=%q dur=%v", kind, dur)
	}

	// ResetCooldown clears one or all accounts.
	if n := store.ResetCooldown("a1"); n != 1 {
		t.Fatalf("expected 1 cleared for a1, got %d", n)
	}
	if n := store.ResetCooldown(""); n != 1 {
		t.Fatalf("expected 1 remaining cleared for all, got %d", n)
	}
}

func TestStoreHotReloadPreservesStateAndUpsert(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	initial := `{"accounts":[
		{"id":"keep","tenant_url":"https://c1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","client_id":"c1","access_token":"fresh-mem","access_token_expiry":2000009999,"refresh_token":"rt-fresh"},
		{"id":"drop","tenant_url":"https://c2.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","client_id":"c2","access_token":"at2","access_token_expiry":2000000000}
	]}`
	if err := os.WriteFile(accPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	store.MarkRateLimited("keep", "brief throttle")

	// Invalid disk write must not mutate live pool.
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"bad","proxy_url":"ftp://bad","tenant_url":"https://x"}]}`), 0o600)
	if _, err := store.Reload(); err == nil {
		t.Fatal("expected Reload to reject invalid proxy_url")
	}
	if store.AccountCount() != 2 {
		t.Fatalf("failed reload mutated live store: count=%d", store.AccountCount())
	}

	// Valid reload: keep gets proxy changed (with older disk token -> must keep newer in-memory token),
	// drop is removed, added is new.
	updated := `{"accounts":[
		{"id":"keep","proxy_url":"socks5h://127.0.0.1:1080","tenant_url":"https://c1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","client_id":"c1","access_token":"stale-disk","access_token_expiry":2000001000,"refresh_token":"rt-old"},
		{"id":"added","tenant_url":"https://c3.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","client_id":"c3","access_token":"at3","access_token_expiry":2000000000}
	]}`
	_ = os.WriteFile(accPath, []byte(updated), 0o600)

	res, err := store.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if len(res.Added) != 1 || res.Added[0] != "added" || len(res.Removed) != 1 || res.Removed[0] != "drop" || len(res.ProxyChanged) != 1 || res.ProxyChanged[0] != "keep" {
		t.Fatalf("unexpected ReloadResult: %+v", res)
	}
	kept, ok := store.GetAccount("keep")
	if !ok || kept.AccessToken != "fresh-mem" || kept.RefreshToken != "rt-fresh" {
		t.Fatalf("expected newer in-memory tokens preserved, got %+v", kept)
	}

	// UpsertAccountsFile preserves existing proxy_url when incoming leaves proxy_url empty.
	addIDs, updIDs, err := UpsertAccountsFile(accPath, []Account{
		{ID: "keep", TenantURL: "https://c1.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev", AccessToken: "newest"},
		{ID: "third", TenantURL: "https://c4.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev", AccessToken: "at4"},
	})
	if err != nil || len(addIDs) != 1 || addIDs[0] != "third" || len(updIDs) != 1 || updIDs[0] != "keep" {
		t.Fatalf("unexpected UpsertAccountsFile result: add=%v upd=%v err=%v", addIDs, updIDs, err)
	}
	reloaded, err := NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := reloaded.GetAccount("keep")
	if k2.ProxyURL != "socks5h://127.0.0.1:1080" || k2.AccessToken != "newest" {
		t.Fatalf("expected UpsertAccountsFile to preserve proxy_url and update token, got %+v", k2)
	}
}
