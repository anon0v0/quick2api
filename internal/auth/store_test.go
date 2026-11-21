package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
