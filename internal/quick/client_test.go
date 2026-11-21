package quick

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quick2api/internal/auth"
)

func TestParseQuota(t *testing.T) {
	if ParseQuota(nil) != nil || ParseQuota(map[string]any{"unrelated": true}) != nil {
		t.Fatal("expected nil quota for empty/unrelated payload")
	}
	raw := map[string]any{
		"monthly": map[string]any{
			"used":      float64(42),
			"limit":     float64(600),
			"percent":   float64(7),
			"resets_at": float64(1780000000),
		},
		"session": map[string]any{
			"used":              float64(100),
			"limit":             float64(100),
			"percent":           float64(100),
			"resets_at":         float64(1777777777),
			"resume_in_minutes": float64(18),
		},
		"subscription": map[string]any{
			"subscription_type": "FREE_TRIAL",
			"free_trial_metadata": map[string]any{
				"status": "ACTIVE",
			},
		},
	}
	q := ParseQuota(raw)
	if q == nil {
		t.Fatal("expected non-nil quota")
	}
	if q.MonthlyUsed != 42 || q.MonthlyLimit != 600 || q.MonthlyPercent != 7 || q.MonthlyResetsAt != 1780000000 {
		t.Fatalf("unexpected monthly quota: %+v", q)
	}
	if q.SessionUsed != 100 || q.SessionLimit != 100 || q.SessionResumeMin != 18 || q.SessionResetsAt != 1777777777 {
		t.Fatalf("unexpected session quota: %+v", q)
	}
	if q.SubscriptionType != "FREE_TRIAL" || q.TrialStatus != "ACTIVE" {
		t.Fatalf("unexpected subscription metadata: %+v", q)
	}
}

func TestProbeProxyAndSanitizeError(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"a1","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}

	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.42"}`))
	}))
	defer echoSrv.Close()

	ip, latency, err := mgr.ProbeProxy(context.Background(), auth.Account{ID: "a1"}, echoSrv.URL)
	if err != nil || ip != "203.0.113.42" || latency < 0 {
		t.Fatalf("ProbeProxy failed: ip=%q latency=%d err=%v", ip, latency, err)
	}

	// Dead proxy with credentials must fail cleanly without leaking userinfo.
	_, _, err = mgr.ProbeProxy(context.Background(), auth.Account{
		ID:       "a1",
		ProxyURL: "http://secretuser:secretpass@127.0.0.1:1",
	}, echoSrv.URL)
	if err == nil {
		t.Fatal("expected dead proxy error")
	}
	if strings.Contains(err.Error(), "secretuser") || strings.Contains(err.Error(), "secretpass") {
		t.Fatalf("proxy credentials leaked in error: %v", err)
	}
}

func TestReconcileReloadSelectiveInvalidation(t *testing.T) {
	dir := t.TempDir()
	accPath := filepath.Join(dir, "accounts.json")
	_ = os.WriteFile(accPath, []byte(`{"accounts":[{"id":"keep","tenant_url":"https://cell.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev","access_token":"at","access_token_expiry":2000000000}]}`), 0o600)
	store, err := auth.NewStore(accPath, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, "QUICK_WORK_DESKTOP_WINDOWS", true, "", false)
	if err != nil {
		t.Fatal(err)
	}

	mkConn := func(id string) *accountConn {
		return &accountConn{accountID: id, alive: true, done: make(chan struct{}), threads: make(map[string]*threadSub)}
	}
	cKeep := mkConn("keep")
	cRemoved := mkConn("removed")
	cDisabled := mkConn("disabled")
	cProxy := mkConn("proxy-changed")
	mgr.mu.Lock()
	mgr.conns["keep"] = cKeep
	mgr.conns["removed"] = cRemoved
	mgr.conns["disabled"] = cDisabled
	mgr.conns["proxy-changed"] = cProxy
	mgr.mu.Unlock()

	mgr.ReconcileReload(auth.ReloadResult{
		Removed:      []string{"removed"},
		Disabled:     []string{"disabled"},
		ProxyChanged: []string{"proxy-changed"},
	})

	if mgr.ActiveConnections() != 1 || !cKeep.isAlive() {
		t.Fatalf("expected only 'keep' alive, active=%d keepAlive=%v", mgr.ActiveConnections(), cKeep.isAlive())
	}
	if cRemoved.isAlive() || cDisabled.isAlive() || cProxy.isAlive() {
		t.Fatal("expected removed/disabled/proxy-changed connections to be closed")
	}
}
