package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestLogBufferParseRedactAndFilter(t *testing.T) {
	buf := NewLogBuffer(4)
	lines := []string{
		"2026/11/22 03:00:00 [auth] refreshed token Bearer supersecrettoken123456\n",
		"2026/11/22 03:00:01 [chat] rate_limited account=acc-1 proxy=socks5h://alice:topsecret@127.0.0.1:1080\n",
		"2026/11/22 03:00:02 [quick-ws] dial failed aoa_secretaccesstoken12345\n",
		"2026/11/22 03:00:03 [admin] hot reloaded accounts total=2\n",
		"2026/11/22 03:00:04 [chat] stale WS closed before first output\n",
	}
	for _, l := range lines {
		if _, err := buf.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}

	page := buf.Query(LogQuery{Limit: 10})
	if page.TotalBuffered != 4 || page.LatestSeq != 5 || len(page.Entries) != 4 {
		t.Fatalf("unexpected ring state: buffered=%d seq=%d len=%d", page.TotalBuffered, page.LatestSeq, len(page.Entries))
	}
	// Verify secret redaction across buffered lines.
	for _, e := range page.Entries {
		if strings.Contains(e.Message, "topsecret") || strings.Contains(e.Message, "secretaccesstoken") || strings.Contains(e.Message, "supersecrettoken") {
			t.Fatalf("log secret leaked: %+v", e)
		}
	}
	if page.Entries[0].Tag != "chat" || page.Entries[0].Level != "warn" {
		t.Fatalf("expected chat/warn on entry 0, got %+v", page.Entries[0])
	}
	if page.Entries[1].Tag != "quick-ws" || page.Entries[1].Level != "error" {
		t.Fatalf("expected quick-ws/error on entry 1, got %+v", page.Entries[1])
	}

	// Incremental since query.
	inc := buf.Query(LogQuery{Since: 3})
	if len(inc.Entries) != 2 || inc.Entries[0].Seq != 4 || inc.Entries[1].Seq != 5 {
		t.Fatalf("unexpected since=3 page: %+v", inc.Entries)
	}

	// Tag + search filter.
	filtered := buf.Query(LogQuery{Tag: "admin", Search: "reloaded"})
	if len(filtered.Entries) != 1 || filtered.Entries[0].Tag != "admin" {
		t.Fatalf("unexpected filtered page: %+v", filtered.Entries)
	}

	buf.Clear()
	afterClear := buf.Query(LogQuery{})
	if afterClear.TotalBuffered != 0 || afterClear.LatestSeq != 5 {
		t.Fatalf("expected cleared buffer keeping seq=5, got %+v", afterClear)
	}
}

func TestMetricsRecordSnapshotAndReset(t *testing.T) {
	m := NewMetrics()
	m.StartTurn()
	now := time.Now().Unix()
	m.Record(RequestRecord{
		ID:               "req-1",
		Timestamp:        now,
		Model:            "quick-opus-5.5",
		AccountID:        "acc-1",
		Stream:           true,
		ToolCalls:        2,
		Status:           "ok",
		HTTPStatus:       200,
		LatencyMs:        1200,
		InputTokens:      1000,
		CacheReadTokens:  67000,
		CacheWriteTokens: 2000,
		OutputTokens:     250,
		CostUSD:          0.0125,
	})
	m.Record(RequestRecord{
		ID:         "req-2",
		Timestamp:  now,
		Model:      "quick-sonnet-5.5",
		AccountID:  "acc-1",
		Status:     "rate_limit_exceeded",
		HTTPStatus: 429,
		LatencyMs:  200,
	})
	m.EndTurn()

	snap := m.Snapshot()
	if snap.ActiveTurns != 0 {
		t.Fatalf("expected active_turns=0, got %d", snap.ActiveTurns)
	}
	if snap.Totals.Requests != 2 || snap.Totals.Success != 1 || snap.Totals.Errors != 1 || snap.Totals.RateLimited != 1 {
		t.Fatalf("unexpected totals: %+v", snap.Totals)
	}
	if snap.Totals.CacheReadTokens != 67000 || snap.Totals.CacheHitRatePercent < 95 || snap.Totals.AvgLatencyMs != 700 {
		t.Fatalf("unexpected token/cache/latency totals: %+v", snap.Totals)
	}
	if len(snap.ByModel) != 2 || len(snap.ByAccount) != 1 || len(snap.Hourly) != 24 {
		t.Fatalf("unexpected breakdown lengths: models=%d accounts=%d hourly=%d", len(snap.ByModel), len(snap.ByAccount), len(snap.Hourly))
	}
	if snap.Hourly[23].Requests != 2 || snap.Hourly[23].Errors != 1 {
		t.Fatalf("expected current hour bucket to hold 2 reqs / 1 err, got %+v", snap.Hourly[23])
	}
	if len(snap.Recent) != 2 || snap.Recent[0].ID != "req-2" || snap.Recent[1].ID != "req-1" {
		t.Fatalf("expected recent newest-first order, got %+v", snap.Recent)
	}

	m.Reset()
	after := m.Snapshot()
	if after.Totals.Requests != 0 || len(after.ByModel) != 0 || len(after.Recent) != 0 {
		t.Fatalf("expected empty snapshot after reset, got %+v", after)
	}
}
