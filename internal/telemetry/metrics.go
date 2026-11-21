package telemetry

import (
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestRecord stores privacy-safe metadata for one completed /v1/chat/completions request.
type RequestRecord struct {
	ID               string  `json:"id"`
	Timestamp        int64   `json:"timestamp"`
	Model            string  `json:"model"`
	AccountID        string  `json:"account_id,omitempty"`
	Stream           bool    `json:"stream"`
	ToolCalls        int     `json:"tool_calls,omitempty"`
	Status           string  `json:"status"` // "ok" or error code
	HTTPStatus       int     `json:"http_status"`
	LatencyMs        int64   `json:"latency_ms"`
	InputTokens      int     `json:"input_tokens"`
	OutputTokens     int     `json:"output_tokens"`
	CacheReadTokens  int     `json:"cache_read_tokens"`
	CacheWriteTokens int     `json:"cache_write_tokens"`
	TotalTokens      int     `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd,omitempty"`
}

// TotalsSnapshot summarizes aggregate request and token activity since startup or last reset.
type TotalsSnapshot struct {
	Requests            int64   `json:"requests"`
	Success             int64   `json:"success"`
	Errors              int64   `json:"errors"`
	RateLimited         int64   `json:"rate_limited"`
	StreamRequests      int64   `json:"stream_requests"`
	ToolCallRequests    int64   `json:"tool_call_requests"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheWriteTokens    int64   `json:"cache_write_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	CacheHitRatePercent float64 `json:"cache_hit_rate_percent"`
	SuccessRatePercent  float64 `json:"success_rate_percent"`
	AvgLatencyMs        int64   `json:"avg_latency_ms"`
	CostUSD             float64 `json:"cost_usd"`
}

// ModelStats summarizes usage metrics for a single model ID.
type ModelStats struct {
	Model               string  `json:"model"`
	Requests            int64   `json:"requests"`
	Success             int64   `json:"success"`
	Errors              int64   `json:"errors"`
	StreamRequests      int64   `json:"stream_requests"`
	ToolCallRequests    int64   `json:"tool_call_requests"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheWriteTokens    int64   `json:"cache_write_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	CacheHitRatePercent float64 `json:"cache_hit_rate_percent"`
	AvgLatencyMs        int64   `json:"avg_latency_ms"`
	CostUSD             float64 `json:"cost_usd"`
	LastUsedAt          int64   `json:"last_used_at"`
}

// AccountUsageStats summarizes request and token activity handled by each pool account.
type AccountUsageStats struct {
	AccountID       string `json:"account_id"`
	Requests        int64  `json:"requests"`
	Success         int64  `json:"success"`
	Errors          int64  `json:"errors"`
	RateLimited     int64  `json:"rate_limited"`
	InputTokens     int64  `json:"input_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
	CacheReadTokens int64  `json:"cache_read_tokens"`
	TotalTokens     int64  `json:"total_tokens"`
	AvgLatencyMs    int64  `json:"avg_latency_ms"`
	LastUsedAt      int64  `json:"last_used_at"`
}

// HourlyBucket holds request and token aggregates for one clock hour.
type HourlyBucket struct {
	HourUnix        int64  `json:"hour_unix"`
	Label           string `json:"label"`
	Requests        int64  `json:"requests"`
	Errors          int64  `json:"errors"`
	InputTokens     int64  `json:"input_tokens"`
	CacheReadTokens int64  `json:"cache_read_tokens"`
	OutputTokens    int64  `json:"output_tokens"`
}

// MetricsSnapshot is the JSON payload returned by GET /admin/metrics.
type MetricsSnapshot struct {
	StartedAt   int64               `json:"started_at"`
	UptimeSec   int64               `json:"uptime_sec"`
	ActiveTurns int64               `json:"active_turns"`
	Totals      TotalsSnapshot      `json:"totals"`
	ByModel     []ModelStats        `json:"by_model"`
	ByAccount   []AccountUsageStats `json:"by_account"`
	Hourly      []HourlyBucket      `json:"hourly"`
	Recent      []RequestRecord     `json:"recent"`
}

type modelAgg struct {
	requests         int64
	success          int64
	errors           int64
	streamRequests   int64
	toolCallRequests int64
	inputTokens      int64
	outputTokens     int64
	cacheReadTokens  int64
	cacheWriteTokens int64
	totalLatencyMs   int64
	costUSD          float64
	lastUsedAt       int64
}

type accountAgg struct {
	requests        int64
	success         int64
	errors          int64
	rateLimited     int64
	inputTokens     int64
	outputTokens    int64
	cacheReadTokens int64
	totalLatencyMs  int64
	lastUsedAt      int64
}

type hourAgg struct {
	hourUnix        int64
	requests        int64
	errors          int64
	inputTokens     int64
	cacheReadTokens int64
	outputTokens    int64
}

// Metrics collects in-memory gateway, model, account, and hourly traffic telemetry.
type Metrics struct {
	startedAt   time.Time
	activeTurns atomic.Int64

	mu           sync.RWMutex
	total        modelAgg
	totalRL      int64
	byModel      map[string]*modelAgg
	byAccount    map[string]*accountAgg
	hourly       map[int64]*hourAgg
	recent       []RequestRecord
	recentMaxCap int
}

// NewMetrics creates a new in-memory telemetry collector.
func NewMetrics() *Metrics {
	return &Metrics{
		startedAt:    time.Now(),
		byModel:      make(map[string]*modelAgg),
		byAccount:    make(map[string]*accountAgg),
		hourly:       make(map[int64]*hourAgg),
		recent:       make([]RequestRecord, 0, 50),
		recentMaxCap: 50,
	}
}

// StartTurn increments the active in-flight turn gauge.
func (m *Metrics) StartTurn() {
	m.activeTurns.Add(1)
}

// EndTurn decrements the active in-flight turn gauge.
func (m *Metrics) EndTurn() {
	if m.activeTurns.Add(-1) < 0 {
		m.activeTurns.Store(0)
	}
}

// Record stores one completed request's metrics across totals, model, account, hourly buckets, and recent feed.
func (m *Metrics) Record(rec RequestRecord) {
	now := time.Now()
	if rec.Timestamp == 0 {
		rec.Timestamp = now.Unix()
	}
	if rec.Model == "" {
		rec.Model = "unknown"
	}
	if rec.Status == "" {
		if rec.HTTPStatus >= 200 && rec.HTTPStatus < 300 {
			rec.Status = "ok"
		} else {
			rec.Status = "error"
		}
	}
	if rec.TotalTokens == 0 {
		rec.TotalTokens = rec.InputTokens + rec.CacheReadTokens + rec.CacheWriteTokens + rec.OutputTokens
	}
	if rec.LatencyMs < 0 {
		rec.LatencyMs = 0
	}

	isSuccess := rec.Status == "ok" && (rec.HTTPStatus == 0 || (rec.HTTPStatus >= 200 && rec.HTTPStatus < 300))
	isRL := rec.HTTPStatus == 429 || strings.Contains(strings.ToLower(rec.Status), "rate_limit")

	m.mu.Lock()
	defer m.mu.Unlock()

	applyModel := func(dst *modelAgg) {
		dst.requests++
		if isSuccess {
			dst.success++
		} else {
			dst.errors++
		}
		if rec.Stream {
			dst.streamRequests++
		}
		if rec.ToolCalls > 0 {
			dst.toolCallRequests++
		}
		dst.inputTokens += int64(rec.InputTokens)
		dst.outputTokens += int64(rec.OutputTokens)
		dst.cacheReadTokens += int64(rec.CacheReadTokens)
		dst.cacheWriteTokens += int64(rec.CacheWriteTokens)
		dst.totalLatencyMs += rec.LatencyMs
		dst.costUSD += rec.CostUSD
		if rec.Timestamp > dst.lastUsedAt {
			dst.lastUsedAt = rec.Timestamp
		}
	}

	applyModel(&m.total)
	if isRL {
		m.totalRL++
	}

	ma, ok := m.byModel[rec.Model]
	if !ok {
		ma = &modelAgg{}
		m.byModel[rec.Model] = ma
	}
	applyModel(ma)

	if rec.AccountID != "" {
		aa, ok := m.byAccount[rec.AccountID]
		if !ok {
			aa = &accountAgg{}
			m.byAccount[rec.AccountID] = aa
		}
		aa.requests++
		if isSuccess {
			aa.success++
		} else {
			aa.errors++
		}
		if isRL {
			aa.rateLimited++
		}
		aa.inputTokens += int64(rec.InputTokens)
		aa.outputTokens += int64(rec.OutputTokens)
		aa.cacheReadTokens += int64(rec.CacheReadTokens)
		aa.totalLatencyMs += rec.LatencyMs
		if rec.Timestamp > aa.lastUsedAt {
			aa.lastUsedAt = rec.Timestamp
		}
	}

	hourKey := time.Unix(rec.Timestamp, 0).Truncate(time.Hour).Unix()
	hb, ok := m.hourly[hourKey]
	if !ok {
		hb = &hourAgg{hourUnix: hourKey}
		m.hourly[hourKey] = hb
	}
	hb.requests++
	if !isSuccess {
		hb.errors++
	}
	hb.inputTokens += int64(rec.InputTokens)
	hb.cacheReadTokens += int64(rec.CacheReadTokens)
	hb.outputTokens += int64(rec.OutputTokens)

	// Prune hourly buckets older than 48h to keep memory strictly bounded.
	cutoff := now.Truncate(time.Hour).Add(-48 * time.Hour).Unix()
	for k := range m.hourly {
		if k < cutoff {
			delete(m.hourly, k)
		}
	}

	if len(m.recent) >= m.recentMaxCap {
		copy(m.recent, m.recent[1:])
		m.recent[len(m.recent)-1] = rec
	} else {
		m.recent = append(m.recent, rec)
	}
}

// Snapshot builds a consistent, sorted telemetry snapshot for /admin/metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	now := time.Now()

	m.mu.RLock()
	defer m.mu.RUnlock()

	totalPrompt := m.total.inputTokens + m.total.cacheReadTokens + m.total.cacheWriteTokens
	totals := TotalsSnapshot{
		Requests:            m.total.requests,
		Success:             m.total.success,
		Errors:              m.total.errors,
		RateLimited:         m.totalRL,
		StreamRequests:      m.total.streamRequests,
		ToolCallRequests:    m.total.toolCallRequests,
		InputTokens:         m.total.inputTokens,
		OutputTokens:        m.total.outputTokens,
		CacheReadTokens:     m.total.cacheReadTokens,
		CacheWriteTokens:    m.total.cacheWriteTokens,
		TotalTokens:         totalPrompt + m.total.outputTokens,
		CacheHitRatePercent: ratioPercent(m.total.cacheReadTokens, totalPrompt),
		SuccessRatePercent:  ratioPercent(m.total.success, m.total.requests),
		AvgLatencyMs:        safeAvg(m.total.totalLatencyMs, m.total.requests),
		CostUSD:             roundCost(m.total.costUSD),
	}

	models := make([]ModelStats, 0, len(m.byModel))
	for name, a := range m.byModel {
		promptToks := a.inputTokens + a.cacheReadTokens + a.cacheWriteTokens
		models = append(models, ModelStats{
			Model:               name,
			Requests:            a.requests,
			Success:             a.success,
			Errors:              a.errors,
			StreamRequests:      a.streamRequests,
			ToolCallRequests:    a.toolCallRequests,
			InputTokens:         a.inputTokens,
			OutputTokens:        a.outputTokens,
			CacheReadTokens:     a.cacheReadTokens,
			CacheWriteTokens:    a.cacheWriteTokens,
			TotalTokens:         promptToks + a.outputTokens,
			CacheHitRatePercent: ratioPercent(a.cacheReadTokens, promptToks),
			AvgLatencyMs:        safeAvg(a.totalLatencyMs, a.requests),
			CostUSD:             roundCost(a.costUSD),
			LastUsedAt:          a.lastUsedAt,
		})
	}
	sort.Slice(models, func(i, j int) bool {
		if models[i].Requests != models[j].Requests {
			return models[i].Requests > models[j].Requests
		}
		return models[i].Model < models[j].Model
	})

	accounts := make([]AccountUsageStats, 0, len(m.byAccount))
	for id, a := range m.byAccount {
		accounts = append(accounts, AccountUsageStats{
			AccountID:       id,
			Requests:        a.requests,
			Success:         a.success,
			Errors:          a.errors,
			RateLimited:     a.rateLimited,
			InputTokens:     a.inputTokens,
			OutputTokens:    a.outputTokens,
			CacheReadTokens: a.cacheReadTokens,
			TotalTokens:     a.inputTokens + a.cacheReadTokens + a.outputTokens,
			AvgLatencyMs:    safeAvg(a.totalLatencyMs, a.requests),
			LastUsedAt:      a.lastUsedAt,
		})
	}
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].Requests != accounts[j].Requests {
			return accounts[i].Requests > accounts[j].Requests
		}
		return accounts[i].AccountID < accounts[j].AccountID
	})

	curHour := now.Truncate(time.Hour)
	hourly := make([]HourlyBucket, 24)
	for i := 0; i < 24; i++ {
		t := curHour.Add(time.Duration(i-23) * time.Hour)
		k := t.Unix()
		b := HourlyBucket{
			HourUnix: k,
			Label:    t.Format("15:04"),
		}
		if agg, ok := m.hourly[k]; ok {
			b.Requests = agg.requests
			b.Errors = agg.errors
			b.InputTokens = agg.inputTokens
			b.CacheReadTokens = agg.cacheReadTokens
			b.OutputTokens = agg.outputTokens
		}
		hourly[i] = b
	}

	recent := make([]RequestRecord, len(m.recent))
	for i := range m.recent {
		recent[len(m.recent)-1-i] = m.recent[i]
	}

	return MetricsSnapshot{
		StartedAt:   m.startedAt.Unix(),
		UptimeSec:   int64(time.Since(m.startedAt).Seconds()),
		ActiveTurns: m.activeTurns.Load(),
		Totals:      totals,
		ByModel:     models,
		ByAccount:   accounts,
		Hourly:      hourly,
		Recent:      recent,
	}
}

// Reset clears accumulated statistics while keeping startup timestamp and active turn count intact.
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total = modelAgg{}
	m.totalRL = 0
	m.byModel = make(map[string]*modelAgg)
	m.byAccount = make(map[string]*accountAgg)
	m.hourly = make(map[int64]*hourAgg)
	m.recent = m.recent[:0]
}

func ratioPercent(num, den int64) float64 {
	if den <= 0 {
		return 0
	}
	return math.Round((float64(num)/float64(den))*1000) / 10
}

func safeAvg(sum, count int64) int64 {
	if count <= 0 {
		return 0
	}
	return sum / count
}

func roundCost(c float64) float64 {
	return math.Round(c*10000) / 10000
}
