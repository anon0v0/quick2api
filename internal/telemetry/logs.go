package telemetry

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single sanitized runtime log line captured in memory.
type LogEntry struct {
	Seq     uint64 `json:"seq"`
	Time    string `json:"time"`
	Level   string `json:"level"` // "info", "warn", "error"
	Tag     string `json:"tag"`
	Message string `json:"message"`
}

// LogQuery specifies optional filters for reading buffered logs.
type LogQuery struct {
	Since  uint64
	Level  string
	Tag    string
	Search string
	Limit  int
}

// LogPage is the response payload returned by GET /admin/logs.
type LogPage struct {
	Entries       []LogEntry `json:"entries"`
	LatestSeq     uint64     `json:"latest_seq"`
	TotalBuffered int        `json:"total_buffered"`
	Tags          []string   `json:"tags"`
}

var (
	stdLogPrefixRe = regexp.MustCompile(`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+`)
	tagPrefixRe    = regexp.MustCompile(`^\[([a-zA-Z0-9._-]+)\]\s*`)
	bearerRe       = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	awsTokenRe     = regexp.MustCompile(`\b(aoa_|aor_)[A-Za-z0-9._~+/=-]{8,}`)
	proxyCredRe    = regexp.MustCompile(`((?:https?|socks5h?)://)([^/\s:@]+):([^/\s@]+)@`)
)

// SanitizeLogLine redacts tokens and embedded proxy credentials before buffering.
func SanitizeLogLine(s string) string {
	s = bearerRe.ReplaceAllString(s, "Bearer [REDACTED]")
	s = awsTokenRe.ReplaceAllString(s, "${1}[REDACTED]")
	s = proxyCredRe.ReplaceAllString(s, "${1}[REDACTED]@")
	return s
}

// LogBuffer is a thread-safe ring buffer implementing io.Writer for Go's standard logger.
type LogBuffer struct {
	mu      sync.RWMutex
	cap     int
	entries []LogEntry
	nextSeq uint64
	pending bytes.Buffer
}

// NewLogBuffer creates a ring buffer retaining up to capacity log lines.
func NewLogBuffer(capacity int) *LogBuffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &LogBuffer{
		cap:     capacity,
		entries: make([]LogEntry, 0, min(capacity, 256)),
	}
}

// Write implements io.Writer, splitting incoming bytes into lines without failing callers.
func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	_, _ = b.pending.Write(p)
	for {
		raw := b.pending.Bytes()
		idx := bytes.IndexByte(raw, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(string(raw[:idx]), "\r")
		b.pending.Next(idx + 1)
		if strings.TrimSpace(line) != "" {
			b.appendLocked(line)
		}
	}
	// Guard against unbounded partial lines without newlines.
	if b.pending.Len() > 16384 {
		line := strings.TrimSpace(b.pending.String())
		b.pending.Reset()
		if line != "" {
			b.appendLocked(line)
		}
	}
	return len(p), nil
}

func (b *LogBuffer) appendLocked(raw string) {
	line := SanitizeLogLine(strings.TrimSpace(raw))
	line = stdLogPrefixRe.ReplaceAllString(line, "")

	tag := "system"
	msg := line
	if m := tagPrefixRe.FindStringSubmatchIndex(line); len(m) == 4 {
		tag = strings.ToLower(line[m[2]:m[3]])
		msg = strings.TrimSpace(line[m[1]:])
	}
	level := classifyLogLevel(msg)

	b.nextSeq++
	entry := LogEntry{
		Seq:     b.nextSeq,
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   level,
		Tag:     tag,
		Message: msg,
	}
	if len(b.entries) >= b.cap {
		copy(b.entries, b.entries[1:])
		b.entries[len(b.entries)-1] = entry
	} else {
		b.entries = append(b.entries, entry)
	}
}

func classifyLogLevel(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "error"),
		strings.Contains(low, "failed"),
		strings.Contains(low, "fatal"),
		strings.Contains(low, "panic"):
		return "error"
	case strings.Contains(low, "warn"),
		strings.Contains(low, "rate_limited"),
		strings.Contains(low, "usage_blocked"),
		strings.Contains(low, "cooldown"),
		strings.Contains(low, "rotating away"),
		strings.Contains(low, "stale ws"),
		strings.Contains(low, "throttl"):
		return "warn"
	default:
		return "info"
	}
}

// Query returns filtered log entries in chronological order (oldest -> newest).
func (b *LogBuffer) Query(q LogQuery) LogPage {
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	wantLevel := strings.ToLower(strings.TrimSpace(q.Level))
	wantTag := strings.ToLower(strings.TrimSpace(q.Tag))
	wantSearch := strings.ToLower(strings.TrimSpace(q.Search))

	b.mu.RLock()
	defer b.mu.RUnlock()

	tagSet := make(map[string]struct{})
	matched := make([]LogEntry, 0, min(len(b.entries), limit))
	for _, e := range b.entries {
		tagSet[e.Tag] = struct{}{}
		if q.Since > 0 && e.Seq <= q.Since {
			continue
		}
		if wantLevel != "" && wantLevel != "all" && e.Level != wantLevel {
			continue
		}
		if wantTag != "" && wantTag != "all" && e.Tag != wantTag {
			continue
		}
		if wantSearch != "" &&
			!strings.Contains(strings.ToLower(e.Message), wantSearch) &&
			!strings.Contains(strings.ToLower(e.Tag), wantSearch) {
			continue
		}
		matched = append(matched, e)
	}
	if len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	return LogPage{
		Entries:       matched,
		LatestSeq:     b.nextSeq,
		TotalBuffered: len(b.entries),
		Tags:          tags,
	}
}

// Clear drops all currently buffered log entries while keeping sequence numbers monotonic.
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	b.entries = b.entries[:0]
	b.mu.Unlock()
}
