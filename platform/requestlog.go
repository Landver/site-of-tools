package platform

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// requestLogTTL: the corpus is recent-traffic observability, not an archive, so it self-prunes.
const requestLogTTL = 30 * 24 * time.Hour

// requestLogBuffer: a Mongo stall drops rows rather than blocking requests; fine for a traffic log.
const requestLogBuffer = 1024

// RequestEntry keeps the client IP on purpose (DEPLOYMENT §4); Cookie and Authorization are never captured.
type RequestEntry struct {
	Method    string    `bson:"method"`
	Host      string    `bson:"host"`
	URI       string    `bson:"uri"`
	Status    int       `bson:"status"`
	RemoteIP  string    `bson:"remote_ip"`
	UserAgent string    `bson:"user_agent,omitempty"`
	LatencyMS int64     `bson:"latency_ms"`
	BytesOut  int64     `bson:"bytes_out"`
	CreatedAt time.Time `bson:"created_at"`
}

// RequestLog writes to Mongo off the request path, dropping overflow; a nil *RequestLog is a no-op store.
type RequestLog struct {
	coll *mongo.Collection
	ch   chan RequestEntry
	done chan struct{}
	// mu guards ch: Close can run while echo finishes in-flight requests, and a send on a closed channel
	// panics (select's default covers a full channel, not a closed one). Send under RLock, close under Lock.
	mu     sync.RWMutex
	closed bool
}

// NewRequestLog returns nil for a nil db; a failed TTL index only forfeits auto-expiry, so it's ignored.
func NewRequestLog(ctx context.Context, db *mongo.Database) *RequestLog {
	if db == nil {
		return nil
	}
	coll := db.Collection("request_logs")
	_ = EnsureTTLIndex(ctx, coll, "created_at", requestLogTTL)
	rl := &RequestLog{
		coll: coll,
		ch:   make(chan RequestEntry, requestLogBuffer),
		done: make(chan struct{}),
	}
	go rl.run()
	return rl
}

// Record never delays the caller: a disabled store or a full buffer drops the entry.
func (rl *RequestLog) Record(e RequestEntry) {
	if rl == nil {
		return
	}
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	if rl.closed {
		return // shutting down; a late entry is not worth a panic
	}
	select {
	case rl.ch <- e:
	default:
	}
}

// run gives each insert its own timeout, so one slow write can't wedge the writer.
func (rl *RequestLog) run() {
	defer close(rl.done)
	for e := range rl.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = rl.coll.InsertOne(ctx, e)
		cancel()
	}
}

// Close waits, bounded by ctx, for the queue to drain, so shutdown keeps buffered entries. Nil-safe.
func (rl *RequestLog) Close(ctx context.Context) error {
	if rl == nil {
		return nil
	}
	// Flag and close under one write lock, so no reader sees closed == false and then sends.
	rl.mu.Lock()
	if rl.closed {
		rl.mu.Unlock()
		return nil
	}
	rl.closed = true
	close(rl.ch)
	rl.mu.Unlock()

	select {
	case <-rl.done:
	case <-ctx.Done():
	}
	return nil
}

// ShouldRecord skips static assets and /mcp, whose messages mcptools records itself.
func ShouldRecord(path string) bool {
	return !strings.HasPrefix(path, "/static/") && path != "/mcp" && !strings.HasPrefix(path, "/mcp/")
}
