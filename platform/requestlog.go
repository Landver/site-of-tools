package platform

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// requestLogTTL bounds doc lifetime. Corpus = recent-traffic observability, not
// permanent archive → self-prunes via TTL index, no manual cleanup, no unbounded
// growth.
const requestLogTTL = 30 * 24 * time.Hour

// requestLogBuffer caps pending writes before drop. One goroutine drains
// sequentially → Mongo stall drops rather than blocks request or grows memory
// unbounded. Personal site's traffic log, not audit trail — losing rows under
// pressure = right trade.
const requestLogBuffer = 1024

// RequestEntry is one recorded request: only fields that make useful traffic
// corpus, nothing more. Client IP intentional (DEPLOYMENT §4); Cookie +
// Authorization never captured (mirrors ConnInfo inspector).
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

// RequestLog persists a rolling corpus of requests to MongoDB, off request path.
// First shared, engine-level Mongo consumer; feature repositories (e.g.
// iptools.History) follow same nil-safe shape — nil *RequestLog = valid
// "disabled" store, methods no-op → Mongo-less boot needs no special-casing
// anywhere.
//
// Writes async: Record does non-blocking send to buffered channel, single
// background goroutine drains → slow/absent database never adds latency to (or
// fails) a request. Overflow dropped, by design.
type RequestLog struct {
	coll *mongo.Collection
	ch   chan RequestEntry
	done chan struct{}
}

// NewRequestLog builds store from app database handle, starts its writer. Nil db
// (Mongo disabled) → returns nil, a valid no-op store. TTL index best-effort:
// failure only forfeits auto-expiry, never writes → intentionally non-fatal,
// unlogged here.
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

// Record queues one entry. Nil-safe + non-blocking: store disabled or buffer
// full → entry dropped, never delays caller.
func (rl *RequestLog) Record(e RequestEntry) {
	if rl == nil {
		return
	}
	select {
	case rl.ch <- e:
	default: // buffer full: drop, never block request path
	}
}

// run drains queue, inserts each entry w/ own bounded context → one slow write
// can't wedge writer.
func (rl *RequestLog) run() {
	defer close(rl.done)
	for e := range rl.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = rl.coll.InsertOne(ctx, e)
		cancel()
	}
}

// Close stops writer, waits (bounded by ctx) for queue to drain → graceful
// shutdown doesn't lose buffered entries. Nil-safe. Must be called only after
// HTTP server stopped accepting requests (no concurrent Record) — natural
// ordering in main: defer runs after Start returns.
func (rl *RequestLog) Close(ctx context.Context) error {
	if rl == nil {
		return nil
	}
	close(rl.ch)
	select {
	case <-rl.done:
	case <-ctx.Done():
	}
	return nil
}

// ShouldRecord reports whether a request path is worth persisting. Static assets
// skipped: high-volume, no analytic value beyond page requests. Exported so the
// one caller (request-logger middleware) reads clearly.
func ShouldRecord(path string) bool {
	return !strings.HasPrefix(path, "/static/")
}
