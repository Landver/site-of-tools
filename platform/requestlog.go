package platform

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// requestLogTTL bounds how long request-log documents live. The corpus is for
// recent-traffic observability, not a permanent archive, so it self-prunes via a
// TTL index — no manual cleanup, no unbounded growth.
const requestLogTTL = 30 * 24 * time.Hour

// requestLogBuffer caps how many pending writes we hold before dropping. One
// goroutine drains sequentially; if Mongo stalls, we drop rather than block a
// request or grow memory without bound. This is a personal site's traffic log,
// not an audit trail — losing a few rows under pressure is the right trade.
const requestLogBuffer = 1024

// RequestEntry is one recorded request: the fields that make a useful traffic
// corpus and nothing more. The client IP is intentional (DEPLOYMENT §4); Cookie
// and Authorization are never captured (mirroring the ConnInfo inspector).
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

// RequestLog persists a rolling corpus of requests to MongoDB, off the request
// path. It is the first shared, engine-level Mongo consumer; feature repositories
// (e.g. iptools.History) follow the same nil-safe shape — a nil *RequestLog is a
// valid "disabled" store whose methods no-op, so a Mongo-less boot needs no
// special-casing anywhere.
//
// Writes are asynchronous: Record does a non-blocking send to a buffered channel
// that a single background goroutine drains, so a slow or absent database never
// adds latency to (or fails) a request. Overflow is dropped, by design.
type RequestLog struct {
	coll *mongo.Collection
	ch   chan RequestEntry
	done chan struct{}
}

// NewRequestLog builds the store from an application database handle and starts
// its writer. A nil db (Mongo disabled) returns nil — a valid no-op store. The
// TTL index is best-effort: a failure only forfeits auto-expiry, never writes, so
// it is intentionally non-fatal and unlogged here.
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

// Record queues one entry. Nil-safe and non-blocking: if the store is disabled or
// the buffer is full, the entry is dropped rather than delaying the caller.
func (rl *RequestLog) Record(e RequestEntry) {
	if rl == nil {
		return
	}
	select {
	case rl.ch <- e:
	default: // buffer full: drop, never block the request path
	}
}

// run drains the queue, inserting each entry with its own bounded context so one
// slow write can't wedge the writer.
func (rl *RequestLog) run() {
	defer close(rl.done)
	for e := range rl.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = rl.coll.InsertOne(ctx, e)
		cancel()
	}
}

// Close stops the writer and waits (bounded by ctx) for the queue to drain, so a
// graceful shutdown doesn't lose buffered entries. Nil-safe. It must be called
// only after the HTTP server has stopped accepting requests (no concurrent
// Record), which is the natural ordering in main: the defer runs after Start
// returns.
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
// are skipped: high-volume and carrying no analytic value the page requests don't
// already. Exported so the one caller (the request-logger middleware) reads clearly.
func ShouldRecord(path string) bool {
	return !strings.HasPrefix(path, "/static/")
}
