package linktools

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mopts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Load controls for the redirect path (docs/04-short-links.md §7).
//
// /s/:code is deliberately not rate-limited per IP: a redirect has to be fast
// and public. That makes it the one unauthenticated route that touches the
// SHARED Mongo server — the same one backing request_logs, iptools' lookup
// history and the botcheck corpus — so an unbounded one is a way to degrade
// every other subdomain on the box from anywhere.
//
// Two bounds, and they cover the two shapes of abuse:
//
//   - A cache, INCLUDING negative entries. Hammering /s/aaaaaaa with a code
//     that does not exist otherwise costs a FindOne per request; with a
//     negative entry it costs one per minute.
//   - A batched hit counter. The previous version span one goroutine per hit,
//     each holding a 5s context and a pooled connection, so a burst on a VALID
//     code was a goroutine- and connection-exhaustion primitive. Now hits
//     coalesce in memory and a single writer flushes them.
const (
	resolveCacheTTL    = 60 * time.Second
	resolveNegativeTTL = 60 * time.Second
	resolveCacheMax    = 4096
	hitFlushInterval   = 2 * time.Second
	hitQueueSize       = 4096
)

type cacheEntry struct {
	link    *Link // nil means "known absent"
	expires time.Time
}

// resolveCache is a small bounded TTL cache in front of LinkStore.ByCode.
//
// Bounded rather than unbounded because the key space is attacker-chosen: a
// scanner walking random codes would otherwise turn the negative cache into a
// memory-growth path. When it is full it is cleared wholesale, which costs a
// brief miss storm and cannot leak.
type resolveCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	// gen increments on every invalidate. A reader captures it BEFORE its
	// database round trip and passes it back to putIfFresh, so a negative
	// result computed before a create cannot land after that create's
	// invalidate and 404 a brand-new alias for the rest of the TTL.
	gen uint64
}

func newResolveCache() *resolveCache {
	return &resolveCache{entries: make(map[string]cacheEntry)}
}

// generation reports the current invalidation counter, for putIfFresh.
func (c *resolveCache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

func (c *resolveCache) get(code string) (*Link, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[code]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.link, true
}

// put stores a hit or a miss. A nil link is a negative entry, which is the half
// that actually defends the database.
func (c *resolveCache) put(code string, l *Link) { c.putIfFresh(code, l, c.generation()) }

// putIfFresh stores an entry only if no invalidation happened since gen was
// taken. See the comment on resolveCache.gen.
func (c *resolveCache) putIfFresh(code string, l *Link, gen uint64) {
	ttl := resolveCacheTTL
	if l == nil {
		ttl = resolveNegativeTTL
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return // something was created or revoked under us; do not cache a stale answer
	}
	if len(c.entries) >= resolveCacheMax {
		// Drop what has already expired before resorting to wiping live
		// entries. A scanner walking random codes fills this with negatives,
		// and clearing wholesale would evict every real link along with them.
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= resolveCacheMax {
			clear(c.entries)
		}
	}
	c.entries[code] = cacheEntry{link: l, expires: now.Add(ttl)}
}

// invalidate drops a code, so a create or revoke is visible immediately rather
// than up to a TTL later. Revocation especially must not wait on a cache.
func (c *resolveCache) invalidate(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.entries, code)
}

// hitBatcher coalesces hit counts in memory and flushes them with one bulk
// write, in the shape platform.RequestLog already uses for the same reason: a
// bounded queue drained by a single goroutine, dropping under pressure rather
// than growing without limit or blocking a request.
//
// A lost count is acceptable — this is a hit counter on a personal link
// shortener, not an audit trail. A redirect that waits on a write is not.
type hitBatcher struct {
	coll *mongo.Collection
	ch   chan string
	done chan struct{}
	once sync.Once
	// mu guards ch against the one race that actually bites here: Close runs
	// from main's shutdown path while redirects can still be in flight, and a
	// send on a closed channel PANICS. The select's default case does not save
	// it — default only covers a full channel, not a closed one. Sending under
	// RLock and closing under Lock makes the two mutually exclusive, so a send
	// can never be in progress when the close happens.
	mu     sync.RWMutex
	closed bool
}

func newHitBatcher(coll *mongo.Collection) *hitBatcher {
	b := &hitBatcher{coll: coll, ch: make(chan string, hitQueueSize), done: make(chan struct{})}
	go b.run()
	return b
}

// record is non-blocking: a full queue drops the count, by design. It is also
// safe to call during and after Close — see the note on mu.
func (b *hitBatcher) record(code string) {
	if b == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	select {
	case b.ch <- code:
	default:
	}
}

func (b *hitBatcher) run() {
	defer close(b.done)
	ticker := time.NewTicker(hitFlushInterval)
	defer ticker.Stop()
	pending := map[string]int64{}
	for {
		select {
		case code, ok := <-b.ch:
			if !ok {
				b.flush(pending)
				return
			}
			pending[code]++
		case <-ticker.C:
			b.flush(pending)
			pending = map[string]int64{}
		}
	}
}

// flush writes one bulk update for every code seen since the last tick, so a
// thousand hits on one code cost one write rather than a thousand.
func (b *hitBatcher) flush(pending map[string]int64) {
	if len(pending) == 0 {
		return
	}
	models := make([]mongo.WriteModel, 0, len(pending))
	now := time.Now()
	for code, n := range pending {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.D{{Key: "code", Value: code}}).
			SetUpdate(bson.D{
				{Key: "$inc", Value: bson.D{{Key: "hits", Value: n}}},
				{Key: "$set", Value: bson.D{{Key: "last_hit_at", Value: now}}},
			}))
	}
	ctx, cancel := context.WithTimeout(context.Background(), hitWriteTimeout)
	defer cancel()
	// Unordered: these are independent counters and one missing document must
	// not stop the rest.
	_, _ = b.coll.BulkWrite(ctx, models, mopts.BulkWrite().SetOrdered(false))
}

// Close drains the queue. Called from main's shutdown path alongside the
// request log's own Close.
func (b *hitBatcher) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		// Flag and close together under the write lock, so no reader can
		// observe closed == false and then send into an already-closed channel.
		b.mu.Lock()
		b.closed = true
		close(b.ch)
		b.mu.Unlock()
	})
	select {
	case <-b.done:
	case <-time.After(2 * time.Second):
	}
}
