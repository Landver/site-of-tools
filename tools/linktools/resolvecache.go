package linktools

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mopts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// /s/:code is the one public route touching the shared Mongo, hence a negative cache and batched hits.
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

// resolveCache is a bounded TTL cache before LinkStore.ByCode: the key space is attacker-chosen.
type resolveCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	// gen increments on every invalidate; readers capture it before the DB round trip so a stale negative
	// can't land after a create's invalidate and 404 the new alias for a whole TTL.
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

// put stores a hit or a miss; a nil link is a negative entry, the half that defends the database.
func (c *resolveCache) put(code string, l *Link) { c.putIfFresh(code, l, c.generation()) }

// putIfFresh stores an entry only if nothing was invalidated since gen was taken (see resolveCache.gen).
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
		// Drop expired entries first; a wipe would evict every real link along with a scanner's negatives.
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

// invalidate drops a code so a create or revoke shows at once; revocation must not wait on a cache.
func (c *resolveCache) invalidate(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.entries, code)
}

// hitBatcher batches hits into bulk writes and drops under pressure: a lost count beats a waiting redirect.
type hitBatcher struct {
	coll *mongo.Collection
	ch   chan string
	done chan struct{}
	once sync.Once
	// mu: Close can run while redirects are in flight, and a send on a closed channel panics (select's
	// default only covers a full one); sends hold RLock and close holds Lock, so they never overlap.
	mu     sync.RWMutex
	closed bool
}

func newHitBatcher(coll *mongo.Collection) *hitBatcher {
	b := &hitBatcher{coll: coll, ch: make(chan string, hitQueueSize), done: make(chan struct{})}
	go b.run()
	return b
}

// record never blocks (a full queue drops the count) and is safe during and after Close.
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

// flush writes one bulk update per code seen since the last tick.
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
	// Unordered: independent counters, so one missing document must not stop the rest.
	_, _ = b.coll.BulkWrite(ctx, models, mopts.BulkWrite().SetOrdered(false))
}

// Close drains the queue; main calls it on shutdown alongside the request log's Close.
func (b *hitBatcher) Close() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		// Flag and close under the write lock, so no sender can pass the closed check and then panic.
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
