package dnstools

import (
	"sync"
	"time"
)

// TTL clamp: a 1s TTL mustn't defeat the cache, nor a 24h NS record hide a change for a day.
const (
	cacheMinTTL = 5 * time.Second
	cacheMaxTTL = 5 * time.Minute
	// Negative answers live briefly: people re-query right after fixing the record.
	cacheNegTTL = 30 * time.Second
	// A public endpoint sees unbounded distinct names, so the map needs a ceiling.
	cacheMaxEntries = 4096
	// Per-entry cap: with the key ceiling it bounds memory (~64 MB) against inflated TCP answers.
	cacheMaxCost = 16 << 10
	// Flat per-record charge for the string headers each Record carries.
	cacheRecordCost = 128
)

// cache: in-process answer cache; deliberately not Mongo, so no answer outlives a deploy.
type cache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

type cacheEntry struct {
	result  Result
	err     error
	stored  time.Time // lets a hit count its TTLs down by how long it sat here
	expires time.Time
}

func newCache() *cache { return &cache{m: make(map[string]cacheEntry)} }

func (c *cache) get(key string, now time.Time) (cacheEntry, bool) {
	if c == nil {
		return cacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.After(e.expires) {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *cache) put(key string, e cacheEntry, now time.Time) {
	if c == nil {
		return
	}
	d := lifetime(e)
	if d <= 0 {
		return // the zone marked it uncacheable
	}
	if answerCost(e.result) > cacheMaxCost {
		return
	}
	e.stored, e.expires = now, now.Add(d)

	c.mu.Lock()
	defer c.mu.Unlock()
	// Full: drop expired, then arbitrary live entries; all expire within minutes, so no LRU.
	if len(c.m) >= cacheMaxEntries {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		// Free a batch rather than one slot, so the scan doesn't run on every put.
		const evictTo = cacheMaxEntries - cacheMaxEntries/8
		for k := range c.m {
			if len(c.m) <= evictTo {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[key] = e
}

// lifetime: the answer's shortest TTL, clamped, or cacheNegTTL when it has no records.
func lifetime(e cacheEntry) time.Duration {
	if e.err != nil || len(e.result.Records) == 0 {
		return cacheNegTTL
	}
	ttl := e.result.Records[0].TTL
	for _, r := range e.result.Records[1:] {
		ttl = min(ttl, r.TTL)
	}
	// TTL 0 means uncacheable; the floor would otherwise stretch it to cacheMinTTL.
	if ttl == 0 {
		return 0
	}
	return min(max(time.Duration(ttl)*time.Second, cacheMinTTL), cacheMaxTTL)
}

// answerCost: a rough memory proxy, enough to tell an ordinary answer from an inflated one.
func answerCost(r Result) int {
	n := 0
	for _, rec := range r.Records {
		n += cacheRecordCost + len(rec.Value) + len(rec.Label) + len(rec.Owner)
		for _, d := range rec.Detail {
			n += len(d.Name) + len(d.Value)
		}
	}
	return n
}
