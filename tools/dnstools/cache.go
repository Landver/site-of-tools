package dnstools

import (
	"sync"
	"time"
)

// Cache defaults. Lower bound stops a 1-second TTL from making the cache
// pointless; upper bound stops a 24-hour NS record from pinning a stale answer
// for a day on a tool people use to watch changes land.
const (
	cacheMinTTL = 5 * time.Second
	cacheMaxTTL = 5 * time.Minute
	// Negative answers (NODATA / NXDOMAIN / SERVFAIL) get a short fixed life:
	// the usual reason someone re-queries is that they just fixed the record.
	cacheNegTTL = 30 * time.Second
	// Bound on distinct keys held. A public endpoint sees unbounded distinct
	// names, so the map needs a ceiling or it is a memory leak with extra steps.
	cacheMaxEntries = 4096
	// A key ceiling alone bounds nothing that matters: one TCP-fallback answer
	// from a zone its owner controls can carry tens of KB, so 4096 fat slots is
	// hundreds of MB. Capping what a single entry may hold is what turns the
	// two into a real memory bound (~64 MB). An answer this big is also the one
	// least worth holding — it is nobody's "is my change live yet" question.
	cacheMaxCost = 16 << 10
	// Flat per-record charge, because a thousand one-byte records cost far more
	// than their bytes: each carries a Record's worth of string headers.
	cacheRecordCost = 128
)

// cache: in-process answer cache keyed on the exact question asked.
//
// This is the highest-leverage abuse control available here
// (reports/abuse-ratelimits-and-ethics.md): one visitor refreshing a page, or
// several asking about the same popular domain, costs the upstream resolver
// one query instead of one per request per type.
//
// Deliberately not Mongo-backed: a cache that outlives the process would make
// "is my change live yet" answers stale across deploys, which is the one
// question this tool exists to answer.
type cache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

type cacheEntry struct {
	result Result
	err    error
	// stored is when the answer was fetched, so a hit can count its TTLs down
	// by how long it has been sitting here. Replaying the TTL captured at fetch
	// is the wrong number on a tool people use to watch a change land.
	stored  time.Time
	expires time.Time
}

func newCache() *cache { return &cache{m: make(map[string]cacheEntry)} }

// get returns a live entry, or ok=false when absent or expired.
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

// put stores an answer for as long as the records themselves say it is good
// for. An answer with no records is negative-cached briefly instead.
func (c *cache) put(key string, e cacheEntry, now time.Time) {
	if c == nil {
		return
	}
	d := lifetime(e)
	if d <= 0 {
		// The zone said this answer is uncacheable. Storing it would also cost
		// a slot out of the ceiling below for something we must not serve.
		return
	}
	if answerCost(e.result) > cacheMaxCost {
		return
	}
	e.stored, e.expires = now, now.Add(d)

	c.mu.Lock()
	defer c.mu.Unlock()
	// Crude but adequate ceiling: once full, drop expired entries, and if that
	// frees too little, evict live ones until there is headroom. Map order is
	// randomised, so those are arbitrary rather than the popular keys a wipe
	// would take with it. Beats an LRU's bookkeeping for a cache whose entries
	// all expire within minutes anyway.
	if len(c.m) >= cacheMaxEntries {
		for k, v := range c.m {
			if now.After(v.expires) {
				delete(c.m, k)
			}
		}
		// Freeing a batch rather than one slot keeps the scan above off the
		// next few thousand puts.
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

// lifetime is how long an answer stays usable: the shortest TTL in it, clamped,
// or the fixed negative TTL when there is nothing to take a TTL from.
func lifetime(e cacheEntry) time.Duration {
	if e.err != nil || len(e.result.Records) == 0 {
		return cacheNegTTL
	}
	min := e.result.Records[0].TTL
	for _, r := range e.result.Records[1:] {
		if r.TTL < min {
			min = r.TTL
		}
	}
	// The floor is the only clamp that lengthens a lifetime, so applying it to
	// TTL 0 would hold and re-serve an answer the zone marked uncacheable.
	if min == 0 {
		return 0
	}
	d := time.Duration(min) * time.Second
	return clamp(d, cacheMinTTL, cacheMaxTTL)
}

// answerCost estimates what holding an answer costs in memory. A proxy, not a
// measurement: it only has to separate the ordinary answer from the one a zone
// owner inflated on purpose.
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

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
