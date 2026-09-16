package dnstools

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// The cache takes its clock as an argument, so every policy question below is
// answered without sleeping and without a network.

func TestCacheLifetimeClamps(t *testing.T) {
	t.Parallel()

	rec := func(ttls ...uint32) []Record {
		var out []Record
		for _, ttl := range ttls {
			out = append(out, Record{Type: "A", Value: "192.0.2.1", TTL: ttl})
		}
		return out
	}

	cases := []struct {
		name  string
		entry cacheEntry
		want  time.Duration
	}{
		{
			// A one-second TTL would make the cache pointless, so it is held
			// for the floor instead.
			name:  "a TTL under the floor is lifted to it",
			entry: cacheEntry{result: Result{Records: rec(1)}},
			want:  cacheMinTTL,
		},
		{
			name:  "a TTL inside the range is used as it stands",
			entry: cacheEntry{result: Result{Records: rec(120)}},
			want:  120 * time.Second,
		},
		{
			// A day-long NS TTL must not pin a stale answer on a tool people
			// use to watch a change land.
			name:  "a day-long TTL is capped",
			entry: cacheEntry{result: Result{Records: rec(86400)}},
			want:  cacheMaxTTL,
		},
		{
			name:  "the shortest TTL in the set wins",
			entry: cacheEntry{result: Result{Records: rec(300, 60, 900)}},
			want:  60 * time.Second,
		},
		{
			// NODATA / NXDOMAIN: the usual reason someone re-queries is that
			// they just fixed the record.
			name:  "an answer with no records is negative-cached",
			entry: cacheEntry{result: Result{Records: nil}},
			want:  cacheNegTTL,
		},
		{
			name:  "an errored answer is negative-cached",
			entry: cacheEntry{result: Result{Records: rec(3600)}, err: errNXDomain},
			want:  cacheNegTTL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := lifetime(tc.entry); got != tc.want {
				t.Errorf("lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := newCache()
	c.put("k", cacheEntry{result: Result{Type: "A", Records: []Record{{Type: "A", Value: "192.0.2.1", TTL: 120}}}}, now)

	if _, ok := c.get("nope", now); ok {
		t.Error("a key never stored came back from the cache")
	}
	if _, ok := c.get("k", now.Add(119*time.Second)); !ok {
		t.Fatal("entry expired before its TTL")
	}
	// The boundary itself is still live: expiry is after, not at.
	if _, ok := c.get("k", now.Add(120*time.Second)); !ok {
		t.Error("entry expired at its expiry instant rather than after it")
	}
	if _, ok := c.get("k", now.Add(120*time.Second).Add(time.Nanosecond)); ok {
		t.Error("expired entry was served")
	}
}

func TestCacheIsBounded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	live := cacheEntry{result: Result{Records: []Record{{Type: "A", Value: "192.0.2.1", TTL: 300}}}}
	c := newCache()

	// A public endpoint sees unbounded distinct names, so the map needs a
	// ceiling or it is a memory leak with extra steps.
	for i := range cacheMaxEntries + 1 {
		c.put(fmt.Sprintf("k%d", i), live, now)
	}
	c.mu.Lock()
	held := len(c.m)
	c.mu.Unlock()
	if held > cacheMaxEntries {
		t.Errorf("cache holds %d entries, ceiling is %d", held, cacheMaxEntries)
	}

	// Expired entries are the first thing dropped, so a cache full of dead
	// keys still has room for a live one.
	c = newCache()
	for i := range cacheMaxEntries {
		c.put(fmt.Sprintf("old%d", i), live, now.Add(-time.Hour))
	}
	c.put("fresh", live, now)
	if _, ok := c.get("fresh", now); !ok {
		t.Error("a fresh entry was not stored once the map hit its ceiling")
	}
	c.mu.Lock()
	held = len(c.m)
	c.mu.Unlock()
	if held > cacheMaxEntries {
		t.Errorf("cache holds %d entries after the prune, ceiling is %d", held, cacheMaxEntries)
	}
}

// A cached answer handed to one caller must not be writable by another: the
// handler enriches records in place (ASN, country), and those writes must not
// reach the cache or another request's answer.
func TestCachedAnswerCannotBeMutatedByACaller(t *testing.T) {
	t.Parallel()

	_, addr := serveZone(t, testZone{
		zoneKey("t.test", "A"): {"t.test. 300 IN A 192.0.2.1"},
	})
	svc := newTestService()

	first, err := svc.lookup(context.Background(), "t.test.", "A", addr)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if len(first.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(first.Records))
	}
	first.Records[0].ASN = "AS64496"

	second, err := svc.lookup(context.Background(), "t.test.", "A", addr)
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if !second.meta.cached {
		t.Error("the second identical question did not come from the cache")
	}
	if second.Records[0].ASN != "" {
		t.Errorf("second caller sees ASN %q written by the first: the cached records are shared", second.Records[0].ASN)
	}
}

// A question that failed to reach the resolver is not cached: it says nothing
// about the zone, and the next click should be free to try again.
func TestTransportFailuresAreNotCached(t *testing.T) {
	t.Parallel()

	// Nothing listens here, so every exchange is a transport failure.
	svc := NewService(50 * time.Millisecond)
	if _, err := svc.lookup(context.Background(), "t.test.", "A", "127.0.0.1:1"); err == nil {
		t.Fatal("a query to a dead address should fail")
	}
	svc.cache.mu.Lock()
	held := len(svc.cache.m)
	svc.cache.mu.Unlock()
	if held != 0 {
		t.Errorf("cache holds %d entries after a transport failure, want 0", held)
	}
	if !isTransportErr(errors.New("read udp: connection refused")) {
		t.Error("a transport error is not recognised as one")
	}
	if isTransportErr(errNoData) || isTransportErr(errNXDomain) {
		t.Error("an rcode we partition on was classed as a transport error")
	}
}
