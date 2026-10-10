package dnstools

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

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

	for i := range cacheMaxEntries + 1 {
		c.put(fmt.Sprintf("k%d", i), live, now)
	}
	if held := cacheLen(c); held > cacheMaxEntries {
		t.Errorf("cache holds %d entries, ceiling is %d", held, cacheMaxEntries)
	}

	// Expired entries go first, so a cache full of dead keys still takes a live one.
	c = newCache()
	for i := range cacheMaxEntries {
		c.put(fmt.Sprintf("old%d", i), live, now.Add(-time.Hour))
	}
	c.put("fresh", live, now)
	if _, ok := c.get("fresh", now); !ok {
		t.Error("a fresh entry was not stored once the map hit its ceiling")
	}
	if held := cacheLen(c); held > cacheMaxEntries {
		t.Errorf("cache holds %d entries after the prune, ceiling is %d", held, cacheMaxEntries)
	}
}

// The handler enriches records in place (ASN, country), so each caller needs its own copy.
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

// A transport failure says nothing about the zone, so the next click must be free to retry.
func TestTransportFailuresAreNotCached(t *testing.T) {
	t.Parallel()

	// Nothing listens here, so every exchange is a transport failure.
	svc := NewService(50 * time.Millisecond)
	if _, err := svc.lookup(context.Background(), "t.test.", "A", "127.0.0.1:1"); err == nil {
		t.Fatal("a query to a dead address should fail")
	}
	if held := cacheLen(svc.cache); held != 0 {
		t.Errorf("cache holds %d entries after a transport failure, want 0", held)
	}
	if !isTransportErr(errors.New("read udp: connection refused")) {
		t.Error("a transport error is not recognised as one")
	}
	if isTransportErr(errNoData) || isTransportErr(errNXDomain) {
		t.Error("an rcode we partition on was classed as a transport error")
	}
}

func cacheLen(c *cache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
