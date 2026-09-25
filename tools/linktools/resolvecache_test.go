package linktools

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	mopts "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// White-box, beside the code, per CLAUDE.md rule #6's exception: resolveCache
// and hitBatcher are unexported and have no exported surface at all. The only
// tests that reached this file before went through LinkStore, which skips
// without Mongo — so on an ordinary CI run these two types, which exist purely
// to bound the one unauthenticated route in the suite, were executed zero
// times. Everything here runs with no database.
//
// Run with -race: both types are touched concurrently by every redirect.

// offlineCollection returns a real *mongo.Collection pointed at a port nothing
// listens on.
//
// Not nil: hitBatcher.flush calls b.coll.BulkWrite, which dereferences the
// collection, so a nil one panics inside the flush goroutine and takes the test
// binary with it. An unreachable-but-real collection exercises the actual flush
// path and fails server selection in ~100ms, which is also exactly what a Mongo
// outage looks like in production — the case the batcher has to survive.
func offlineCollection(t *testing.T) *mongo.Collection {
	t.Helper()
	cl, err := mongo.Connect(mopts.Client().
		ApplyURI("mongodb://127.0.0.1:1/").
		SetServerSelectionTimeout(100 * time.Millisecond).
		SetConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Skipf("cannot build an offline mongo client: %v", err)
	}
	t.Cleanup(func() { _ = cl.Disconnect(context.Background()) })
	return cl.Database("linktools_test").Collection("links")
}

func testLink(code string) *Link {
	return &Link{Code: code, Target: "https://example.com/" + code, CreatedAt: time.Now()}
}

// TestResolveCacheRoundTrip. The negative half is the one that matters: a
// scanner walking random codes costs one FindOne per request without it, and
// /s/:code is deliberately not rate-limited, so "known absent" has to come back
// as a HIT carrying a nil link, never as a miss.
func TestResolveCacheRoundTrip(t *testing.T) {
	c := newResolveCache()

	if _, ok := c.get("never-stored"); ok {
		t.Error("empty cache reported a hit; every lookup would answer from nothing")
	}

	l := testLink("abc1234")
	c.put("abc1234", l)
	got, ok := c.get("abc1234")
	if !ok {
		t.Fatal("stored link missed — the cache is not caching, so every redirect is a database round trip")
	}
	if got != l {
		t.Errorf("get returned %v, want the stored link %v", got, l)
	}

	c.put("missing1", nil)
	got, ok = c.get("missing1")
	if !ok {
		t.Fatal("a negative entry came back as a miss — the half that actually defends the database does nothing, and hammering an unknown code hits Mongo every time")
	}
	if got != nil {
		t.Errorf("negative entry returned %v, want nil — a non-nil link here would redirect to something that does not exist", got)
	}
}

// TestResolveCachePutSetsTheRightTTL reads the stored entry directly, because
// the TTL is only observable from outside by waiting a minute for it.
func TestResolveCachePutSetsTheRightTTL(t *testing.T) {
	cases := []struct {
		name string
		link *Link
		want time.Duration
		why  string
	}{
		{"hit", testLink("abc1234"), resolveCacheTTL,
			"a create or revoke is made visible by invalidate, not by a short TTL, so this one can be generous — but not unbounded"},
		{"negative", nil, resolveNegativeTTL,
			"the negative TTL is the bound on how often a scan of nonexistent codes reaches the database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newResolveCache()
			before := time.Now()
			c.put("code", tc.link)
			e, ok := c.entries["code"]
			if !ok {
				t.Fatal("put stored nothing")
			}
			got := e.expires.Sub(before)
			if got < tc.want || got > tc.want+time.Second {
				t.Errorf("entry expires in %v, want about %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestResolveCacheExpires: entries are written straight into the map with a
// chosen expiry rather than sleeping out a real 60s TTL. A stale entry served
// after expiry is a redirect to a target that may have been revoked.
func TestResolveCacheExpires(t *testing.T) {
	c := newResolveCache()
	l := testLink("fresh")
	c.entries["fresh"] = cacheEntry{link: l, expires: time.Now().Add(time.Minute)}
	c.entries["stale"] = cacheEntry{link: testLink("stale"), expires: time.Now().Add(-time.Second)}
	c.entries["staleneg"] = cacheEntry{link: nil, expires: time.Now().Add(-time.Second)}

	if got, ok := c.get("fresh"); !ok || got != l {
		t.Errorf("unexpired entry not served (link=%v ok=%v); the TTL check is rejecting live entries and the cache is useless", got, ok)
	}
	if _, ok := c.get("stale"); ok {
		t.Error("expired entry served — a revoked or edited link keeps redirecting to its old target forever")
	}
	if _, ok := c.get("staleneg"); ok {
		t.Error("expired negative entry served — a code created after the miss would 404 until the process restarts")
	}
}

// TestResolveCacheIsBounded. The key space is attacker-chosen: without the
// bound, a scanner walking random codes turns the negative cache into a
// memory-growth path, which is the same outcome the cache exists to prevent.
func TestResolveCacheIsBounded(t *testing.T) {
	c := newResolveCache()
	for i := 0; i < resolveCacheMax; i++ {
		c.put(fmt.Sprintf("code%d", i), nil)
	}
	if len(c.entries) != resolveCacheMax {
		t.Fatalf("filled cache holds %d entries, want %d", len(c.entries), resolveCacheMax)
	}

	c.put("one-too-many", testLink("one-too-many"))
	if len(c.entries) > resolveCacheMax {
		t.Errorf("cache grew to %d entries, past its %d bound — a code scan is now a memory-growth path", len(c.entries), resolveCacheMax)
	}
	// Clearing wholesale costs a brief miss storm and cannot leak; what it must
	// not do is drop the entry being written.
	if _, ok := c.get("one-too-many"); !ok {
		t.Error("the put that triggered the clear lost its own entry; the cache would thrash instead of refilling")
	}
}

// TestResolveCacheInvalidate: revocation must not wait on a TTL. A link revoked
// because it was pasted somewhere it should not have been keeps working for up
// to a minute otherwise.
func TestResolveCacheInvalidate(t *testing.T) {
	c := newResolveCache()
	c.put("abc1234", testLink("abc1234"))
	c.invalidate("abc1234")
	if _, ok := c.get("abc1234"); ok {
		t.Error("invalidated code still cached — a revoke does not take effect until the TTL runs out")
	}
	c.invalidate("never-existed") // must not panic
}

// TestHitBatcherNilIsSafe: a nil *hitBatcher is how "Mongo is off" propagates
// down here, same contract as a nil LinkStore or a nil RequestLog. Both methods
// are called from the redirect path and from shutdown.
func TestHitBatcherNilIsSafe(t *testing.T) {
	var b *hitBatcher
	b.record("abc1234") // must not panic
	b.Close()           // must not panic or block
}

// TestHitBatcherRecordNeverBlocks. record runs on the redirect path, so a full
// queue must drop the count rather than make the visitor wait on a writer that
// is busy talking to Mongo. A lost hit count on a personal link shortener is
// acceptable; a redirect that waits on a write is not.
//
// This batcher is built by hand, without run(), precisely so nothing drains the
// queue: with the real goroutine running, "full" is not reachable on purpose.
func TestHitBatcherRecordNeverBlocks(t *testing.T) {
	b := &hitBatcher{ch: make(chan string, 8), done: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < cap(b.ch)*4; i++ {
			b.record("abc1234")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("record blocked on a full queue — every redirect now waits on the hit writer, which is the goroutine-and-connection exhaustion this batcher replaced")
	}
	if len(b.ch) != cap(b.ch) {
		t.Errorf("queue holds %d of %d; record is dropping or losing counts it did not need to", len(b.ch), cap(b.ch))
	}
}

// TestHitBatcherCloseIsIdempotent. Close is called from main's shutdown path,
// and closing an already-closed channel panics — a crash during shutdown that
// only shows up when the shutdown path is touched twice (a signal handler plus
// a deferred Close, say). sync.Once is the thing being tested here.
//
// It also proves Close drains and flushes without a reachable database: flush
// errors out and is discarded, because a lost hit count must never stop the
// process from exiting.
func TestHitBatcherCloseIsIdempotent(t *testing.T) {
	b := newHitBatcher(offlineCollection(t))
	b.record("abc1234")
	b.record("abc1234")
	b.record("def5678")

	for i := 0; i < 3; i++ {
		done := make(chan struct{})
		go func() { defer close(done); b.Close() }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Close #%d did not return; shutdown hangs", i+1)
		}
	}
}

// TestResolveCacheAndBatcherUnderConcurrency is the -race test. Every redirect
// reads the cache, writes it on a miss, and records a hit; a create or revoke
// invalidates from a different request at the same time. A data race here is
// not theoretical, it is the normal traffic pattern.
//
// Note the ordering: every record finishes before Close is called. That is not
// incidental tidiness — record sends on b.ch and Close closes it, with no guard
// between them, so a record racing a Close would panic with "send on closed
// channel". See the report accompanying these tests.
func TestResolveCacheAndBatcherUnderConcurrency(t *testing.T) {
	c := newResolveCache()
	b := newHitBatcher(offlineCollection(t))

	const workers, iterations = 16, 400
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				code := fmt.Sprintf("code%d", i%64)
				switch (w + i) % 4 {
				case 0:
					c.put(code, testLink(code))
				case 1:
					c.put(code, nil) // negative entry
				case 2:
					c.invalidate(code)
				default:
					if _, ok := c.get(code); ok {
						b.record(code)
					}
				}
			}
		}(w)
	}
	wg.Wait()

	// Shutdown while the flush ticker is live, which is the real shutdown shape.
	b.Close()

	if len(c.entries) > resolveCacheMax {
		t.Errorf("cache holds %d entries after concurrent use, past its %d bound", len(c.entries), resolveCacheMax)
	}
}

// TestRecordIsSafeDuringAndAfterClose covers the property that did NOT hold
// when these tests were first written: Close() closed the channel with no
// guard, and record()'s `select { case ch <- code: default: }` panics on a
// closed channel — `default` covers a FULL channel, not a closed one.
//
// It matters because Close runs from main's shutdown path (SIGTERM, which is
// what `docker compose up -d --build` sends on every deploy) while redirects
// can still be in flight, so the crash window is a real one rather than a
// theoretical one.
func TestRecordIsSafeDuringAndAfterClose(t *testing.T) {
	b := newHitBatcher(offlineCollection(t))

	var wg sync.WaitGroup
	// Writers keep going deliberately past the Close below.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.record("code" + strconv.Itoa(n))
			}
		}(i)
	}
	// Close concurrently with the writers. A panic here fails the test, which
	// is the whole point.
	b.Close()
	wg.Wait()

	// And after Close has definitely returned.
	b.record("after-close")

	// Idempotent: a second Close must not close an already-closed channel.
	b.Close()
}
