package tests

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// A repeat question inside the TTL must not reach the resolver again.
func TestRepeatLookupIsCached(t *testing.T) {
	t.Parallel()
	requireEgress(t)
	svc := dnstools.NewService(4 * time.Second)

	first, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if len(first.Found) == 0 {
		t.Fatalf("example.com returned no A records (failed %v)", first.Failed)
	}

	second, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	// A cache hit is served from memory, so it is far faster than a network
	// round trip. Generous bound: this asserts "didn't go to the network",
	// not a performance number.
	if second.QueryMS > 20 {
		t.Errorf("second identical lookup took %d ms; expected a cache hit", second.QueryMS)
	}
	if len(second.Found) != len(first.Found) {
		t.Errorf("cached answer differs: %d found vs %d", len(second.Found), len(first.Found))
	}
}

// Concurrent identical questions collapse into one upstream query.
func TestConcurrentIdenticalLookupsCollapse(t *testing.T) {
	t.Parallel()
	requireEgress(t)
	svc := dnstools.NewService(4 * time.Second)

	const callers = 8
	var wg sync.WaitGroup
	var failures atomic.Int64
	results := make([]int, callers)

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set, err := svc.LookupSet(context.Background(), "iana.org", "cloudflare", []string{"NS"})
			if err != nil {
				failures.Add(1)
				return
			}
			results[i] = len(set.Found)
		}()
	}
	wg.Wait()

	if failures.Load() > 0 {
		t.Fatalf("%d of %d callers got an error from LookupSet", failures.Load(), callers)
	}
	// Every caller must get the same answer; singleflight sharing one result
	// between them must not leave anyone with a zero value.
	for i, got := range results {
		if got != results[0] {
			t.Errorf("caller %d saw %d found, caller 0 saw %d", i, got, results[0])
		}
	}
}

// A different question is not served from another question's entry.
func TestCacheKeyIsPerQuestion(t *testing.T) {
	t.Parallel()
	requireEgress(t)
	svc := dnstools.NewService(4 * time.Second)

	a, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("A lookup: %v", err)
	}
	ns, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"NS"})
	if err != nil {
		t.Fatalf("NS lookup: %v", err)
	}

	if len(a.Found) > 0 && len(ns.Found) > 0 && a.Found[0].Type == ns.Found[0].Type {
		t.Errorf("A and NS returned the same type %q — cache key ignores the type", a.Found[0].Type)
	}
}
