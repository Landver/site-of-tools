package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

var egress struct {
	once sync.Once
	ok   bool
}

// requireEgress skips a live test on a host without UDP/53, probing once per run.
// LookupSet reports transport failures in Failed with a nil err, so the signal is nothing Found.
func requireEgress(t *testing.T) {
	t.Helper()
	egress.once.Do(func() {
		set, err := dnstools.NewService(5*time.Second).LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
		egress.ok = err == nil && len(set.Found) > 0
	})
	if !egress.ok {
		t.Skip("no UDP/53 egress from this host, skipping live query")
	}
}

// A 1ms timeout gives the shape of an egress-blocked host: every type Failed, no error.
func TestRequireEgressDetectsATotalFailure(t *testing.T) {
	t.Parallel()

	set, err := dnstools.NewService(time.Millisecond).LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("transport failure should not surface as an error: %v", err)
	}
	if len(set.Found) != 0 || len(set.Failed) != set.Asked {
		t.Fatalf("expected every type to fail: found %d, failed %d of %d asked",
			len(set.Found), len(set.Failed), set.Asked)
	}
}
