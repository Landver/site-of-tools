package tests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// requireEgress skips a live test on a host that cannot reach UDP/53.
//
// The obvious guard — checking the error LookupSet returns — never fires: the
// domain layer returns an error only for bad input, and a transport failure is
// reported per type in set.Failed with err == nil. Guards written that way turn
// an egress-blocked host into a mix of red tests and vacuous passes, which is
// worse than either. The observable signal is the one used here: every type
// asked for failed and nothing was found.
//
// Probed once per run: the answer cannot change mid-suite, and the point is to
// spend one query deciding, not one per test.
var egress struct {
	once sync.Once
	ok   bool
}

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

// The guard has to be honest in both directions: a host WITH egress must not
// skip the live half of the suite.
func TestRequireEgressDetectsATotalFailure(t *testing.T) {
	t.Parallel()

	// A 1ms timeout fails every query, which is the shape an egress-blocked
	// host produces: a full Failed list and no error.
	set, err := dnstools.NewService(time.Millisecond).LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("transport failure should not surface as an error: %v", err)
	}
	if len(set.Found) != 0 || len(set.Failed) != set.Asked {
		t.Fatalf("expected every type to fail: found %d, failed %d of %d asked",
			len(set.Found), len(set.Failed), set.Asked)
	}
}
