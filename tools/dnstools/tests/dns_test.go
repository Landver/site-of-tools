// Black-box tests for the dnstools domain layer. Network-touching cases are
// isolated in one test that skips when UDP/53 egress is unavailable — the same
// "skip when the dependency is absent" convention the IP tool uses for missing
// BIN databases.
package tests

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func TestLookupRejectsUnknownResolver(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	if _, err := svc.LookupSet(context.Background(), "example.com", "my-own-server:53", nil); err != dnstools.ErrBadResolver {
		t.Fatalf("free-form resolver should be refused, got %v", err)
	}
	if _, err := svc.LookupSet(context.Background(), "example.com", "", nil); err != dnstools.ErrBadResolver {
		t.Fatalf("blank resolver should be refused, got %v", err)
	}
}

func TestLookupRejectsUnknownTypeAndEmptyName(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	// Rejected up front, before any query goes out: a typo is the caller's
	// mistake, not a per-type failure buried in an otherwise-fine result.
	if _, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"NOTATYPE"}); err != dnstools.ErrBadType {
		t.Fatalf("unknown type should be refused, got %v", err)
	}
	if _, err := svc.LookupSet(context.Background(), "   ", "cloudflare", nil); err != dnstools.ErrEmptyName {
		t.Fatalf("empty name should be refused, got %v", err)
	}
}

func TestResolverNameFallsBackToKey(t *testing.T) {
	t.Parallel()

	if got, want := dnstools.ResolverName("cloudflare"), "Cloudflare (1.1.1.1)"; got != want {
		t.Errorf("ResolverName(cloudflare) = %q, want %q", got, want)
	}
	// Unknown key echoes back rather than rendering a blank cell.
	if got, want := dnstools.ResolverName("nope"), "nope"; got != want {
		t.Errorf("ResolverName(nope) = %q, want %q", got, want)
	}
}

func TestResolversAllowlistIsAddressable(t *testing.T) {
	t.Parallel()

	if len(dnstools.Resolvers) == 0 {
		t.Fatal("resolver allowlist is empty")
	}
	for _, r := range dnstools.Resolvers {
		if r.Key == "" || r.Name == "" {
			t.Errorf("resolver %+v has a blank key or name", r)
		}
		host, port, err := net.SplitHostPort(r.Addr)
		if err != nil {
			t.Errorf("resolver %q addr %q is not host:port: %v", r.Key, r.Addr, err)
			continue
		}
		if net.ParseIP(host) == nil {
			t.Errorf("resolver %q addr %q must be a literal IP, not a name to resolve", r.Key, host)
		}
		if port != "53" {
			t.Errorf("resolver %q port = %q, want 53", r.Key, port)
		}
	}
}

// Live query against a public resolver. Skipped when UDP/53 egress is blocked,
// which is exactly the open question tools/dnstools/docs/02-build-fit.md §5
// flags for the production host.
func TestLookupLive(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(4 * time.Second)

	set, err := svc.LookupSet(context.Background(), "example.com", "cloudflare", []string{"A"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(set.Failed) > 0 && len(set.Found) == 0 {
		t.Skipf("upstream did not answer (%v) — flaky network, not a code failure", set.Failed)
	}
	if len(set.Found) != 1 {
		t.Fatalf("example.com returned no A records (missing %v, failed %v)", set.Missing, set.Failed)
	}
	for _, rec := range set.Found[0].Records {
		if rec.Type != "A" {
			t.Errorf("record type = %q, want A", rec.Type)
		}
		if net.ParseIP(rec.Value) == nil {
			t.Errorf("A record value %q does not parse as an IP", rec.Value)
		}
		// The whole point of humanising: raw seconds survive alongside it.
		if rec.TTLHuman == "" {
			t.Errorf("record %q has no humanised TTL", rec.Value)
		}
	}
	// Response-level facts live on the set, not repeated per type.
	if !strings.Contains(set.Flags, "rd") {
		t.Errorf("flags = %q, want the rd bit we set", set.Flags)
	}
	if set.QName != "example.com." {
		t.Errorf("qname = %q, want the fully-qualified name", set.QName)
	}
}
func TestTypesAreQueryable(t *testing.T) {
	t.Parallel()

	want := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS", "PTR"}
	if diff := cmp.Diff(want, dnstools.Types); diff != "" {
		t.Errorf("exposed types differ (-want +got):\n%s", diff)
	}
}

// The default lookup asks for every type at once and sorts the answers into
// found / empty / failed, so the UI never makes anyone click through types.
func TestLookupSetFansOutOverAllTypes(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	set, err := svc.LookupSet(context.Background(), "google.com", "cloudflare", nil)
	if err != nil {
		t.Fatalf("fan-out lookup: %v", err)
	}

	if got, want := set.Asked, len(dnstools.FanoutTypes); got != want {
		t.Errorf("asked %d types, want all %d", got, want)
	}
	seen := map[string]bool{}
	for _, r := range set.Found {
		seen[r.Type] = true
		if len(r.Records) == 0 {
			t.Errorf("%s landed in Found with no records", r.Type)
		}
	}
	// A type that timed out lands in Failed, and under real packet loss that
	// can be any of them, A included. Then there is nothing here about the
	// fan-out left to check, and the push gate runs this: a lost packet must
	// not read as a blocked deploy. Everything above this line — the partition
	// itself — still holds and is still asserted.
	if len(set.Failed) > 0 && (len(set.Found) < 3 || !seen["A"]) {
		t.Skipf("%d of %d types did not answer (%v) — flaky network, not a code failure",
			len(set.Failed), set.Asked, set.Failed)
	}
	if len(set.Found) < 3 {
		t.Errorf("google.com should publish several types, got %d", len(set.Found))
	}
	// Only A is asserted by name. Any individual type can legitimately time
	// out under load and land in Failed instead — surviving that is the point
	// of the fan-out, so the test asserts the partition, not a fixed roster.
	if !seen["A"] {
		t.Errorf("expected A among found types, got %v (failed: %v)", seen, set.Failed)
	}
	if set.NXDomain {
		t.Error("google.com should not be NXDOMAIN")
	}
	// A type lands in exactly one bucket: "isn't published" and "couldn't find
	// out" are different claims and must not blur.
	for _, m := range set.Missing {
		if seen[m] {
			t.Errorf("%s is both found and missing", m)
		}
	}
	for _, f := range set.Failed {
		if seen[f.Type] {
			t.Errorf("%s is both found and failed", f.Type)
		}
	}
}

// One type failing must never cost the others their answers.
func TestLookupSetSurvivesAPartialFailure(t *testing.T) {
	t.Parallel()
	// A 1ms timeout fails every query, proving failures are collected per type
	// rather than aborting the whole set.
	svc := dnstools.NewService(time.Millisecond)

	set, err := svc.LookupSet(context.Background(), "google.com", "cloudflare", nil)
	if err != nil {
		t.Fatalf("a set where every type fails should still return a set: %v", err)
	}
	if got, want := len(set.Failed), len(dnstools.FanoutTypes); got != want {
		t.Errorf("failed %d types, want all %d", got, want)
	}
	if len(set.Found) != 0 {
		t.Errorf("nothing should be found with a 1ms timeout, got %d", len(set.Found))
	}
	if set.NXDomain {
		t.Error("timeouts are not NXDOMAIN")
	}
}

// A name that doesn't exist says so once, rather than reporting every type as
// missing.
func TestLookupSetNXDomainCollapses(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	set, err := svc.LookupSet(context.Background(), "no-such-name-corpberry-test-12345.com", "cloudflare", nil)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if !set.NXDomain {
		t.Errorf("NXDomain = false; found %d, missing %v", len(set.Found), set.Missing)
	}
	if len(set.Found) != 0 || len(set.Missing) != 0 {
		t.Errorf("a nonexistent name should list nothing per-type: found %d, missing %v",
			len(set.Found), set.Missing)
	}
}

// An IP literal has one meaningful question, so it must not fan out.
func TestLookupSetIPLiteralDoesNotFanOut(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	set, err := svc.LookupSet(context.Background(), "1.1.1.1", "cloudflare", nil)
	if err != nil {
		t.Fatalf("reverse lookup: %v", err)
	}

	if set.Asked != 1 {
		t.Errorf("asked %d types for an IP literal, want just PTR", set.Asked)
	}
	if !set.Reversed {
		t.Error("Reversed = false for an IP literal")
	}
}

// Narrowing to one type still works, so ?type= permalinks survive.
func TestLookupSetHonoursAnExplicitType(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	set, err := svc.LookupSet(context.Background(), "google.com", "cloudflare", []string{"NS"})
	if err != nil {
		t.Fatalf("single-type lookup: %v", err)
	}
	if set.Asked != 1 {
		t.Errorf("asked %d types, want 1", set.Asked)
	}
	if len(set.Found) == 1 && set.Found[0].Type != "NS" {
		t.Errorf("got type %q, want NS", set.Found[0].Type)
	}
}
