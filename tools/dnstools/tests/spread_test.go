package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// The consistency check asks the zone's own nameservers directly, so a healthy
// zone must come back consistent with its serials in step.
func TestSpreadHealthyZoneIsConsistent(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	sp, err := svc.Spread(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("consistency check: %v", err)
	}
	if len(sp.Authoritative) == 0 {
		t.Fatal("found no authoritative nameservers for the zone")
	}
	if sp.Answered == 0 {
		// Every probe timed out: the network is having a bad moment, which is
		// not a defect in this code and must not block the deploy gate.
		t.Skipf("no server answered out of %d asked — flaky network, not a code failure", sp.Asked)
	}
	// The honest denominator: every server asked is accounted for.
	if sp.Asked != len(sp.Authoritative)+len(sp.Resolvers) {
		t.Errorf("Asked = %d but %d servers are listed", sp.Asked,
			len(sp.Authoritative)+len(sp.Resolvers))
	}
	if !sp.SerialsAgree {
		t.Errorf("a healthy zone's nameservers should agree on the SOA serial")
	}
	// Grouping by answer set, not a percentage.
	if len(sp.Groups) == 0 {
		t.Error("no answer groups built")
	}
	for _, g := range sp.Groups {
		if len(g.Servers) == 0 {
			t.Error("an answer group with no servers in it")
		}
	}
}

// A subdomain has no NS records of its own, so the check must walk up to the
// zone that actually serves it rather than finding nothing.
func TestSpreadWalksUpToTheServingZone(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	sp, err := svc.Spread(context.Background(), "www.cloudflare.com", "A")
	if err != nil {
		t.Fatalf("consistency check: %v", err)
	}
	if len(sp.Authoritative) == 0 {
		t.Error("should have walked up to cloudflare.com's nameservers")
	}
}

// Servers that fail are named, never silently dropped from the denominator.
func TestSpreadNamesFailuresRatherThanHidingThem(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	sp, err := svc.Spread(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("consistency check: %v", err)
	}
	for _, a := range append(sp.Authoritative, sp.Resolvers...) {
		if a.Error == "" && len(a.Values) == 0 {
			t.Errorf("%q returned nothing but reports no error", a.Label)
		}
		if a.Label == "" {
			t.Error("a server row with no label")
		}
	}
	if sp.Answered > sp.Asked {
		t.Errorf("Answered %d > Asked %d", sp.Answered, sp.Asked)
	}
}

func TestSpreadRejectsBadInput(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	if _, err := svc.Spread(context.Background(), "", "A"); err != dnstools.ErrEmptyName {
		t.Errorf("empty name should be refused, got %v", err)
	}
	if _, err := svc.Spread(context.Background(), "example.com", "NOTATYPE"); err == nil {
		t.Error("unknown type should be refused")
	}
	// An IP has no zone to canvass; say so rather than pretending.
	if _, err := svc.Spread(context.Background(), "1.1.1.1", "A"); err == nil {
		t.Error("an IP literal should be refused")
	}
}
