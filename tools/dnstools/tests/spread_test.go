package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// Asked of its own nameservers, a healthy zone is consistent with its serials in step.
func TestSpreadHealthyZoneIsConsistent(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	sp, err := svc.Spread(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("consistency check: %v", err)
	}
	if len(sp.Authoritative) == 0 {
		t.Skip("no authoritative nameservers came back — the NS discovery lookup did not answer, which is flaky network rather than a code failure")
	}
	if sp.Answered == 0 {
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

// A subdomain has no NS of its own, so the check walks up to the zone serving it.
// www.example.com is neither a delegation nor a CNAME, so the walk must climb a label.
func TestSpreadWalksUpToTheServingZone(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)
	ctx := context.Background()

	// Skip on this control question, not on an empty result: a broken walk also finds no zone.
	if ns, err := svc.LookupSet(ctx, "example.com", dnstools.DefaultResolver, []string{"NS"}); err != nil || len(ns.Found) == 0 {
		t.Skipf("upstream did not answer NS for example.com (%v) — flaky network, not a code failure", err)
	}

	sp, err := svc.Spread(ctx, "www.example.com", "A")
	if err != nil {
		t.Fatalf("consistency check: %v", err)
	}
	if sp.Zone != "example.com." {
		t.Errorf("Zone = %q, want the parent zone example.com. — the walk up from www. is what this checks", sp.Zone)
	}
	if len(sp.Authoritative) == 0 {
		t.Error("walked up to a zone but listed none of its nameservers")
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
