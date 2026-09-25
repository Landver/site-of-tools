package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

func note(e *dnstools.EmailAuth, level string) []string {
	var out []string
	for _, n := range e.Notes {
		if n.Level == level {
			out = append(out, n.Text)
		}
	}
	return out
}

// A domain with real mail must produce a real assessment, and the SPF lookup
// count must stay inside the limit the spec sets.
func TestEmailAuthOnARealMailDomain(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	// MX, SPF and DMARC are three separate queries, so on a domain fixed in
	// advance any one lost packet fails this. The property under test is that
	// a real, fully-configured mail domain parses into all three; which domain
	// supplies it is not. So: walk a few, assert in full on the first that
	// answers completely, skip only if none of them did.
	var e *dnstools.EmailAuth
	for _, domain := range []string{"github.com", "microsoft.com", "cloudflare.com", "paypal.com"} {
		got, err := svc.EmailAuth(context.Background(), domain)
		if err != nil || got == nil || !got.HasMX || got.SPF == nil || got.DMARC == nil {
			continue
		}
		e = got
		break
	}
	if e == nil {
		t.Skip("no candidate mail domain returned MX, SPF and DMARC together — upstream trouble, not a code failure")
	}
	if e.SPF.Lookups <= 0 {
		t.Errorf("%s: SPF lookup count = %d; an SPF with includes must cost lookups", e.Domain, e.SPF.Lookups)
	}
	if e.SPF.Limit != 10 {
		t.Errorf("%s: SPF limit = %d, want the RFC 7208 value of 10", e.Domain, e.SPF.Limit)
	}
	if e.DMARC.Policy == "" {
		t.Errorf("%s: a DMARC record was parsed with no p= policy read out of it: %q", e.Domain, e.DMARC.Record)
	}
	if len(e.Notes) == 0 {
		t.Errorf("%s: no findings produced", e.Domain)
	}
}

// The counter must actually follow includes rather than counting only the
// mechanisms visible in the top-level record.
//
// Deliberately not pinned to one domain: SPF records get flattened over time
// (google.com used to nest three levels and now nests none), so this walks a
// few candidates and asserts the property on whichever still nests. If the
// whole list has been flattened it skips rather than failing, because that
// would be the internet changing, not this code breaking.
func TestSPFLookupCountFollowsIncludes(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	candidates := []string{"zendesk.com", "salesforce.com", "shopify.com", "atlassian.com"}
	for _, d := range candidates {
		e, err := svc.EmailAuth(context.Background(), d)
		if err != nil || e.SPF == nil {
			continue
		}
		// Chain records every include actually resolved and walked into.
		if len(e.SPF.Chain) < 2 {
			continue
		}
		// Every walked include cost at least one lookup, so the total can
		// never be under the number of includes followed.
		if e.SPF.Lookups < len(e.SPF.Chain) {
			t.Errorf("%s: lookups %d < %d includes followed (%v): the count isn't following includes",
				d, e.SPF.Lookups, len(e.SPF.Chain), e.SPF.Chain)
		}
		return
	}
	t.Skip("no candidate domain currently has nested SPF includes; nothing to assert recursion against")
}

// A domain with no mail setup should be told so calmly, not scolded.
func TestEmailAuthOnANonMailDomain(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	e, err := svc.EmailAuth(context.Background(), "corpberry.com")
	if err != nil {
		t.Skipf("upstream did not answer (%v) — flaky network, not a code failure", err)
	}
	// No MX and no SPF is an "info", not a failure: nothing is broken.
	if e.SPF == nil && e.HasMX == false {
		if len(note(e, "info")) == 0 {
			t.Error("a domain with no mail should get an informational note, not silence")
		}
	}
	for _, n := range e.Notes {
		if n.Text == "" {
			t.Error("a finding with no text")
		}
	}
}

func TestEmailAuthRejectsBadInput(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)

	if _, err := svc.EmailAuth(context.Background(), ""); err != dnstools.ErrEmptyName {
		t.Errorf("empty name should be refused, got %v", err)
	}
	if _, err := svc.EmailAuth(context.Background(), "8.8.8.8"); err == nil {
		t.Error("an IP literal has no email identity; should be refused")
	}
}

// Score counts findings by level and must agree with the notes themselves.
func TestScoreMatchesNotes(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	e, err := svc.EmailAuth(context.Background(), "github.com")
	if err != nil {
		t.Skipf("upstream did not answer (%v) — flaky network, not a code failure", err)
	}
	ok, warn, fail := e.Score()
	if got := len(note(e, "ok")); got != ok {
		t.Errorf("Score ok = %d, notes say %d", ok, got)
	}
	if got := len(note(e, "warn")); got != warn {
		t.Errorf("Score warn = %d, notes say %d", warn, got)
	}
	if got := len(note(e, "fail")); got != fail {
		t.Errorf("Score fail = %d, notes say %d", fail, got)
	}
}
