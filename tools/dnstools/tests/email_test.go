package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// notesAt returns the text of every note at this level.
func notesAt(notes []dnstools.Note, level string) []string {
	var out []string
	for _, n := range notes {
		if n.Level == level {
			out = append(out, n.Text)
		}
	}
	return out
}

// A real mail domain parses into MX, SPF and DMARC, with SPF lookups inside the spec's limit.
func TestEmailAuthOnARealMailDomain(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	// Any of three queries can lose a packet, so assert on the first domain that answers all three.
	candidates := []string{"github.com", "microsoft.com", "cloudflare.com", "paypal.com"}
	var e *dnstools.EmailAuth
	var sawMX, sawSPF, sawDMARC int
	for _, domain := range candidates {
		got, err := svc.EmailAuth(context.Background(), domain)
		if err != nil || got == nil {
			continue
		}
		if got.HasMX {
			sawMX++
		}
		if got.SPF != nil {
			sawSPF++
		}
		if got.DMARC != nil {
			sawDMARC++
		}
		if got.HasMX && got.SPF != nil && got.DMARC != nil {
			e = got
			break
		}
	}
	if e == nil {
		// All candidates publish all three, so MX with no SPF or DMARC anywhere is a broken reader.
		if sawMX > 0 && (sawSPF == 0 || sawDMARC == 0) {
			t.Fatalf("%d of %d candidate domains answered with MX, and SPF parsed %d times, DMARC %d times. That is not lost packets: one of the two readers is returning nothing.",
				sawMX, len(candidates), sawSPF, sawDMARC)
		}
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

// The count follows includes; candidates rotate because SPF records get flattened over time.
func TestSPFLookupCountFollowsIncludes(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(5 * time.Second)

	candidates := []string{"zendesk.com", "salesforce.com", "shopify.com", "atlassian.com"}
	for _, d := range candidates {
		e, err := svc.EmailAuth(context.Background(), d)
		if err != nil || e.SPF == nil {
			continue
		}
		if len(e.SPF.Chain) < 2 {
			continue
		}
		// Every include walked into (Chain) cost at least one lookup.
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
		if len(notesAt(e.Notes, "info")) == 0 {
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
	if got := len(notesAt(e.Notes, "ok")); got != ok {
		t.Errorf("Score ok = %d, notes say %d", ok, got)
	}
	if got := len(notesAt(e.Notes, "warn")); got != warn {
		t.Errorf("Score warn = %d, notes say %d", warn, got)
	}
	if got := len(notesAt(e.Notes, "fail")); got != fail {
		t.Errorf("Score fail = %d, notes say %d", fail, got)
	}
}
