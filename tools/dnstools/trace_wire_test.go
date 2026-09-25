// Over-the-wire tests for the one decision on this page that is dangerous to
// get wrong: what a DNSKEY fetch is entitled to conclude.
//
// trace_test.go drives traceKeySetVerdict with hand-built traceReply values.
// That is necessary and not sufficient. The reply is built by query(), and
// query() is where a wire response becomes one of those structs — a SERVFAIL
// lands in `skipped` with `answered` set and no message, a TC=1 reply lands in
// `unreadable`, a NOERROR lands in `msg`. A test that constructs the struct
// itself asserts the author's belief about that mapping, not the mapping. The
// bug being guarded against here was a mapping that looked reasonable and was
// wrong, so these tests start at the socket.
//
// Each case serves one DNSKEY response from a real nameserver on loopback and
// reads the chain link the walk builds out of it.
package dnstools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// traceWireLink runs validateZone against a single loopback nameserver
// answering with h, under a parent DS that is present and verified — so the
// only thing left to decide is what the DNSKEY reply means.
func traceWireLink(t *testing.T, ds *dns.DS, h dns.HandlerFunc) TraceLink {
	t.Helper()
	srv := serveNS(t, h)
	w := &traceWalk{svc: NewService(2 * time.Second), ctx: context.Background(), out: &Trace{}}
	link, _ := w.validateZone("example.test.", "test.", []traceServer{srv},
		traceDS{set: []*dns.DS{ds}, status: traceDSVerified}, true)
	return link
}

// accusesTheZone fails when a sentence blames the zone for something a lost or
// refused packet produces just as well. These are the words a domain owner
// reads as "my domain is broken".
func accusesTheZone(t *testing.T, where, detail string) {
	t.Helper()
	for _, word := range []string{"broken", "bogus", "do not back it up", "does not verify", "unsigned"} {
		if strings.Contains(strings.ToLower(detail), word) {
			t.Errorf("%s: detail %q accuses the zone (%q) on the strength of a transport failure", where, detail, word)
		}
	}
}

// The three cases the fix has to hold apart, driven from the wire.
//
//	TC=1 whose TCP retry cannot complete -> not a verdict. The root's DNSKEY
//	   set is over 512 bytes, so this is the routine case and it is what put
//	   "this name's chain of trust is broken" on the root zone.
//	SERVFAIL (and REFUSED) -> not a verdict either. A server that answers with
//	   an rcode instead of records has said nothing about what it publishes,
//	   which is the rule traceUnreadable already writes down.
//	NOERROR carrying no DNSKEY -> a verdict, and the right one. The zone
//	   answered in full, under a DS that says it is signed, and served no key.
func TestValidateZoneOverTheWireTellsTransportApartFromABrokenZone(t *testing.T) {
	t.Parallel()
	_, _, _, ds := traceTestZone(t, "example.test")

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		link := traceWireLink(t, ds, func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			m.Authoritative, m.Truncated = true, true
			_ = w.WriteMsg(m)
		})
		if link.Status != traceUnknown {
			t.Errorf("a truncated DNSKEY reply gave status %q, want %q. Detail: %s", link.Status, traceUnknown, link.Detail)
		}
		accusesTheZone(t, "truncated", link.Detail)
	})

	t.Run("servfail", func(t *testing.T) {
		t.Parallel()
		for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotAuth} {
			name := dns.RcodeToString[rcode]
			link := traceWireLink(t, ds, func(w dns.ResponseWriter, req *dns.Msg) {
				m := new(dns.Msg).SetReply(req)
				m.Rcode = rcode
				_ = w.WriteMsg(m)
			})
			if link.Status == traceBogus {
				t.Errorf("%s on the DNSKEY query was called %q: %s", name, traceBogus, link.Detail)
			}
			if link.Status != traceUnknown {
				t.Errorf("%s on the DNSKEY query gave status %q, want %q. Detail: %s", name, link.Status, traceUnknown, link.Detail)
			}
			accusesTheZone(t, name, link.Detail)
			if len(link.Unanswered) == 0 {
				t.Errorf("%s: a link that could not be checked must name the servers it could not read", name)
			}
		}
	})

	// The mirror-image failure. A guard that answers "could not tell" to
	// everything is not a validator, and it would pass every test above.
	t.Run("nodata is still bogus", func(t *testing.T) {
		t.Parallel()
		link := traceWireLink(t, ds, func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			m.Authoritative = true
			_ = w.WriteMsg(m)
		})
		if link.Status != traceBogus {
			t.Errorf("a whole NOERROR reply carrying no DNSKEY under a DS gave %q, want %q. Detail: %s",
				link.Status, traceBogus, link.Detail)
		}
	})

	// And the happy path over the same wire, so "not checked" cannot quietly
	// become the answer to everything.
	t.Run("a correctly signed key set still verifies", func(t *testing.T) {
		t.Parallel()
		key, rrset, sig, realDS := traceTestZone(t, "example.test")
		link := traceWireLink(t, realDS, func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			m.Authoritative = true
			m.Answer = append(m.Answer, rrset...)
			m.Answer = append(m.Answer, sig)
			_ = w.WriteMsg(m)
		})
		if link.Status != traceSecure {
			t.Fatalf("a correctly signed key set gave %q, want %q. Detail: %s", link.Status, traceSecure, link.Detail)
		}
		if link.MatchedTag != key.KeyTag() {
			t.Errorf("matched tag = %d, want %d", link.MatchedTag, key.KeyTag())
		}
	})

	// A key set that genuinely does not match the parent's DS must still be
	// called what it is, over the wire and not only in the pure verifier.
	t.Run("a mismatched key set is still bogus", func(t *testing.T) {
		t.Parallel()
		_, rrset, sig, _ := traceTestZone(t, "example.test")
		link := traceWireLink(t, ds, func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			m.Authoritative = true
			m.Answer = append(m.Answer, rrset...)
			m.Answer = append(m.Answer, sig)
			_ = w.WriteMsg(m)
		})
		if link.Status != traceBogus {
			t.Errorf("a key set no DS digest matches gave %q, want %q. Detail: %s", link.Status, traceBogus, link.Detail)
		}
	})
}

// The DS side, over the same wire. fetchDS reads the parent's word about the
// child, and reading an unreadable reply as "this parent publishes no DS" is
// the quiet false verdict: it prints no red and marks a signed zone unsigned.
func TestFetchDSOverTheWireTellsTransportApartFromAnUnsignedDelegation(t *testing.T) {
	t.Parallel()
	parentKey, _, _, _ := traceTestZone(t, "test")

	fetch := func(h dns.HandlerFunc) traceDS {
		srv := serveNS(t, h)
		w := &traceWalk{svc: NewService(2 * time.Second), ctx: context.Background(), out: &Trace{}}
		return w.fetchDS("example.test.", []traceServer{srv}, []*dns.DNSKEY{parentKey}, true)
	}

	truncated := fetch(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative, m.Truncated = true, true
		_ = w.WriteMsg(m)
	})
	if truncated.status == traceDSAbsent {
		t.Error("a truncated DS reply was read as a parent publishing no DS, which marks a signed zone unsigned")
	}
	if truncated.status != traceDSUnreadable {
		t.Errorf("a truncated DS reply gave %q, want %q", truncated.status, traceDSUnreadable)
	}

	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotAuth} {
		got := fetch(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			m.Rcode = rcode
			_ = w.WriteMsg(m)
		})
		if got.status == traceDSAbsent || got.status == traceDSBogus {
			t.Errorf("%s on the DS query gave %q, which is a verdict about the zone", dns.RcodeToString[rcode], got.status)
		}
	}

	// A parent that answers in full and publishes nothing is still an unsigned
	// delegation, which is the ordinary state of most of the internet.
	absent := fetch(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative = true
		_ = w.WriteMsg(m)
	})
	if absent.status != traceDSAbsent {
		t.Errorf("a whole NOERROR reply with no DS gave %q, want %q", absent.status, traceDSAbsent)
	}
}

// The other direction of the same mistake, at the whole-walk level.
//
// Once one link comes back unchecked the walk stops treating the chain as
// secure, and every zone below it was then reported "insecure" with the words
// "the delegation above this one is unsigned" — and verdict() ranks insecure
// above indeterminate, so the page printed "this name is not signed with
// DNSSEC" about a fully signed name. That is the same false verdict as the one
// this change set out to fix, in the quiet direction: one lost root DNSKEY
// packet, and cloudflare.com reads as an unsigned domain.
func TestAnUncheckedLinkIsNotReportedAsAnUnsignedDelegation(t *testing.T) {
	t.Parallel()

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	// The root came back unchecked, exactly as a truncated DNSKEY leaves it.
	w.out.Chain = append(w.out.Chain, TraceLink{Zone: ".", Parent: "IANA trust anchor", Status: traceUnknown,
		Detail: "This zone's DNSKEY set could not be read."})
	w.noteLinkStatus(traceUnknown)

	link, keys := w.validateZone("com.", ".", nil, traceDS{status: traceDSAbsent}, false)
	if keys != nil {
		t.Errorf("keys = %v, want none", keys)
	}
	if link.Status == traceInsecure {
		t.Errorf("a zone under an unchecked link was reported as an unsigned delegation: %s", link.Detail)
	}
	if link.Status != traceUnknown {
		t.Errorf("status = %q, want %q. Detail: %s", link.Status, traceUnknown, link.Detail)
	}
	if strings.Contains(strings.ToLower(link.Detail), "unsigned") {
		t.Errorf("detail %q calls a zone unsigned on the strength of a link that was never checked", link.Detail)
	}

	// And the whole-walk sentence that reader actually sees.
	w.out.Chain = append(w.out.Chain, link)
	w.out.AnswerZone, w.answer = "cloudflare.com.", traceAnswerUnchecked
	w.verdict()
	if w.out.DNSSEC == traceInsecure {
		t.Fatalf("verdict = %q: %s", w.out.DNSSEC, w.out.Verdict.Text)
	}
	if w.out.DNSSEC != traceUnknown {
		t.Errorf("verdict = %q, want %q: %s", w.out.DNSSEC, traceUnknown, w.out.Verdict.Text)
	}
	if strings.Contains(strings.ToLower(w.out.Verdict.Text), "not signed with dnssec") {
		t.Errorf("the page told a signed name it is unsigned: %s", w.out.Verdict.Text)
	}

	// The genuine unsigned delegation is untouched: most of the internet is
	// unsigned and saying so plainly is the point.
	u := &traceWalk{ctx: context.Background(), out: &Trace{}}
	u.out.Chain = []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "com.", Status: traceSecure},
		{Zone: "github.com.", Status: traceInsecure}}
	u.out.AnswerZone, u.answer = "github.com.", traceAnswerUnchecked
	u.verdict()
	if u.out.DNSSEC != traceInsecure {
		t.Errorf("an unsigned delegation gave %q, want %q: %s", u.out.DNSSEC, traceInsecure, u.out.Verdict.Text)
	}
}
