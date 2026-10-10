// Wire tests: hand-built traceReply values test a belief about query(); these test query() itself.
package dnstools

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// traceWireLink validates example.test. under parent via one loopback nameserver answering with h.
func traceWireLink(t *testing.T, parent traceDS, h dns.HandlerFunc) TraceLink {
	t.Helper()
	w := &traceWalk{svc: newTestService(), ctx: context.Background(), out: &Trace{}}
	link, _ := w.validateZone("example.test.", "test.", []traceServer{serveNS(t, h)}, parent, true)
	return link
}

func verifiedDS(ds *dns.DS) traceDS { return traceDS{set: []*dns.DS{ds}, status: traceDSVerified} }

func wireTruncated(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative, m.Truncated = true, true
	_ = w.WriteMsg(m)
}

func wireRcode(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Rcode = rcode
		_ = w.WriteMsg(m)
	}
}

// wireAnswer replies authoritatively with rrs; with none it is a whole NOERROR/NODATA.
func wireAnswer(rrs ...dns.RR) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative = true
		m.Answer = rrs
		_ = w.WriteMsg(m)
	}
}

// accusesTheZone fails if detail blames the zone for what a lost or refused packet also produces.
func accusesTheZone(t *testing.T, where, detail string) {
	t.Helper()
	for _, word := range []string{"broken", "bogus", "do not back it up", "does not verify", "unsigned"} {
		if strings.Contains(strings.ToLower(detail), word) {
			t.Errorf("%s: detail %q accuses the zone (%q) on the strength of a transport failure", where, detail, word)
		}
	}
}

// TC=1 with a failed TCP retry and an rcode are not verdicts; a whole NOERROR with no DNSKEY is.
func TestValidateZoneOverTheWireTellsTransportApartFromABrokenZone(t *testing.T) {
	t.Parallel()
	_, _, _, ds := traceTestZone(t, "example.test")

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		link := traceWireLink(t, verifiedDS(ds), wireTruncated)
		if link.Status != traceUnknown {
			t.Errorf("a truncated DNSKEY reply gave status %q, want %q. Detail: %s", link.Status, traceUnknown, link.Detail)
		}
		accusesTheZone(t, "truncated", link.Detail)
	})

	t.Run("servfail", func(t *testing.T) {
		t.Parallel()
		for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotAuth} {
			name := dns.RcodeToString[rcode]
			link := traceWireLink(t, verifiedDS(ds), wireRcode(rcode))
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

	// A guard answering "could not tell" to everything would pass every case above.
	t.Run("nodata is still bogus", func(t *testing.T) {
		t.Parallel()
		link := traceWireLink(t, verifiedDS(ds), wireAnswer())
		if link.Status != traceBogus {
			t.Errorf("a whole NOERROR reply carrying no DNSKEY under a DS gave %q, want %q. Detail: %s",
				link.Status, traceBogus, link.Detail)
		}
	})

	t.Run("a correctly signed key set still verifies", func(t *testing.T) {
		t.Parallel()
		key, rrset, sig, realDS := traceTestZone(t, "example.test")
		link := traceWireLink(t, verifiedDS(realDS), wireAnswer(append(rrset, sig)...))
		if link.Status != traceSecure {
			t.Fatalf("a correctly signed key set gave %q, want %q. Detail: %s", link.Status, traceSecure, link.Detail)
		}
		if link.MatchedTag != key.KeyTag() {
			t.Errorf("matched tag = %d, want %d", link.MatchedTag, key.KeyTag())
		}
	})

	t.Run("a mismatched key set is still bogus", func(t *testing.T) {
		t.Parallel()
		_, rrset, sig, _ := traceTestZone(t, "example.test")
		link := traceWireLink(t, verifiedDS(ds), wireAnswer(append(rrset, sig)...))
		if link.Status != traceBogus {
			t.Errorf("a key set no DS digest matches gave %q, want %q. Detail: %s", link.Status, traceBogus, link.Detail)
		}
	})
}

// Reading an unreadable DS reply as "no DS" would quietly mark a signed zone unsigned.
func TestFetchDSOverTheWireTellsTransportApartFromAnUnsignedDelegation(t *testing.T) {
	t.Parallel()
	parentKey, _, _, _ := traceTestZone(t, "test")

	fetch := func(h dns.HandlerFunc) traceDS {
		w := &traceWalk{svc: newTestService(), ctx: context.Background(), out: &Trace{}}
		return w.fetchDS("example.test.", []traceServer{serveNS(t, h)}, []*dns.DNSKEY{parentKey}, true)
	}

	truncated := fetch(wireTruncated)
	if truncated.status == traceDSAbsent {
		t.Error("a truncated DS reply was read as a parent publishing no DS, which marks a signed zone unsigned")
	}
	if truncated.status != traceDSUnreadable {
		t.Errorf("a truncated DS reply gave %q, want %q", truncated.status, traceDSUnreadable)
	}

	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotAuth} {
		got := fetch(wireRcode(rcode))
		if got.status == traceDSAbsent || got.status == traceDSBogus {
			t.Errorf("%s on the DS query gave %q, which is a verdict about the zone", dns.RcodeToString[rcode], got.status)
		}
	}

	absent := fetch(wireAnswer())
	if absent.status != traceDSAbsent {
		t.Errorf("a whole NOERROR reply with no DS gave %q, want %q", absent.status, traceDSAbsent)
	}
}

// One unchecked root link must not make every zone below it read as an unsigned delegation.
func TestAnUncheckedLinkIsNotReportedAsAnUnsignedDelegation(t *testing.T) {
	t.Parallel()

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
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

	u := &traceWalk{ctx: context.Background(), out: &Trace{}}
	u.out.Chain = []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "com.", Status: traceSecure},
		{Zone: "github.com.", Status: traceInsecure}}
	u.out.AnswerZone, u.answer = "github.com.", traceAnswerUnchecked
	u.verdict()
	if u.out.DNSSEC != traceInsecure {
		t.Errorf("an unsigned delegation gave %q, want %q: %s", u.out.DNSSEC, traceInsecure, u.out.Verdict.Text)
	}
}

// DNSKEYs but no parent DS: signed at the DNS host, DS never added at the registrar.
func TestValidateZoneOverTheWireFindsKeysWithoutADS(t *testing.T) {
	t.Parallel()
	key, _, _, _ := traceTestZone(t, "example.test")
	noDS := traceDS{status: traceDSAbsent}

	signed := traceWireLink(t, noDS, wireAnswer(key))
	if signed.Status != traceInsecure || !signed.KeysWithoutDS {
		t.Errorf("keys and no DS: status %q, KeysWithoutDS %v; want insecure with the flag. Detail: %s", signed.Status, signed.KeysWithoutDS, signed.Detail)
	}
	if !strings.Contains(signed.Detail, "DS record at the registrar") {
		t.Errorf("detail %q should name the missing step", signed.Detail)
	}

	unsigned := traceWireLink(t, noDS, wireAnswer())
	if unsigned.Status != traceInsecure || unsigned.KeysWithoutDS {
		t.Errorf("no keys and no DS: status %q, KeysWithoutDS %v; want plain insecure", unsigned.Status, unsigned.KeysWithoutDS)
	}
	if !strings.Contains(unsigned.Detail, "Most names are") {
		t.Errorf("detail %q should still say unsigned is the common case", unsigned.Detail)
	}
}
