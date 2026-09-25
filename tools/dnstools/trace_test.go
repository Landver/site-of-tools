// White-box tests for the +trace walk. The rule #6 exception: the subjects
// here are unexported, and two of them — the DNSSEC verifier and the address
// guard — are the kind of code that passes every happy-path test while being
// wrong, so they are driven directly rather than through a live walk.
//
// traceCheckKeys in particular is tested against keys generated and
// signatures made in this file. A validator that always answered "secure"
// would sail through a test that only ever walks correctly-signed zones; it
// cannot sail through one that hands it a deliberately mismatched digest.
//
// Nothing in this file touches the network.
package dnstools

import (
	"context"
	"crypto"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// traceTestKey makes a key-signing key for zone and hands back the private
// half, so a test can sign whatever window it needs.
func traceTestKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, // ZONE | SEP, i.e. a key-signing key
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate key for %s: %v", zone, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key for %s is not a crypto.Signer", zone)
	}
	return key, signer
}

// traceTestSign signs an RRset for real, over the window given. The window is
// a parameter because the expired-signature case cannot be faked by editing
// the timestamps afterwards: RFC 4035 folds them into the signed data, so a
// doctored RRSIG fails the cryptographic check and never reaches the validity
// test that is actually under examination.
func traceTestSign(t *testing.T, key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(h.Name)),
		OrigTtl:     h.Ttl,
		Inception:   uint32(inception.Unix()),
		Expiration:  uint32(expiration.Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign %s: %v", h.Name, err)
	}
	return sig
}

// traceTestZone builds a signed zone: a key-signing key, the DNSKEY RRset it
// owns, a currently-valid RRSIG over that RRset, and the DS a parent would
// publish. Everything a chain link needs, with nothing faked.
func traceTestZone(t *testing.T, zone string) (key *dns.DNSKEY, rrset []dns.RR, sig *dns.RRSIG, ds *dns.DS) {
	t.Helper()
	key, signer := traceTestKey(t, zone)
	rrset = []dns.RR{key}
	now := time.Now()
	sig = traceTestSign(t, key, signer, rrset, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	return key, rrset, sig, key.ToDS(dns.SHA256)
}

// The happy path, end to end through the verifier: the parent's DS digest
// reproduces the child's key, and that key signed the child's key set.
func TestTraceCheckKeysAcceptsARealChain(t *testing.T) {
	t.Parallel()
	key, rrset, sig, ds := traceTestZone(t, "example.test")

	matched, status, detail := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{sig})
	if status != traceSecure {
		t.Fatalf("status = %q (%s), want %q", status, detail, traceSecure)
	}
	if matched == nil || matched.KeyTag() != key.KeyTag() {
		t.Fatalf("matched key = %v, want the key tag %d the DS points at", matched, key.KeyTag())
	}
	if !strings.Contains(detail, "verifies") {
		t.Errorf("detail %q should say the signature verified", detail)
	}
}

// The root KSK is mid-rollover in this era, so the anchor list holds two DS
// records and only one of them can match. Accepting ANY configured anchor is
// the whole reason the list is a list: a validator that insisted on the first
// entry would call the entire internet bogus on rollover day.
func TestTraceCheckKeysAcceptsAnyConfiguredAnchor(t *testing.T) {
	t.Parallel()
	key, rrset, sig, ds := traceTestZone(t, "example.test")

	// A second, unrelated anchor sitting AHEAD of the real one.
	other, _, _, decoy := traceTestZone(t, "example.test")
	if other.KeyTag() == key.KeyTag() {
		t.Skip("two generated keys collided on key tag, which says nothing about this code")
	}

	_, status, detail := traceCheckKeys([]*dns.DS{decoy, ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{sig})
	if status != traceSecure {
		t.Fatalf("status = %q (%s), want %q: a non-matching anchor before the matching one must not veto it",
			status, detail, traceSecure)
	}
}

// A DS whose digest does not reproduce the key is the classic broken
// delegation — the dnssec-failed.org shape. It must be bogus, and the wording
// must name the digest rather than blaming the signature.
func TestTraceCheckKeysRejectsAMismatchedDigest(t *testing.T) {
	t.Parallel()
	key, rrset, sig, ds := traceTestZone(t, "example.test")

	// Same key tag and algorithm, different digest: this is precisely the case
	// the cheap key-tag pre-filter would wave through, so it is the one worth
	// testing.
	broken := *ds
	broken.Digest = strings.Repeat("ab", len(ds.Digest)/2)
	if strings.EqualFold(broken.Digest, ds.Digest) {
		t.Fatal("the deliberately broken digest is identical to the real one")
	}

	_, status, detail := traceCheckKeys([]*dns.DS{&broken}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{sig})
	if status != traceBogus {
		t.Fatalf("status = %q (%s), want %q", status, detail, traceBogus)
	}
	if !strings.Contains(detail, "matching digest") {
		t.Errorf("detail %q should say no key matched the digest", detail)
	}
}

// The digest matches but the signature over the key set was made by somebody
// else. A validator that stopped at the digest would call this secure.
func TestTraceCheckKeysRejectsAnUnsignedKeySet(t *testing.T) {
	t.Parallel()
	key, rrset, _, ds := traceTestZone(t, "example.test")
	_, _, foreignSig, _ := traceTestZone(t, "example.test")

	_, status, detail := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{foreignSig})
	if status != traceBogus {
		t.Fatalf("status = %q (%s), want %q: the DS matched but nothing signed the key set", status, detail, traceBogus)
	}
}

// An expired signature breaks validation for everyone, and is one of the most
// common real DNSSEC outages. Cryptographically the signature is perfect, so
// only the validity-period check catches it.
func TestTraceCheckKeysRejectsAnExpiredSignature(t *testing.T) {
	t.Parallel()
	key, signer := traceTestKey(t, "example.test")
	rrset := []dns.RR{key}
	ds := key.ToDS(dns.SHA256)

	// Signed for real, over a window that closed a week ago. Cryptographically
	// this signature is perfect, so nothing but the validity check can catch
	// it — which is the point.
	past := time.Now().Add(-30 * 24 * time.Hour)
	expired := traceTestSign(t, key, signer, rrset, past, past.Add(14*24*time.Hour))
	if err := expired.Verify(key, rrset); err != nil {
		t.Fatalf("the expired signature should still verify cryptographically, got %v", err)
	}
	if expired.ValidityPeriod(time.Time{}) {
		t.Fatal("the deliberately expired signature still reports as in-window")
	}

	_, status, detail := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{expired})
	if status != traceBogus {
		t.Fatalf("status = %q (%s), want %q", status, detail, traceBogus)
	}
	if !strings.Contains(detail, "validity period") {
		t.Errorf("detail %q should name the expiry, not blame the digest", detail)
	}
}

// The shipped anchors have to parse, and both live root KSKs have to be in
// there. A single-anchor list is the bug this test exists to prevent.
func TestTraceRootAnchorsCarryBothLiveRootKSKs(t *testing.T) {
	t.Parallel()
	if len(traceRootAnchors) < 2 {
		t.Fatalf("configured %d root anchors, want both KSK-2017 and KSK-2024 — a single pinned key breaks on rollover day", len(traceRootAnchors))
	}
	want := map[uint16]bool{20326: false, 38696: false}
	for _, ds := range traceRootAnchors {
		if ds.Hdr.Name != "." {
			t.Errorf("anchor %d is owned by %q, want the root", ds.KeyTag, ds.Hdr.Name)
		}
		if ds.DigestType != dns.SHA256 {
			t.Errorf("anchor %d uses digest type %d, want SHA-256", ds.KeyTag, ds.DigestType)
		}
		if _, ok := want[ds.KeyTag]; ok {
			want[ds.KeyTag] = true
		}
	}
	for tag, seen := range want {
		if !seen {
			t.Errorf("root anchor for key tag %d is missing", tag)
		}
	}
}

// The address guard is the one place a walk's target is chosen by somebody
// else's zone file, so a nameserver name pointing at loopback or a private
// range must never be sent a packet.
func TestTraceServerRefusesUnroutableAddresses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		srv  traceServer
		want string
	}{
		{"loopback", traceServer{Name: "ns.evil.test.", IP: "127.0.0.1"}, ""},
		{"private", traceServer{Name: "ns.evil.test.", IP: "10.1.2.3"}, ""},
		{"link-local metadata", traceServer{Name: "ns.evil.test.", IP: "169.254.169.254"}, ""},
		{"unspecified", traceServer{Name: "ns.evil.test.", IP: "0.0.0.0"}, ""},
		{"ipv6 loopback only", traceServer{Name: "ns.evil.test.", IP6: "::1"}, ""},
		// Addresses that are neither loopback nor private and so sail past
		// spread.go's routable(), but that no nameserver lives at. trace.go is
		// the caller that takes addresses straight out of a third party's
		// referral, so its guard has to be the stricter one: glue of 224.0.0.1
		// would otherwise make this host query the all-hosts multicast group.
		{"multicast", traceServer{Name: "ns.evil.test.", IP: "224.0.0.1"}, ""},
		{"ssdp multicast", traceServer{Name: "ns.evil.test.", IP: "239.255.255.250"}, ""},
		{"broadcast", traceServer{Name: "ns.evil.test.", IP: "255.255.255.255"}, ""},
		{"carrier-grade NAT", traceServer{Name: "ns.evil.test.", IP: "100.64.1.1"}, ""},
		{"TEST-NET-1", traceServer{Name: "ns.evil.test.", IP: "192.0.2.1"}, ""},
		{"benchmarking", traceServer{Name: "ns.evil.test.", IP: "198.18.0.1"}, ""},
		{"reserved 240/4", traceServer{Name: "ns.evil.test.", IP: "241.0.0.1"}, ""},
		{"ipv6 multicast", traceServer{Name: "ns.evil.test.", IP6: "ff02::1"}, ""},
		{"ipv6 documentation", traceServer{Name: "ns.evil.test.", IP6: "2001:db8::1"}, ""},

		// Real, globally routable addresses: the root servers' own, so the
		// happy path is not asserted against documentation space that the
		// guard above is right to refuse.
		{"public v4", traceServer{Name: "ns.ok.test.", IP: "198.41.0.4"}, "198.41.0.4:53"},
		{"v4 preferred over v6", traceServer{Name: "ns.ok.test.", IP: "198.41.0.4", IP6: "2001:500:2::c"}, "198.41.0.4:53"},
		{"v6 when that is all there is", traceServer{Name: "ns.ok.test.", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
		{"private v4 does not hide a usable v6", traceServer{Name: "ns.ok.test.", IP: "10.0.0.1", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
		{"reserved v4 does not hide a usable v6", traceServer{Name: "ns.ok.test.", IP: "100.64.1.1", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
	} {
		if got := tc.srv.addr(); got != tc.want {
			t.Errorf("%s: addr() = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Every root hint this walk starts from has to pass its own guard, or the
	// walk would refuse to leave the ground.
	for _, h := range traceRootHints {
		if !traceRoutable(h.IP) {
			t.Errorf("root hint %s (%s) is refused by traceRoutable", h.Name, h.IP)
		}
		if !traceRoutable(h.IP6) {
			t.Errorf("root hint %s (%s) is refused by traceRoutable", h.Name, h.IP6)
		}
	}
}

// A referral must descend. Following an NS set whose owner is the zone we
// just asked, or one outside it, is how a walk loops forever.
func TestTraceReferralOnlyDescends(t *testing.T) {
	t.Parallel()

	msg := func(owner string, ns ...string) *dns.Msg {
		m := new(dns.Msg)
		for _, n := range ns {
			m.Ns = append(m.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 172800},
				Ns:  n,
			})
		}
		return m
	}

	const qname = "www.example.com."

	if child, names := traceReferral(msg("com.", "b.gtld-servers.net.", "a.gtld-servers.net."), ".", qname); child != "com." {
		t.Errorf("root referral to com. = %q (%v), want com.", child, names)
	} else if len(names) != 2 || names[0] != "a.gtld-servers.net." {
		t.Errorf("nameservers = %v, want them sorted and de-duplicated", names)
	}

	// The zone answering with its own NS set is not a delegation downwards.
	if child, _ := traceReferral(msg("com.", "a.gtld-servers.net."), "com.", qname); child != "" {
		t.Errorf("a self-referral returned %q, want none — following it loops", child)
	}
	// An NS set for a name outside the zone we asked is not ours to follow.
	if child, _ := traceReferral(msg("evil.test.", "ns.evil.test."), "com.", qname); child != "" {
		t.Errorf("an out-of-tree referral returned %q, want none", child)
	}
	// Below the zone we asked, and nowhere near the name we are looking for.
	// Following it aims the rest of the walk — its hops, its chain links and
	// its packets — at a zone nobody asked about, while the page presents the
	// result as the delegation for what the visitor typed.
	if child, names := traceReferral(msg("other.example.com.", "ns1.attacker.test."), "com.", qname); child != "" {
		t.Errorf("a referral to %q (%v) was followed while heading for %s; only a cut on the path may be", child, names, qname)
	}
	// The same cut IS on the path for a name inside it.
	if child, _ := traceReferral(msg("other.example.com.", "ns1.example.com."), "com.", "a.other.example.com."); child != "other.example.com." {
		t.Errorf("a referral on the path returned %q, want other.example.com.", child)
	}
	// The apex of the delegated zone is itself on the path.
	if child, _ := traceReferral(msg("example.com.", "ns1.example.com."), "com.", "example.com."); child != "example.com." {
		t.Errorf("the delegation of the name itself returned %q, want example.com.", child)
	}
	// No NS records at all is the end of the walk, not a crash.
	if child, _ := traceReferral(new(dns.Msg), "com.", qname); child != "" {
		t.Errorf("an empty response returned %q, want none", child)
	}
}

// The starting root is picked from the name, so a walk is repeatable (the page
// prints which root it used) while different names spread over all thirteen.
func TestTraceRotateIsDeterministicAndComplete(t *testing.T) {
	t.Parallel()

	first := traceRotate(traceRootHints, "example.com.")
	again := traceRotate(traceRootHints, "example.com.")
	if first[0].Name != again[0].Name {
		t.Errorf("the same name started at %q then %q; the walk must be repeatable", first[0].Name, again[0].Name)
	}
	if len(first) != len(traceRootHints) {
		t.Fatalf("rotation returned %d hints, want all %d — a dead root must still be a fallback", len(first), len(traceRootHints))
	}
	seen := map[string]bool{}
	for _, h := range first {
		if h.IP == "" {
			t.Errorf("root hint %q has no IPv4 address", h.Name)
		}
		seen[h.Name] = true
	}
	if len(seen) != len(traceRootHints) {
		t.Errorf("rotation lost or duplicated hints: %d distinct of %d", len(seen), len(traceRootHints))
	}

	// Different names must not all pile onto one root.
	starts := map[string]bool{}
	for _, n := range []string{"a.test.", "b.test.", "c.test.", "d.test.", "e.test.", "f.test.", "g.test."} {
		starts[traceRotate(traceRootHints, n)[0].Name] = true
	}
	if len(starts) < 2 {
		t.Errorf("seven names all started at the same root (%v); the rotation is not spreading load", starts)
	}

	// An empty list is not a division by zero.
	if got := traceRotate(nil, "example.com."); len(got) != 0 {
		t.Errorf("rotating nothing returned %v", got)
	}
}

// The budget is the only thing between a public endpoint and an unbounded
// walk, so it has to hold on both axes: the query ceiling and a dead context.
func TestTraceBudgetStopsTheWalk(t *testing.T) {
	t.Parallel()

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	for i := 0; i < traceMaxQueries; i++ {
		if !w.spend() {
			t.Fatalf("budget refused query %d of %d", i+1, traceMaxQueries)
		}
	}
	if w.spend() {
		t.Fatalf("budget allowed a %dst query past its ceiling of %d", traceMaxQueries+1, traceMaxQueries)
	}
	if !w.out.Truncated {
		t.Error("hitting the ceiling must be reported as a truncated walk, not hidden")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	w2 := &traceWalk{ctx: cancelled, out: &Trace{}}
	if w2.spend() {
		t.Error("a cancelled request still sent a query")
	}
	if !w2.out.Truncated {
		t.Error("a cancelled walk must be marked truncated")
	}
}

// The section filters feed RRSIG.Verify, which rejects a mixed RRset outright.
// Handing it a whole answer section would fail every signature for the wrong
// reason, so the owner and type filtering is load-bearing.
func TestTraceRRsetFiltersByOwnerAndType(t *testing.T) {
	t.Parallel()

	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}}
	other := &dns.A{Hdr: dns.RR_Header{Name: "other.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}}
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}}
	sigA := &dns.RRSIG{Hdr: dns.RR_Header{Name: "WWW.example.test.", Rrtype: dns.TypeRRSIG}, TypeCovered: dns.TypeA}
	sigC := &dns.RRSIG{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeRRSIG}, TypeCovered: dns.TypeCNAME}
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY}}
	all := []dns.RR{a, other, cname, sigA, sigC, key}

	if got := traceRRset(all, "www.example.test.", dns.TypeA); len(got) != 1 || got[0] != dns.RR(a) {
		t.Errorf("traceRRset picked %v, want only the one A record for that owner", got)
	}
	// Owners are compared case-insensitively: a server may echo the name back
	// in whatever case it was asked in.
	if got := traceSigs(all, "www.EXAMPLE.test.", dns.TypeA); len(got) != 1 || got[0] != sigA {
		t.Errorf("traceSigs picked %v, want the A signature regardless of case", got)
	}
	if got := traceKeys(all, "example.test."); len(got) != 1 || got[0] != key {
		t.Errorf("traceKeys picked %v, want the one DNSKEY", got)
	}
	if got := traceKeys(all, "www.example.test."); len(got) != 0 {
		t.Errorf("traceKeys picked %v for a name that owns no key", got)
	}
}

// A DNSKEY RRset that arrives with no RRSIG at all is a transport problem, not
// a broken zone. A middlebox that strips EDNS so the server never sees the DO
// bit produces exactly this, and the difference between "the signature failed"
// and "the signature never reached us" is the difference between a lost packet
// and telling a domain owner their zone is down for every validating resolver.
func TestTraceCheckKeysSeparatesAMissingSignatureFromAFailedOne(t *testing.T) {
	t.Parallel()
	key, rrset, _, ds := traceTestZone(t, "example.test")

	_, status, detail := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, nil)
	if status != traceUnknown {
		t.Fatalf("status = %q (%s), want %q: no signature came back, so nothing failed", status, detail, traceUnknown)
	}
	if !strings.Contains(detail, "never returned") {
		t.Errorf("detail %q should say the signature did not arrive, not that it failed", detail)
	}

	// And the genuinely broken case still is broken: a signature that is
	// present and does not verify.
	_, _, foreignSig, _ := traceTestZone(t, "example.test")
	if _, st, _ := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{foreignSig}); st != traceBogus {
		t.Errorf("a present-but-invalid signature gave %q, want %q", st, traceBogus)
	}
}

// A link nobody answered for must not be reported as a broken chain. Three
// lost UDP packets, or a blocked TCP fallback on a large DNSKEY set, is a
// failure on the way to the servers and says nothing about the zone.
//
// Driven with a server list whose only entry has an address the walk refuses
// to send to: query() then returns no message and answered == false, which is
// the same shape a total transport failure produces, without a packet leaving
// this process.
func TestValidateZoneDoesNotCallAnUnansweredLinkBroken(t *testing.T) {
	t.Parallel()
	_, _, _, ds := traceTestZone(t, "example.test")

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	link, keys := w.validateZone("example.test.", "test.",
		[]traceServer{{Name: "ns.example.test.", IP: "10.0.0.1"}},
		traceDS{set: []*dns.DS{ds}, status: traceDSVerified}, true)

	if link.Status != traceUnknown {
		t.Fatalf("status = %q (%s), want %q — nobody answered, so nothing is proved either way", link.Status, link.Detail, traceUnknown)
	}
	if keys != nil {
		t.Errorf("keys = %v, want none", keys)
	}
	if len(link.Unanswered) == 0 {
		t.Error("an unanswered link must name the servers that would not answer")
	}
	for _, bad := range []string{"broken", "bogus", "does not verify"} {
		if strings.Contains(strings.ToLower(link.Detail), bad) {
			t.Errorf("detail %q accuses the zone of %q on the strength of a transport failure", link.Detail, bad)
		}
	}
}

// A DS that arrives without a signature is reported as unchecked, with its own
// sentence, rather than as a parent whose word failed.
func TestValidateZoneSeparatesAnUnsignedDSFromABogusOne(t *testing.T) {
	t.Parallel()
	_, _, _, ds := traceTestZone(t, "example.test")
	servers := []traceServer{{Name: "ns.example.test.", IP: "10.0.0.1"}}

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	unsigned, _ := w.validateZone("example.test.", "test.", servers,
		traceDS{set: []*dns.DS{ds}, status: traceDSUnsigned}, true)
	if unsigned.Status != traceUnknown {
		t.Errorf("a DS with no RRSIG gave %q (%s), want %q", unsigned.Status, unsigned.Detail, traceUnknown)
	}
	if !strings.Contains(unsigned.Detail, "never arrived") {
		t.Errorf("detail %q should name the missing signature, not a failed one", unsigned.Detail)
	}

	bogus, _ := w.validateZone("example.test.", "test.", servers,
		traceDS{set: []*dns.DS{ds}, status: traceDSBogus}, true)
	if bogus.Status != traceBogus {
		t.Errorf("a DS whose signature failed gave %q, want %q", bogus.Status, traceBogus)
	}

	noAnswer, _ := w.validateZone("example.test.", "test.", servers,
		traceDS{status: traceDSNoAnswer, unanswered: []string{"ns.example.test.: no response"}}, true)
	if noAnswer.Status != traceUnknown {
		t.Errorf("an unanswered DS query gave %q, want %q", noAnswer.Status, traceUnknown)
	}
	if len(noAnswer.Unanswered) == 0 {
		t.Error("an unanswered DS link must name the servers")
	}

	absent, _ := w.validateZone("example.test.", "test.", servers, traceDS{status: traceDSAbsent}, true)
	if absent.Status != traceInsecure {
		t.Errorf("no DS at all gave %q, want %q — an unsigned zone is ordinary", absent.Status, traceInsecure)
	}
	if !strings.Contains(strings.ToLower(absent.Detail), "most names are") {
		t.Errorf("detail %q should say plainly that unsigned is the common case", absent.Detail)
	}
}

// AA=1 is not "this rung's zone owns the name". A parent and its child very
// often share nameservers, and then the parent's server answers the child's
// name directly. Missing that cut meant validating the child's records under
// the parent's keys, which cannot work, and calling the result bogus.
func TestTraceAnswerZoneFindsACutNoReferralAnnounced(t *testing.T) {
	t.Parallel()

	sigOver := func(owner, signer string, covers uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
			TypeCovered: covers, SignerName: signer,
		}
	}
	soa := func(owner string) *dns.SOA {
		return &dns.SOA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET}}
	}

	// The live case: cz.'s servers answer www.nic.cz with AA=1, and the RRSIG
	// says nic.cz signed it.
	signed := new(dns.Msg)
	signed.Answer = []dns.RR{sigOver("www.nic.cz.", "nic.cz.", dns.TypeA)}
	if got := traceAnswerZone(signed, "www.nic.cz.", "cz."); got != "nic.cz." {
		t.Errorf("signer witness gave %q, want nic.cz.", got)
	}

	// NODATA: the SOA in the authority section names the zone instead.
	nodata := new(dns.Msg)
	nodata.Ns = []dns.RR{soa("nic.cz.")}
	if got := traceAnswerZone(nodata, "ns.nic.cz.", "cz."); got != "nic.cz." {
		t.Errorf("SOA witness gave %q, want nic.cz.", got)
	}

	// The ordinary case: the zone we are standing on is the zone that signed.
	same := new(dns.Msg)
	same.Answer = []dns.RR{sigOver("www.example.com.", "example.com.", dns.TypeA)}
	if got := traceAnswerZone(same, "www.example.com.", "example.com."); got != "" {
		t.Errorf("a zone signing its own name reported a cut at %q; there is none", got)
	}

	// A signer that is not on the path to the name asked for must not steer
	// the walk: the DS and DNSKEY queries it would cost are packets aimed at a
	// zone nobody asked about.
	stray := new(dns.Msg)
	stray.Answer = []dns.RR{sigOver("www.example.com.", "other.example.com.", dns.TypeA)}
	if got := traceAnswerZone(stray, "www.example.com.", "example.com."); got != "" {
		t.Errorf("an off-path signer steered the walk to %q", got)
	}

	// A signer ABOVE the zone being walked is not a cut below it either.
	above := new(dns.Msg)
	above.Answer = []dns.RR{sigOver("www.example.com.", "com.", dns.TypeA)}
	if got := traceAnswerZone(above, "www.example.com.", "example.com."); got != "" {
		t.Errorf("a signer above the current zone reported a cut at %q", got)
	}

	// Two witnesses at different depths: the first cut below where we stand
	// is the one to cross.
	deep := new(dns.Msg)
	deep.Answer = []dns.RR{
		sigOver("a.b.example.com.", "b.example.com.", dns.TypeA),
		sigOver("a.b.example.com.", "example.com.", dns.TypeA),
	}
	if got := traceAnswerZone(deep, "a.b.example.com.", "com."); got != "example.com." {
		t.Errorf("shallowest-first: got %q, want example.com.", got)
	}
}

// finish() must prove the records the page SHOWS. A CNAME whose target lives
// in the same zone puts the target's records in the same message, and those
// are what the page prints; verifying the alias and then claiming "the records
// themselves verify" over the target's addresses is a green tick over data
// nothing looked at.
func TestFinishVerifiesTheRecordsItDisplaysNotTheAlias(t *testing.T) {
	t.Parallel()

	// One zone, one key, signing only the CNAME. The target's A record is left
	// entirely unsigned, which is what the old code waved through.
	zoneKey, zoneSigner := traceTestKey(t, "example.test")
	now := time.Now()
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.example.test.",
	}
	cnameSig := traceTestSign(t, zoneKey, zoneSigner, []dns.RR{cname}, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "target.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4"),
	}
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{cname, cnameSig, a}

	w := &traceWalk{ctx: context.Background(), out: &Trace{Answer: []string{}, Notes: []Note{}}}
	w.finish("example.test.", "www.example.test.", "A", resp, []*dns.DNSKEY{zoneKey}, true)

	if len(w.out.Answer) != 1 || w.out.Answer[0] != "1.2.3.4" {
		t.Fatalf("Answer = %v, want the target address the page prints", w.out.Answer)
	}
	if w.out.AnswerVerified {
		t.Error("AnswerVerified is true for an UNSIGNED target record; the page renders that as proof over those addresses")
	}
	if w.out.AnswerSigned {
		t.Error("AnswerSigned is true although the displayed records carry no signature")
	}
	if w.answer != traceAnswerUnsigned {
		t.Errorf("answer state = %q, want %q", w.answer, traceAnswerUnsigned)
	}

	// Sign the target too, and the claim becomes true.
	aSig := traceTestSign(t, zoneKey, zoneSigner, []dns.RR{a}, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	resp2 := new(dns.Msg)
	resp2.Answer = []dns.RR{cname, cnameSig, a, aSig}
	w2 := &traceWalk{ctx: context.Background(), out: &Trace{Answer: []string{}, Notes: []Note{}}}
	w2.finish("example.test.", "www.example.test.", "A", resp2, []*dns.DNSKEY{zoneKey}, true)
	if !w2.out.AnswerVerified || !w2.out.AnswerSigned {
		t.Errorf("a signed target gave signed=%v verified=%v, want both true", w2.out.AnswerSigned, w2.out.AnswerVerified)
	}

	// And an alias with no target records at all is judged on the alias, which
	// is the only thing the page then shows.
	resp3 := new(dns.Msg)
	resp3.Answer = []dns.RR{cname, cnameSig}
	w3 := &traceWalk{ctx: context.Background(), out: &Trace{Answer: []string{}, Notes: []Note{}}}
	w3.finish("example.test.", "www.example.test.", "A", resp3, []*dns.DNSKEY{zoneKey}, true)
	if !w3.out.AnswerVerified || w3.out.CNAME != "target.example.test." {
		t.Errorf("an alias-only answer gave cname=%q verified=%v, want the alias verified",
			w3.out.CNAME, w3.out.AnswerVerified)
	}
}

// A signature made by a zone whose keys this walk never anchored is not this
// walk's to judge. "We cannot tell" is a different sentence from "this is
// broken", and printing the second was the www.nic.cz false verdict.
func TestFinishWillNotCallAForeignSignatureBogus(t *testing.T) {
	t.Parallel()
	parentKey, _ := traceTestKey(t, "cz")
	childKey, childSigner := traceTestKey(t, "nic.cz")

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.nic.cz.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("217.31.205.50"),
	}
	now := time.Now()
	sig := traceTestSign(t, childKey, childSigner, []dns.RR{a}, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{a, sig}

	// Standing at cz. with cz.'s keys, looking at a signature made by nic.cz.
	w := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: "cz.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "cz.", Status: traceSecure}},
	}}
	w.finish("cz.", "www.nic.cz.", "A", resp, []*dns.DNSKEY{parentKey}, true)
	w.verdict()

	if w.answer != traceAnswerForeign {
		t.Fatalf("answer state = %q, want %q", w.answer, traceAnswerForeign)
	}
	if w.out.DNSSEC == traceBogus {
		t.Error("a signature by a zone whose keys we never anchored was reported as bogus")
	}
	if w.out.DNSSEC != traceUnknown {
		t.Errorf("DNSSEC = %q, want %q", w.out.DNSSEC, traceUnknown)
	}
	if strings.Contains(strings.ToLower(w.out.Verdict.Text), "servfail") {
		t.Errorf("verdict %q threatens SERVFAIL over a signature it could not check", w.out.Verdict.Text)
	}

	// The same signature, checked against the keys that actually made it, is
	// the good case — so the guard above is not just refusing to ever verify.
	w2 := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: "nic.cz.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "nic.cz.", Status: traceSecure}},
	}}
	w2.finish("nic.cz.", "www.nic.cz.", "A", resp, []*dns.DNSKEY{childKey}, true)
	w2.verdict()
	if !w2.out.AnswerVerified || w2.out.DNSSEC != traceSecure {
		t.Errorf("the right keys gave verified=%v dnssec=%q, want true/secure", w2.out.AnswerVerified, w2.out.DNSSEC)
	}

	// A signature made by THIS zone that does not verify is still bogus: the
	// guard above must not have turned the verifier into a no-op.
	broken, brokenSigner := traceTestKey(t, "nic.cz")
	badSig := traceTestSign(t, broken, brokenSigner, []dns.RR{a}, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	badSig.KeyTag = childKey.KeyTag() // claims to be the anchored key, is not
	resp3 := new(dns.Msg)
	resp3.Answer = []dns.RR{a, badSig}
	w3 := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: "nic.cz.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "nic.cz.", Status: traceSecure}},
	}}
	w3.finish("nic.cz.", "www.nic.cz.", "A", resp3, []*dns.DNSKEY{childKey}, true)
	w3.verdict()
	if w3.answer != traceAnswerFailed || w3.out.DNSSEC != traceBogus {
		t.Errorf("a failing signature by this very zone gave state=%q dnssec=%q, want %q/%q",
			w3.answer, w3.out.DNSSEC, traceAnswerFailed, traceBogus)
	}
}

// An empty answer is not a proved absence. Reporting NXDOMAIN or NODATA as
// "secure" with a green tick is a cryptographic claim on zero cryptographic
// evidence: the proof of an absence is an NSEC or NSEC3 record, and this walk
// does not read one.
func TestVerdictWillNotCallAnUncheckedAbsenceSecure(t *testing.T) {
	t.Parallel()

	for _, rcode := range []string{"NXDOMAIN", "NOERROR"} {
		w := &traceWalk{ctx: context.Background(), out: &Trace{
			Answer: []string{}, Notes: []Note{}, AnswerZone: "example.test.", AnswerRcode: rcode,
			Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "example.test.", Status: traceSecure}},
		}}
		w.worsen(traceAnswerNone)
		w.verdict()

		if w.out.DNSSEC == traceSecure {
			t.Errorf("%s: DNSSEC = secure with no denial-of-existence evidence at all", rcode)
		}
		if w.out.DNSSEC != traceUnknown {
			t.Errorf("%s: DNSSEC = %q, want %q", rcode, w.out.DNSSEC, traceUnknown)
		}
		// The caveat has to be in the verdict itself, not delegated to a card
		// further down the page that a reader may never reach.
		if !strings.Contains(w.out.Verdict.Text, "NSEC") {
			t.Errorf("%s: the verdict %q does not carry the NSEC caveat", rcode, w.out.Verdict.Text)
		}
		if w.out.Verdict.Level == "ok" {
			t.Errorf("%s: the verdict is level %q, which the page renders as a green tick", rcode, w.out.Verdict.Level)
		}
	}
}

// The verdict paragraph lives in exactly one place. It used to be written
// twice — once as a Note and again, differently worded, in the template — so
// an edit to one drifted silently from the other.
func TestVerdictIsNotAlsoAppendedToNotes(t *testing.T) {
	t.Parallel()

	w := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{"1.2.3.4"}, Notes: []Note{}, AnswerZone: "example.test.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "example.test.", Status: traceSecure}},
	}}
	w.worsen(traceAnswerVerified)
	w.verdict()

	if w.out.Verdict.Text == "" || w.out.DNSSEC != traceSecure {
		t.Fatalf("verdict = %q / %q, want a secure verdict with text", w.out.DNSSEC, w.out.Verdict.Text)
	}
	for _, n := range w.out.Notes {
		if n.Text == w.out.Verdict.Text {
			t.Errorf("the verdict is repeated in Notes as well: %q", n.Text)
		}
	}
}

// A response that arrived is not the same thing as an answer. This is the
// predicate the DNSKEY, DS and answer sites all consult, and getting it wrong
// is what printed "this name's chain of trust is broken" about the root zone,
// live, several times an hour, on a healthy network.
func TestTraceUnreadableSeparatesAFragmentFromAnAnswer(t *testing.T) {
	t.Parallel()

	whole := new(dns.Msg)
	if why := traceUnreadable(whole, false); why != "" {
		t.Errorf("a whole NOERROR message was called unreadable: %q", why)
	}

	// TC=1 survives only when ask()'s TCP retry did not complete, and what is
	// left is a PREFIX of the RRset: the DNSKEY the parent's DS points at may
	// be in the part that never arrived.
	frag := new(dns.Msg)
	frag.Truncated = true
	if traceUnreadable(frag, false) == "" {
		t.Error("a truncated reply was accepted as the zone's whole answer")
	}
	if traceUnreadable(frag, true) == "" {
		t.Error("a truncated reply was accepted as a final answer even at the end of the walk")
	}

	// An rcode instead of records tells us nothing about what the zone
	// publishes, so it cannot be evidence either way.
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeFormatError, dns.RcodeNotImplemented} {
		m := new(dns.Msg)
		m.Rcode = rcode
		if traceUnreadable(m, false) == "" {
			t.Errorf("%s was read as an answer about the zone's records", dns.RcodeToString[rcode])
		}
	}

	// NXDOMAIN is the one that depends on where we are standing. At the end of
	// the walk it is the zone's real and final word; while fetching that same
	// zone's keys it is a server contradicting the delegation that sent us to
	// it, which is a fact about the server.
	nx := new(dns.Msg)
	nx.Rcode = dns.RcodeNameError
	if why := traceUnreadable(nx, true); why != "" {
		t.Errorf("NXDOMAIN as the walk's answer was called unreadable: %q", why)
	}
	if traceUnreadable(nx, false) == "" {
		t.Error("NXDOMAIN for a zone's own DNSKEY set was taken as evidence about its keys")
	}
}

// The bug this whole guard exists for. A DNSKEY fetch that came back empty has
// several possible causes and exactly one of them is the zone's fault; the
// code used to reach traceBogus for all of them, and the user-facing sentence
// that produced told domain owners their name was broken for every validating
// resolver on the strength of one lost UDP packet.
func TestTraceKeySetVerdictWillNotCallALostPacketBroken(t *testing.T) {
	t.Parallel()

	accuses := func(t *testing.T, detail string) {
		t.Helper()
		for _, word := range []string{"broken", "bogus", "does not verify", "do not back it up"} {
			if strings.Contains(strings.ToLower(detail), word) {
				t.Errorf("detail %q accuses the zone of %q on the strength of a transport failure", detail, word)
			}
		}
	}

	// A truncated reply whose TCP retry did not complete. The root's DNSKEY
	// set is well over 512 bytes, so this is the common case, not an exotic
	// one.
	frag := new(dns.Msg)
	frag.Truncated = true
	status, detail, usable := traceKeySetVerdict(traceReply{msg: frag, answered: true}, false)
	if usable {
		t.Fatal("a truncated DNSKEY reply was handed on as a key set to read")
	}
	if status != traceUnknown {
		t.Errorf("a truncated DNSKEY reply gave %q, want %q", status, traceUnknown)
	}
	accuses(t, detail)

	// Every server that replied sent a fragment, so query() moved past them
	// all and there is no message at the end of it.
	status, detail, usable = traceKeySetVerdict(traceReply{answered: true, unreadable: "truncated"}, false)
	if usable || status != traceUnknown {
		t.Errorf("fragments from every server gave %q (usable=%v), want %q", status, usable, traceUnknown)
	}
	accuses(t, detail)

	// An rcode in place of a key set.
	bad := new(dns.Msg)
	bad.Rcode = dns.RcodeFormatError
	if status, detail, usable = traceKeySetVerdict(traceReply{msg: bad, answered: true}, false); usable || status != traceUnknown {
		t.Errorf("a FORMERR DNSKEY reply gave %q (usable=%v), want %q", status, usable, traceUnknown)
	}
	accuses(t, detail)

	// Nobody answered at all, and the walk running out of budget: both already
	// behaved, and both stay that way.
	if status, _, _ = traceKeySetVerdict(traceReply{}, false); status != traceUnknown {
		t.Errorf("an unanswered DNSKEY query gave %q, want %q", status, traceUnknown)
	}
	if status, _, _ = traceKeySetVerdict(traceReply{}, true); status != traceInsecure {
		t.Errorf("a walk that stopped gave %q, want %q", status, traceInsecure)
	}

	// The verifier must not have become a no-op. A server that answered with
	// SERVFAIL or REFUSED is still the zone's own servers failing to serve the
	// keys its parent's DS promises...
	if status, _, _ = traceKeySetVerdict(traceReply{answered: true}, false); status != traceBogus {
		t.Errorf("servers answering the DNSKEY query with an error gave %q, want %q", status, traceBogus)
	}
	// ...and a whole NOERROR message is still read, so a zone that genuinely
	// serves no keys under a DS is still caught.
	if _, _, usable = traceKeySetVerdict(traceReply{msg: new(dns.Msg), answered: true}, false); !usable {
		t.Error("a whole NOERROR reply was not read as a key set")
	}
}

// The DS side of the same mistake, and the quieter one. Reading an unreadable
// DS reply as "this parent publishes no DS" marks a signed zone unsigned and
// drags everything below it down with it, without ever printing a word that
// looks like an error.
func TestValidateZoneWillNotCallAnUnreadableDSAbsentOrBroken(t *testing.T) {
	t.Parallel()
	servers := []traceServer{{Name: "ns.example.test.", IP: "10.0.0.1"}}

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	link, keys := w.validateZone("example.test.", "test.", servers,
		traceDS{status: traceDSUnreadable, unanswered: []string{"ns.test.: answer truncated"},
			why: "the answer came back truncated"}, true)

	if link.Status != traceUnknown {
		t.Fatalf("status = %q (%s), want %q", link.Status, link.Detail, traceUnknown)
	}
	if link.Status == traceInsecure {
		t.Error("an unreadable DS was reported as an unsigned delegation")
	}
	if keys != nil {
		t.Errorf("keys = %v, want none", keys)
	}
	if len(link.Unanswered) == 0 {
		t.Error("a link that could not be checked must name the servers it could not read")
	}
	if !strings.Contains(link.Detail, "truncated") {
		t.Errorf("detail %q does not say what actually arrived", link.Detail)
	}
	for _, word := range []string{"unsigned", "broken", "bogus"} {
		if strings.Contains(strings.ToLower(link.Detail), word) {
			t.Errorf("detail %q calls the zone %q on the strength of a transport failure", link.Detail, word)
		}
	}
}

// A signature cannot verify over a fragment of the RRset it covers, and
// traceAnswerFailed is the one answer state verdict() turns into the word
// "broken". So a truncated answer must never reach the verifier at all.
func TestFinishWillNotJudgeASignatureOverAFragment(t *testing.T) {
	t.Parallel()
	key, signer := traceTestKey(t, "example.test")
	now := time.Now()

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4"),
	}
	// A signature over a record set that is not the one being shown: exactly
	// what a dropped A record out of a larger RRset leaves behind.
	other := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("5.6.7.8"),
	}
	sig := traceTestSign(t, key, signer, []dns.RR{a, other}, now.Add(-time.Hour), now.Add(14*24*time.Hour))

	resp := new(dns.Msg)
	resp.Truncated = true
	resp.Answer = []dns.RR{a, sig}

	w := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: "example.test.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "example.test.", Status: traceSecure}},
	}}
	w.finish("example.test.", "www.example.test.", "A", resp, []*dns.DNSKEY{key}, true)
	w.verdict()

	if w.answer == traceAnswerFailed {
		t.Fatal("a signature checked over a fragment of its own RRset was reported as a failed signature")
	}
	if w.answer != traceAnswerUnchecked {
		t.Errorf("answer state = %q, want %q", w.answer, traceAnswerUnchecked)
	}
	if w.out.DNSSEC == traceBogus {
		t.Errorf("verdict = bogus on a truncated answer: %q", w.out.Verdict.Text)
	}
	if w.out.AnswerVerified {
		t.Error("AnswerVerified is true for records the walk never saw in full")
	}
	if strings.Contains(strings.ToLower(w.out.Verdict.Text), "servfail") {
		t.Errorf("verdict %q threatens SERVFAIL over an answer it never read in full", w.out.Verdict.Text)
	}

	// The same records, whole, still verify — so the guard is a guard and not
	// a way of never checking anything.
	good := traceTestSign(t, key, signer, []dns.RR{a}, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	whole := new(dns.Msg)
	whole.Answer = []dns.RR{a, good}
	w2 := &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: "example.test.",
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "example.test.", Status: traceSecure}},
	}}
	w2.finish("example.test.", "www.example.test.", "A", whole, []*dns.DNSKEY{key}, true)
	w2.verdict()
	if !w2.out.AnswerVerified || w2.out.DNSSEC != traceSecure {
		t.Errorf("a whole signed answer gave verified=%v dnssec=%q, want true/secure", w2.out.AnswerVerified, w2.out.DNSSEC)
	}
}
