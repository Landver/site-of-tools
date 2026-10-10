package dnstools

import (
	"context"
	"crypto"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Landver/site-of-tools/platform"
)

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

// traceTestSign signs for real: RRSIG timestamps are signed, so an expired one can't be faked.
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

func traceTestSignNow(t *testing.T, key *dns.DNSKEY, signer crypto.Signer, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	now := time.Now()
	return traceTestSign(t, key, signer, rrset, now.Add(-time.Hour), now.Add(14*24*time.Hour))
}

// traceTestZone returns a KSK, its DNSKEY RRset, a valid RRSIG over it and the parent's DS.
func traceTestZone(t *testing.T, zone string) (key *dns.DNSKEY, rrset []dns.RR, sig *dns.RRSIG, ds *dns.DS) {
	t.Helper()
	key, signer := traceTestKey(t, zone)
	rrset = []dns.RR{key}
	sig = traceTestSignNow(t, key, signer, rrset)
	return key, rrset, sig, key.ToDS(dns.SHA256)
}

// traceSecureWalk stands on zone with a secure chain from the root down to it.
func traceSecureWalk(zone string) *traceWalk {
	return &traceWalk{ctx: context.Background(), out: &Trace{
		Answer: []string{}, Notes: []Note{}, AnswerZone: zone,
		Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: zone, Status: traceSecure}},
	}}
}

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

// Mid-rollover the root has two anchors and only one matches; any of them must do.
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

// The dnssec-failed.org shape: bogus, and the wording blames the digest, not the signature.
func TestTraceCheckKeysRejectsAMismatchedDigest(t *testing.T) {
	t.Parallel()
	key, rrset, sig, ds := traceTestZone(t, "example.test")

	// Same key tag and algorithm, so the cheap key-tag pre-filter alone would wave it through.
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

func TestTraceCheckKeysRejectsAnUnsignedKeySet(t *testing.T) {
	t.Parallel()
	key, rrset, _, ds := traceTestZone(t, "example.test")
	_, _, foreignSig, _ := traceTestZone(t, "example.test")

	_, status, detail := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{foreignSig})
	if status != traceBogus {
		t.Fatalf("status = %q (%s), want %q: the DS matched but nothing signed the key set", status, detail, traceBogus)
	}
}

func TestTraceCheckKeysRejectsAnExpiredSignature(t *testing.T) {
	t.Parallel()
	key, signer := traceTestKey(t, "example.test")
	rrset := []dns.RR{key}
	ds := key.ToDS(dns.SHA256)

	// Cryptographically perfect, so only the validity-period check can catch it.
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

// Glue is chosen by someone else's zone, so it must never reach loopback or private ranges.
func TestTraceServerRefusesUnroutableAddresses(t *testing.T) {
	t.Parallel()
	guarded := newTestService().WithEgressGuard(platform.NewEgressGuard([]string{"443"}, nil))
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
		// Not private, but glue of 224.0.0.1 would query the all-hosts multicast group.
		{"multicast", traceServer{Name: "ns.evil.test.", IP: "224.0.0.1"}, ""},
		{"ssdp multicast", traceServer{Name: "ns.evil.test.", IP: "239.255.255.250"}, ""},
		{"broadcast", traceServer{Name: "ns.evil.test.", IP: "255.255.255.255"}, ""},
		{"carrier-grade NAT", traceServer{Name: "ns.evil.test.", IP: "100.64.1.1"}, ""},
		{"TEST-NET-1", traceServer{Name: "ns.evil.test.", IP: "192.0.2.1"}, ""},
		{"benchmarking", traceServer{Name: "ns.evil.test.", IP: "198.18.0.1"}, ""},
		{"reserved 240/4", traceServer{Name: "ns.evil.test.", IP: "241.0.0.1"}, ""},
		{"ipv6 multicast", traceServer{Name: "ns.evil.test.", IP6: "ff02::1"}, ""},
		{"ipv6 documentation", traceServer{Name: "ns.evil.test.", IP6: "2001:db8::1"}, ""},

		// Root server addresses, since documentation space is rightly refused above.
		{"public v4", traceServer{Name: "ns.ok.test.", IP: "198.41.0.4"}, "198.41.0.4:53"},
		{"v4 preferred over v6", traceServer{Name: "ns.ok.test.", IP: "198.41.0.4", IP6: "2001:500:2::c"}, "198.41.0.4:53"},
		{"v6 when that is all there is", traceServer{Name: "ns.ok.test.", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
		{"private v4 does not hide a usable v6", traceServer{Name: "ns.ok.test.", IP: "10.0.0.1", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
		{"reserved v4 does not hide a usable v6", traceServer{Name: "ns.ok.test.", IP: "100.64.1.1", IP6: "2001:500:2::c"}, "[2001:500:2::c]:53"},
	} {
		for _, svc := range []*Service{nil, guarded} {
			if got := tc.srv.addr(svc); got != tc.want {
				t.Errorf("%s (guarded %v): addr() = %q, want %q", tc.name, svc != nil, got, tc.want)
			}
		}
	}

	for _, h := range traceRootHints {
		for _, ip := range []string{h.IP, h.IP6} {
			if !guarded.nsRoutable(ip) {
				t.Errorf("root hint %s (%s) is refused by nsRoutable", h.Name, ip)
			}
		}
	}
}

// A referral must descend: following a self-referral or an out-of-zone NS set loops forever.
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

	if child, _ := traceReferral(msg("com.", "a.gtld-servers.net."), "com.", qname); child != "" {
		t.Errorf("a self-referral returned %q, want none — following it loops", child)
	}
	if child, _ := traceReferral(msg("evil.test.", "ns.evil.test."), "com.", qname); child != "" {
		t.Errorf("an out-of-tree referral returned %q, want none", child)
	}
	// A cut below the zone but off the path would aim the walk at a zone nobody asked about.
	if child, names := traceReferral(msg("other.example.com.", "ns1.attacker.test."), "com.", qname); child != "" {
		t.Errorf("a referral to %q (%v) was followed while heading for %s; only a cut on the path may be", child, names, qname)
	}
	if child, _ := traceReferral(msg("other.example.com.", "ns1.example.com."), "com.", "a.other.example.com."); child != "other.example.com." {
		t.Errorf("a referral on the path returned %q, want other.example.com.", child)
	}
	if child, _ := traceReferral(msg("example.com.", "ns1.example.com."), "com.", "example.com."); child != "example.com." {
		t.Errorf("the delegation of the name itself returned %q, want example.com.", child)
	}
	if child, _ := traceReferral(new(dns.Msg), "com.", qname); child != "" {
		t.Errorf("an empty response returned %q, want none", child)
	}
}

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

	starts := map[string]bool{}
	for _, n := range []string{"a.test.", "b.test.", "c.test.", "d.test.", "e.test.", "f.test.", "g.test."} {
		starts[traceRotate(traceRootHints, n)[0].Name] = true
	}
	if len(starts) < 2 {
		t.Errorf("seven names all started at the same root (%v); the rotation is not spreading load", starts)
	}

	if got := traceRotate(nil, "example.com."); len(got) != 0 {
		t.Errorf("rotating nothing returned %v", got)
	}
}

// The budget bounds a public endpoint's walk on both axes: query count and a dead context.
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

// RRSIG.Verify rejects a mixed RRset, so the owner and type filtering is load-bearing.
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
	// A server may echo the owner back in whatever case it was asked in.
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

// No RRSIG at all is a transport problem (e.g. a middlebox stripping EDNS DO), not a broken zone.
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

	_, _, foreignSig, _ := traceTestZone(t, "example.test")
	if _, st, _ := traceCheckKeys([]*dns.DS{ds}, []*dns.DNSKEY{key}, rrset, []*dns.RRSIG{foreignSig}); st != traceBogus {
		t.Errorf("a present-but-invalid signature gave %q, want %q", st, traceBogus)
	}
}

// 10.0.0.1 is refused, so query() gets no answer: a total transport failure, offline.
func TestValidateZoneDoesNotCallAnUnansweredLinkBroken(t *testing.T) {
	t.Parallel()
	_, _, _, ds := traceTestZone(t, "example.test")

	w := &traceWalk{ctx: context.Background(), out: &Trace{}}
	link, keys := w.validateZone("example.test.", "test.",
		[]traceServer{{Name: "ns.example.test.", IP: "10.0.0.1"}}, verifiedDS(ds), true)

	if link.Status != traceUnknown {
		t.Fatalf("status = %q (%s), want %q — nobody answered, so nothing is proved either way", link.Status, link.Detail, traceUnknown)
	}
	if keys != nil {
		t.Errorf("keys = %v, want none", keys)
	}
	if len(link.Unanswered) == 0 {
		t.Error("an unanswered link must name the servers that would not answer")
	}
	accusesTheZone(t, "unanswered", link.Detail)
}

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

// Parent and child often share servers, so AA=1 from the parent's server can be the child's zone.
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

	// cz.'s servers answer www.nic.cz with AA=1; the RRSIG says nic.cz signed it.
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

	same := new(dns.Msg)
	same.Answer = []dns.RR{sigOver("www.example.com.", "example.com.", dns.TypeA)}
	if got := traceAnswerZone(same, "www.example.com.", "example.com."); got != "" {
		t.Errorf("a zone signing its own name reported a cut at %q; there is none", got)
	}

	stray := new(dns.Msg)
	stray.Answer = []dns.RR{sigOver("www.example.com.", "other.example.com.", dns.TypeA)}
	if got := traceAnswerZone(stray, "www.example.com.", "example.com."); got != "" {
		t.Errorf("an off-path signer steered the walk to %q", got)
	}

	above := new(dns.Msg)
	above.Answer = []dns.RR{sigOver("www.example.com.", "com.", dns.TypeA)}
	if got := traceAnswerZone(above, "www.example.com.", "example.com."); got != "" {
		t.Errorf("a signer above the current zone reported a cut at %q", got)
	}

	// Two witnesses: cross the shallowest cut below where we stand.
	deep := new(dns.Msg)
	deep.Answer = []dns.RR{
		sigOver("a.b.example.com.", "b.example.com.", dns.TypeA),
		sigOver("a.b.example.com.", "example.com.", dns.TypeA),
	}
	if got := traceAnswerZone(deep, "a.b.example.com.", "com."); got != "example.com." {
		t.Errorf("shallowest-first: got %q, want example.com.", got)
	}
}

// The page prints a same-zone CNAME target's records, so they, not just the alias, must verify.
func TestFinishVerifiesTheRecordsItDisplaysNotTheAlias(t *testing.T) {
	t.Parallel()

	zoneKey, zoneSigner := traceTestKey(t, "example.test")
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.example.test.",
	}
	cnameSig := traceTestSignNow(t, zoneKey, zoneSigner, []dns.RR{cname})
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

	aSig := traceTestSignNow(t, zoneKey, zoneSigner, []dns.RR{a})
	resp2 := new(dns.Msg)
	resp2.Answer = []dns.RR{cname, cnameSig, a, aSig}
	w2 := &traceWalk{ctx: context.Background(), out: &Trace{Answer: []string{}, Notes: []Note{}}}
	w2.finish("example.test.", "www.example.test.", "A", resp2, []*dns.DNSKEY{zoneKey}, true)
	if !w2.out.AnswerVerified || !w2.out.AnswerSigned {
		t.Errorf("a signed target gave signed=%v verified=%v, want both true", w2.out.AnswerSigned, w2.out.AnswerVerified)
	}

	resp3 := new(dns.Msg)
	resp3.Answer = []dns.RR{cname, cnameSig}
	w3 := &traceWalk{ctx: context.Background(), out: &Trace{Answer: []string{}, Notes: []Note{}}}
	w3.finish("example.test.", "www.example.test.", "A", resp3, []*dns.DNSKEY{zoneKey}, true)
	if !w3.out.AnswerVerified || w3.out.CNAME != "target.example.test." {
		t.Errorf("an alias-only answer gave cname=%q verified=%v, want the alias verified",
			w3.out.CNAME, w3.out.AnswerVerified)
	}
}

// A signature by a zone whose keys the walk never anchored is unknown, not bogus (www.nic.cz).
func TestFinishWillNotCallAForeignSignatureBogus(t *testing.T) {
	t.Parallel()
	parentKey, _ := traceTestKey(t, "cz")
	childKey, childSigner := traceTestKey(t, "nic.cz")

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.nic.cz.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("217.31.205.50"),
	}
	sig := traceTestSignNow(t, childKey, childSigner, []dns.RR{a})
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{a, sig}

	w := traceSecureWalk("cz.")
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

	w2 := traceSecureWalk("nic.cz.")
	w2.finish("nic.cz.", "www.nic.cz.", "A", resp, []*dns.DNSKEY{childKey}, true)
	w2.verdict()
	if !w2.out.AnswerVerified || w2.out.DNSSEC != traceSecure {
		t.Errorf("the right keys gave verified=%v dnssec=%q, want true/secure", w2.out.AnswerVerified, w2.out.DNSSEC)
	}

	broken, brokenSigner := traceTestKey(t, "nic.cz")
	badSig := traceTestSignNow(t, broken, brokenSigner, []dns.RR{a})
	badSig.KeyTag = childKey.KeyTag() // claims to be the anchored key, is not
	resp3 := new(dns.Msg)
	resp3.Answer = []dns.RR{a, badSig}
	w3 := traceSecureWalk("nic.cz.")
	w3.finish("nic.cz.", "www.nic.cz.", "A", resp3, []*dns.DNSKEY{childKey}, true)
	w3.verdict()
	if w3.answer != traceAnswerFailed || w3.out.DNSSEC != traceBogus {
		t.Errorf("a failing signature by this very zone gave state=%q dnssec=%q, want %q/%q",
			w3.answer, w3.out.DNSSEC, traceAnswerFailed, traceBogus)
	}
}

// Absence is proved by NSEC/NSEC3, which this walk does not read, so it is never "secure".
func TestVerdictWillNotCallAnUncheckedAbsenceSecure(t *testing.T) {
	t.Parallel()

	for _, rcode := range []string{"NXDOMAIN", "NOERROR"} {
		w := traceSecureWalk("example.test.")
		w.out.AnswerRcode = rcode
		w.worsen(traceAnswerNone)
		w.verdict()

		if w.out.DNSSEC == traceSecure {
			t.Errorf("%s: DNSSEC = secure with no denial-of-existence evidence at all", rcode)
		}
		if w.out.DNSSEC != traceUnknown {
			t.Errorf("%s: DNSSEC = %q, want %q", rcode, w.out.DNSSEC, traceUnknown)
		}
		if !strings.Contains(w.out.Verdict.Text, "NSEC") {
			t.Errorf("%s: the verdict %q does not carry the NSEC caveat", rcode, w.out.Verdict.Text)
		}
		if w.out.Verdict.Level == "ok" {
			t.Errorf("%s: the verdict is level %q, which the page renders as a green tick", rcode, w.out.Verdict.Level)
		}
	}
}

func TestVerdictIsNotAlsoAppendedToNotes(t *testing.T) {
	t.Parallel()

	w := traceSecureWalk("example.test.")
	w.out.Answer = []string{"1.2.3.4"}
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

func TestTraceUnreadableSeparatesAFragmentFromAnAnswer(t *testing.T) {
	t.Parallel()

	whole := new(dns.Msg)
	if why := traceUnreadable(whole, false); why != "" {
		t.Errorf("a whole NOERROR message was called unreadable: %q", why)
	}

	// TC=1 survives only a failed TCP retry and holds a prefix that may lack the DS's key.
	frag := new(dns.Msg)
	frag.Truncated = true
	if traceUnreadable(frag, false) == "" {
		t.Error("a truncated reply was accepted as the zone's whole answer")
	}
	if traceUnreadable(frag, true) == "" {
		t.Error("a truncated reply was accepted as a final answer even at the end of the walk")
	}

	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeFormatError, dns.RcodeNotImplemented} {
		m := new(dns.Msg)
		m.Rcode = rcode
		if traceUnreadable(m, false) == "" {
			t.Errorf("%s was read as an answer about the zone's records", dns.RcodeToString[rcode])
		}
	}

	// NXDOMAIN is final as the answer, but for a zone's own DNSKEY it contradicts the delegation.
	nx := new(dns.Msg)
	nx.Rcode = dns.RcodeNameError
	if why := traceUnreadable(nx, true); why != "" {
		t.Errorf("NXDOMAIN as the walk's answer was called unreadable: %q", why)
	}
	if traceUnreadable(nx, false) == "" {
		t.Error("NXDOMAIN for a zone's own DNSKEY set was taken as evidence about its keys")
	}
}

// Of the ways a DNSKEY fetch comes back empty, only a whole NOERROR is the zone's fault.
func TestTraceKeySetVerdictWillNotCallALostPacketBroken(t *testing.T) {
	t.Parallel()

	frag := new(dns.Msg)
	frag.Truncated = true
	status, detail, usable := traceKeySetVerdict(traceReply{msg: frag, answered: true}, false)
	if usable {
		t.Fatal("a truncated DNSKEY reply was handed on as a key set to read")
	}
	if status != traceUnknown {
		t.Errorf("a truncated DNSKEY reply gave %q, want %q", status, traceUnknown)
	}
	accusesTheZone(t, "truncated", detail)

	// Every server sent a fragment, so query() ends with no message.
	status, detail, usable = traceKeySetVerdict(traceReply{answered: true, unreadable: "truncated"}, false)
	if usable || status != traceUnknown {
		t.Errorf("fragments from every server gave %q (usable=%v), want %q", status, usable, traceUnknown)
	}
	accusesTheZone(t, "all fragments", detail)

	bad := new(dns.Msg)
	bad.Rcode = dns.RcodeFormatError
	if status, detail, usable = traceKeySetVerdict(traceReply{msg: bad, answered: true}, false); usable || status != traceUnknown {
		t.Errorf("a FORMERR DNSKEY reply gave %q (usable=%v), want %q", status, usable, traceUnknown)
	}
	accusesTheZone(t, "FORMERR", detail)

	if status, _, _ = traceKeySetVerdict(traceReply{}, false); status != traceUnknown {
		t.Errorf("an unanswered DNSKEY query gave %q, want %q", status, traceUnknown)
	}
	if status, _, _ = traceKeySetVerdict(traceReply{}, true); status != traceInsecure {
		t.Errorf("a walk that stopped gave %q, want %q", status, traceInsecure)
	}

	// SERVFAIL/REFUSED/NOTAUTH from every server: query() records answered but no message.
	if status, detail, _ = traceKeySetVerdict(traceReply{answered: true}, false); status != traceUnknown {
		t.Errorf("servers answering the DNSKEY query with an error gave %q, want %q", status, traceUnknown)
	}
	accusesTheZone(t, "rcode only", detail)
	if _, _, usable = traceKeySetVerdict(traceReply{msg: new(dns.Msg), answered: true}, false); !usable {
		t.Error("a whole NOERROR reply was not read as a key set")
	}
}

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
	accusesTheZone(t, "unreadable DS", link.Detail)
}

// A fragment can't verify, and verdict() calls traceAnswerFailed "broken": never check one.
func TestFinishWillNotJudgeASignatureOverAFragment(t *testing.T) {
	t.Parallel()
	key, signer := traceTestKey(t, "example.test")

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("1.2.3.4"),
	}
	// Signed over two A records, but the truncated reply carries only one.
	other := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("5.6.7.8"),
	}
	sig := traceTestSignNow(t, key, signer, []dns.RR{a, other})

	resp := new(dns.Msg)
	resp.Truncated = true
	resp.Answer = []dns.RR{a, sig}

	w := traceSecureWalk("example.test.")
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

	good := traceTestSignNow(t, key, signer, []dns.RR{a})
	whole := new(dns.Msg)
	whole.Answer = []dns.RR{a, good}
	w2 := traceSecureWalk("example.test.")
	w2.finish("example.test.", "www.example.test.", "A", whole, []*dns.DNSKEY{key}, true)
	w2.verdict()
	if !w2.out.AnswerVerified || w2.out.DNSSEC != traceSecure {
		t.Errorf("a whole signed answer gave verified=%v dnssec=%q, want true/secure", w2.out.AnswerVerified, w2.out.DNSSEC)
	}
}

func TestVerdictNamesKeysWithoutADS(t *testing.T) {
	t.Parallel()

	chain := func(noDS bool) *traceWalk {
		return &traceWalk{ctx: context.Background(), out: &Trace{
			Answer: []string{"1.2.3.4"}, Notes: []Note{}, AnswerZone: "example.test.",
			Chain: []TraceLink{{Zone: ".", Status: traceSecure}, {Zone: "test.", Status: traceSecure},
				{Zone: "example.test.", Status: traceInsecure, KeysWithoutDS: noDS}},
		}}
	}
	half := chain(true)
	half.verdict()
	if half.out.DNSSEC != traceInsecure || half.out.Verdict.Level != "warn" || !strings.Contains(half.out.Verdict.Text, "registrar") {
		t.Errorf("keys without a DS: %q / %q: %s", half.out.DNSSEC, half.out.Verdict.Level, half.out.Verdict.Text)
	}
	plain := chain(false)
	plain.verdict()
	if plain.out.DNSSEC != traceInsecure || plain.out.Verdict.Level != "info" {
		t.Errorf("unsigned: %q / %q, want insecure / info", plain.out.DNSSEC, plain.out.Verdict.Level)
	}
}
