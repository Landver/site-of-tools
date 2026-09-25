package dnstools

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Trace answers "who actually decides this name, and can I prove it".
//
// Two questions in one walk, because they are the same walk:
//
//   - The delegation. Start at a root server, ask with recursion off, follow
//     the referral one zone cut at a time until a server answers with AA=1.
//     Every popular lookup tool hides this behind a resolver, so when a
//     delegation is broken the page says SERVFAIL and stops. Here the hop that
//     broke is named.
//   - The chain of trust, validated HERE. What /? ships today is what the
//     *resolver* claims: the AD bit, plus a bogus verdict inferred from a
//     checking-disabled retry. That is a second-hand opinion. This walk fetches
//     the DS at each parent and the DNSKEY at each child and checks the digests
//     and the signatures itself, anchored at the IANA root trust anchors below.
//
// The tone matters as much as the crypto. Most names on the internet are
// unsigned, and an unsigned name is not a fault: it is the ordinary state of
// DNS. INSECURE is reported as a plain fact. BOGUS — a parent that publishes a
// DS whose chain does not verify — is the only failing outcome, and it is rare.
type Trace struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`

	// Hops: the ladder, root first. One entry per zone cut asked.
	Hops []TraceHop `json:"hops"`
	// Chain: one entry per parent -> child link, root first. Parallel to Hops
	// in spirit but not in index: the chain has a link for the root itself,
	// whose "parent" is the hardcoded trust anchor rather than a zone.
	Chain []TraceLink `json:"chain"`

	// DNSSEC: the whole-walk verdict, in RFC 4035's own vocabulary —
	// "secure", "insecure", "bogus" or "indeterminate".
	//
	//   secure        the chain verified here AND so did the signature over the
	//                 records this walk is showing.
	//   insecure      a cut on the way down is unsigned, so nothing below it can
	//                 be validated. The common case, and not a failure.
	//   bogus         something that claims to be signed demonstrably is not.
	//                 The only failing outcome, and it is rare.
	//   indeterminate the walk reached an answer it is not entitled to judge: a
	//                 NXDOMAIN or NODATA whose NSEC/NSEC3 proof this walk does
	//                 not read, a signature made by a zone whose keys it could
	//                 not anchor, or a key set that arrived with no signature at
	//                 all. "We cannot tell" is a different sentence from
	//                 "this is broken", and printing the second for the first is
	//                 the worst thing this feature could do.
	DNSSEC string `json:"dnssec"`
	// Verdict: that verdict in one paragraph, written once. The page renders
	// this; it is deliberately NOT repeated in Notes, which carry findings.
	Verdict Note `json:"verdict"`

	// RootServer: which root we started from, named so the walk is repeatable.
	RootServer string `json:"root_server"`

	// AnswerZone: the zone that actually owns the answer. Usually the zone whose
	// server answered with AA=1, but not always: see traceAnswerZone.
	AnswerZone string `json:"answer_zone,omitempty"`
	// Answer: the records that zone returned for the type asked.
	Answer []string `json:"answer"`
	// AnswerRcode: what the authoritative server said. NXDOMAIN and NODATA are
	// answers, and the walk that reached them is still a complete walk.
	AnswerRcode string `json:"answer_rcode,omitempty"`
	// CNAME: the walk reached an alias rather than the type asked for. The
	// resolution continues at the target, in a different zone, and this walk
	// stops here rather than pretending it followed it.
	CNAME string `json:"cname,omitempty"`
	// AnswerSigned: the records this walk is SHOWING arrived with an RRSIG over
	// them. Not "something in the message was signed": when a CNAME's target
	// records are what is on the page, this is about those records, because
	// those are what a reader will take the claim to be about.
	AnswerSigned bool `json:"answer_signed"`
	// AnswerVerified: that same RRSIG — over the records being shown — verified
	// here, under a key from AnswerZone's own DNSKEY set, which itself chains to
	// the root anchor.
	AnswerVerified bool `json:"answer_verified"`

	// Notes: severity-tagged findings, rendered by the shared dns/notes list.
	// The verdict itself is not one of them; it lives in Verdict.
	Notes []Note `json:"notes"`

	// Queries: how many queries this walk spent from its budget. Not a packet
	// count: a query repeated over TCP because the UDP answer was truncated
	// (routine for a DNSKEY set) is one query here and two packets on the wire.
	Queries int `json:"queries"`
	// Truncated: the walk hit its own query or depth ceiling, so what is shown
	// is a prefix of the real delegation rather than all of it.
	Truncated bool  `json:"truncated,omitempty"`
	QueryMS   int64 `json:"query_ms"`
}

// TraceHop: one rung of the ladder — one zone's servers, asked the question.
type TraceHop struct {
	// Zone: the zone cut whose servers were asked. "." for the root.
	Zone string `json:"zone"`
	// Server / ServerIP: which one of that zone's servers answered.
	Server   string `json:"server"`
	ServerIP string `json:"server_ip"`
	RTTMS    int64  `json:"rtt_ms"`
	Rcode    string `json:"rcode,omitempty"`
	// Authoritative: the AA bit. The walk ends on the first server that sets it.
	Authoritative bool `json:"authoritative"`

	// Referral: the child zone this hop delegated to, empty on the last hop.
	Referral string `json:"referral,omitempty"`
	// ZoneCut: this rung asked one zone's servers and the server that answered
	// turned out to be serving a zone BELOW it, without sending a referral.
	// Extremely common where a registry operator runs both. Named because the
	// answer belongs to this zone, not to the one on the rung.
	ZoneCut string `json:"zone_cut,omitempty"`
	// Nameservers: the NS RRset this hop returned, for the referral or for the
	// zone itself.
	Nameservers []string `json:"nameservers"`
	// Glue: the A/AAAA records that rode along in the additional section.
	Glue []string `json:"glue"`
	// GlueMissing: the referral named a nameserver *inside* the child zone and
	// sent no address for it. That is a real finding, not cosmetics: the
	// resolver cannot ask the child where the child's own servers are, so it
	// has to take a detour through another zone before it can continue. Out-of
	// -bailiwick nameservers need no glue and are not counted here.
	GlueMissing bool `json:"glue_missing,omitempty"`
	// SideLookups: the addresses this walk had to fetch elsewhere because the
	// referral carried no usable glue. Named, so the extra cost is visible.
	SideLookups []string `json:"side_lookups,omitempty"`

	// Skipped: servers tried before this one, and why they did not answer. A
	// dead root or a lame nameserver is worth seeing, not worth stopping for.
	Skipped []string `json:"skipped,omitempty"`
	// Error: no server for this zone produced a usable response.
	Error string `json:"error,omitempty"`
}

// TraceLink: one parent -> child step of the chain of trust.
type TraceLink struct {
	// Zone: the child, i.e. the zone being vouched for.
	Zone string `json:"zone"`
	// Parent: the zone holding the DS. For the root this is the literal
	// "IANA trust anchor", because nothing in DNS vouches for the root.
	Parent string `json:"parent"`
	// Status: "secure", "insecure", "bogus" or "indeterminate".
	Status string `json:"status"`
	// Detail: the finding in plain words. An unsigned zone gets a calm
	// sentence, not an apology and not an alarm.
	Detail string `json:"detail"`
	// Unanswered: the nameservers that did not answer, or refused, while this
	// link was being checked. A link that could not be checked has to be able
	// to say who would not talk to us, or "indeterminate" reads as a shrug.
	Unanswered []string `json:"unanswered,omitempty"`

	// DSKeyTags: the key tags the parent's DS RRset points at.
	DSKeyTags []uint16 `json:"ds_key_tags"`
	// KeyTags: every key tag in the child's DNSKEY RRset.
	KeyTags []uint16 `json:"dnskey_tags"`
	// MatchedTag: the child key whose DS digest matched the parent's DS, i.e.
	// the key-signing key this link actually rests on.
	MatchedTag uint16 `json:"matched_key_tag,omitempty"`
	// Algorithm: that key's signing algorithm, named (e.g. "ECDSAP256SHA256").
	Algorithm string `json:"algorithm,omitempty"`
}

// The four link verdicts. Unexported: callers read TraceLink.Status, and the
// template compares against the literals, so these exist to stop the domain
// layer spelling them four different ways.
//
// traceUnknown is the one that earns its keep. Without it every "we could not
// check this" collapses into either "secure" (a lie in the dangerous
// direction) or "bogus" (an accusation about somebody's working zone). Three
// real conditions land here: a key set or DS that arrived with no signature at
// all, nameservers that did not answer, and an answer signed by a zone whose
// keys this walk was never able to anchor.
const (
	traceSecure   = "secure"
	traceInsecure = "insecure"
	traceBogus    = "bogus"
	traceUnknown  = "indeterminate"
)

// Bounds. This endpoint is public and every hop is an outbound packet to a
// third party's nameserver, so the walk is capped on both axes and every loop
// checks ctx.Err(). email.go's SPF walker is the cautionary tale: an unbounded
// recursion over attacker-chosen names burned 3m40s of CPU on one request.
const (
	// traceMaxQueries is the whole walk's packet budget: referrals, DNSKEY and
	// DS queries, and any side lookup a missing glue record forces. A real
	// three-label name costs roughly a dozen.
	traceMaxQueries = 48
	// traceMaxDepth caps zone cuts. validDomain already rejects a name with
	// more than maxNameLabels labels, so this only has to be larger than that.
	traceMaxDepth = 12
	// traceMaxServersPerHop is how many of a zone's servers we will try before
	// calling the hop dead. Falling over is the point; canvassing is not.
	traceMaxServersPerHop = 3
	// traceMaxSideLookups caps the out-of-band address lookups one glueless
	// referral may cost.
	traceMaxSideLookups = 2
	// traceWalkTimeout is the whole walk's wall-clock ceiling, independent of
	// the budget above. The two are not the same guard: 48 queries at the
	// Service's own 5s per-query timeout, each able to retry over TCP for
	// another 5s, is eight minutes of one goroutine for one HTTP request that
	// nothing else bounds (Echo is started with no WriteTimeout). The ECS
	// feature added its own ceiling for the same reason.
	traceWalkTimeout = 20 * time.Second
)

// traceRootHints: the full root server list, addresses as published by IANA.
// Hardcoded on purpose — a walk that starts by asking a resolver where the
// root is has not started at the root.
//
// b.root-servers.net moved to 170.247.170.2 in November 2023; the old
// 199.9.14.201 still answers but is not the published address. IPv6 is carried
// for completeness and only used when a hint has no v4 address, which is never
// today: this box's egress to UDP/53 was verified over IPv4.
var traceRootHints = []traceServer{
	{Name: "a.root-servers.net.", IP: "198.41.0.4", IP6: "2001:503:ba3e::2:30"},
	{Name: "b.root-servers.net.", IP: "170.247.170.2", IP6: "2801:1b8:10::b"},
	{Name: "c.root-servers.net.", IP: "192.33.4.12", IP6: "2001:500:2::c"},
	{Name: "d.root-servers.net.", IP: "199.7.91.13", IP6: "2001:500:2d::d"},
	{Name: "e.root-servers.net.", IP: "192.203.230.10", IP6: "2001:500:a8::e"},
	{Name: "f.root-servers.net.", IP: "192.5.5.241", IP6: "2001:500:2f::f"},
	{Name: "g.root-servers.net.", IP: "192.112.36.4", IP6: "2001:500:12::d0d"},
	{Name: "h.root-servers.net.", IP: "198.97.190.53", IP6: "2001:500:1::53"},
	{Name: "i.root-servers.net.", IP: "192.36.148.17", IP6: "2001:7fe::53"},
	{Name: "j.root-servers.net.", IP: "192.58.128.30", IP6: "2001:503:c27::2:30"},
	{Name: "k.root-servers.net.", IP: "193.0.14.129", IP6: "2001:7fd::1"},
	{Name: "l.root-servers.net.", IP: "199.7.83.42", IP6: "2001:500:9f::42"},
	{Name: "m.root-servers.net.", IP: "202.12.27.33", IP6: "2001:dc3::35"},
}

// traceRootAnchorRRs: the IANA root trust anchors, as DS records.
//
// Both live anchors are configured and ANY match is accepted, deliberately.
// The root KSK is mid-rollover in this era: KSK-2017 (tag 20326) and KSK-2024
// (tag 38696) are both published in the root DNSKEY RRset, and which one signs
// it changes when IANA says so. A tool pinned to a single key tag breaks on
// that day, silently, and reports the whole internet as bogus.
//
// Verified live against a.root-servers.net (198.41.0.4) on 2026-09-25 while
// writing this. The root answered AA=1 with five records: ZSK tags 8763 and
// 57780, KSK tags 20326 and 38696, and one RRSIG over the DNSKEY RRset made by
// tag 20326 (valid at the time of the query). Computing DNSKEY.ToDS(SHA256) on
// each KSK reproduced exactly the two digests below, which is how they were
// obtained rather than copied. Note what that means: today only KSK-2017
// actually signs, so an implementation that configured only KSK-2024 would
// verify nothing — which is the failure mode this two-anchor list avoids in
// both directions.
var traceRootAnchorRRs = []string{
	".\t172800\tIN\tDS\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	".\t172800\tIN\tDS\t38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// traceRootAnchors parses the anchors once, at init. A malformed anchor is a
// bug in this file rather than a runtime condition, so it panics at startup
// instead of turning every trace insecure at 3am.
var traceRootAnchors = func() []*dns.DS {
	out := make([]*dns.DS, 0, len(traceRootAnchorRRs))
	for _, s := range traceRootAnchorRRs {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic("dnstools: malformed root trust anchor: " + err.Error())
		}
		ds, ok := rr.(*dns.DS)
		if !ok {
			panic("dnstools: root trust anchor is not a DS record")
		}
		out = append(out, ds)
	}
	return out
}()

// traceServer: one nameserver the walk may ask. IP6 is only consulted when
// there is no IPv4 address, matching spread.go's preference and this host's
// verified egress.
type traceServer struct {
	Name string
	IP   string
	IP6  string
}

// addr returns the address to send to, preferring IPv4, or "" when neither
// address is one we are willing to send a packet to. The nameserver names come
// from zones the caller chose, so this is the guard that stops a hostile
// delegation turning the walk into a port-53 probe of our own host — the same
// rule spread.go's nameserverAddress applies, tightened by traceRoutable.
func (t traceServer) addr() string {
	for _, ip := range [...]string{t.IP, t.IP6} {
		if ip != "" && traceRoutable(ip) {
			return net.JoinHostPort(ip, "53")
		}
	}
	return ""
}

// traceReserved: address blocks that are neither private nor loopback and so
// slip past spread.go's routable(), but that no real nameserver lives in.
// Reserved rather than routable, all of them.
var traceReserved = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, 7)
	for _, cidr := range []string{
		"100.64.0.0/10",   // RFC 6598 carrier-grade NAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // RFC 1112 reserved
		"2001:db8::/32",   // documentation
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("dnstools: malformed reserved range " + cidr)
		}
		out = append(out, n)
	}
	return out
}()

// traceRoutable is the address guard this walk sends packets through.
//
// spread.go's routable() rejects loopback, RFC1918/ULA, link-local and the
// unspecified address, which is the right set for a nameserver name a visitor
// typed. It is not the right set here: trace takes addresses straight out of
// an arbitrary referral's additional section, and that source can name a
// multicast group (glue of 224.0.0.1 makes this host query all-hosts), a
// broadcast address, or CGNAT space belonging to somebody else's customers.
// IsGlobalUnicast rules out multicast, broadcast and the unspecified address
// in one go; the explicit list covers the reserved unicast blocks it allows.
//
// Kept here rather than folded into routable() because this file may not edit
// spread.go. Tightening routable() itself, and collapsing the two, is the
// follow-up — the comment there already anticipates a shared helper.
func traceRoutable(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || !ip.IsGlobalUnicast() || !routable(ipStr) {
		return false
	}
	for _, n := range traceReserved {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// traceWalk is one walk's mutable state: the budget, the context, and the
// result being assembled. Per request, never shared.
type traceWalk struct {
	svc *Service
	ctx context.Context
	out *Trace
	// via: a public resolver, used only for the side lookup a glueless
	// referral forces. Never for the walk itself, which would defeat it.
	via string
	// queries counts budget slots spent, against traceMaxQueries.
	queries int
	// dead: addresses that did not answer earlier in this same walk, tried
	// last from then on.
	//
	// Measured, not theoretical: tracing nic.cz, one of cz.'s nameservers was
	// unreachable from this host, and the walk re-asked it first for the
	// DNSKEY, then the question, then the DS — three 6-second timeouts, 18 of
	// the walk's 20 seconds, and a signed name that got no verdict. Tracing
	// www.nic.cz rotated to a different server and finished in 0.65s. Last
	// rather than never: one silent packet is not proof a server is down, and
	// a zone whose every server has failed once must still be asked.
	dead map[string]bool
	// answer records what this walk is entitled to say about the records it
	// will display. Unexported: the page and the JSON read DNSSEC and Verdict,
	// and a sixth public field spelling out the same thing would be a second
	// place for the two to disagree.
	answer string
}

// What the walk can say about the DATA it shows, as opposed to the delegation
// above it. Ranked: worse states win when an answer holds several RRsets.
const (
	// traceAnswerVerified: the displayed records' own signature checked out
	// here, under the answering zone's keys.
	traceAnswerVerified = "verified"
	// traceAnswerNone: there are no records to check — NXDOMAIN or NODATA. The
	// proof of an absence is an NSEC or NSEC3 record, which this walk does not
	// read, so "nothing came back" is the server's word and nothing more.
	traceAnswerNone = "none"
	// traceAnswerUnchecked: the chain above is not secure, or the walk stopped,
	// so no signature was even attempted.
	traceAnswerUnchecked = "unchecked"
	// traceAnswerUnsigned: the records arrived with no RRSIG. Under a signed
	// zone that is suspicious, but it is also exactly what an unsigned child
	// zone served by the same nameserver looks like, and this walk cannot tell
	// the two apart without the NSEC the parent would carry.
	traceAnswerUnsigned = "unsigned"
	// traceAnswerForeign: the records are signed, by a zone whose DNSKEY set
	// this walk never anchored. Not our signature to judge.
	traceAnswerForeign = "foreign-signer"
	// traceAnswerFailed: the records are signed by the very zone whose keys
	// this walk holds, and the signature does not verify. The one state that
	// earns the word bogus, because a validating resolver will SERVFAIL too.
	traceAnswerFailed = "failed"
)

// traceAnswerRank orders the states above so the worst one wins.
var traceAnswerRank = map[string]int{
	traceAnswerVerified:  0,
	traceAnswerNone:      1,
	traceAnswerUnchecked: 2,
	traceAnswerUnsigned:  3,
	traceAnswerForeign:   4,
	traceAnswerFailed:    5,
}

// worsen keeps the least favourable state seen so far.
func (w *traceWalk) worsen(state string) {
	if w.answer == "" || traceAnswerRank[state] > traceAnswerRank[w.answer] {
		w.answer = state
	}
}

// spend takes one packet from the budget. Every loop and every recursion in
// this file goes through it, so the ctx check and the ceiling cannot be
// forgotten in one place and remembered in another.
func (w *traceWalk) spend() bool {
	if w.ctx.Err() != nil || w.queries >= traceMaxQueries {
		w.out.Truncated = true
		return false
	}
	w.queries++
	return true
}

// Trace walks the delegation from the root and validates the chain of trust
// along the way. qtype defaults to A.
func (s *Service) Trace(ctx context.Context, name, qtype string) (*Trace, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	if qtype = strings.ToUpper(strings.TrimSpace(qtype)); qtype == "" {
		qtype = "A"
	}
	// The package allowlist, not miekg's whole registry: this page aims its
	// queries at third-party nameservers of the caller's choosing, so ANY and
	// AXFR would make it an amplification pipe. Same rule as Spread.
	if !slices.Contains(Types, qtype) {
		return nil, ErrBadType
	}
	// A reverse name has a perfectly good delegation, but the in-addr.arpa
	// ladder is a different explanation than the one this page tells, and
	// validDomain would reject the literal anyway.
	if _, isIP := reverseName(name); isIP {
		return nil, fmt.Errorf("%w: give a domain name, not an IP", ErrBadType)
	}
	if err := validDomain(name); err != nil {
		return nil, err
	}

	qname := strings.ToLower(dns.Fqdn(name))
	via, _ := resolverAddr(DefaultResolver)

	// The walk's own deadline, on top of the query budget. The budget bounds
	// how many questions one request may ask; only a clock bounds how long the
	// slowest possible answer to each of them may take. The existing
	// Truncated / ctx.Err() plumbing reports the cut-off correctly, so this is
	// the whole change: everything below already asks the context first.
	ctx, cancel := context.WithTimeout(ctx, traceWalkTimeout)
	defer cancel()

	w := &traceWalk{
		svc: s,
		ctx: ctx,
		via: via,
		out: &Trace{
			Name: name, QName: qname, Type: qtype,
			Hops:   []TraceHop{},
			Chain:  []TraceLink{},
			Answer: []string{},
			Notes:  []Note{},
		},
	}

	start := time.Now()
	w.run(qname, qtype)
	w.out.Queries = w.queries
	w.out.QueryMS = time.Since(start).Milliseconds()
	w.verdict()
	return w.out, nil
}

// run is the walk proper: validate the current zone's keys, ask its servers the
// question, follow the referral, repeat.
func (w *traceWalk) run(qname, qtype string) {
	servers := traceRotate(traceRootHints, qname)
	w.out.RootServer = strings.TrimSuffix(servers[0].Name, ".")

	zone, parent := ".", "IANA trust anchor"
	ds := traceDS{set: traceRootAnchors, status: traceDSVerified}
	// secure tracks whether the chain is still provably signed. Once it is
	// false nothing below can be secure, and there is no point spending
	// queries on DNSKEY sets we could not anchor.
	secure := true

	for depth := 0; depth < traceMaxDepth; depth++ {
		if w.ctx.Err() != nil {
			w.out.Truncated = true
			return
		}

		// 1. Does this zone's DNSKEY set chain to what the parent vouched for?
		link, keys := w.validateZone(zone, parent, servers, ds, secure)
		w.out.Chain = append(w.out.Chain, link)
		if link.Status != traceSecure {
			secure = false
		}

		// 2. Ask this zone's servers the question the visitor actually typed.
		hop, resp := w.askZone(zone, servers, qname, qtype)
		w.out.Hops = append(w.out.Hops, hop)
		if resp == nil {
			return
		}

		// 3a. An authoritative answer ends the walk, whatever it says: a
		// NXDOMAIN from the zone that owns the name is a complete result, not a
		// failure of the walk.
		//
		// AA=1 does NOT mean "this rung's zone owns the name", though, and
		// treating it that way was this walk's worst bug. A parent and its
		// child very often share nameservers — every registry operator that
		// also runs zones under its own TLD, and any company whose parent
		// nameservers also serve a delegated subzone — and then the parent's
		// server answers the child's name with AA=1 instead of sending a
		// referral. Validating the child's records under the PARENT's keys
		// cannot succeed, and the old code turned that into a red "bogus"
		// verdict on correctly signed names (www.nic.cz was the live case).
		if resp.Authoritative {
			if cut := traceAnswerZone(resp, qname, zone); cut != "" {
				zone, keys, secure = w.crossHiddenCut(zone, cut, servers, keys, secure)
			}
			w.finish(zone, qname, qtype, resp, keys, secure)
			return
		}

		// 3b. A referral: descend. Anything else (a non-authoritative response
		// with no referral in it) is the end of what this walk can follow.
		child, nsNames := traceReferral(resp, zone, qname)
		if child == "" {
			w.out.Notes = append(w.out.Notes, Note{Level: "warn", Text: strings.TrimSuffix(hop.Server, ".") +
				" answered without the authoritative bit and without a referral, so the walk cannot go further. That server is delegated this zone but is not serving it, which is a lame delegation."})
			return
		}

		last := &w.out.Hops[len(w.out.Hops)-1]
		last.Referral = child

		// 4. The DS the parent publishes for the child, asked at the parent's
		// own servers — which is the only place it lives.
		next := w.fetchDS(child, servers, keys, secure)

		// 5. Where the child's servers are. Glue if the referral carried it, a
		// side lookup if it did not.
		children := w.resolveServers(last, resp, child, nsNames)
		if len(children) == 0 {
			last.Error = "none of this referral's nameservers resolved to an address we could ask"
			w.out.Notes = append(w.out.Notes, Note{Level: "fail", Text: "The referral to " +
				strings.TrimSuffix(child, ".") + " named " + fmt.Sprint(len(nsNames)) +
				" nameserver(s), and none of them resolved to a usable address. Nothing can resolve this name."})
			return
		}

		zone, parent, ds, servers = child, zone, next, children
	}
	w.out.Truncated = true
}

// traceAnswerZone reports the zone that actually owns an authoritative answer,
// when that zone is strictly below the one whose servers were asked.
//
// Two witnesses, both of which the responding server puts in the message
// itself: the SignerName on an RRSIG over the answer, and the owner of the SOA
// a NODATA or NXDOMAIN carries in the authority section. Either one names the
// apex of the zone the data really lives in.
//
// Two guards, and both matter. The candidate must be strictly below the zone
// being walked, or a zone answering for its own name would restart the walk on
// itself; and it must be an ancestor-or-self of qname, or a server could name
// any zone it liked and steer the next DS and DNSKEY queries — and the packets
// they cost — at a name nobody asked about. The shallowest qualifying
// candidate wins, because that is the first cut below where we stand.
//
// Returns "" when there is no evidence of a cut, which is the common case and
// is not a finding: an unsigned NOERROR answer carries neither witness, and
// then this walk simply cannot see a cut that may be there. finish() is
// written so that "cannot see" never becomes "is broken".
func traceAnswerZone(resp *dns.Msg, qname, zone string) string {
	best := ""
	consider := func(name string) {
		n := strings.ToLower(dns.Fqdn(name))
		switch {
		case strings.EqualFold(n, zone), !dns.IsSubDomain(zone, n):
			return // not below the zone we are standing on
		case !dns.IsSubDomain(n, qname):
			return // not on the path to the name that was asked for
		case best == "" || dns.CountLabel(n) < dns.CountLabel(best):
			best = n
		}
	}
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			consider(sig.SignerName)
		}
	}
	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *dns.SOA:
			consider(v.Hdr.Name)
		case *dns.RRSIG:
			consider(v.SignerName)
		}
	}
	return best
}

// crossHiddenCut validates a zone cut the delegation never announced, using
// the same servers: they answered AA=1 for a name inside the child, so they
// serve the child, and the DS still lives on the parent's side of the cut
// where these same servers also hold it.
//
// Returns the zone, keys and secure flag the answer must now be judged under.
// A cut this walk cannot complete leaves the chain unproven rather than
// broken — the whole point of noticing the cut at all.
func (w *traceWalk) crossHiddenCut(zone, cut string, servers []traceServer, keys []*dns.DNSKEY, secure bool) (string, []*dns.DNSKEY, bool) {
	if len(w.out.Hops) > 0 {
		w.out.Hops[len(w.out.Hops)-1].ZoneCut = cut
	}
	w.out.Notes = append(w.out.Notes, Note{Level: "info", Text: strings.TrimSuffix(cut, ".") +
		" is a zone of its own, and the same nameservers serve it and " + strings.TrimSuffix(zone, ".") +
		" above it. So there was no referral to follow: the server answered directly. The cut is real all the same, and the records below are checked against " +
		strings.TrimSuffix(cut, ".") + "'s own keys."})

	ds := w.fetchDS(cut, servers, keys, secure)
	link, childKeys := w.validateZone(cut, zone, servers, ds, secure)
	w.out.Chain = append(w.out.Chain, link)
	if link.Status != traceSecure {
		secure = false
	}
	return cut, childKeys, secure
}

// traceDSStatus: how well the parent's word about a child zone held up. The
// distinction that matters is the one between "the signature failed" and "the
// signature never reached us" — the first is a statement about the zone, the
// second about the path between us and it, and only the first is a fault.
type traceDSStatus string

const (
	// traceDSAbsent: the parent answered and published no DS. An unsigned
	// delegation, which is the ordinary state of most of the internet.
	traceDSAbsent traceDSStatus = "absent"
	// traceDSVerified: a DS RRset came back and its signature verified under
	// the parent's own keys.
	traceDSVerified traceDSStatus = "verified"
	// traceDSUnsigned: a DS RRset came back carrying no RRSIG at all. A
	// middlebox that strips EDNS so the server never sees the DO bit produces
	// exactly this, as does a lossy path. Not a failed signature: an absent one.
	traceDSUnsigned traceDSStatus = "unsigned"
	// traceDSBogus: a DS RRset came back with signatures, and none of them
	// verified. The genuinely broken case.
	traceDSBogus traceDSStatus = "bogus"
	// traceDSNoAnswer: the parent's servers did not answer the DS query.
	traceDSNoAnswer traceDSStatus = "no-answer"
)

// traceDS: the parent's word on a child zone, plus how that word held up.
type traceDS struct {
	set    []*dns.DS
	status traceDSStatus
	// unanswered: which of the parent's servers would not answer, when that is
	// why there is nothing here.
	unanswered []string
}

// validateZone checks one zone's DNSKEY set against the DS its parent
// published (or, for the root, against the hardcoded anchors) and returns both
// the link to report and the keys the caller needs for the next step.
//
// Every "no" here is a plain statement. Most zones are unsigned; the sentences
// below say so without hedging or scolding.
func (w *traceWalk) validateZone(zone, parent string, servers []traceServer, ds traceDS, secure bool) (TraceLink, []*dns.DNSKEY) {
	link := TraceLink{Zone: zone, Parent: parent, DSKeyTags: []uint16{}, KeyTags: []uint16{}}
	for _, d := range ds.set {
		link.DSKeyTags = append(link.DSKeyTags, d.KeyTag)
	}

	switch {
	case !secure:
		link.Status = traceInsecure
		link.Detail = "The delegation above this one is unsigned, so nothing below it can be validated, signed or not."
		return link, nil
	case ds.status == traceDSBogus:
		link.Status = traceBogus
		link.Detail = "The parent's DS record did not verify under the parent's own keys, so the parent's word about this zone cannot be trusted."
		return link, nil
	case ds.status == traceDSNoAnswer:
		// Nobody answered. That is a statement about the path to those
		// servers, not about the zone, and it must not be dressed up as one.
		link.Status, link.Unanswered = traceUnknown, ds.unanswered
		link.Detail = "The parent's servers did not answer when asked what DS record they publish for this zone, so the chain could not be followed past here. That is a failure on the way to them, not a finding about this zone."
		return link, nil
	case ds.status == traceDSUnsigned:
		link.Status = traceUnknown
		link.Detail = "The parent returned a DS record for this zone but no signature over it, so the parent's word could not be checked. A signature that never arrived is not a signature that failed: this is usually something on the path stripping EDNS, and says nothing about either zone."
		return link, nil
	case len(ds.set) == 0:
		link.Status = traceInsecure
		link.Detail = "The parent publishes no DS record for this zone, so the zone is unsigned. Most names are. (Proving an absence properly needs the parent's NSEC or NSEC3 records; this walk takes the parent's answer at face value.)"
		return link, nil
	}

	r := w.query(servers, zone, "DNSKEY")
	if r.msg == nil {
		// Three different reasons to have no key set, and exactly one of them
		// is the zone's fault. Collapsing them into "bogus" is how a few lost
		// UDP packets turn into a confident cryptographic accusation about a
		// perfectly healthy zone.
		switch {
		case w.ctx.Err() != nil || w.out.Truncated:
			link.Status = traceInsecure
			link.Detail = "This walk stopped before it could fetch this zone's keys, so the chain is unfinished rather than broken. Nothing here says anything about the zone itself."
		case !r.answered:
			link.Status, link.Unanswered = traceUnknown, r.skipped
			link.Detail = "None of this zone's nameservers answered the query for its DNSKEY set, so the chain could not be checked here. Lost packets or a blocked TCP retry look exactly like this, and neither is a fault in the zone."
		default:
			link.Status, link.Unanswered = traceBogus, r.skipped
			link.Detail = "The parent publishes a DS record for this zone, but the zone's servers answered the DNSKEY query with an error rather than a key set, so the chain cannot be completed. A validating resolver gets the same answer."
		}
		return link, nil
	}
	resp := r.msg

	keys := traceKeys(resp.Answer, zone)
	if len(keys) == 0 {
		link.Status = traceBogus
		link.Detail = "The parent publishes a DS record for this zone, but the zone serves no DNSKEY records. A signed delegation pointing at no key is broken."
		return link, nil
	}
	// A zone is free to publish as many keys as fit in a response, and the
	// digest-and-verify loop below is quadratic in (DS × DNSKEY). Bounded here
	// for the same reason the SPF walker has a step budget: a public endpoint
	// must not let a third party's zone choose how much CPU one click costs.
	if len(keys) > traceMaxKeys {
		keys = keys[:traceMaxKeys]
	}
	for _, k := range keys {
		link.KeyTags = append(link.KeyTags, k.KeyTag())
	}
	if w.ctx.Err() != nil {
		w.out.Truncated = true
		link.Status = traceInsecure
		link.Detail = "The request was cancelled before this link could be checked."
		return link, nil
	}

	// Verify wants the whole DNSKEY RRset, not just the key that signed it.
	matched, status, detail := traceCheckKeys(ds.set, keys,
		traceRRset(resp.Answer, zone, dns.TypeDNSKEY),
		traceSigs(resp.Answer, zone, dns.TypeDNSKEY))
	link.Status, link.Detail = status, detail
	if matched != nil && status == traceSecure {
		link.MatchedTag = matched.KeyTag()
		link.Algorithm = dns.AlgorithmToString[matched.Algorithm]
	}
	return link, keys
}

// traceMaxKeys caps how many of a zone's DNSKEY records are considered. Real
// zones publish two to five; the ceiling exists so a hostile one cannot make
// the digest loop below expensive.
const traceMaxKeys = 24

// traceCheckKeys is the crypto, and nothing else: no network, no state, no
// clock beyond "now". Given what the parent published and what the child
// serves, it decides whether this link of the chain holds.
//
// Pure on purpose. It is the one part of this feature where being wrong is
// invisible — a validator that always says "secure" passes every happy-path
// test — so it is written to be driven directly by a test with keys it
// generated and signatures it made itself.
//
// Two things must both be true, and both use miekg's own primitives rather
// than any hand-rolled crypto:
//
//  1. Some key the child serves has a DS digest equal to one the parent
//     published (DNSKEY.ToDS, i.e. the RFC 4034 digest).
//  2. That same key signed the child's DNSKEY RRset, and the signature is
//     inside its validity period (RRSIG.Verify + RRSIG.ValidityPeriod).
func traceCheckKeys(ds []*dns.DS, keys []*dns.DNSKEY, rrset []dns.RR, sigs []*dns.RRSIG) (matched *dns.DNSKEY, status, detail string) {
	digestMatched := false
	for _, d := range ds {
		for _, k := range keys {
			// Key tag and algorithm are a cheap pre-filter; they prove nothing
			// on their own (a key tag is a checksum, and collisions are legal),
			// so the digest below is what actually decides.
			if k.KeyTag() != d.KeyTag || k.Algorithm != d.Algorithm {
				continue
			}
			cand := k.ToDS(d.DigestType)
			if cand == nil || !strings.EqualFold(cand.Digest, d.Digest) {
				continue
			}
			digestMatched = true
			for _, sig := range sigs {
				if sig.KeyTag != k.KeyTag() {
					continue
				}
				if err := sig.Verify(k, rrset); err != nil {
					continue
				}
				if !sig.ValidityPeriod(time.Time{}) {
					return k, traceBogus, fmt.Sprintf("Key %d matches the parent's DS, but its signature over this zone's DNSKEY set is outside its validity period. An expired signature makes the whole zone fail validation for everyone.", k.KeyTag())
				}
				return k, traceSecure, fmt.Sprintf("The parent's DS matches key %d (%s), and that key's signature over this zone's DNSKEY set verifies.",
					k.KeyTag(), dns.AlgorithmToString[k.Algorithm])
			}
		}
	}
	if digestMatched {
		// Nothing signed it, or nothing it sent us signed it: two different
		// sentences. A DNSKEY RRset that arrives with no RRSIG at all is what
		// a stripped OPT record or a lossy path produces, and calling that
		// "the signature failed" tells a domain owner their zone is broken for
		// every validating resolver on the strength of a transport problem.
		if len(sigs) == 0 {
			return nil, traceUnknown, "A key here matches the parent's DS digest, but the zone's DNSKEY set arrived with no signature over it at all, so the link could not be checked. A signature that was never returned is not a signature that failed."
		}
		return nil, traceBogus, "A key here matches the parent's DS digest, but no valid signature over this zone's DNSKEY set was made by it. The chain stops at this zone."
	}
	return nil, traceBogus, "The parent publishes a DS record, but no key this zone serves has a matching digest. The delegation claims to be signed and the keys do not back it up."
}

// fetchDS asks the parent's own servers what DS it publishes for the child,
// and verifies the answer's signature under the parent's keys when the chain
// is still intact. The DS lives only at the parent, which is why this is asked
// before descending rather than after.
func (w *traceWalk) fetchDS(child string, parentServers []traceServer, parentKeys []*dns.DNSKEY, secure bool) traceDS {
	if !secure {
		// Nothing below an unsigned cut can be secure, so spending a query on
		// a DS we could not anchor buys nothing.
		return traceDS{status: traceDSAbsent}
	}
	r := w.query(parentServers, child, "DS")
	if r.msg == nil {
		return traceDS{status: traceDSNoAnswer, unanswered: r.skipped}
	}
	resp := r.msg

	// Answer section for an authoritative DS query; some servers put the same
	// RRset in the authority section instead, so read both.
	sections := append(slices.Clone(resp.Answer), resp.Ns...)
	var set []*dns.DS
	for _, rr := range sections {
		if d, ok := rr.(*dns.DS); ok && strings.EqualFold(d.Hdr.Name, child) {
			set = append(set, d)
		}
	}
	if len(set) == 0 {
		// An unsigned delegation. Said plainly at the link, with the caveat
		// that we are trusting the parent's word rather than its NSEC proof.
		return traceDS{status: traceDSAbsent}
	}

	rrset := traceRRset(sections, child, dns.TypeDS)
	sigs := traceSigs(sections, child, dns.TypeDS)
	if len(sigs) == 0 {
		// Records but no signature over them. See traceDSUnsigned: this is the
		// shape of a path problem, not of a broken parent.
		return traceDS{set: set, status: traceDSUnsigned}
	}
	for _, sig := range sigs {
		for _, k := range parentKeys {
			if w.ctx.Err() != nil {
				w.out.Truncated = true
				return traceDS{set: set, status: traceDSNoAnswer}
			}
			if sig.KeyTag != k.KeyTag() {
				continue
			}
			if err := sig.Verify(k, rrset); err == nil && sig.ValidityPeriod(time.Time{}) {
				return traceDS{set: set, status: traceDSVerified}
			}
		}
	}
	return traceDS{set: set, status: traceDSBogus}
}

// askZone sends the visitor's own question to this zone's servers with
// recursion off, falling over to the next server rather than giving up.
func (w *traceWalk) askZone(zone string, servers []traceServer, qname, qtype string) (TraceHop, *dns.Msg) {
	hop := TraceHop{Zone: zone, Nameservers: []string{}, Glue: []string{}}

	r := w.query(servers, qname, qtype)
	hop.Skipped = r.skipped
	if r.msg == nil {
		hop.Error = "no server for this zone answered"
		if w.out.Truncated {
			hop.Error = "the walk ran out of its query budget before this zone answered"
		}
		return hop, nil
	}
	resp := r.msg
	// The bare address, not the host:port ask() dialled: the port is always 53
	// and a column of ":53" is noise.
	ip, _, _ := net.SplitHostPort(r.srv.addr())
	hop.Server, hop.ServerIP, hop.RTTMS = strings.TrimSuffix(r.srv.Name, "."), ip, r.rttMS
	hop.Rcode, hop.Authoritative = dns.RcodeToString[resp.Rcode], resp.Authoritative

	for _, rr := range append(slices.Clone(resp.Answer), resp.Ns...) {
		if ns, ok := rr.(*dns.NS); ok {
			hop.Nameservers = append(hop.Nameservers, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	slices.Sort(hop.Nameservers)
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			hop.Glue = append(hop.Glue, v.A.String())
		case *dns.AAAA:
			hop.Glue = append(hop.Glue, v.AAAA.String())
		}
	}
	slices.Sort(hop.Glue)
	return hop, resp
}

// traceReply: what one round of asking a zone's servers produced.
//
// answered is the field that matters and the reason this is a struct rather
// than four return values. "Nobody sent us a packet back" and "a server
// answered and refused" are different facts, and a caller that cannot tell
// them apart has to guess — which is how three lost DNSKEY packets became a
// red "this zone's chain of trust is broken".
type traceReply struct {
	msg   *dns.Msg
	srv   traceServer
	rttMS int64
	// skipped: the servers tried before this one, and why each did not answer.
	skipped []string
	// answered: at least one server sent back a DNS response, even a refusal.
	answered bool
}

// query sends one question to the first server in the list that will answer
// it, and reports which ones would not. Recursion is always off: the whole
// point of this page is that no cache stands between it and the zone.
//
// Returns a nil message when nothing usable came back, in which case the
// caller decides whether that ends the walk.
func (w *traceWalk) query(servers []traceServer, qname, qtype string) traceReply {
	var out traceReply
	for i, srv := range w.liveFirst(servers) {
		if i >= traceMaxServersPerHop {
			break
		}
		// The budget is charged after the address check, not before: a server
		// whose address we refuse to send to costs no packet, and charging it
		// made Trace.Queries overstate what the walk actually did. The loop is
		// bounded by traceMaxServersPerHop either way, so nothing runs away.
		addr := srv.addr()
		if addr == "" {
			out.skipped = append(out.skipped, strings.TrimSuffix(srv.Name, ".")+": no routable address")
			continue
		}
		if !w.spend() {
			return out
		}
		// newQuery, not a hand-built message: it carries the 1232-byte EDNS0
		// buffer and the DO bit, and DO is what makes the RRSIGs come back at
		// all. ask() repeats over TCP when the answer is truncated, which a
		// DNSKEY set routinely is.
		m := newQuery(qname, qtype)
		m.RecursionDesired = false
		start := time.Now()
		r, err := w.svc.ask(w.ctx, m, addr)
		rtt := time.Since(start).Milliseconds()
		switch {
		case err != nil:
			if w.dead == nil {
				w.dead = map[string]bool{}
			}
			w.dead[addr] = true
			out.skipped = append(out.skipped, strings.TrimSuffix(srv.Name, ".")+": no response")
		case r.Rcode == dns.RcodeServerFailure, r.Rcode == dns.RcodeRefused, r.Rcode == dns.RcodeNotAuth:
			out.answered = true
			out.skipped = append(out.skipped, strings.TrimSuffix(srv.Name, ".")+": answered "+dns.RcodeToString[r.Rcode])
		default:
			out.msg, out.srv, out.rttMS, out.answered = r, srv, rtt, true
			return out
		}
	}
	return out
}

// liveFirst puts the servers that have already gone silent in this walk at the
// back of the list, without dropping them. Order only; nothing is excluded.
func (w *traceWalk) liveFirst(servers []traceServer) []traceServer {
	if len(w.dead) == 0 {
		return servers
	}
	live := make([]traceServer, 0, len(servers))
	var quiet []traceServer
	for _, srv := range servers {
		if w.dead[srv.addr()] {
			quiet = append(quiet, srv)
			continue
		}
		live = append(live, srv)
	}
	return append(live, quiet...)
}

// traceReferral reads the child zone a response delegates to, plus the
// nameserver names it delegates to it.
//
// Three things disqualify a referral. An NS owner equal to the zone we just
// asked is not a descent and following it would loop. An owner outside that
// zone is not the zone's to delegate. And an owner that is not an ancestor of
// the name being looked up is simply not on the way there: without that last
// guard a zone can point the rest of the walk at an unrelated subzone, and
// every hop, chain link and address after it describes a delegation that has
// nothing to do with what the visitor typed — while the page presents it as
// theirs, and spends the query budget on packets to servers that zone chose.
func traceReferral(resp *dns.Msg, zone, qname string) (child string, nsNames []string) {
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := strings.ToLower(ns.Hdr.Name)
		if child == "" {
			child = owner
		}
		if owner != child {
			continue
		}
		nsNames = append(nsNames, strings.ToLower(ns.Ns))
	}
	if child == "" || strings.EqualFold(child, zone) ||
		!dns.IsSubDomain(zone, child) || !dns.IsSubDomain(child, qname) {
		return "", nil
	}
	slices.Sort(nsNames)
	return child, slices.Compact(nsNames)
}

// resolveServers turns a referral's nameserver names into addresses to ask.
//
// Glue first, because that is what the parent sent and what a resolver would
// use. When an in-bailiwick nameserver arrives without an address the referral
// is broken in a way worth naming: the resolver cannot ask the child zone where
// the child zone's servers are, so it detours through a second lookup before it
// can continue. That detour is made here, through a public resolver, capped,
// and recorded on the hop so the cost is visible rather than hidden.
func (w *traceWalk) resolveServers(hop *TraceHop, resp *dns.Msg, child string, nsNames []string) []traceServer {
	glue := map[string]*traceServer{}
	for _, rr := range resp.Extra {
		switch v := rr.(type) {
		case *dns.A:
			n := strings.ToLower(v.Hdr.Name)
			if glue[n] == nil {
				glue[n] = &traceServer{Name: n}
			}
			if glue[n].IP == "" {
				glue[n].IP = v.A.String()
			}
		case *dns.AAAA:
			n := strings.ToLower(v.Hdr.Name)
			if glue[n] == nil {
				glue[n] = &traceServer{Name: n}
			}
			if glue[n].IP6 == "" {
				glue[n].IP6 = v.AAAA.String()
			}
		}
	}

	var out []traceServer
	var glueless []string
	for _, ns := range nsNames {
		if g := glue[ns]; g != nil && g.addr() != "" {
			out = append(out, *g)
			continue
		}
		// Out-of-bailiwick nameservers need no glue and their absence is not a
		// finding; in-bailiwick ones do, and theirs is.
		if dns.IsSubDomain(child, ns) {
			hop.GlueMissing = true
		}
		glueless = append(glueless, ns)
	}
	// Deterministically rotated, for the same reason the root hints are: the
	// same question always asks the same server, and different questions do
	// not all land on whichever nameserver sorts first.
	out = traceRotate(out, w.out.QName)

	// Top up rather than only rescuing a referral with no glue at all. A
	// referral can carry glue for one nameserver out of eight (github.com's
	// does), and when that one server is unreachable a walk with no fallback
	// simply stops — which is what happened here before this loop existed.
	// Nothing is spent when the referral is properly glued, which is the
	// ordinary case.
	for i, ns := range glueless {
		if len(out) >= traceMaxServersPerHop || i >= traceMaxSideLookups || w.ctx.Err() != nil {
			w.out.Truncated = w.out.Truncated || w.ctx.Err() != nil
			break
		}
		// nameserverAddress, not a second copy of it. It already does exactly
		// this — A then AAAA, first ROUTABLE rather than first, through the
		// same public resolver — and two copies of the guard that decides
		// which addresses this box sends packets to is the one duplication
		// worth refusing: a fix to one silently misses the other.
		//
		// Charged before the call and for both types it may ask, because the
		// budget has to be spent before the packets rather than audited after.
		// It stops at A when A answers, so this over-counts by one in the
		// common case. Over-counting is the safe direction for a ceiling.
		if !w.spend() || !w.spend() {
			break
		}
		ip, _ := w.svc.nameserverAddress(w.ctx, ns, w.via)
		srv := traceServer{Name: ns, IP: ip}
		addr := srv.addr()
		if addr == "" {
			continue
		}
		host, _, _ := net.SplitHostPort(addr)
		hop.SideLookups = append(hop.SideLookups, strings.TrimSuffix(ns, ".")+" → "+host)
		out = append(out, srv)
	}
	return out
}

// finish records the authoritative answer and checks the signature over the
// records this walk is actually going to SHOW — the last link of the chain,
// and the one that covers the data the visitor asked for.
//
// "Actually going to show" is the whole correction here. The previous version
// checked the RRset owned by the name asked for, which for an alias is the
// CNAME; it then reported AnswerVerified, which the page renders as "the
// records themselves are signed too, and that signature verifies" directly
// above the TARGET's addresses. A signed CNAME to an unsigned target got a
// green tick over records nothing had looked at.
func (w *traceWalk) finish(zone, qname, qtype string, resp *dns.Msg, keys []*dns.DNSKEY, secure bool) {
	w.out.AnswerZone, w.out.AnswerRcode = zone, dns.RcodeToString[resp.Rcode]
	want := dns.StringToType[qtype]

	// Collect the records the page will print, keeping each one's owner: a
	// CNAME'd name returns the target's records in the same message, and those
	// belong to a different owner and a different signature.
	var owners []string
	for _, rr := range resp.Answer {
		switch {
		case rr.Header().Rrtype == want:
			w.out.Answer = append(w.out.Answer, rdata(rr))
			if o := strings.ToLower(rr.Header().Name); !slices.Contains(owners, o) {
				owners = append(owners, o)
			}
		case rr.Header().Rrtype == dns.TypeCNAME && want != dns.TypeCNAME:
			if w.out.CNAME == "" {
				w.out.CNAME = rdata(rr)
			}
		}
	}

	// With records of the type asked for, those records are the claim. With
	// only an alias, the alias itself is, and the page says so.
	covered := want
	if len(owners) == 0 && w.out.CNAME != "" {
		covered, owners = dns.TypeCNAME, []string{qname}
	}
	switch {
	case len(owners) == 0:
		// NXDOMAIN or NODATA. Nothing is displayed, so there is nothing to
		// verify — and the proof that the absence is genuine is an NSEC or
		// NSEC3 record this walk does not read. Said, not implied.
		w.worsen(traceAnswerNone)
		return
	case !secure || len(keys) == 0:
		w.worsen(traceAnswerUnchecked)
		return
	}

	signed, verified := true, true
	for _, owner := range owners {
		state := w.verifyDisplayed(traceRRset(resp.Answer, owner, covered),
			traceSigs(resp.Answer, owner, covered), keys, zone)
		w.worsen(state)
		if state != traceAnswerVerified {
			verified = false
		}
		if state == traceAnswerUnsigned {
			signed = false
		}
	}
	w.out.AnswerSigned, w.out.AnswerVerified = signed, verified
}

// verifyDisplayed checks one RRset the page will print, and is careful about
// which failures it is entitled to call failures.
//
// The SignerName test is the guard. A signature made by a zone whose DNSKEY
// set this walk never anchored is not a signature this walk can judge; saying
// "bogus" about it is the false accusation the zone-cut fix exists to prevent,
// and the guard stays here as a second line in case some other path reaches
// finish() with the wrong keys in hand.
func (w *traceWalk) verifyDisplayed(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, zone string) string {
	if len(rrset) == 0 {
		return traceAnswerUnchecked
	}
	if len(sigs) == 0 {
		return traceAnswerUnsigned
	}
	ours := false
	for _, sig := range sigs {
		if !strings.EqualFold(dns.Fqdn(sig.SignerName), zone) {
			continue
		}
		ours = true
		for _, k := range keys {
			if w.ctx.Err() != nil {
				w.out.Truncated = true
				return traceAnswerUnchecked
			}
			if sig.KeyTag != k.KeyTag() {
				continue
			}
			if err := sig.Verify(k, rrset); err == nil && sig.ValidityPeriod(time.Time{}) {
				return traceAnswerVerified
			}
		}
	}
	if !ours {
		return traceAnswerForeign
	}
	return traceAnswerFailed
}

// verdict folds the chain and the answer into one word and one paragraph.
//
// The wording is the feature. An unsigned name is the ordinary case and gets a
// neutral sentence; only evidence of an actual break earns the word "broken".
// Everything this walk could not check says so in those words, because the
// page's whole value is that a reader can believe what it prints.
//
// The paragraph is written HERE and only here. It used to be written twice —
// once as a Note and again, in different words, in the verdict card — so an
// edit to one drifted from the other. The card now renders Verdict.Text and
// Notes carry findings only.
func (w *traceWalk) verdict() {
	out := w.out
	bogus, insecure, unknown := false, false, false
	for _, l := range out.Chain {
		switch l.Status {
		case traceBogus:
			bogus = true
		case traceInsecure:
			insecure = true
		case traceUnknown:
			unknown = true
		}
	}

	// "Insecure" is the floor, not a claim: it is where a walk that never
	// finished lands too. Those are different sentences, and a walk that
	// stopped halfway must never print a verdict about somebody's zone.
	incomplete := out.Truncated || len(out.Chain) == 0 || out.AnswerZone == ""

	switch {
	case bogus:
		out.DNSSEC, out.Verdict = traceBogus, Note{Level: "fail", Text: "This name's chain of trust is broken. A parent zone publishes a DS record saying the zone below it is signed, and the signatures do not check out. Validating resolvers will refuse to answer for this name at all, which looks to users like the domain is down."}
	case w.answer == traceAnswerFailed:
		out.DNSSEC, out.Verdict = traceBogus, Note{Level: "fail", Text: "The delegation chain verifies, and the signature over the records themselves does not. It was made by a key of this very zone, so this is the zone's own signature failing rather than a mix-up about which zone owns the name: a validating resolver will treat this name as bogus and answer SERVFAIL."}
	case incomplete:
		// One sentence for every unfinished walk, whatever it managed to see
		// on the way. The old version had two, and the one it printed when a
		// link had gone insecure claimed the walk "did not reach an
		// authoritative answer" — which was untrue whenever the answer arrived
		// and the key fetch after it was what ran out of time.
		out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "This walk did not finish: it stopped at its own limits before it could check the whole chain. There is no DNSSEC verdict to give, and nothing above is a finding about the name."}
	case insecure:
		out.DNSSEC, out.Verdict = traceInsecure, Note{Level: "info", Text: "This name is not signed with DNSSEC. That is the ordinary state of most of the internet and is not a fault: it simply means answers for this name cannot be cryptographically verified, only trusted to have come from the right servers."}
	case unknown:
		out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "One link of the chain could not be checked from here, so there is no verdict to give. See the chain below for which one and why. This is a statement about what this walk could reach, not about the zone: it is not evidence of anything being wrong."}
	default:
		// The chain verified end to end. What remains is what can be said
		// about the DATA, which is a separate question and used to be answered
		// with the chain's own green tick.
		switch w.answer {
		case traceAnswerVerified:
			out.DNSSEC, out.Verdict = traceSecure, Note{Level: "ok", Text: "Every link from the root trust anchor down to this zone verified here, and so did the signature over the very records shown above. Nothing was taken on a resolver's word."}
		case traceAnswerNone:
			out.DNSSEC = traceUnknown
			absent := "there are no records of this type"
			if out.AnswerRcode == "NXDOMAIN" {
				absent = "the name does not exist"
			}
			out.Verdict = Note{Level: "warn", Text: "Every link from the root trust anchor down to this zone verified here, and the zone says " + absent + ". That last part is unproved: an absence is proved by the zone's NSEC or NSEC3 records, which this walk does not read. Take it as the server's word, which is all it is."}
		case traceAnswerForeign:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "The chain verified down to the zone this walk reached, but the records it returned are signed by a different zone below it — one whose keys this walk could not anchor. The signature may well be perfectly good; this walk simply is not in a position to say, and will not guess in either direction."}
		case traceAnswerUnsigned:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "The chain verified down to the zone this walk reached, and the records it returned carry no signature at all. That is either an unsigned zone below this cut that sent no referral to reveal itself, or a signed zone not signing its own data. Those are very different things and this walk cannot tell them apart, so it is not calling the name broken."}
		default:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "This walk reached an answer but did not get as far as checking a signature over it, so there is no verdict about the records themselves."}
		}
	}

	// Delegation findings, drawn from what the walk already saw. No extra
	// queries: the same rule spread.go's health() follows.
	for _, h := range out.Hops {
		if h.GlueMissing {
			out.Notes = append(out.Notes, Note{Level: "warn", Text: strings.TrimSuffix(h.Zone, ".") +
				" delegates " + strings.TrimSuffix(h.Referral, ".") + " to a nameserver inside that zone but sent no address for it. Resolvers have to make an extra lookup before they can continue, which adds latency to every cold query for this name."})
		}
		if h.Error != "" {
			out.Notes = append(out.Notes, Note{Level: "fail", Text: "At " + strings.TrimSuffix(h.Zone, ".") + ": " + h.Error + "."})
		}
	}
	if out.Truncated {
		// Which ceiling it was. Saying "the query budget" when the clock ran
		// out sends a reader looking for a deep delegation that isn't there.
		why := fmt.Sprintf("ran past its %s time limit", traceWalkTimeout)
		if out.Queries >= traceMaxQueries {
			why = fmt.Sprintf("reached its ceiling of %d queries", traceMaxQueries)
		}
		out.Notes = append(out.Notes, Note{Level: "warn", Text: "This walk " + why +
			" and stopped. What is shown above is the start of the delegation, not all of it. Slow or unresponsive nameservers are the usual cause."})
	}
	if out.CNAME != "" {
		tail := "resolving that is a separate walk through whatever zone owns it."
		if len(out.Answer) > 0 {
			// The target happens to live in the same zone, so the one server
			// answered both halves. The records above are the target's, not
			// this name's, which is worth saying before someone edits the
			// wrong record.
			tail = "the target is in the same zone, so this server answered both at once. The records above belong to the target, not to the name you asked for."
		}
		out.Notes = append(out.Notes, Note{Level: "info", Text: "This name is an alias. " + strings.TrimSuffix(out.AnswerZone, ".") +
			" answers with a CNAME pointing at " + strings.TrimSuffix(out.CNAME, ".") + ", and " + tail})
	}
}

// traceRotate picks the starting root server from the name being looked up, so
// the same question always starts at the same root (a repeatable walk, which
// is the point of printing the server) while different questions spread across
// all thirteen rather than hammering one.
func traceRotate(hints []traceServer, qname string) []traceServer {
	if len(hints) == 0 {
		return hints
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(qname))
	// Reduced as uint32 rather than int: on a 32-bit build int(h.Sum32()) can
	// be negative and so can the remainder.
	n := int(h.Sum32() % uint32(len(hints)))
	out := make([]traceServer, 0, len(hints))
	out = append(out, hints[n:]...)
	return append(out, hints[:n]...)
}

// traceKeys pulls the DNSKEY records for one owner out of a response.
func traceKeys(rrs []dns.RR, owner string) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && strings.EqualFold(k.Hdr.Name, owner) {
			out = append(out, k)
		}
	}
	return out
}

// traceRRset collects one owner+type RRset, which is what RRSIG.Verify needs:
// it rejects a mixed set outright, so handing it a whole answer section would
// fail every signature for the wrong reason.
func traceRRset(rrs []dns.RR, owner string, t uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == t && strings.EqualFold(h.Name, owner) {
			out = append(out, rr)
		}
	}
	return out
}

// traceSigs collects the RRSIGs covering one owner+type.
func traceSigs(rrs []dns.RR, owner string, covers uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covers && strings.EqualFold(sig.Hdr.Name, owner) {
			out = append(out, sig)
		}
	}
	return out
}
