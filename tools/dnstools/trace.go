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

// Trace walks a name's delegation from the root and validates the DNSSEC chain itself.
type Trace struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`

	Hops []TraceHop `json:"hops"`
	// Chain: root first, with an extra link for the root itself, so indexes do not match Hops.
	Chain []TraceLink `json:"chain"`

	// DNSSEC: RFC 4035's "secure", "insecure" (ordinary, not a fault) or "bogus" (the only failure),
	// or "indeterminate" when the walk cannot judge; "cannot tell" must never read as "broken".
	DNSSEC string `json:"dnssec"`
	// Verdict: the verdict paragraph, deliberately not repeated in Notes.
	Verdict Note `json:"verdict"`

	RootServer string `json:"root_server"`

	// AnswerZone: the zone that owns the answer, possibly below the AA=1 server's (see traceAnswerZone).
	AnswerZone  string   `json:"answer_zone,omitempty"`
	Answer      []string `json:"answer"`
	AnswerRcode string   `json:"answer_rcode,omitempty"`
	// CNAME: the walk reached an alias; it stops there rather than following the target.
	CNAME string `json:"cname,omitempty"`
	// AnswerSigned: the records shown (a CNAME target's, when those are shown) carry an RRSIG.
	AnswerSigned bool `json:"answer_signed"`
	// AnswerVerified: that RRSIG verified under AnswerZone's keys, chained to the root anchor.
	AnswerVerified bool `json:"answer_verified"`

	Notes []Note `json:"notes"`

	// Queries: budget slots spent; a TCP retry of a truncated answer is not counted again.
	Queries   int   `json:"queries"`
	Truncated bool  `json:"truncated,omitempty"`
	QueryMS   int64 `json:"query_ms"`
}

// TraceHop is one zone's servers asked the question.
type TraceHop struct {
	Zone     string `json:"zone"`
	Server   string `json:"server"`
	ServerIP string `json:"server_ip"`
	RTTMS    int64  `json:"rtt_ms"`
	Rcode    string `json:"rcode,omitempty"`
	// Authoritative: the AA bit; the walk ends on the first server that sets it.
	Authoritative bool `json:"authoritative"`

	Referral string `json:"referral,omitempty"`
	// ZoneCut: the server answered for a zone below Zone without a referral (shared nameservers).
	ZoneCut     string   `json:"zone_cut,omitempty"`
	Nameservers []string `json:"nameservers"`
	Glue        []string `json:"glue"`
	// GlueMissing: an in-bailiwick nameserver came with no address, forcing a detour lookup.
	GlueMissing bool `json:"glue_missing,omitempty"`
	// SideLookups: addresses fetched elsewhere because the referral lacked usable glue.
	SideLookups []string `json:"side_lookups,omitempty"`

	Skipped []string `json:"skipped,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// TraceLink is one parent -> child step of the chain of trust.
type TraceLink struct {
	Zone string `json:"zone"`
	// Parent: the zone holding the DS, or "IANA trust anchor" for the root.
	Parent     string   `json:"parent"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail"`
	Unanswered []string `json:"unanswered,omitempty"`

	DSKeyTags []uint16 `json:"ds_key_tags"`
	KeyTags   []uint16 `json:"dnskey_tags"`
	// MatchedTag: the child key whose digest matched the parent's DS.
	MatchedTag    uint16 `json:"matched_key_tag,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
	KeysWithoutDS bool   `json:"keys_without_ds,omitempty"`
}

// Link verdicts; traceUnknown keeps "could not check" from collapsing into secure or bogus.
const (
	traceSecure   = "secure"
	traceInsecure = "insecure"
	traceBogus    = "bogus"
	traceUnknown  = "indeterminate"
)

// Every hop is a packet to a third party's nameserver from a public endpoint, so the walk is capped.
const (
	traceMaxQueries = 48
	// traceMaxDepth only has to exceed maxNameLabels, which validDomain enforces.
	traceMaxDepth         = 12
	traceMaxServersPerHop = 3
	traceMaxSideLookups   = 2
	// traceWalkTimeout: the budget alone allows minutes (48 x 5s, plus TCP retries).
	traceWalkTimeout = 20 * time.Second
)

// traceRootHints: IANA's root servers, hardcoded so the walk never starts at a resolver.
// b.root moved to 170.247.170.2 in Nov 2023; the old 199.9.14.201 still answers but is unpublished.
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

// traceRootAnchorRRs: both live root KSKs (2017 tag 20326, 2024 tag 38696), any match accepted,
// so the rollover cannot silently make every trace bogus. Digests are DNSKEY.ToDS(SHA256) of each.
var traceRootAnchorRRs = []string{
	".\t172800\tIN\tDS\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	".\t172800\tIN\tDS\t38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// traceRootAnchors panics at startup on a malformed anchor: a bug in this file, not a runtime state.
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

type traceServer struct {
	Name string
	IP   string
	IP6  string
}

// traceAddrOverride lets tests point the walk at loopback, which addr otherwise refuses.
// nil in production; set once in TestMain before any test goroutine, so it needs no lock.
var traceAddrOverride func(ip string) (string, bool)

// addr returns host:53 for the first routable address, IPv4 first, or "".
// Nameservers come from caller-chosen zones, so this keeps the walk off our own network.
func (t traceServer) addr(s *Service) string {
	for _, ip := range [...]string{t.IP, t.IP6} {
		if ip == "" {
			continue
		}
		if traceAddrOverride != nil {
			if a, ok := traceAddrOverride(ip); ok {
				return a
			}
		}
		if s.nsRoutable(ip) {
			return net.JoinHostPort(ip, "53")
		}
	}
	return ""
}

type traceWalk struct {
	svc *Service
	ctx context.Context
	out *Trace
	// via: public resolver for glueless side lookups only, never for the walk itself.
	via     string
	queries int
	// dead: addresses that went silent earlier in this walk; tried last, never dropped.
	dead map[string]bool
	// answer: what the walk may say about the records it shows (a traceAnswer* state).
	answer string
	// unchecked: the chain stopped being provable because a link was unreadable, not unsigned.
	unchecked bool
}

func (w *traceWalk) noteLinkStatus(status string) {
	if status == traceUnknown {
		w.unchecked = true
	}
}

// addLink records a chain link and reports whether the chain is still secure.
func (w *traceWalk) addLink(link TraceLink) bool {
	w.out.Chain = append(w.out.Chain, link)
	w.noteLinkStatus(link.Status)
	return link.Status == traceSecure
}

// Answer states for the records shown, ranked so the worst one wins.
const (
	traceAnswerVerified = "verified"
	// traceAnswerNone: NXDOMAIN or NODATA; the NSEC/NSEC3 proof is not read, so it is the server's word.
	traceAnswerNone      = "none"
	traceAnswerUnchecked = "unchecked"
	// traceAnswerUnsigned: no RRSIG; an unsigned child zone on the same server looks identical.
	traceAnswerUnsigned = "unsigned"
	// traceAnswerForeign: signed by a zone whose keys this walk never anchored.
	traceAnswerForeign = "foreign-signer"
	// traceAnswerFailed: the answering zone's own signature fails; the only bogus answer state.
	traceAnswerFailed = "failed"
)

var traceAnswerRank = map[string]int{
	traceAnswerVerified:  0,
	traceAnswerNone:      1,
	traceAnswerUnchecked: 2,
	traceAnswerUnsigned:  3,
	traceAnswerForeign:   4,
	traceAnswerFailed:    5,
}

func (w *traceWalk) worsen(state string) {
	if w.answer == "" || traceAnswerRank[state] > traceAnswerRank[w.answer] {
		w.answer = state
	}
}

// spend charges one query, or marks the walk truncated once ctx is done or the budget is gone.
func (w *traceWalk) spend() bool {
	if w.ctx.Err() != nil || w.queries >= traceMaxQueries {
		w.out.Truncated = true
		return false
	}
	w.queries++
	return true
}

// cancelled marks the walk truncated once ctx is done.
func (w *traceWalk) cancelled() bool {
	if w.ctx.Err() != nil {
		w.out.Truncated = true
		return true
	}
	return false
}

// Trace walks name's delegation from the root, validating DNSSEC on the way; qtype defaults to A.
func (s *Service) Trace(ctx context.Context, name, qtype string) (*Trace, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	qtype = walkType(qtype)
	// The package allowlist: ANY or AXFR aimed at caller-chosen nameservers would be an amplifier.
	if !slices.Contains(Types, qtype) {
		return nil, ErrBadType
	}
	if err := needDomain(name); err != nil {
		return nil, err
	}

	qname := strings.ToLower(dns.Fqdn(name))
	via, _ := resolverAddr(DefaultResolver)

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

// run validates each zone's keys, asks its servers the question and follows the referral down.
func (w *traceWalk) run(qname, qtype string) {
	servers := traceRotate(traceRootHints, qname)
	w.out.RootServer = strings.TrimSuffix(servers[0].Name, ".")

	zone, parent := ".", "IANA trust anchor"
	ds := traceDS{set: traceRootAnchors, status: traceDSVerified}
	// Once false, nothing below can be validated and no DS or DNSKEY queries are spent.
	secure := true

	for depth := 0; depth < traceMaxDepth; depth++ {
		if w.cancelled() {
			return
		}

		link, keys := w.validateZone(zone, parent, servers, ds, secure)
		secure = w.addLink(link)

		hop, resp := w.askZone(zone, servers, qname, qtype)
		w.out.Hops = append(w.out.Hops, hop)
		if resp == nil {
			return
		}

		// AA=1 ends the walk, but parent and child often share servers (www.nic.cz), and
		// judging the child's records under this zone's keys would wrongly read as bogus.
		if resp.Authoritative {
			if cut := traceAnswerZone(resp, qname, zone); cut != "" {
				zone, keys, secure = w.crossHiddenCut(zone, cut, servers, keys, secure)
			}
			w.finish(zone, qname, qtype, resp, keys, secure)
			return
		}

		child, nsNames := traceReferral(resp, zone, qname)
		if child == "" {
			w.out.Notes = append(w.out.Notes, Note{Level: "warn", Text: strings.TrimSuffix(hop.Server, ".") +
				" answered without the authoritative bit and without a referral, so the walk cannot go further. That server is delegated this zone but is not serving it, which is a lame delegation."})
			return
		}

		last := &w.out.Hops[len(w.out.Hops)-1]
		last.Referral = child

		next := w.fetchDS(child, servers, keys, secure)

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

// traceAnswerZone returns the shallowest zone strictly below zone that an RRSIG signer or SOA owner
// names as owning the answer, or "". It must be on qname's path, so a server cannot steer the walk.
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

// crossHiddenCut validates a cut the delegation never announced, on the same servers that hold its DS.
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
	return cut, childKeys, w.addLink(link)
}

// traceDSStatus: how the parent's DS answer held up. A signature that never arrived is not a failed one.
type traceDSStatus string

const (
	traceDSAbsent   traceDSStatus = "absent"
	traceDSVerified traceDSStatus = "verified"
	// traceDSUnsigned: DS records with no RRSIG, typically EDNS stripped on the path.
	traceDSUnsigned traceDSStatus = "unsigned"
	traceDSBogus    traceDSStatus = "bogus"
	traceDSNoAnswer traceDSStatus = "no-answer"
	// traceDSUnreadable: a fragment or an rcode; reading it as absent would call a signed zone unsigned.
	traceDSUnreadable traceDSStatus = "unreadable"
)

type traceDS struct {
	set        []*dns.DS
	status     traceDSStatus
	unanswered []string
	// why: for traceDSUnreadable, what did arrive.
	why string
}

// traceUnreadable says why a reply is no basis for a conclusion (TC=1 after the TCP retry leaves a
// fragment; an rcode says nothing), or "". NXDOMAIN counts as an answer only for the final question.
func traceUnreadable(resp *dns.Msg, nxdomainIsAnswer bool) string {
	switch {
	case resp == nil:
		return "no response came back at all"
	case resp.Truncated:
		return "the answer came back truncated and the retry over TCP did not complete, so what arrived is a fragment of the real record set rather than all of it"
	case resp.Rcode == dns.RcodeNameError && nxdomainIsAnswer:
		return ""
	case resp.Rcode != dns.RcodeSuccess:
		return "the server answered " + dns.RcodeToString[resp.Rcode] + " rather than returning records"
	}
	return ""
}

// validateZone checks zone's DNSKEY set against the parent's DS (or the root anchors).
func (w *traceWalk) validateZone(zone, parent string, servers []traceServer, ds traceDS, secure bool) (TraceLink, []*dns.DNSKEY) {
	link := TraceLink{Zone: zone, Parent: parent, DSKeyTags: []uint16{}, KeyTags: []uint16{}}
	for _, d := range ds.set {
		link.DSKeyTags = append(link.DSKeyTags, d.KeyTag)
	}

	switch {
	case !secure && w.unchecked:
		// Unreadable above, not unsigned: saying "unsigned" here would become verdict()'s "not signed".
		link.Status = traceUnknown
		link.Detail = "A link above this one could not be checked from here, so nothing below it can be verified either. That is a gap in what this walk could reach, not a finding about this zone or the delegation above it."
		return link, nil
	case !secure:
		link.Status = traceInsecure
		link.Detail = "The delegation above this one is unsigned, so nothing below it can be validated, signed or not."
		return link, nil
	case ds.status == traceDSBogus:
		link.Status = traceBogus
		link.Detail = "The parent's DS record did not verify under the parent's own keys, so the parent's word about this zone cannot be trusted."
		return link, nil
	case ds.status == traceDSNoAnswer:
		link.Status, link.Unanswered = traceUnknown, ds.unanswered
		link.Detail = "The parent's servers did not answer when asked what DS record they publish for this zone, so the chain could not be followed past here. That is a failure on the way to them, not a finding about this zone."
		return link, nil
	case ds.status == traceDSUnreadable:
		link.Status, link.Unanswered = traceUnknown, ds.unanswered
		link.Detail = "The parent's answer about what DS record it publishes for this zone could not be read: " + ds.why + ". That is a statement about the path to the parent's servers, not a finding about either zone."
		return link, nil
	case ds.status == traceDSUnsigned:
		link.Status = traceUnknown
		link.Detail = "The parent returned a DS record for this zone but no signature over it, so the parent's word could not be checked. A signature that never arrived is not a signature that failed: this is usually something on the path stripping EDNS, and says nothing about either zone."
		return link, nil
	case len(ds.set) == 0:
		link.Status = traceInsecure
		link.Detail = "The parent publishes no DS record for this zone, so validators treat it as unsigned. Most names are. (Proving an absence properly needs the parent's NSEC or NSEC3 records; this walk takes the parent's answer at face value.)"
		// Fetch the keys anyway, to tell an unsigned zone from one whose DS was never published.
		if r := w.query(servers, zone, "DNSKEY"); r.msg != nil && r.msg.Rcode == dns.RcodeSuccess && !r.msg.Truncated {
			if keys := traceKeys(r.msg.Answer, zone); len(keys) > 0 {
				for _, k := range keys {
					link.KeyTags = append(link.KeyTags, k.KeyTag())
				}
				link.KeysWithoutDS = true
				link.Detail = "The zone publishes DNSSEC keys, but the parent has no DS record for any of them, so nothing vouches for those keys. If DNSSEC is meant to be on, the missing step is publishing the DS record at the registrar."
			}
		}
		return link, nil
	}

	r := w.query(servers, zone, "DNSKEY")
	if status, detail, usable := traceKeySetVerdict(r, w.ctx.Err() != nil || w.out.Truncated); !usable {
		link.Status, link.Detail = status, detail
		if status != traceInsecure {
			link.Unanswered = r.skipped
		}
		return link, nil
	}
	resp := r.msg

	keys := traceKeys(resp.Answer, zone)
	if len(keys) == 0 {
		// Only reached on a whole NOERROR reply, so the zone really publishes no keys.
		link.Status = traceBogus
		link.Detail = "The parent publishes a DS record for this zone, but the zone serves no DNSKEY records. A signed delegation pointing at no key is broken."
		return link, nil
	}
	if len(keys) > traceMaxKeys {
		keys = keys[:traceMaxKeys]
	}
	for _, k := range keys {
		link.KeyTags = append(link.KeyTags, k.KeyTag())
	}
	if w.cancelled() {
		link.Status = traceInsecure
		link.Detail = "The request was cancelled before this link could be checked."
		return link, nil
	}

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

// traceKeySetVerdict decides what one DNSKEY fetch may conclude. usable means a whole NOERROR
// reply is in hand to read keys from; otherwise status and detail are the link's.
func traceKeySetVerdict(r traceReply, walkStopped bool) (status, detail string, usable bool) {
	switch {
	case r.msg != nil:
		if why := traceUnreadable(r.msg, false); why != "" {
			return traceUnknown, "This zone's DNSKEY set could not be read: " + why +
				". Nothing here is a finding about the zone; the chain simply could not be followed from here.", false
		}
		return "", "", true
	case walkStopped:
		return traceInsecure, "This walk stopped before it could fetch this zone's keys, so the chain is unfinished rather than broken. Nothing here says anything about the zone itself.", false
	case !r.answered:
		return traceUnknown, "None of this zone's nameservers answered the query for its DNSKEY set, so the chain could not be checked here. Lost packets or a blocked TCP retry look exactly like this, and neither is a fault in the zone.", false
	case r.unreadable != "":
		return traceUnknown, "This zone's servers answered the DNSKEY query with a truncated message and the retry over TCP did not complete, so only a fragment of the key set ever arrived. A fragment is not evidence about the zone: the key the parent's DS points at may be sitting in the part that never got here.", false
	default:
		// Only rcodes came back (SERVFAIL, REFUSED, NOTAUTH): a server fault, not a failed signature.
		// answered is sticky across servers, so timeouts plus one REFUSED also land here.
		return traceUnknown, "This zone's nameservers answered the query for its DNSKEY set with an error rather than a key set, so the chain could not be checked here. A server refusing or failing a query is a fault on the way to the keys, not a finding about them: no signature was examined either way.", false
	}
}

// traceMaxKeys caps DNSKEYs checked (real zones publish 2-5): the DS x DNSKEY loop is quadratic.
const traceMaxKeys = 24

// traceCheckKeys is the pure crypto for one link: a child key's DS digest must match the parent's,
// and that key must have signed the DNSKEY RRset within its validity period.
func traceCheckKeys(ds []*dns.DS, keys []*dns.DNSKEY, rrset []dns.RR, sigs []*dns.RRSIG) (matched *dns.DNSKEY, status, detail string) {
	digestMatched := false
	for _, d := range ds {
		for _, k := range keys {
			// Tag and algorithm only pre-filter (tags can collide); the digest decides.
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
		// No RRSIG at all is a transport symptom (stripped OPT, lossy path), not a failed signature.
		if len(sigs) == 0 {
			return nil, traceUnknown, "A key here matches the parent's DS digest, but the zone's DNSKEY set arrived with no signature over it at all, so the link could not be checked. A signature that was never returned is not a signature that failed."
		}
		return nil, traceBogus, "A key here matches the parent's DS digest, but no valid signature over this zone's DNSKEY set was made by it. The chain stops at this zone."
	}
	return nil, traceBogus, "The parent publishes a DS record, but no key this zone serves has a matching digest. The delegation claims to be signed and the keys do not back it up."
}

// traceSigValid reports whether sig is k's in-date signature over rrset.
func traceSigValid(sig *dns.RRSIG, k *dns.DNSKEY, rrset []dns.RR) bool {
	return sig.KeyTag == k.KeyTag() && sig.Verify(k, rrset) == nil && sig.ValidityPeriod(time.Time{})
}

// fetchDS asks the parent's servers (the DS lives only there) and verifies it under the parent's keys.
func (w *traceWalk) fetchDS(child string, parentServers []traceServer, parentKeys []*dns.DNSKEY, secure bool) traceDS {
	if !secure {
		return traceDS{status: traceDSAbsent}
	}
	r := w.query(parentServers, child, "DS")
	if r.msg == nil {
		if r.unreadable != "" {
			return traceDS{status: traceDSUnreadable, unanswered: r.skipped,
				why: "every server that replied sent a truncated message and the retry over TCP did not complete"}
		}
		return traceDS{status: traceDSNoAnswer, unanswered: r.skipped}
	}
	resp := r.msg
	if why := traceUnreadable(resp, false); why != "" {
		return traceDS{status: traceDSUnreadable, unanswered: r.skipped, why: why}
	}

	// Some servers put the DS RRset in the authority section instead of the answer.
	sections := append(slices.Clone(resp.Answer), resp.Ns...)
	var set []*dns.DS
	for _, rr := range sections {
		if d, ok := rr.(*dns.DS); ok && strings.EqualFold(d.Hdr.Name, child) {
			set = append(set, d)
		}
	}
	if len(set) == 0 {
		return traceDS{status: traceDSAbsent}
	}

	rrset := traceRRset(sections, child, dns.TypeDS)
	sigs := traceSigs(sections, child, dns.TypeDS)
	if len(sigs) == 0 {
		return traceDS{set: set, status: traceDSUnsigned}
	}
	for _, sig := range sigs {
		for _, k := range parentKeys {
			if w.cancelled() {
				return traceDS{set: set, status: traceDSNoAnswer}
			}
			if traceSigValid(sig, k, rrset) {
				return traceDS{set: set, status: traceDSVerified}
			}
		}
	}
	return traceDS{set: set, status: traceDSBogus}
}

func (w *traceWalk) askZone(zone string, servers []traceServer, qname, qtype string) (TraceHop, *dns.Msg) {
	hop := TraceHop{Zone: zone, Nameservers: []string{}, Glue: []string{}}

	r := w.query(servers, qname, qtype)
	hop.Skipped = r.skipped
	if r.msg == nil {
		hop.Error = "no server for this zone answered"
		if r.unreadable != "" {
			hop.Error = "every server that replied sent a truncated answer and the retry over TCP did not complete"
		}
		if w.out.Truncated {
			hop.Error = "the walk ran out of its query budget before this zone answered"
		}
		return hop, nil
	}
	resp := r.msg
	ip, _, _ := net.SplitHostPort(r.srv.addr(w.svc))
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

type traceReply struct {
	msg     *dns.Msg
	srv     traceServer
	rttMS   int64
	skipped []string
	// answered: some server sent any DNS response, even a refusal, as opposed to silence.
	answered bool
	// unreadable: only a truncated fragment came back, which is not the same as an empty answer.
	unreadable string
}

// query asks servers in turn with recursion off; msg is nil when no usable answer came back.
func (w *traceWalk) query(servers []traceServer, qname, qtype string) traceReply {
	var out traceReply
	for i, srv := range w.liveFirst(servers) {
		if i >= traceMaxServersPerHop {
			break
		}
		name := strings.TrimSuffix(srv.Name, ".")
		// Checked before spend: a server we refuse to send to costs no query.
		addr := srv.addr(w.svc)
		if addr == "" {
			out.skipped = append(out.skipped, name+": no routable address")
			continue
		}
		if !w.spend() {
			return out
		}
		// newQuery sets DO (no RRSIGs otherwise); ask() retries a truncated answer over TCP.
		m := newQuery(qname, qtype)
		m.RecursionDesired = false
		start := time.Now()
		r, _, err := w.svc.ask(w.ctx, m, addr)
		rtt := time.Since(start).Milliseconds()
		switch {
		case err != nil:
			if w.dead == nil {
				w.dead = map[string]bool{}
			}
			w.dead[addr] = true
			out.skipped = append(out.skipped, name+": no response")
		case r.Rcode == dns.RcodeServerFailure, r.Rcode == dns.RcodeRefused, r.Rcode == dns.RcodeNotAuth:
			out.answered = true
			out.skipped = append(out.skipped, name+": answered "+dns.RcodeToString[r.Rcode])
		case r.Truncated:
			// TC=1 survived the TCP retry: a prefix of the RRset. Try the next server (the root has 13).
			out.answered, out.unreadable = true, "truncated"
			out.skipped = append(out.skipped, name+": answer truncated and the TCP retry did not complete")
		default:
			out.msg, out.srv, out.rttMS, out.answered = r, srv, rtt, true
			return out
		}
	}
	return out
}

// liveFirst moves servers that went silent earlier in this walk to the back.
func (w *traceWalk) liveFirst(servers []traceServer) []traceServer {
	if len(w.dead) == 0 {
		return servers
	}
	live := make([]traceServer, 0, len(servers))
	var quiet []traceServer
	for _, srv := range servers {
		if w.dead[srv.addr(w.svc)] {
			quiet = append(quiet, srv)
			continue
		}
		live = append(live, srv)
	}
	return append(live, quiet...)
}

// traceReferral returns the child zone a referral delegates to, and its NS names. The child must be
// strictly below zone (no loop) and on qname's path, or a zone could steer the walk elsewhere.
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

// resolveServers maps a referral's NS names to servers: glue first, then capped side lookups.
func (w *traceWalk) resolveServers(hop *TraceHop, resp *dns.Msg, child string, nsNames []string) []traceServer {
	glue := map[string]traceServer{}
	for _, rr := range resp.Extra {
		n := strings.ToLower(rr.Header().Name)
		g := glue[n]
		switch v := rr.(type) {
		case *dns.A:
			if g.IP == "" {
				g.IP = v.A.String()
			}
		case *dns.AAAA:
			if g.IP6 == "" {
				g.IP6 = v.AAAA.String()
			}
		default:
			continue
		}
		g.Name = n
		glue[n] = g
	}

	var out []traceServer
	var glueless []string
	for _, ns := range nsNames {
		if g := glue[ns]; g.addr(w.svc) != "" {
			out = append(out, g)
			continue
		}
		// Only in-bailiwick nameservers need glue.
		if dns.IsSubDomain(child, ns) {
			hop.GlueMissing = true
		}
		glueless = append(glueless, ns)
	}
	out = traceRotate(out, w.out.QName)

	// Top up even with some glue: one glued server of eight (github.com) may be unreachable.
	for i, ns := range glueless {
		if w.cancelled() || len(out) >= traceMaxServersPerHop || i >= traceMaxSideLookups {
			break
		}
		// Charged up front for both A and AAAA; over-counting is the safe side of a ceiling.
		if !w.spend() || !w.spend() {
			break
		}
		// nameserverAddress, not a copy: one routability guard for every packet this box sends.
		ip, _ := w.svc.nameserverAddress(w.ctx, ns, w.via)
		srv := traceServer{Name: ns, IP: ip}
		addr := srv.addr(w.svc)
		if addr == "" {
			continue
		}
		host, _, _ := net.SplitHostPort(addr)
		hop.SideLookups = append(hop.SideLookups, strings.TrimSuffix(ns, ".")+" → "+host)
		out = append(out, srv)
	}
	return out
}

// finish records the authoritative answer and checks the signature over the records the page
// will show: a CNAME target's records, not the alias, when both are present.
func (w *traceWalk) finish(zone, qname, qtype string, resp *dns.Msg, keys []*dns.DNSKEY, secure bool) {
	w.out.AnswerZone, w.out.AnswerRcode = zone, dns.RcodeToString[resp.Rcode]
	want := dns.StringToType[qtype]

	// Owners matter: a CNAME'd name returns the target's records under another owner and signature.
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

	// With only an alias, the alias itself is what gets verified.
	covered := want
	if len(owners) == 0 && w.out.CNAME != "" {
		covered, owners = dns.TypeCNAME, []string{qname}
	}
	switch {
	case traceUnreadable(resp, true) != "":
		// Before the absence case: a fragment or an rcode also looks like "nothing published".
		w.worsen(traceAnswerUnchecked)
		return
	case len(owners) == 0:
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

// verifyDisplayed checks one RRset the page shows; a signer other than zone is not ours to call bogus.
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
			if w.cancelled() {
				return traceAnswerUnchecked
			}
			if traceSigValid(sig, k, rrset) {
				return traceAnswerVerified
			}
		}
	}
	if !ours {
		return traceAnswerForeign
	}
	return traceAnswerFailed
}

// verdict folds the chain and the answer into DNSSEC and the one Verdict paragraph.
func (w *traceWalk) verdict() {
	out := w.out
	bogus, insecure, unknown, keysNoDS := false, false, false, false
	for _, l := range out.Chain {
		switch l.Status {
		case traceBogus:
			bogus = true
		case traceInsecure:
			insecure = true
			keysNoDS = keysNoDS || l.KeysWithoutDS
		case traceUnknown:
			unknown = true
		}
	}

	// A walk that stopped halfway must never give a verdict about somebody's zone.
	incomplete := out.Truncated || len(out.Chain) == 0 || out.AnswerZone == ""

	switch {
	case bogus:
		out.DNSSEC, out.Verdict = traceBogus, Note{Level: "fail", Text: "A parent zone publishes a DS record saying the zone below it is signed, and the signatures do not check out. Validating resolvers will refuse to answer for this name at all, which looks to users like the domain is down."}
	case w.answer == traceAnswerFailed:
		out.DNSSEC, out.Verdict = traceBogus, Note{Level: "fail", Text: "The delegation chain verifies, and the signature over the records themselves does not. It was made by a key of this very zone, so this is the zone's own signature failing rather than a mix-up about which zone owns the name: a validating resolver will treat this name as bogus and answer SERVFAIL."}
	case incomplete:
		out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "This walk did not finish: it stopped at its own limits before it could check the whole chain. There is no DNSSEC verdict to give, and nothing the walk did reach is a finding about the name."}
	// Unknown outranks insecure: one unread link must not become "this name is not signed".
	case unknown:
		out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "One link couldn't be checked from here; the chain below shows which and why. That is a gap in this walk, not a fault in the zone."}
	case insecure && keysNoDS:
		out.DNSSEC, out.Verdict = traceInsecure, Note{Level: "warn", Text: "Resolvers treat it as unsigned, because nothing vouches for its keys. If you meant to turn DNSSEC on, the last step is adding the DS record at your registrar; the chain below shows where it stops."}
	case insecure:
		out.DNSSEC, out.Verdict = traceInsecure, Note{Level: "info", Text: "Unsigned is the ordinary state of most of the internet and is not a fault: it simply means answers for this name cannot be cryptographically verified, only trusted to have come from the right servers."}
	default:
		switch w.answer {
		case traceAnswerVerified:
			// An alias into another zone: only the CNAME was verified.
			over := "the answer itself"
			if out.CNAME != "" && len(out.Answer) == 0 {
				over = "the alias record; the name it points to is outside this zone and not part of this walk"
			}
			out.DNSSEC, out.Verdict = traceSecure, Note{Level: "ok", Text: "Every link from the root trust anchor down to this zone verified here, and so did the signature over " + over + ". Nothing was taken on a resolver's word."}
		case traceAnswerNone:
			out.DNSSEC = traceUnknown
			absent := "there are no records of this type"
			if out.AnswerRcode == "NXDOMAIN" {
				absent = "the name does not exist"
			}
			chain := "Every link from the root trust anchor down to " + strings.TrimSuffix(out.AnswerZone, ".") + " verified here, and the zone says "
			if out.AnswerZone == "." {
				chain = "The root's own keys verified here against the trust anchor, and the root says "
			}
			out.Verdict = Note{Level: "warn", Text: chain + absent + ". That absence is the zone's word: proving it takes NSEC or NSEC3 records, which this walk doesn't read."}
		case traceAnswerForeign:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "The chain verified down to the zone this walk reached, but the records it returned are signed by a different zone below it — one whose keys this walk could not anchor. The signature may well be perfectly good; this walk simply is not in a position to say, and will not guess in either direction."}
		case traceAnswerUnsigned:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "The chain verified down to the zone this walk reached, and the records it returned carry no signature at all. That is either an unsigned zone below this cut that sent no referral to reveal itself, or a signed zone not signing its own data. Those are very different things and this walk cannot tell them apart, so it is not calling the name broken."}
		default:
			out.DNSSEC, out.Verdict = traceUnknown, Note{Level: "warn", Text: "This walk reached an answer but did not get as far as checking a signature over it, so there is no verdict about the records themselves."}
		}
	}

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
		// Name the ceiling hit, so a timeout is not mistaken for a deep delegation.
		why := fmt.Sprintf("ran past its %s time limit", traceWalkTimeout)
		if out.Queries >= traceMaxQueries {
			why = fmt.Sprintf("reached its ceiling of %d queries", traceMaxQueries)
		}
		out.Notes = append(out.Notes, Note{Level: "warn", Text: "This walk " + why +
			" and stopped. What is shown above is the start of the delegation, not all of it. Slow or unresponsive nameservers are the usual cause."})
	}
	// Same-zone alias: the records shown are the target's, not this name's.
	if out.CNAME != "" && len(out.Answer) > 0 {
		name, target, zone := strings.TrimSuffix(out.QName, "."), strings.TrimSuffix(out.CNAME, "."), strings.TrimSuffix(out.AnswerZone, ".")
		out.Notes = append(out.Notes, Note{Level: "info", Text: name + " is an alias (CNAME) for " + target + ". Both are in the " + zone + " zone, so one server answered both: the records above are " + target + "'s, not " + name + "'s."})
	}
	sortNotes(out.Notes)
}

// traceRotate rotates hints by a hash of qname: repeatable per name, spread across names.
func traceRotate(hints []traceServer, qname string) []traceServer {
	if len(hints) == 0 {
		return hints
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(qname))
	// Reduce as uint32: int(h.Sum32()) can be negative on a 32-bit build.
	n := int(h.Sum32() % uint32(len(hints)))
	out := make([]traceServer, 0, len(hints))
	out = append(out, hints[n:]...)
	return append(out, hints[:n]...)
}

func traceKeys(rrs []dns.RR, owner string) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && strings.EqualFold(k.Hdr.Name, owner) {
			out = append(out, k)
		}
	}
	return out
}

// traceRRset collects one owner+type RRset; RRSIG.Verify rejects a mixed set outright.
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

func traceSigs(rrs []dns.RR, owner string, covers uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covers && strings.EqualFold(sig.Hdr.Name, owner) {
			out = append(out, sig)
		}
	}
	return out
}
