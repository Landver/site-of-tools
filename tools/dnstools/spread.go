package dnstools

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Spread answers "is my change live yet", honestly.
//
// Every popular propagation checker fans a query out to resolvers in many
// countries and prints a map. We have one box, so claiming geography would be
// a lie (reports/propagation-checking-methodology.md is explicit: label by
// operator, never by flag, unless real multi-vantage probing backs it).
//
// What one box CAN do is the check those tools bury or skip, and the one that
// actually answers the question:
//
//   - ask the zone's OWN authoritative nameservers, directly, with recursion
//     off. If they disagree, the change has not finished rolling out. This
//     costs third parties nothing and is the only authoritative signal.
//   - ask the public resolvers, and report how long they have been holding
//     what they hold (cache age), rather than a meaningless raw TTL.
//
// Answers are grouped by identical answer set rather than reduced to a
// percentage, so healthy GeoDNS doesn't read as "17% propagated".
type Spread struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`
	// Zone: the apex the NS set actually came from, which for any non-apex
	// query is a name the caller never typed. Anything that asks a registry
	// about "this domain" means this, not QName.
	Zone string `json:"zone,omitempty"`

	// Authoritative: the zone's own nameservers, asked directly (RD=0).
	Authoritative []ServerAnswer `json:"authoritative"`
	// Resolvers: the public resolvers on the allowlist, asked normally.
	Resolvers []ServerAnswer `json:"resolvers"`

	// NSTotal / NSTruncated: how many nameservers the zone actually delegates,
	// and whether maxAuthoritative dropped some of them. Without this a zone
	// with nine nameservers can render a green verdict off a sample that never
	// touched the one disagreeing server.
	NSTotal     int  `json:"ns_total,omitempty"`
	NSTruncated bool `json:"ns_truncated,omitempty"`

	// Groups: distinct answer sets seen, largest first. One group means
	// everybody agrees. Counts BOTH halves, so it is never the right number
	// for a sentence about what public resolvers see — that is ResolverGroups.
	Groups []AnswerGroup `json:"groups"`
	// ResolverGroups: distinct answer sets among the public resolvers alone.
	// Anycast or geo steering can only be claimed when this is above one; at
	// exactly one, differing from the zone, the change is simply still cached.
	ResolverGroups int `json:"resolver_groups"`
	// ResolversStale: every resolver that answered agrees with every other
	// resolver, and all of them disagree with a zone that is itself in step.
	// That is a change which has left the nameservers and is waiting out a
	// cache — not steering, and not a stalled rollout.
	ResolversStale bool `json:"resolvers_stale,omitempty"`

	// Consistent: every server that answered returned the same set.
	Consistent bool `json:"consistent"`
	// AuthConsistent: the zone's OWN nameservers agree with each other. This
	// is the distinction that matters. If they agree but the public resolvers
	// differ, the zone is answering by location (GeoDNS, anycast steering) and
	// nothing is rolling out — the case a "% propagated" number reports as a
	// failure when it is normal, healthy behaviour.
	//
	// Only meaningful once AuthAnswered is at least 2: one sample cannot
	// disagree with anything, so read the count before quoting the flag.
	AuthConsistent bool `json:"auth_consistent"`
	// AuthAnswered: how many of the zone's own nameservers returned a set that
	// could be compared at all. The denominator behind AuthConsistent.
	AuthAnswered int `json:"auth_answered"`
	// Rotation: the zone's servers returned different answer sets while
	// reporting the SAME zone version. That is one zone answering differently
	// per query (round-robin, latency steering), not a change mid-rollout —
	// the exact false alarm this feature exists to avoid. The serial is the
	// only discriminator a single vantage point can honestly use.
	Rotation bool `json:"rotation,omitempty"`
	// SerialsAgree: nameservers run by the SAME provider report the same SOA
	// serial. Compared per provider on purpose: two independent DNS providers
	// legitimately keep independent serials, so comparing across them reports
	// a healthy multi-provider zone as mid-rollout.
	//
	// Like AuthConsistent it starts true, so SerialsSeen is what says whether
	// any serial was read at all.
	SerialsAgree bool `json:"serials_agree"`
	// SerialsSeen: how many nameservers reported a serial.
	SerialsSeen int `json:"serials_seen"`
	// MultiProvider: the zone is served by more than one DNS provider, which
	// is why serials are only ever compared within a provider. A fact, not a
	// fault, and it says nothing about whether the serials differ.
	MultiProvider bool `json:"multi_provider,omitempty"`
	// Answered / Asked: the honest denominator. Servers that timed out are
	// named in the lists above rather than quietly dropped.
	Answered int `json:"answered"`
	Asked    int `json:"asked"`
	// Rcode: the response code every server that responded agreed on, empty
	// when they differed or none responded. This is what separates "the name
	// does not exist" from "it exists but publishes no record of this type"
	// from "nobody answered", all three of which otherwise look like Answered
	// being zero.
	Rcode string `json:"rcode,omitempty"`
	// Health: delegation findings across the zone's nameservers — diversity,
	// open recursion, TCP reachability. Severity-tagged like the email checks.
	Health []Note `json:"health,omitempty"`
	// StaleFor: the longest remaining TTL seen at a public resolver, i.e.
	// roughly how much longer a stale answer can survive out there.
	StaleFor string `json:"stale_for,omitempty"`
	QueryMS  int64  `json:"query_ms"`
}

// ServerAnswer: what one server said, or why it didn't.
type ServerAnswer struct {
	// Label is what to show: a nameserver hostname, or a resolver's name.
	Label string `json:"label"`
	Addr  string `json:"addr"`
	// Values: the answer set for the question type only, sorted so two servers
	// with the same records compare equal regardless of the order they sent
	// them in.
	Values []string `json:"values"`
	// CNAME: the alias this name pointed at, when the answer was a CNAME
	// rather than the type asked for. Kept out of Values on purpose: an
	// authoritative server cannot chase a CNAME out of its own zone and a
	// resolver always does, so counting the chain would make the two halves
	// permanently incomparable.
	CNAME string `json:"cname,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	// Rcode: the response code this server returned, verbatim. miekg reports
	// err == nil for every rcode, so without this a NXDOMAIN, a REFUSED and a
	// clean answer are indistinguishable.
	Rcode string `json:"rcode,omitempty"`
	// AA: the authoritative-answer bit. A nameserver asked directly that
	// answers without it is not serving the zone — a lame delegation.
	AA bool `json:"aa,omitempty"`
	// CacheAge: how long this resolver has been holding the answer, derived
	// from the authoritative TTL minus the TTL it reported. Only set when both
	// sides returned the SAME set, because otherwise the two TTLs describe
	// different records and the subtraction means nothing. The column the
	// corpus says nobody ships, and the one that explains a stale answer.
	CacheAge string `json:"cache_age,omitempty"`
	// Serial: the SOA serial this nameserver is serving (authoritative only).
	Serial uint32 `json:"serial,omitempty"`
	RTTMS  int64  `json:"rtt_ms"`
	// Error: why this server produced nothing. Named, never hidden.
	Error string `json:"error,omitempty"`

	// OpenResolver: this nameserver answered a recursive query for a zone it
	// is not authoritative for. That makes it usable as a DNS amplification
	// reflector by anyone on the internet, and it is the single most serious
	// misconfiguration a nameserver can have.
	OpenResolver bool `json:"open_resolver,omitempty"`
	// TCPFail: TCP/53 was refused. DNS requires it — any answer too big for
	// UDP falls back to TCP, so blocking it breaks DNSSEC and large RRsets in
	// ways that look intermittent and are miserable to diagnose.
	TCPFail bool `json:"tcp_fail,omitempty"`
}

// AnswerGroup: one distinct answer set and who returned it.
type AnswerGroup struct {
	Values  []string `json:"values"`
	Servers []string `json:"servers"`
}

// maxAuthoritative bounds the fan-out: a zone with 30 nameservers must not
// turn one click into 60 queries.
const maxAuthoritative = 8

// maxZoneWalk bounds the climb towards the apex. The registrable-domain stop
// below normally ends the walk long before this, but the walk is the one place
// where a name's shape decides how many upstream queries we issue, so it gets
// a named ceiling like every other fan-out here.
const maxZoneWalk = 8

// Spread runs the check. qtype defaults to A.
func (s *Service) Spread(ctx context.Context, name, qtype string) (*Spread, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	if qtype = strings.ToUpper(strings.TrimSpace(qtype)); qtype == "" {
		qtype = "A"
	}
	// The package allowlist, not miekg's whole RR registry: this page aims its
	// queries at third-party nameservers of the caller's choosing, so ANY and
	// AXFR — which /? rejects — would make it an amplification pipe.
	if !slices.Contains(Types, qtype) {
		return nil, ErrBadType
	}
	// A reverse lookup has no zone to canvass in a useful way.
	if _, isIP := reverseName(name); isIP {
		return nil, fmt.Errorf("%w: give a domain name, not an IP", ErrBadType)
	}

	if err := validDomain(name); err != nil {
		return nil, err
	}
	// Lowercased once here for the same reason LookupSet does it: the wire is
	// case-insensitive, so a capitalised name is the same question.
	qname := strings.ToLower(dns.Fqdn(name))
	out := &Spread{Name: name, QName: qname, Type: qtype}
	start := time.Now()

	// Default resolver does the groundwork: find the zone's nameservers.
	defaultAddr, _ := resolverAddr(DefaultResolver)
	nsNames, zone, total := s.zoneNameservers(ctx, qname, defaultAddr)
	out.Zone, out.NSTotal = zone, total
	out.NSTruncated = total > len(nsNames)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	auth := make([]ServerAnswer, len(nsNames))
	res := make([]ServerAnswer, len(Resolvers))

	for i, ns := range nsNames {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			// Stands until the probe returns. A blank slot has no Error, and
			// health() would count it as a nameserver that answered.
			auth[i] = ServerAnswer{Label: strings.TrimSuffix(ns, "."), Error: errPanic.Error()}
			sem <- struct{}{}
			defer func() { <-sem }()
			auth[i] = s.askAuthoritative(ctx, qname, qtype, ns, defaultAddr)
		})
	}
	for i, r := range Resolvers {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			res[i] = ServerAnswer{Label: r.Name, Addr: r.Addr, Error: errPanic.Error()}
			sem <- struct{}{}
			defer func() { <-sem }()
			res[i] = s.askResolver(ctx, qname, qtype, r)
		})
	}
	wg.Wait()

	out.Authoritative, out.Resolvers = auth, res
	out.QueryMS = time.Since(start).Milliseconds()
	out.summarise()
	return out, nil
}

// zoneNameservers finds the nameservers responsible for qname, walking up the
// tree when the name itself has no NS records (www.example.com is served by
// example.com's nameservers).
//
// The walk stops at the registrable domain. Above that sits the registry, and
// its nameservers are emphatically not "the zone's own": for an unregistered
// name the old unbounded walk listed Nominet's servers and printed a green
// health report about them. Returns the total NS count as well as the capped
// list, so the caller can say how much of the delegation it actually asked.
func (s *Service) zoneNameservers(ctx context.Context, qname, addr string) (names []string, zone string, total int) {
	apex, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(qname, "."))
	if err != nil {
		// No registrable domain means qname IS a public suffix. Canvassing a
		// TLD's nameservers answers nobody's question and costs a registry.
		return nil, "", 0
	}
	apex = dns.Fqdn(apex)

	n := qname
	for steps := 0; steps < maxZoneWalk; steps++ {
		r, err := s.lookup(ctx, n, "NS", addr)
		if err == nil {
			var out []string
			for _, rec := range r.Records {
				if rec.Type == "NS" {
					out = append(out, rec.Value)
				}
			}
			if len(out) > 0 {
				sort.Strings(out)
				total = len(out)
				if len(out) > maxAuthoritative {
					out = out[:maxAuthoritative]
				}
				return out, n, total
			}
		}
		if n == apex {
			break
		}
		n = n[strings.Index(n, ".")+1:]
	}
	return nil, "", 0
}

// ask sends one query and repeats it over TCP when the answer came back
// truncated, exactly as exchange() does. Without the retry the authoritative
// half sees whatever fits in 512 bytes while every resolver sees the full
// EDNS0 answer, and google.com's TXT set renders as "your nameservers
// disagree" — the flagship false verdict this page exists to prevent.
func (s *Service) ask(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	resp, _, err := s.udp.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		if full, _, tcpErr := s.tcp.ExchangeContext(ctx, m, addr); tcpErr == nil {
			return full, nil
		}
	}
	return resp, nil
}

// askAuthoritative queries one nameserver directly with recursion disabled, so
// the answer is the zone's own, not a cache's. Also reads its SOA serial, which
// is what reveals a zone mid-rollout.
func (s *Service) askAuthoritative(ctx context.Context, qname, qtype, nsName, viaAddr string) ServerAnswer {
	a := ServerAnswer{Label: strings.TrimSuffix(nsName, ".")}

	// Resolve the nameserver's own address first.
	ipRec, err := s.lookup(ctx, dns.Fqdn(nsName), "A", viaAddr)
	if err != nil || len(ipRec.Records) == 0 {
		a.Error = "could not resolve this nameserver's address"
		return a
	}
	ip := ipRec.Records[0].Value
	// The NS names come from a zone the caller chose, so this is the one place
	// a request decides which address we send packets to. A name pointing at
	// 127.0.0.1 or 169.254.169.254 turns the page into a port-53 probe of our
	// own host, and the timings answer back.
	if !routable(ip) {
		a.Error = "this nameserver resolves to a non-public address, so it was not probed"
		return a
	}
	a.Addr = ip + ":53"

	start := time.Now()
	// newQuery, not a hand-built message: it carries the 1232-byte EDNS0
	// buffer, without which this half is capped at 512 bytes.
	m := newQuery(qname, qtype)
	m.RecursionDesired = false // the whole point: no cache in the way
	resp, err := s.ask(ctx, m, a.Addr)
	a.RTTMS = time.Since(start).Milliseconds()
	if err != nil {
		a.Error = "no response"
		return a
	}
	a.Rcode, a.AA = dns.RcodeToString[resp.Rcode], resp.Authoritative
	a.Values, a.TTL, a.CNAME = answerValues(resp, qtype)
	switch {
	case resp.Rcode == dns.RcodeRefused, resp.Rcode == dns.RcodeServerFailure, resp.Rcode == dns.RcodeNotAuth:
		a.Error = "answered " + a.Rcode + ", so it is delegated this zone but not serving it (a lame delegation)"
		return a
	case !resp.Authoritative && len(a.Values) == 0 && a.CNAME == "":
		a.Error = "answered without the authoritative bit, so it is not serving this zone (a lame delegation)"
		return a
	}

	// Open-recursion probe: ask this server to recurse for a name it does not
	// serve. An authoritative-only server must refuse; one that answers is an
	// open resolver and can be abused as an amplifier.
	probe := new(dns.Msg)
	probe.SetQuestion("a.root-servers.net.", dns.TypeA)
	probe.RecursionDesired = true
	if pr, _, err := s.udp.ExchangeContext(ctx, probe, a.Addr); err == nil {
		a.OpenResolver = pr.RecursionAvailable && pr.Rcode == dns.RcodeSuccess && len(pr.Answer) > 0
	}

	// TCP/53 must work: anything too big for UDP falls back to it.
	tcpProbe := new(dns.Msg)
	tcpProbe.SetQuestion(qname, dns.TypeSOA)
	tcpProbe.RecursionDesired = false
	if _, _, err := s.tcp.ExchangeContext(ctx, tcpProbe, a.Addr); err != nil {
		a.TCPFail = true
	}

	// Serial is a second, cheap question that says which version of the zone
	// this server is serving.
	soa := new(dns.Msg)
	soa.SetQuestion(qname, dns.TypeSOA)
	soa.RecursionDesired = false
	if sr, _, err := s.udp.ExchangeContext(ctx, soa, a.Addr); err == nil {
		for _, rr := range append(sr.Answer, sr.Ns...) {
			if v, ok := rr.(*dns.SOA); ok {
				a.Serial = v.Serial
				break
			}
		}
	}
	return a
}

// askResolver queries a public resolver normally, so the answer reflects what
// the wider internet is currently being told.
func (s *Service) askResolver(ctx context.Context, qname, qtype string, r Resolver) ServerAnswer {
	a := ServerAnswer{Label: r.Name, Addr: r.Addr}
	start := time.Now()
	resp, err := s.ask(ctx, newQuery(qname, qtype), r.Addr)
	a.RTTMS = time.Since(start).Milliseconds()
	if err != nil {
		a.Error = "no response"
		return a
	}
	a.Rcode = dns.RcodeToString[resp.Rcode]
	a.Values, a.TTL, a.CNAME = answerValues(resp, qtype)
	if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeServerFailure {
		a.Error = "answered " + a.Rcode
	}
	return a
}

// answerValues extracts the answer set for the asked type plus the lowest TTL
// in it. Sorting matters: two servers holding the same records must compare
// equal even when they rotate the order.
//
// Only the asked type is kept. The answer section of a CNAME'd name also
// carries the chain, and an authoritative server stops at the alias while a
// resolver follows it to the end, so counting everything guarantees the two
// halves never match. The alias itself comes back separately.
func answerValues(m *dns.Msg, qtype string) (vals []string, ttl uint32, cname string) {
	want := dns.StringToType[qtype]
	for _, rr := range m.Answer {
		rrType := rr.Header().Rrtype
		if rrType == dns.TypeCNAME && want != dns.TypeCNAME {
			if cname == "" {
				cname = rdata(rr)
			}
			continue
		}
		if rrType != want {
			continue
		}
		vals = append(vals, rdata(rr))
		if t := rr.Header().Ttl; ttl == 0 || t < ttl {
			ttl = t
		}
	}
	sort.Strings(vals)
	return vals, ttl, cname
}

// answerKey collapses a sorted answer set into one comparable string.
func answerKey(vals []string) string { return strings.Join(vals, "\n") }

// routable rejects the addresses a nameserver name must never point at before
// we send it a packet. Mirrors the guard tools/iptools applies to user-supplied
// addresses; worth promoting to a shared helper once a third caller wants it.
func routable(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

// summarise derives the verdict: who agrees with whom, whether the zone's own
// servers are in step, and how stale the cached copies are.
func (sp *Spread) summarise() {
	all := append(slices.Clone(sp.Authoritative), sp.Resolvers...)
	sp.Asked = len(all)
	sp.Rcode = unanimousRcode(all)

	byKey := map[string][]string{}
	var order []string
	for _, a := range all {
		if a.Error != "" || len(a.Values) == 0 {
			continue
		}
		sp.Answered++
		k := answerKey(a.Values)
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], a.Label)
	}

	for _, k := range order {
		sp.Groups = append(sp.Groups, AnswerGroup{
			Values:  strings.Split(k, "\n"),
			Servers: byKey[k],
		})
	}
	sort.SliceStable(sp.Groups, func(i, j int) bool {
		return len(sp.Groups[i].Servers) > len(sp.Groups[j].Servers)
	})
	// Nothing answered means nothing to be consistent ABOUT. Without this the
	// verdict reads green while the panel beside it says no records came back.
	sp.Consistent = sp.Answered > 0 && len(sp.Groups) <= 1

	// Serial agreement, bucketed by provider. github.com is the worked example:
	// its four nsone.net servers serve one serial and its four awsdns servers
	// another, which is correct operation of a two-provider zone, not a
	// rollout in progress.
	sp.SerialsAgree = true
	byProvider := map[string]uint32{}
	for _, a := range sp.Authoritative {
		if a.Error != "" || a.Serial == 0 {
			continue
		}
		sp.SerialsSeen++
		p := providerKey(a.Label)
		if first, seen := byProvider[p]; !seen {
			byProvider[p] = a.Serial
		} else if a.Serial != first {
			sp.SerialsAgree = false
		}
	}
	sp.MultiProvider = len(byProvider) > 1

	// Do the zone's own servers agree among themselves?
	authKeys := map[string]bool{}
	var authKey string
	for _, a := range sp.Authoritative {
		if a.Error != "" || len(a.Values) == 0 {
			continue
		}
		sp.AuthAnswered++
		k := answerKey(a.Values)
		if authKey == "" {
			authKey = k
		}
		authKeys[k] = true
	}
	sp.AuthConsistent = len(authKeys) <= 1
	// Different records, one zone version: the servers are rotating a pool,
	// not finishing a rollout. Stating a cause from a single sample per server
	// is what makes github.com read as mid-rollout on every other page load,
	// and the serials already collected are the discriminator that needs no
	// second query. Read per provider for the same reason SerialsAgree is:
	// independent providers keep independent serials, so a global comparison
	// would rule out rotation on every multi-provider zone.
	sp.Rotation = len(authKeys) > 1 && sp.AuthAnswered > 1 &&
		sp.SerialsAgree && sp.SerialsSeen > 1

	// The authoritative TTL is the yardstick for cache age, and only earns
	// that role when the zone speaks with one voice: subtracting a resolver's
	// 20s A TTL from an authoritative 3600s CNAME TTL printed "59m cached" for
	// a record that lives 20 seconds.
	var authTTL uint32
	if len(authKeys) == 1 {
		for _, a := range sp.Authoritative {
			if a.Error == "" && answerKey(a.Values) == authKey && a.TTL > authTTL {
				authTTL = a.TTL
			}
		}
	}

	// StaleFor counts every resolver that answered, including one whose TTL
	// exceeds the authoritative value — that case IS a TTL-lowering migration,
	// which is precisely what this number exists to report.
	var worst uint32
	resolverKeys := map[string]bool{}
	var resolverKey string
	for i, r := range sp.Resolvers {
		if r.Error != "" || len(r.Values) == 0 {
			continue
		}
		k := answerKey(r.Values)
		if resolverKey == "" {
			resolverKey = k
		}
		resolverKeys[k] = true
		if r.TTL > worst {
			worst = r.TTL
		}
		if authTTL > 0 && k == authKey && r.TTL > 0 && r.TTL <= authTTL {
			sp.Resolvers[i].CacheAge = humanizeTTL(authTTL - r.TTL)
		}
	}
	if worst > 0 {
		sp.StaleFor = humanizeTTL(worst)
	}
	sp.ResolverGroups = len(resolverKeys)
	// One answer everywhere downstream, a different one at the zone, and the
	// zone in step: a change already made and still cached. Nothing about that
	// is anycast steering, which needs the resolvers to disagree.
	sp.ResolversStale = sp.ResolverGroups == 1 && sp.AuthConsistent &&
		authKey != "" && resolverKey != authKey

	sp.health()
}

// unanimousRcode returns the response code every server that responded agreed
// on, or empty when they differed. Unanimity is the only case worth a verdict:
// one NXDOMAIN among eight NOERRORs says something is broken, not that the
// name is gone.
func unanimousRcode(all []ServerAnswer) string {
	var code string
	for _, a := range all {
		if a.Rcode == "" {
			continue
		}
		if code == "" {
			code = a.Rcode
			continue
		}
		if a.Rcode != code {
			return ""
		}
	}
	return code
}

// health derives delegation findings from what the probes already saw. Pure
// judgement over collected data: no extra queries.
func (sp *Spread) health() {
	add := func(level, text string) { sp.Health = append(sp.Health, Note{Level: level, Text: text}) }

	live := 0
	for _, a := range sp.Authoritative {
		if a.Error == "" {
			live++
		}
		if a.OpenResolver {
			add("fail", a.Label+" answers recursive queries for zones it doesn't serve. That makes it usable as a DNS amplification reflector by anyone on the internet. Restrict recursion to your own clients.")
		}
		if a.TCPFail {
			add("warn", a.Label+" refused TCP/53. DNS falls back to TCP for any answer too large for UDP, so blocking it breaks DNSSEC and large record sets in ways that look intermittent.")
		}
	}

	// RFC 2182: at least two nameservers, and they should not share a fate.
	switch {
	case len(sp.Authoritative) == 0:
		// Now the ordinary outcome for an unregistered name, since the walk
		// stops at the registrable domain instead of climbing to the registry.
		// Saying "none answered" would blame servers that were never found.
		add("fail", "No nameservers are delegated for this name, so nothing serves it.")
	case live == 0:
		add("fail", "None of the zone's nameservers answered.")
	case live == 1:
		add("fail", "Only one nameserver answered. RFC 2182 asks for at least two: a single server is a single point of failure for the whole domain.")
	default:
		add("ok", fmt.Sprintf("%d nameservers answered, so the zone survives losing one.", live))
	}
}

// AddDelegationHealth appends the findings that need data the DNS probes
// cannot supply on their own: which networks the nameserver addresses sit in,
// and what the registry says the delegation is.
//
// Both inputs are the caller's to fetch, because one is an in-process geo
// lookup and the other an outbound RDAP request, and neither belongs in this
// file. Both are optional: a nil asnOf or an empty registryNS adds no finding
// rather than a wrong one. registryNS must describe sp.Zone, not sp.QName —
// the registry has no record of a name below the apex.
//
// Reports whether any ASN actually reached a finding, which is what drives the
// IP2Location credit their licence requires wherever their data is shown.
func (sp *Spread) AddDelegationHealth(asnOf func(ip string) string, registryNS []string) bool {
	add := func(level, text string) { sp.Health = append(sp.Health, Note{Level: level, Text: text}) }
	usedASN := false

	// Diversity: nameservers sharing one network share one outage.
	if asnOf != nil {
		asns, nets := map[string]bool{}, map[string]bool{}
		resolved := 0
		for _, a := range sp.Authoritative {
			ip, _, found := strings.Cut(a.Addr, ":")
			if !found || a.Error != "" {
				continue
			}
			resolved++
			if i := strings.LastIndex(ip, "."); i > 0 {
				nets[ip[:i]] = true // rough /24
			}
			if asn := asnOf(ip); asn != "" {
				asns[asn] = true
			}
		}
		if resolved > 1 {
			switch {
			case len(asns) == 1:
				for asn := range asns {
					add("warn", "Every nameserver sits in the same network (AS"+asn+"). One provider outage takes the whole domain offline; the usual fix is a secondary DNS provider.")
				}
				usedASN = true
			case len(asns) > 1:
				add("ok", fmt.Sprintf("Nameservers are spread across %d different networks.", len(asns)))
				usedASN = true
			}
			if len(nets) == 1 && len(asns) <= 1 {
				add("warn", "All nameserver addresses are in the same /24, so they likely share a rack, a router and a fate.")
			}
		}
	}

	// Registry vs zone: the parent's delegation and the zone's own NS records
	// must agree, or resolvers and your control panel disagree about reality.
	if len(registryNS) == 0 {
		return usedASN
	}
	atRegistry := map[string]bool{}
	for _, ns := range registryNS {
		atRegistry[strings.ToLower(strings.TrimSuffix(ns, "."))] = true
	}
	var missing []string
	for _, a := range sp.Authoritative {
		if !atRegistry[strings.ToLower(a.Label)] {
			missing = append(missing, a.Label)
		}
	}
	switch {
	case len(missing) > 0:
		add("warn", "The zone serves nameservers the registry doesn't list ("+strings.Join(missing, ", ")+"). Resolvers follow the registry's delegation, so these may never be asked.")
	case sp.NSTruncated:
		// We only probed maxAuthoritative of the zone's nameservers, so the
		// counts cannot be compared: doing so reported every zone with 9+
		// nameservers as mis-delegated when the cause was our own sampling.
	case len(atRegistry) != sp.NSTotal:
		add("warn", fmt.Sprintf("The registry lists %d nameservers but the zone serves %d. A delegation mismatch sends some queries to servers that won't answer.", len(atRegistry), sp.NSTotal))
	default:
		add("ok", "The registry's delegation matches the nameservers the zone serves.")
	}
	return usedASN
}

// providerKey reduces a nameserver hostname to the operator running it, so
// serials are only compared between servers of the same operator.
//
// The providers table in decode.go is consulted first, because it already
// knows the shapes that defeat any suffix rule: Route 53 spreads one zone's
// nameservers across .com/.net/.org/.co.uk, and bucketing those by registrable
// domain put a single-provider AWS zone in four buckets, where no two serials
// were ever compared and the page announced several DNS providers.
//
// Anything unknown falls back to the registrable domain with the TLD dropped
// and a trailing -<digits> stripped, so awsdns-21.co.uk and awsdns-01.net
// would still meet even if the table lost that entry.
func providerKey(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range providers {
		if strings.Contains(h, p.suffix) {
			return p.name
		}
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		base = h
	}
	label, _, _ := strings.Cut(base, ".")
	return strings.TrimRight(strings.TrimRight(label, "0123456789"), "-")
}
