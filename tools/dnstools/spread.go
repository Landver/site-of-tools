package dnstools

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Spread compares the zone's own nameservers (RD=0) with public resolvers, grouped by answer
// set rather than a "% propagated" figure, so healthy GeoDNS doesn't read as a stalled change.
type Spread struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`
	// Zone: the apex the NS set came from; registry lookups use this, not QName.
	Zone string `json:"zone,omitempty"`

	Authoritative []ServerAnswer `json:"authoritative"`
	Resolvers     []ServerAnswer `json:"resolvers"`

	// NSTruncated: maxAuthoritative dropped some of the NSTotal delegated nameservers.
	NSTotal     int  `json:"ns_total,omitempty"`
	NSTruncated bool `json:"ns_truncated,omitempty"`

	// Groups counts both halves; a sentence about public resolvers wants ResolverGroups.
	Groups         []AnswerGroup `json:"groups"`
	ResolverGroups int           `json:"resolver_groups"`
	// ResolversStale: resolvers agree with each other but not with an in-step zone: still cached.
	ResolversStale bool `json:"resolvers_stale,omitempty"`

	Consistent bool `json:"consistent"`
	// AuthConsistent: the zone's own servers agree; meaningless until AuthAnswered is 2+.
	AuthConsistent bool `json:"auth_consistent"`
	AuthAnswered   int  `json:"auth_answered"`
	// Rotation: one provider's servers differ at the same serial: round-robin, not a rollout.
	Rotation bool `json:"rotation,omitempty"`
	// SerialsAgree is per provider (independent providers keep independent serials) and
	// starts true, so SerialsSeen says whether any serial was read.
	SerialsAgree  bool `json:"serials_agree"`
	SerialsSeen   int  `json:"serials_seen"`
	MultiProvider bool `json:"multi_provider,omitempty"`
	Answered      int  `json:"answered"`
	Asked         int  `json:"asked"`
	// Rcode: the code every responding server agreed on; empty if they differed or none did.
	Rcode  string `json:"rcode,omitempty"`
	Health []Note `json:"health,omitempty"`
	// StaleFor: the longest TTL at a public resolver, i.e. how long a stale answer can survive.
	StaleFor string `json:"stale_for,omitempty"`
	QueryMS  int64  `json:"query_ms"`
}

// ServerAnswer: what one server said, or why it didn't.
type ServerAnswer struct {
	Label string `json:"label"`
	Addr  string `json:"addr"`
	// Values: the asked type only, sorted so equal sets compare equal.
	Values []string `json:"values"`
	// CNAME stays out of Values: an authoritative server stops at the alias, a resolver chases it.
	CNAME string `json:"cname,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	// Rcode: miekg returns err == nil for every rcode, NXDOMAIN and REFUSED included.
	Rcode string `json:"rcode,omitempty"`
	AA    bool   `json:"aa,omitempty"`
	// CacheAge: authoritative TTL minus this TTL, set only when both returned the same set.
	CacheAge string `json:"cache_age,omitempty"`
	Serial   uint32 `json:"serial,omitempty"`
	RTTMS    int64  `json:"rtt_ms"`
	Error    string `json:"error,omitempty"`

	// OpenResolver: recursed for a stranger on a zone it doesn't serve, so it's an amplifier.
	OpenResolver bool `json:"open_resolver,omitempty"`
	// TCPFail: TCP/53 failed (a timeout gets one retry); large answers and DNSSEC need TCP.
	TCPFail bool `json:"tcp_fail,omitempty"`
	// TCPRefused: refused or reset. A timeout may be our egress, so only this names the operator.
	TCPRefused bool `json:"tcp_refused,omitempty"`
}

// AnswerGroup: one distinct answer set and who returned it.
type AnswerGroup struct {
	Values  []string `json:"values"`
	Servers []string `json:"servers"`
}

const (
	maxAuthoritative = 8 // 30 nameservers must not turn one click into 60 queries
	maxZoneWalk      = 8 // the registrable-domain stop normally ends the walk first
)

// Spread runs the check. qtype defaults to A.
func (s *Service) Spread(ctx context.Context, name, qtype string) (*Spread, error) {
	name, qtype = strings.TrimSpace(name), walkType(qtype)
	// Types, not miekg's registry: ANY/AXFR at caller-chosen nameservers is an amplification pipe.
	if !slices.Contains(Types, qtype) {
		return nil, ErrBadType
	}
	if err := needDomain(name); err != nil {
		return nil, err
	}
	qname := strings.ToLower(dns.Fqdn(name))
	out := &Spread{Name: name, QName: qname, Type: qtype}
	start := time.Now()

	via, _ := resolverAddr(DefaultResolver)
	nsNames, zone, total := s.zoneNameservers(ctx, qname, via)
	out.Zone, out.NSTotal, out.NSTruncated = zone, total, total > len(nsNames)

	n := len(nsNames)
	out.Authoritative, out.Resolvers = make([]ServerAnswer, n), make([]ServerAnswer, len(Resolvers))
	fanOut(n+len(Resolvers), 6, func(i int) {
		// Each slot holds errPanic until its probe returns: a blank slot would count as answering.
		if i < n {
			out.Authoritative[i] = ServerAnswer{Label: strings.TrimSuffix(nsNames[i], "."), Error: errPanic.Error()}
			out.Authoritative[i] = s.askAuthoritative(ctx, qname, qtype, nsNames[i], via)
			return
		}
		r := Resolvers[i-n]
		out.Resolvers[i-n] = ServerAnswer{Label: r.Name, Addr: r.Addr, Error: errPanic.Error()}
		out.Resolvers[i-n] = s.askResolver(ctx, qname, qtype, r)
	})
	out.QueryMS = time.Since(start).Milliseconds()
	out.summarise()
	return out, nil
}

// zoneNameservers walks up from qname to the first name with NS records, stopping at the
// registrable domain: above it sit the registry's servers, not the zone's own.
func (s *Service) zoneNameservers(ctx context.Context, qname, addr string) (names []string, zone string, total int) {
	apex, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(qname, "."))
	if err != nil {
		return nil, "", 0 // qname is a public suffix
	}
	n := qname
	for range maxZoneWalk {
		if r, err := s.lookup(ctx, n, "NS", addr); err == nil {
			for _, rec := range r.Records {
				names = append(names, rec.Value)
			}
			slices.Sort(names)
			return names[:min(len(names), maxAuthoritative)], n, len(names)
		}
		if n == apex+"." {
			break
		}
		_, n, _ = strings.Cut(n, ".")
	}
	return nil, "", 0
}

// askAuthoritative asks one nameserver with RD=0, then probes recursion, TCP/53 and its serial.
func (s *Service) askAuthoritative(ctx context.Context, qname, qtype, nsName, viaAddr string) ServerAnswer {
	a := ServerAnswer{Label: strings.TrimSuffix(nsName, ".")}

	ip, found := s.nameserverAddress(ctx, nsName, viaAddr)
	if ip == "" {
		a.Error = "this nameserver resolves to a non-public address, so it was not probed"
		if !found {
			a.Error = "could not resolve this nameserver's address (no A or AAAA record)"
		}
		return a
	}
	a.Addr = net.JoinHostPort(ip, "53")

	start := time.Now()
	// newQuery carries the 1232-byte EDNS0 buffer; a bare message caps this half at 512 bytes.
	m := newQuery(qname, qtype)
	m.RecursionDesired = false
	resp, _, err := s.ask(ctx, m, a.Addr)
	a.RTTMS = time.Since(start).Milliseconds()
	if err != nil {
		a.Error = "no response"
		return a
	}
	a.Rcode, a.AA = dns.RcodeToString[resp.Rcode], resp.Authoritative
	a.Values, a.TTL, a.CNAME = answerValues(resp, qtype)
	if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeNotAuth ||
		!resp.Authoritative && len(a.Values) == 0 && a.CNAME == "" {
		a.Error = "answered " + a.Rcode + " without authority, so it is delegated this zone but not serving it (a lame delegation)"
		return a
	}

	// A real name, since an open resolver also NXDOMAINs a random label; AA spares a server
	// that happens to serve the probe name.
	probe := new(dns.Msg).SetQuestion("a.root-servers.net.", dns.TypeA) // RD=1
	if pr, _, err := s.udp.ExchangeContext(ctx, probe, a.Addr); err == nil {
		a.OpenResolver = pr.RecursionAvailable && !pr.Authoritative &&
			pr.Rcode == dns.RcodeSuccess && len(pr.Answer) > 0
	}

	// The serial comes over TCP, so TCP/53 is probed for free; UDP only when TCP fails.
	soa := new(dns.Msg).SetQuestion(qname, dns.TypeSOA)
	soa.RecursionDesired = false
	sr, _, err := s.tcp.ExchangeContext(ctx, soa, a.Addr)
	if isTimeout(err) { // one slow handshake isn't evidence against a named operator
		sr, _, err = s.tcp.ExchangeContext(ctx, soa, a.Addr)
	}
	if err != nil {
		a.TCPFail = true
		a.TCPRefused = errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
		sr, _, err = s.udp.ExchangeContext(ctx, soa, a.Addr)
	}
	if err == nil {
		for _, rr := range append(sr.Answer, sr.Ns...) {
			if v, ok := rr.(*dns.SOA); ok {
				a.Serial = v.Serial
				break
			}
		}
	}
	return a
}

// nameserverAddress picks the first routable A, else AAAA, address. The zone is caller-chosen,
// so this is the SSRF gate; found separates "no address" from "only unroutable ones".
func (s *Service) nameserverAddress(ctx context.Context, nsName, viaAddr string) (ip string, found bool) {
	for _, t := range [...]string{"A", "AAAA"} {
		r, _ := s.lookup(ctx, dns.Fqdn(nsName), t, viaAddr)
		for _, rec := range r.Records {
			found = true
			if s.nsRoutable(rec.Value) {
				return rec.Value, true
			}
		}
	}
	return "", found
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *Service) askResolver(ctx context.Context, qname, qtype string, r Resolver) ServerAnswer {
	a := ServerAnswer{Label: r.Name, Addr: r.Addr}
	start := time.Now()
	resp, _, err := s.ask(ctx, newQuery(qname, qtype), r.Addr)
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

// answerValues returns the sorted set of the asked type, its lowest TTL and the first CNAME.
func answerValues(m *dns.Msg, qtype string) (vals []string, ttl uint32, cname string) {
	want := dns.StringToType[qtype]
	for _, rr := range m.Answer {
		switch h := rr.Header(); {
		case h.Rrtype == want:
			vals = append(vals, rdata(rr))
			if ttl == 0 || h.Ttl < ttl {
				ttl = h.Ttl
			}
		case h.Rrtype == dns.TypeCNAME && cname == "":
			cname = rdata(rr)
		}
	}
	slices.Sort(vals)
	return vals, ttl, cname
}

// answerKey collapses a sorted answer set into one comparable string.
func answerKey(vals []string) string { return strings.Join(vals, "\n") }

// answerGroups groups labels by identical answer set, largest first, ties first-seen; an empty set is a group.
func answerGroups(labels []string, sets [][]string) []AnswerGroup {
	var groups []AnswerGroup
	at := map[string]int{}
	for i, s := range sets {
		k := answerKey(s)
		j, seen := at[k]
		if !seen {
			j, at[k] = len(groups), len(groups)
			// The set itself, not the key split back apart: Split turns the empty set into [""].
			groups = append(groups, AnswerGroup{Values: s})
		}
		groups[j].Servers = append(groups[j].Servers, labels[i])
	}
	slices.SortStableFunc(groups, func(a, b AnswerGroup) int { return len(b.Servers) - len(a.Servers) })
	return groups
}

// nsRoutable: may a nameserver address from a caller-chosen zone get a packet?
func (s *Service) nsRoutable(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if s != nil && s.guard != nil {
		return s.guard.AllowAddr(ip) == nil
	}
	return platform.PubliclyRoutable(ip)
}

func (sp *Spread) summarise() {
	all := append(slices.Clone(sp.Authoritative), sp.Resolvers...)
	sp.Asked = len(all)
	sp.Rcode = unanimousRcode(all, func(a ServerAnswer) string { return a.Rcode })

	var labels []string
	var sets [][]string
	for _, a := range all {
		if a.Error == "" && len(a.Values) > 0 {
			labels, sets = append(labels, a.Label), append(sets, a.Values)
		}
	}
	sp.Answered = len(labels)
	sp.Groups = answerGroups(labels, sets)
	sp.Consistent = len(sp.Groups) == 1

	// Serials and answer sets compare within one provider: independent providers keep independent serials.
	serialOf, keyOf, authKeys := map[string]uint32{}, map[string]string{}, map[string]bool{}
	var authKey string
	var authTTL uint32
	splitInside := false
	sp.SerialsAgree = true
	for _, a := range sp.Authoritative {
		if a.Error != "" {
			continue
		}
		p := providerKey(a.Label)
		if a.Serial != 0 {
			sp.SerialsSeen++
			if first, seen := serialOf[p]; !seen {
				serialOf[p] = a.Serial
			} else if first != a.Serial {
				sp.SerialsAgree = false
			}
		}
		if len(a.Values) == 0 {
			continue
		}
		sp.AuthAnswered++
		authKey = answerKey(a.Values)
		authKeys[authKey] = true
		authTTL = max(authTTL, a.TTL)
		if first, seen := keyOf[p]; !seen {
			keyOf[p] = authKey
		} else if first != authKey {
			splitInside = true
		}
	}
	sp.MultiProvider = len(serialOf) > 1
	sp.AuthConsistent = len(authKeys) <= 1
	sp.Rotation = splitInside && sp.SerialsAgree && sp.SerialsSeen > 1
	if len(authKeys) != 1 {
		authTTL = 0 // only a unanimous zone has a TTL to measure cache age against
	}

	// StaleFor includes TTLs above the authoritative one: that is a TTL-lowering migration.
	var worst uint32
	resolverKeys := map[string]bool{}
	for i, r := range sp.Resolvers {
		if r.Error != "" || len(r.Values) == 0 {
			continue
		}
		k := answerKey(r.Values)
		resolverKeys[k] = true
		worst = max(worst, r.TTL)
		if k == authKey && r.TTL > 0 && r.TTL <= authTTL {
			sp.Resolvers[i].CacheAge = humanizeTTL(authTTL - r.TTL)
		}
	}
	if worst > 0 {
		sp.StaleFor = humanizeTTL(worst)
	}
	sp.ResolverGroups = len(resolverKeys)
	sp.ResolversStale = sp.ResolverGroups == 1 && sp.AuthConsistent && authKey != "" && !resolverKeys[authKey]
	sp.health()
}

// unanimousRcode: one NXDOMAIN among eight NOERRORs means breakage, so only unanimity counts.
func unanimousRcode[T any](all []T, rcodeOf func(T) string) string {
	var code string
	for _, a := range all {
		c := rcodeOf(a)
		if c != "" && code != "" && c != code {
			return ""
		}
		code = cmp.Or(c, code)
	}
	return code
}

func (sp *Spread) addHealth(level, text string) {
	sp.Health = append(sp.Health, Note{Level: level, Text: text})
}

// health judges the delegation from what the probes already saw; no extra queries.
func (sp *Spread) health() {
	live := 0
	for _, a := range sp.Authoritative {
		if a.Error == "" {
			live++
		}
		if a.OpenResolver {
			sp.addHealth("fail", a.Label+" answered a recursive query from this checker for a zone it doesn't serve, so its recursion isn't restricted to its own clients. That makes it usable as a DNS amplification reflector. Restrict recursion, or refuse it.")
		}
		if a.TCPFail {
			what := " did not complete a TCP/53 query"
			if a.TCPRefused {
				what = " refused TCP/53"
			}
			sp.addHealth("warn", a.Label+what+". DNS falls back to TCP for any answer too large for UDP, so blocking it breaks DNSSEC and large record sets in ways that look intermittent.")
		}
	}

	// RFC 2182: at least two nameservers, and they should not share a fate.
	switch n := len(sp.Authoritative); {
	case n == 0:
		sp.addHealth("fail", "No nameservers are delegated for this name, so nothing serves it.")
	case live == 0:
		sp.addHealth("fail", fmt.Sprintf("None of the zone's %d nameservers answered.", n))
	case n == 1:
		sp.addHealth("fail", "Only one nameserver is delegated. RFC 2182 asks for at least two: a single server is a single point of failure for the whole domain.")
	case live == 1:
		sp.addHealth("fail", fmt.Sprintf("Only 1 of the zone's %d nameservers answered. The rest are lame, and the one left is a single point of failure for the whole domain.", n))
	default:
		sp.addHealth("ok", fmt.Sprintf("%d nameservers answered, so the zone survives losing one.", live))
	}
}

// addDelegationHealth adds ASN-diversity and registry findings (registryNS describes sp.Zone).
func (sp *Spread) addDelegationHealth(asnOf func(ip string) string, registryNS []string) {
	asns, nets := map[string]bool{}, map[string]bool{}
	resolved, v4 := 0, 0
	for _, a := range sp.Authoritative {
		// SplitHostPort, not a cut at the first colon: an IPv6 Addr is bracketed.
		ip, _, err := net.SplitHostPort(a.Addr)
		if err != nil || a.Error != "" {
			continue
		}
		resolved++
		if i := strings.LastIndex(ip, "."); i > 0 {
			v4++
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
				sp.addHealth("warn", "Every nameserver sits in the same network (AS"+asn+"). One provider outage takes the whole domain offline; the usual fix is a secondary DNS provider.")
			}
		case len(asns) > 1:
			sp.addHealth("ok", fmt.Sprintf("Nameservers are spread across %d different networks.", len(asns)))
		}
		// All-IPv4 only: one shared /24 says nothing about where v6 servers sit.
		if len(nets) == 1 && v4 == resolved && len(asns) <= 1 {
			sp.addHealth("warn", "All nameserver addresses are in the same /24, so they likely share a rack, a router and a fate.")
		}
	}

	atRegistry := map[string]bool{}
	for _, ns := range registryNS {
		atRegistry[bareName(ns)] = true
	}
	var missing []string
	for _, a := range sp.Authoritative {
		if !atRegistry[strings.ToLower(a.Label)] {
			missing = append(missing, a.Label)
		}
	}
	switch {
	case len(registryNS) == 0: // no registry answer, nothing to compare
	case len(missing) > 0:
		sp.addHealth("warn", "The zone serves nameservers the registry doesn't list ("+strings.Join(missing, ", ")+"). Resolvers follow the registry's delegation, so these may never be asked.")
	case sp.NSTruncated: // only maxAuthoritative were probed, so the counts can't be compared
	case len(atRegistry) != sp.NSTotal:
		sp.addHealth("warn", fmt.Sprintf("The registry lists %d nameservers but the zone's own NS records name %d. Resolvers start from the registry's list, so check that every server on it still serves this zone.", len(atRegistry), sp.NSTotal))
	default:
		sp.addHealth("ok", "The registry's delegation matches the nameservers the zone serves.")
	}
	sortNotes(sp.Health)
}

type Spreader interface {
	Spread(ctx context.Context, name, qtype string) (*Spread, error)
}

// Consistency is GET /consistency: the canvass, the ECS card (ecs may be nil) beside it.
func Consistency(ctx context.Context, spr Spreader, ecs ECSer, geo iptools.Looker, dom *DomainClient, name, qtype string) (*ECSEnvelope, error) {
	if spr == nil {
		return nil, ErrDisabled
	}
	name, qtype = NormalizeName(name), walkType(qtype)
	var wg sync.WaitGroup
	var steer *ECS
	if ecs != nil {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			if res, err := ecs.ECS(ctx, name, qtype); err == nil {
				steer = res
			}
		})
	}
	sp, err := spr.Spread(ctx, name, qtype)
	if err == nil && sp != nil {
		delegationHealth(ctx, sp, geo, dom)
	}
	wg.Wait()
	if err != nil {
		return nil, err
	}
	return NewECSEnvelope(sp, steer)
}

func walkType(qtype string) string {
	return cmp.Or(strings.ToUpper(strings.TrimSpace(qtype)), "A")
}

func delegationHealth(ctx context.Context, sp *Spread, geo iptools.Looker, dom *DomainClient) {
	var registryNS []string
	if dom != nil && sp.Zone != "" {
		if reg, err := dom.Registration(ctx, sp.Zone); err == nil {
			registryNS = reg.Nameservers
		}
	}
	sp.addDelegationHealth(func(ip string) string {
		if geo != nil {
			if g, err := geo.Lookup(ip); err == nil && g != nil {
				return g.ASN
			}
		}
		return ""
	}, registryNS)
}

// providerKey reduces a nameserver to its operator: decode.go's providers table first (Route 53
// spans .com/.net/.org/.co.uk), else the registrable label minus a -<digits> suffix.
func providerKey(host string) string {
	h := bareName(host)
	if name := knownProvider(h); name != "" {
		return name
	}
	label, _, _ := strings.Cut(RegistrableDomain(h), ".")
	return strings.TrimRight(strings.TrimRight(label, "0123456789"), "-")
}
