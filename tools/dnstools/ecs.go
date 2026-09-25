package dnstools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ECS answers "does the answer this name gives change with the network the
// query says it is coming from?" — and nothing wider than that.
//
// It is NOT a geographic measurement, and no field here is allowed to read
// like one. RFC 7871's EDNS Client Subnet lets a query carry a client network,
// and a server that tailors its answer per network answers for THAT network
// instead of for ours. We send the same question several times, each carrying
// a different well-known public /24, and read what comes back. The place names
// on those prefixes are OURS, labels on a fixed table (see ecsVantages); the
// wire carries a prefix, never a location, and six prefixes could not map a
// zone's footprint even if it did.
//
// Two measured facts set the ceiling on what may be claimed, both reproducible
// with dig:
//
//  1. A scope equal to the prefix length we sent is what an ECHO looks like.
//     Cloudflare's authoritative servers return scope /24 for a /24 source on
//     corpberry.com while handing two different subnets byte-identical
//     answers — the scope is a copy of our number, not a statement about
//     theirs. Only a scope the zone chose for itself (ScopeDistinct: /17, /10
//     for a /24 source, as www.wikipedia.org returns) is evidence the client
//     network was read at all.
//
//  2. Differing answers are not by themselves a property of the network.
//     Three consecutive runs against corpberry.com produced three different
//     groupings of the same six prefixes — an anycast pool rotating under one
//     query per prefix. With one sample each, "these networks were given
//     different answers" is the whole finding; "because they are those
//     networks" is not in evidence, and reporting it would be the confident
//     verdict this suite exists to refuse.
//
// Scope 0 is bounded in the other direction, and the verdict is named
// Untailored rather than "not steered" for exactly this reason: it means no
// client-subnet tailoring happened on the path to THIS resolver. A zone that
// steers on the resolver's own location instead returns scope 0 too
// (www.apple.com, behind Akamai, does), and so does a resolver that chose not
// to forward the subnet. None of those is "this name is the same everywhere".
//
// Answers are compared as SETS (sorted, joined), for the same reason: a
// round-robin that reorders two addresses is not two different answers.
type ECS struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`
	// Resolver / ResolverAddr: who was asked. Named in the output because the
	// choice is load-bearing and not the caller's (see ecsResolverAddr).
	Resolver     string `json:"resolver"`
	ResolverAddr string `json:"resolver_addr"`

	// Vantages: one entry per client subnet sent, in the fixed order below,
	// including the ones that failed. A vantage point dropped for timing out
	// would quietly shrink the denominator behind Verdict.
	Vantages []ECSAnswer `json:"vantages"`
	// Groups: the distinct answer sets seen, largest first. One group means
	// every vantage point was told the same thing.
	//
	// "Told nothing" is a group too. A vantage point handed no record is not
	// missing from the comparison, it is one side of it: a name that resolves
	// in the US and answers NODATA in APAC is textbook steering, and dropping
	// the empty side would render that as "same answer everywhere". Such a
	// group carries an empty Values.
	Groups []ECSGroup `json:"groups"`
	// Rcode: the response code every vantage point that responded agreed on,
	// empty when they differed. Same contract as Spread's, and here for the
	// same reason: without it a name that exists nowhere and a name that
	// publishes no record of this type read identically.
	Rcode string `json:"rcode,omitempty"`

	// Verdict: one of the ECSVerdict* values. Six outcomes rather than a
	// boolean, because "no tailoring was applied on this path" and "we could
	// not tell" are different facts and collapsing them publishes confidence
	// we do not have. Every value names what was OBSERVED (the answers
	// differed; they matched; every scope was 0) rather than a mechanism the
	// observation cannot pin down.
	Verdict string `json:"verdict"`
	// MaxScope: the longest scope prefix any response came back with. The
	// single number the verdict turns on. Counted only over responses whose
	// echoed prefix was the one we sent (see ECSAnswer.Mismatch).
	MaxScope uint8 `json:"max_scope"`
	// Echoed: how many responses carried a client-subnet option back that
	// describes the network we asked about. Zero means the option was stripped
	// — or answered for somebody else — somewhere between us and the zone, so
	// nothing here measured anything.
	Echoed int `json:"echoed"`
	// WithRecords: how many of the answered vantage points were given at least
	// one record. Zero is its own verdict; a value between 1 and Answered is
	// the mixed case the notes call out.
	WithRecords int `json:"with_records"`
	// Mismatched: responses whose echoed client subnet was not the prefix we
	// sent. They are shown but not counted, because their scope describes a
	// network nobody here probed.
	Mismatched int `json:"mismatched,omitempty"`
	// ScopeDistinct: at least one counted response reported a non-zero scope
	// whose prefix length is NOT the length we sent it. That distinction is
	// the difference between evidence and noise. A server that simply echoes
	// the option back returns the source length unchanged — Cloudflare returns
	// /24 for our /24 on names it demonstrably does not tailor — so a scope
	// equal to the source proves only that the option survived the round trip.
	// A length the zone picked itself (/17, /10 for a /24 source) is the
	// authoritative side describing the block its answer covers, which is a
	// statement it had to mean.
	ScopeDistinct bool `json:"scope_distinct,omitempty"`
	// Rotation: the answers differ but every scope was 0, so the zone is
	// varying its answer per query rather than per client network.
	Rotation bool `json:"rotation,omitempty"`

	// Answered / Asked: the honest denominator, same contract as Spread's.
	Answered int    `json:"answered"`
	Asked    int    `json:"asked"`
	Notes    []Note `json:"notes,omitempty"`
	QueryMS  int64  `json:"query_ms"`
}

// ECSAnswer: what one vantage point was told, or why it was told nothing.
type ECSAnswer struct {
	// Region / Place: where the subnet sits. Both are ours, from the table
	// below — nothing here is geolocated at request time.
	Region string `json:"region"`
	Place  string `json:"place"`
	// Subnet: the client subnet we sent, verbatim.
	Subnet string `json:"subnet"`

	// Values: the answer set for the asked type, sorted so two vantage points
	// holding the same records compare equal whatever order they arrived in.
	Values []string `json:"values"`
	// CNAME: the alias the answer came through, kept out of Values for the
	// same reason Spread keeps it out of its own.
	CNAME string `json:"cname,omitempty"`
	TTL   uint32 `json:"ttl,omitempty"`
	Rcode string `json:"rcode,omitempty"`

	// Echoed: the response carried a client-subnet option. Without it Scope is
	// not "0", it is unknown, and the two must not render alike.
	Echoed bool `json:"ecs_echoed"`
	// Scope: the scope prefix length the response reported. 0 = the answer is
	// not tailored to the subnet we sent.
	Scope uint8 `json:"scope"`
	// SourceNetmask: the prefix length THIS row put on the wire, recorded next
	// to Scope so the two can be compared without the reader deriving one of
	// them from a constant. Scope == SourceNetmask is an echo; Scope different
	// from it is the zone's own number. Rendered on the row for that reason.
	SourceNetmask uint8 `json:"source_netmask,omitempty"`
	// EchoedSubnet: the prefix the resolver echoed, always recorded and
	// rendered whenever it is not Subnet.
	EchoedSubnet string `json:"echoed_subnet,omitempty"`
	// Mismatch: the echoed prefix is not the one we sent. A resolver serving a
	// cached ECS answer keyed to another prefix, or a middlebox rewriting the
	// option, produces a perfectly well-formed scope that describes a network
	// this page never probed. Such a row is displayed but kept out of Echoed
	// and MaxScope, so it cannot carry the verdict.
	Mismatch bool `json:"ecs_mismatch,omitempty"`

	RTTMS int64  `json:"rtt_ms"`
	Error string `json:"error,omitempty"`
}

// ECSGroup: one distinct answer set and the vantage points that were given it.
// An empty Values is a real group: those vantage points were given no record.
type ECSGroup struct {
	Values   []string `json:"values"`
	Vantages []string `json:"vantages"`
}

// The verdicts. Distinct constants rather than a bool, because four of the
// six are some flavour of "nothing varied" for entirely different reasons and
// a reader deserves to know which.
//
// The three scope-reading values are named after what was seen, not after a
// cause. "steered" and "not-steered" were the earlier names and both claimed
// more than the probe can reach: the first read an anycast pool's rotation as
// location, the second read a resolver's silence as a zone's statement.
const (
	// ECSVerdictDiffers: a non-zero scope came back AND the vantage points were
	// given different answer sets. Says the answers differed between the
	// prefixes we sent. Whether the prefix is the REASON they differed is what
	// ScopeDistinct speaks to, and even then only weakly.
	ECSVerdictDiffers = "answers-differ"
	// ECSVerdictMatches: a non-zero scope came back and every vantage point was
	// given the same answer. Without ScopeDistinct the non-zero scope is very
	// likely an echo of our own prefix length (Cloudflare does this on names it
	// does not tailor), so this is not "the zone looked and decided".
	ECSVerdictMatches = "answers-match"
	// ECSVerdictUntailored: every response reported scope 0. No client-subnet
	// tailoring was applied on the path to this resolver — which is not the
	// same claim as "this name answers the same everywhere", see the type doc.
	ECSVerdictUntailored = "untailored"
	// ECSVerdictUnsupported: no response carried a client-subnet option back,
	// so the option was dropped somewhere and we measured nothing. NOT the same
	// as not steered.
	ECSVerdictUnsupported = "unsupported"
	// ECSVerdictNoRecords: every vantage point that answered was given no
	// record of this type at all. There is nothing to steer, so none of the
	// four verdicts above can be earned — and "everyone gets the same records"
	// would be a sentence about records that do not exist.
	ECSVerdictNoRecords = "no-records"
	// ECSVerdictInconclusive: fewer than two vantage points answered, so there
	// is nothing to compare.
	ECSVerdictInconclusive = "inconclusive"
)

// ecsResolverKey: this feature does NOT use the caller's chosen resolver, and
// does not use the package default either.
//
// Cloudflare (1.1.1.1), the package default, deliberately never forwards EDNS
// Client Subnet and never returns the option. Measured against it,
// www.wikipedia.org — which really does steer, and returns six different
// addresses through Google with scopes between /10 and /17 — comes back as one
// identical address for all six subnets with no scope at all. A feature that
// reported "not steered" from that would report it for every domain on earth.
// So the resolver here is fixed to one that honours ECS rather than being
// offered as a choice that silently breaks the answer.
//
// Google is that resolver: it forwards the subnet and echoes the scope the
// authoritative side returned, which is the number the verdict reads.
//
// Held as a KEY into the Resolvers table, not as a copy of its address and
// label. Two string literals that have to stay equal to a row in dns.go are
// two chances to drift with nothing failing.
const ecsResolverKey = "google"

// ecsSourceNetmask: the documented default prefix length for the table below.
// /24 is coarse enough that it names a network rather than a household, and it
// is the prefix length authoritative servers are tuned for. The addresses
// themselves are fixed and ours (below) — a real visitor's address is never
// put on the wire here.
//
// Documentation only: what goes on the wire is the length parsed out of each
// entry's own CIDR string, so a table entry and its probe cannot disagree.
const ecsSourceNetmask = 24

// maxECSVantages caps the fan-out. One vantage point is one upstream query, so
// this is the whole query budget for the feature, and it is a package const
// rather than a property of the table so growing the table cannot quietly
// widen a request.
const maxECSVantages = 8

// ecsQueryTimeout bounds one vantage query. The Service-wide client timeout
// already applies; this is the per-query ceiling the request contributes on
// top of it, so a resolver that accepts the packet and never answers cannot
// hold a request open for the caller's whole context.
//
// Well under the Service's own timeout on purpose. This card is a passenger on
// a page whose main check is slower than it, and a measured round trip to
// Google is around 60 ms, so a probe still unanswered after three seconds is
// a lost packet: waiting longer buys a row nobody is still reading.
//
// Because ecsConcurrency covers the whole table in one wave, this is also the
// card's worst-case wall clock: ~3s, not a multiple of it.
const ecsQueryTimeout = 3 * time.Second

// ecsConcurrency: the whole table at once, and maxECSVantages is what bounds
// the fan-out.
//
// dns.go's narrower limit is right there because it is spraying packets at a
// zone's own nameservers; these all go to one public resolver, six or eight
// UDP queries deep, which is nothing. Sizing it below the table is what turns
// one unresponsive resolver into TWO ecsQueryTimeout waves — 6s of a page that
// cannot render until this card is done — for no benefit anyone measured.
const ecsConcurrency = maxECSVantages

// ecsSteerableTypes: the types worth asking this question about. Location
// steering is done by handing out different addresses, different aliases or
// different service endpoints; an MX or a SOA is the same everywhere and a
// card reporting "not steered" for it is noise dressed as a finding.
var ecsSteerableTypes = []string{"A", "AAAA", "CNAME", "HTTPS"}

// ecsVantage: one fixed probe point.
type ecsVantage struct {
	region string
	place  string
	subnet string
}

// ecsVantages: the client subnets we send, one per region.
//
// Every entry is a /24 inside a long-standing, RIR-registered allocation of a
// university or a national registry — networks that have sat in the same city
// for decades and are not anycast. That matters twice: an anycast prefix has
// no single location to steer towards, and a prefix that moves would make this
// page's answer drift for reasons that have nothing to do with the zone.
//
// These are ours, fixed, and public. The visitor's own address is never sent.
var ecsVantages = []ecsVantage{
	{region: "North America (east)", place: "New York, US", subnet: "128.59.0.0/24"},   // Columbia University
	{region: "North America (west)", place: "California, US", subnet: "171.64.0.0/24"}, // Stanford University
	{region: "Europe", place: "Amsterdam, NL", subnet: "192.87.0.0/24"},                // SURF
	{region: "Asia", place: "Tokyo, JP", subnet: "133.11.0.0/24"},                      // University of Tokyo
	{region: "South America", place: "São Paulo, BR", subnet: "200.160.0.0/24"},        // NIC.br
	{region: "Oceania", place: "Melbourne, AU", subnet: "130.194.0.0/24"},              // Monash University
}

// ECSer: handler dependency for the geo-steering card. Separate from Looker
// and Spreader so a test can fake this half alone. *Service satisfies it.
type ECSer interface {
	ECS(ctx context.Context, name, qtype string) (*ECS, error)
}

// ECSEnvelope: /consistency's JSON body once this card is on the page.
//
// *Spread is embedded rather than nested, so every key that endpoint already
// returns stays exactly where it was at the top level and the response simply
// gains "ecs". A nested {"spread": …, "ecs": …} would have been a breaking
// change to a published API for the sake of one new field.
//
// Build it with NewECSEnvelope, never as a literal. A nil embedded *Spread
// does not make encoding/json fail — it silently skips every promoted field,
// so the endpoint would answer 200 with a body that had quietly lost name,
// type, consistent and auth_consistent and carried nothing but "ecs". A
// breaking change to a published API is not a thing to discover in prod.
type ECSEnvelope struct {
	*Spread
	ECS *ECS `json:"ecs,omitempty"`
}

// ErrNoSpread: an envelope was asked for without the thing it wraps.
var ErrNoSpread = errors.New("an ECS envelope needs a spread to wrap")

// NewECSEnvelope is the only way to build the /consistency body. A nil ecs is
// fine (the card did not run, and "ecs" is omitted); a nil spread is the
// degenerate body above and is refused rather than served.
func NewECSEnvelope(sp *Spread, e *ECS) (*ECSEnvelope, error) {
	if sp == nil {
		return nil, ErrNoSpread
	}
	return &ECSEnvelope{Spread: sp, ECS: e}, nil
}

// ECS runs the check. qtype defaults to A.
func (s *Service) ECS(ctx context.Context, name, qtype string) (*ECS, error) {
	addr, ok := resolverAddr(ecsResolverKey)
	// Unreachable while ecsResolverKey names a row of Resolvers, which a test
	// asserts; kept so deleting that row is a failed check rather than a
	// query sent to the empty string.
	if !ok {
		return nil, ErrBadResolver
	}
	return s.ecsRun(ctx, name, qtype, addr, ResolverName(ecsResolverKey))
}

// ecsRun is ECS with the resolver as a parameter, which is the seam a
// white-box test drives a loopback server through. Unexported and never
// reached from a request: ECS above is the only caller in a shipped build, and
// it passes the constant, so no visitor can steer these packets anywhere.
func (s *Service) ecsRun(ctx context.Context, name, qtype, addr, resolverName string) (*ECS, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	if qtype = strings.ToUpper(strings.TrimSpace(qtype)); qtype == "" {
		qtype = "A"
	}
	if !slices.Contains(ecsSteerableTypes, qtype) {
		return nil, fmt.Errorf("%w: location steering is only measurable on %s",
			ErrBadType, strings.Join(ecsSteerableTypes, ", "))
	}
	if _, isIP := reverseName(name); isIP {
		return nil, fmt.Errorf("%w: give a domain name, not an IP", ErrBadType)
	}
	if err := validDomain(name); err != nil {
		return nil, err
	}
	// Lowercased once, for the same reason LookupSet and Spread do it: the wire
	// is case-insensitive, so a capitalised name is the same question.
	qname := strings.ToLower(dns.Fqdn(name))

	points := ecsVantages
	if len(points) > maxECSVantages {
		points = points[:maxECSVantages]
	}

	out := &ECS{
		Name: name, QName: qname, Type: qtype,
		Resolver: resolverName, ResolverAddr: addr,
		Asked:    len(points),
		Vantages: make([]ECSAnswer, len(points)),
		Groups:   []ECSGroup{},
	}

	start := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, ecsConcurrency)
	for i, v := range points {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			// Stands until the probe returns, so a recovered panic reports a
			// vantage point that failed rather than one that answered blank —
			// which summarise would otherwise count towards the verdict.
			out.Vantages[i] = ecsBlank(v, errPanic.Error())
			// Checked before queueing and again after: the semaphore is where a
			// cancelled request spends its time, and a query sent after the
			// caller has gone is a query nobody will read.
			if ctx.Err() != nil {
				out.Vantages[i] = ecsBlank(v, "the request ended before this vantage point was asked")
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				out.Vantages[i] = ecsBlank(v, "the request ended before this vantage point was asked")
				return
			}
			out.Vantages[i] = s.ecsAsk(ctx, qname, qtype, addr, v)
		})
	}
	wg.Wait()

	out.QueryMS = time.Since(start).Milliseconds()
	out.summarise()
	return out, nil
}

// ecsBlank is a vantage point that produced no answer, with the reason named.
// Values is non-nil so the JSON carries [] rather than null.
func ecsBlank(v ecsVantage, reason string) ECSAnswer {
	return ECSAnswer{
		Region: v.region, Place: v.place, Subnet: v.subnet,
		Values: []string{}, Error: reason,
	}
}

// ecsAsk sends one query carrying v's client subnet and reads back both the
// answer and the scope the authoritative side reported.
func (s *Service) ecsAsk(ctx context.Context, qname, qtype, addr string, v ecsVantage) ECSAnswer {
	a := ecsBlank(v, "")

	ip, netw, err := net.ParseCIDR(v.subnet)
	// Unreachable with the table above, which is a compile-time-fixed list of
	// literals; kept because a bad entry must not send a query with no subnet
	// on it, which would answer the question for the wrong network.
	if err != nil || ip.To4() == nil {
		a.Error = "this vantage point's subnet is not a usable IPv4 prefix"
		return a
	}
	// The length that goes on the wire is read out of the entry's own CIDR,
	// not taken from ecsSourceNetmask. Two sources for one number means a
	// table entry written as /20 would be displayed as /20, probed as /24, and
	// the only symptom would be a wrong answer.
	ones, _ := netw.Mask.Size()

	// newQuery, not a hand-built message: it carries the 1232-byte EDNS0
	// buffer, without which a steered answer set can be capped at 512 bytes and
	// two vantage points differ because of truncation rather than location.
	m := newQuery(qname, qtype)
	opt := m.IsEdns0()
	if opt == nil {
		a.Error = "could not attach a client subnet to the query"
		return a
	}
	// Family 1 = IPv4, and the client subnet stays IPv4 even for an AAAA
	// question: it describes the client's network, not the record's family.
	// SourceScope is 0 in a query; it is only meaningful in a response.
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ip.To4(),
	})

	// Per-query ceiling on top of the Service-wide client timeout, so one
	// unresponsive vantage cannot hold the request for the caller's whole
	// context. Derived from ctx, so a cancelled request still cuts it short.
	qctx, cancel := context.WithTimeout(ctx, ecsQueryTimeout)
	defer cancel()

	start := time.Now()
	resp, err := s.ask(qctx, m, addr)
	a.RTTMS = time.Since(start).Milliseconds()
	if err != nil {
		a.Error = "no response"
		return a
	}

	a.SourceNetmask = uint8(ones)
	a.Rcode = dns.RcodeToString[resp.Rcode]
	a.Values, a.TTL, a.CNAME = answerValues(resp, qtype)
	if a.Values == nil {
		a.Values = []string{}
	}
	if sub := ecsOptionOf(resp); sub != nil {
		a.Echoed = true
		a.Scope = sub.SourceScope
		a.EchoedSubnet = fmt.Sprintf("%s/%d", sub.Address, sub.SourceNetmask)
		// RFC 7871 §7.3: the response's SOURCE PREFIX-LENGTH is the query's,
		// echoed back. Anything else — a cached answer keyed to another
		// prefix, a middlebox rewriting the option — is a scope about a
		// network we never asked about, and reading a verdict off it would
		// describe somebody else's traffic in our table.
		a.Mismatch = int(sub.SourceNetmask) != ones || !netw.Contains(sub.Address)
	}
	if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeServerFailure {
		a.Error = "answered " + a.Rcode
	}
	return a
}

// ecsOptionOf pulls the client-subnet option out of a response's OPT record.
// nil means the option never came back, which is a different fact from a
// scope of 0 and is kept distinct all the way to the verdict.
func ecsOptionOf(m *dns.Msg) *dns.EDNS0_SUBNET {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if sub, ok := o.(*dns.EDNS0_SUBNET); ok {
			return sub
		}
	}
	return nil
}

// answerGroups collapses per-source answer sets into the distinct sets seen,
// first-seen order, carrying each set's members alongside. labels[i] names the
// source of sets[i], so the two must be the same length.
//
// An EMPTY set is a set. Callers that skip empty answers before grouping
// cannot tell "everybody was given the same thing" from "half of them were
// given nothing", which is the difference a comparison exists to find.
//
// Wiring: spread.go's summarise runs this exact algorithm inline (its byKey /
// order / answerKey / strings.Split round trip) and should call this instead,
// mapping the result into AnswerGroup. That edit is out of this change's
// scope, which is why the helper lives here rather than beside answerKey.
func answerGroups(labels []string, sets [][]string) (values [][]string, members [][]string) {
	at := map[string]int{}
	for i, s := range sets {
		k := answerKey(s)
		j, seen := at[k]
		if !seen {
			j = len(values)
			at[k] = j
			// The set itself, not a key to be split apart again: a round trip
			// through strings.Join/Split turns the empty set into []string{""}.
			values = append(values, s)
			members = append(members, nil)
		}
		members[j] = append(members[j], labels[i])
	}
	return values, members
}

// ecsUnanimousRcode is spread.go's unanimousRcode over this type's answers:
// the code every vantage point that responded agreed on, empty when they
// differed. Duplicated rather than shared only because unifying them means
// editing spread.go; noted as wiring.
func ecsUnanimousRcode(vs []ECSAnswer) string {
	var code string
	for _, v := range vs {
		if v.Rcode == "" {
			continue
		}
		if code == "" {
			code = v.Rcode
			continue
		}
		if v.Rcode != code {
			return ""
		}
	}
	return code
}

// summarise derives the verdict from what the probes saw. Pure judgement over
// collected data: no extra queries.
func (e *ECS) summarise() {
	e.Rcode = ecsUnanimousRcode(e.Vantages)

	var labels []string
	var sets [][]string
	for _, v := range e.Vantages {
		if v.Error != "" {
			continue
		}
		e.Answered++
		if v.Echoed {
			if v.Mismatch {
				// A scope for a prefix we never sent. Shown in its row, kept
				// out of the two numbers the verdict is read from.
				e.Mismatched++
			} else {
				e.Echoed++
				if v.Scope > e.MaxScope {
					e.MaxScope = v.Scope
				}
				// A scope the zone chose rather than a copy of ours. Compared
				// against THIS row's own source length, not the package
				// constant, so a table entry probed at another length is
				// judged against what it actually sent.
				if v.Scope != 0 && v.Scope != v.SourceNetmask {
					e.ScopeDistinct = true
				}
			}
		}
		if len(v.Values) > 0 {
			e.WithRecords++
		}
		// Including the empty sets. A vantage point told "no record of that
		// type" was told something, and if another was told an address then
		// these two networks were given different answers — which is exactly
		// the shape of a geo-blocked or region-scoped name.
		labels = append(labels, v.Place)
		sets = append(sets, v.Values)
	}

	values, members := answerGroups(labels, sets)
	for i := range values {
		vals := values[i]
		if vals == nil {
			vals = []string{}
		}
		e.Groups = append(e.Groups, ECSGroup{Values: vals, Vantages: members[i]})
	}
	sort.SliceStable(e.Groups, func(i, j int) bool {
		return len(e.Groups[i].Vantages) > len(e.Groups[j].Vantages)
	})

	differ := len(e.Groups) > 1
	switch {
	case e.Answered < 2:
		// One sample cannot differ from anything, and nor can none.
		e.Verdict = ECSVerdictInconclusive
	case e.WithRecords == 0:
		// Nowhere got a record. Ahead of every scope-reading verdict below,
		// because there is no answer here to be tailored or untailored and
		// "everyone gets the same records" would be a claim about records
		// that do not exist. Rcode says which flavour of nothing it was.
		e.Verdict = ECSVerdictNoRecords
	case e.Echoed == 0:
		// The option was stripped between us and the zone. Everything below
		// this line would be reading a number nobody sent.
		e.Verdict = ECSVerdictUnsupported
	case e.MaxScope == 0:
		e.Verdict = ECSVerdictUntailored
		e.Rotation = differ
	case differ:
		e.Verdict = ECSVerdictDiffers
	default:
		e.Verdict = ECSVerdictMatches
	}

	e.notes()
}

// notes states what the verdict cannot.
//
// Deliberately NOT a second copy of the verdict sentence. The card's headline
// prose lives in templates/ecs.html, one branch per verdict, exactly as
// spread.html carries its own; a note that restated it would be the same
// claim maintained in two layers, and the two would drift the first time
// either was edited. Everything below is a fact the headline has no room for.
func (e *ECS) notes() {
	add := func(level, text string) { e.Notes = append(e.Notes, Note{Level: level, Text: text}) }

	if missing := e.Asked - e.Answered; missing > 0 {
		add("warn", fmt.Sprintf("%d of %d vantage points got no usable answer, so the comparison is over the rest. Their rows below say why.", missing, e.Asked))
	}
	if e.Echoed > 0 && e.Echoed < e.Answered {
		add("warn", fmt.Sprintf("Only %d of the %d answers came back with a client-subnet option for the network we asked about. Where there is none there is no scope to read, so those rows neither support nor contradict the verdict.", e.Echoed, e.Answered))
	}
	if e.Mismatched > 0 {
		add("warn", fmt.Sprintf("%d response(s) came back with a scope for a prefix we never sent — a cached answer keyed to somebody else's network, or a middlebox rewriting the option. Their rows show which prefix, and their scope is excluded from the verdict.", e.Mismatched))
	}
	// The signal the whole card exists to find, and the one the verdict can
	// state only indirectly: a name that resolves in some regions and returns
	// nothing in others.
	if e.WithRecords > 0 && e.WithRecords < e.Answered {
		add("warn", fmt.Sprintf("%d of the %d networks that got an answer were given no %s record at all, while the other %d were given records. Those two groups are listed separately below.",
			e.Answered-e.WithRecords, e.Answered, e.Type, e.WithRecords))
	}
	// What the headline sentence has no room for, never a second copy of it.
	switch {
	case e.Verdict == ECSVerdictDiffers:
		add("info", "The places below are our labels for a fixed table of public prefixes; the wire carried a prefix, not a location. Six prefixes can show that answers differed between them. They cannot show that the split follows geography, and this card does not claim it.")
	case e.Verdict == ECSVerdictUntailored:
		add("warn", "Scope 0 covers this resolver's path only. A zone that picks its answer from the resolver's own location instead of the client subnet reports scope 0 as well, and so does a resolver that chose not to forward the subnet at all, so this is not evidence that every client of every resolver is given these records.")
	}
	if e.MaxScope > 0 && !e.ScopeDistinct {
		add("warn", fmt.Sprintf("Every scope came back as exactly the /%d we sent. A server that echoes the option unchanged produces that whether it tailors anything or not, so read it as \"the option survived the round trip\", not as \"the zone read the network\". A scope the zone shortens to its own block is the version that means something.", e.MaxScope))
	}
}
