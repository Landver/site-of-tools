package dnstools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ECS: does a name's answer change with the EDNS client subnet (RFC 7871) the query carries?
// Not a geographic measurement: the place names are our labels, the wire carries only a prefix.
type ECS struct {
	Name  string `json:"name"`
	QName string `json:"qname"`
	Type  string `json:"type"`
	// Pinned, not the caller's choice: see ecsResolverKey.
	Resolver     string `json:"resolver"`
	ResolverAddr string `json:"resolver_addr"`

	// One per subnet sent, failures included, so the verdict's denominator never shrinks.
	Vantages []ECSAnswer `json:"vantages"`
	// Distinct answer sets, largest first; an empty Values (NODATA) is a group too.
	Groups []ECSGroup `json:"groups"`
	// The rcode every responder agreed on, empty when they differed.
	Rcode string `json:"rcode,omitempty"`

	// One of the ECSVerdict* values.
	Verdict string `json:"verdict"`
	// Longest scope over the echoed, non-mismatched responses.
	MaxScope uint8 `json:"max_scope"`
	// Responses that echoed our own subnet; 0 means the option was stripped on the way.
	Echoed      int `json:"echoed"`
	WithRecords int `json:"with_records"`
	// Responses echoing a prefix we never sent: shown, but kept out of the verdict.
	Mismatched int `json:"mismatched,omitempty"`
	// A non-zero scope other than the length sent: the zone's own block, not an echo.
	ScopeDistinct bool `json:"scope_distinct,omitempty"`
	// Answers differ but every scope was 0: varied per query, not per network.
	Rotation bool `json:"rotation,omitempty"`

	Answered int    `json:"answered"`
	Asked    int    `json:"asked"`
	Notes    []Note `json:"notes,omitempty"`
	QueryMS  int64  `json:"query_ms"`
}

// ECSAnswer is what one vantage point was told, or why it was told nothing.
type ECSAnswer struct {
	// Our labels from ecsVantages, never geolocated.
	Region string `json:"region"`
	Place  string `json:"place"`
	Subnet string `json:"subnet"`

	Values []string `json:"values"`
	CNAME  string   `json:"cname,omitempty"`
	TTL    uint32   `json:"ttl,omitempty"`
	Rcode  string   `json:"rcode,omitempty"`

	// Without an echoed option Scope is unknown, not 0.
	Echoed bool  `json:"ecs_echoed"`
	Scope  uint8 `json:"scope"`
	// Scope == SourceNetmask is an echo; any other non-zero scope is the zone's own.
	SourceNetmask uint8  `json:"source_netmask,omitempty"`
	EchoedSubnet  string `json:"echoed_subnet,omitempty"`
	// Echoed prefix is not the one sent (stale cache, rewriting middlebox): kept out of the verdict.
	Mismatch bool `json:"ecs_mismatch,omitempty"`

	RTTMS int64  `json:"rtt_ms"`
	Error string `json:"error,omitempty"`
}

// ECSGroup is one distinct answer set and the vantage points given it.
type ECSGroup struct {
	Values   []string `json:"values"`
	Vantages []string `json:"vantages"`
}

const (
	// Non-zero scope and differing answers; ScopeDistinct says whether the prefix is why.
	ECSVerdictDiffers = "answers-differ"
	// Non-zero scope, one answer set; without ScopeDistinct the scope is likely an echo.
	ECSVerdictMatches = "answers-match"
	// Every scope was 0: no subnet tailoring on this path, which is not "the same everywhere".
	ECSVerdictUntailored = "untailored"
	// No response echoed the option, so nothing was measured.
	ECSVerdictUnsupported = "unsupported"
	// No answering vantage point got a record of this type.
	ECSVerdictNoRecords = "no-records"
	// Fewer than two vantage points answered.
	ECSVerdictInconclusive = "inconclusive"
)

// ecsResolverKey: Cloudflare, the package default, never forwards ECS, so every name would read
// as untailored. Google forwards the subnet and echoes the zone's scope.
const ecsResolverKey = "google"

// maxECSVantages caps the fan-out (one upstream query each), whatever the table grows to.
const maxECSVantages = 8

// ecsQueryTimeout bounds each probe, and so the whole card: all probes run in one wave.
const ecsQueryTimeout = 3 * time.Second

// ecsConcurrency covers the table in one wave; a narrower limit doubles the worst case.
const ecsConcurrency = maxECSVantages

// ecsSteerableTypes: steering hands out addresses, aliases or endpoints; MX or SOA never vary.
var ecsSteerableTypes = []string{"A", "AAAA", "CNAME", "HTTPS"}

type ecsVantage struct {
	region string
	place  string
	subnet string
}

// ecsVantages: fixed, non-anycast /24s of long-standing networks; the visitor's IP is never sent.
var ecsVantages = []ecsVantage{
	{region: "North America (east)", place: "New York, US", subnet: "128.59.0.0/24"},   // Columbia University
	{region: "North America (west)", place: "California, US", subnet: "171.64.0.0/24"}, // Stanford University
	{region: "Europe", place: "Amsterdam, NL", subnet: "192.87.0.0/24"},                // SURF
	{region: "Asia", place: "Tokyo, JP", subnet: "133.11.0.0/24"},                      // University of Tokyo
	{region: "South America", place: "São Paulo, BR", subnet: "200.160.0.0/24"},        // NIC.br
	{region: "Oceania", place: "Melbourne, AU", subnet: "130.194.0.0/24"},              // Monash University
}

// ECSer is the handler's dependency for the ECS card; *Service satisfies it.
type ECSer interface {
	ECS(ctx context.Context, name, qtype string) (*ECS, error)
}

// ECSEnvelope embeds *Spread so /consistency's existing keys stay top-level. Build it with
// NewECSEnvelope: a nil embedded *Spread silently drops every promoted field from the JSON.
type ECSEnvelope struct {
	*Spread
	ECS *ECS `json:"ecs,omitempty"`
}

var ErrNoSpread = errors.New("an ECS envelope needs a spread to wrap")

// NewECSEnvelope refuses a nil spread; a nil ECS just omits the card.
func NewECSEnvelope(sp *Spread, e *ECS) (*ECSEnvelope, error) {
	if sp == nil {
		return nil, ErrNoSpread
	}
	return &ECSEnvelope{Spread: sp, ECS: e}, nil
}

// ECS runs the check against the pinned resolver. qtype defaults to A.
func (s *Service) ECS(ctx context.Context, name, qtype string) (*ECS, error) {
	addr, ok := resolverAddr(ecsResolverKey)
	if !ok {
		return nil, ErrBadResolver
	}
	return s.ecsRun(ctx, name, qtype, addr, ResolverName(ecsResolverKey))
}

// ecsRun takes addr so a white-box test can aim it at loopback; production passes only the pinned resolver.
func (s *Service) ecsRun(ctx context.Context, name, qtype, addr, resolverName string) (*ECS, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	qtype = walkType(qtype)
	if !slices.Contains(ecsSteerableTypes, qtype) {
		return nil, fmt.Errorf("%w: location steering is only measurable on %s",
			ErrBadType, strings.Join(ecsSteerableTypes, ", "))
	}
	if err := needDomain(name); err != nil {
		return nil, err
	}
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
	fanOut(len(points), ecsConcurrency, func(i int) {
		v := points[i]
		// Stands until the probe returns, so a recovered panic reads as a failure, not a blank answer.
		out.Vantages[i] = ecsBlank(v, errPanic.Error())
		if ctx.Err() != nil {
			out.Vantages[i] = ecsBlank(v, "the request ended before this vantage point was asked")
			return
		}
		out.Vantages[i] = s.ecsAsk(ctx, qname, qtype, addr, v)
	})

	out.QueryMS = time.Since(start).Milliseconds()
	out.summarise()
	return out, nil
}

// ecsBlank is a vantage point with no answer; Values is [] so the JSON never carries null.
func ecsBlank(v ecsVantage, reason string) ECSAnswer {
	return ECSAnswer{
		Region: v.region, Place: v.place, Subnet: v.subnet,
		Values: []string{}, Error: reason,
	}
}

// ecsAsk sends one query carrying v's client subnet and reads back the answer and its scope.
func (s *Service) ecsAsk(ctx context.Context, qname, qtype, addr string, v ecsVantage) ECSAnswer {
	a := ecsBlank(v, "")

	ip, netw, err := net.ParseCIDR(v.subnet)
	ip4 := ip.To4()
	if err != nil || ip4 == nil {
		a.Error = "this vantage point's subnet is not a usable IPv4 prefix"
		return a
	}
	// The wire length comes from the entry's own CIDR, so display and probe cannot disagree.
	ones, _ := netw.Mask.Size()

	// newQuery sets a 1232-byte EDNS0 buffer; at 512 bytes truncation could split vantage points.
	m := newQuery(qname, qtype)
	opt := m.IsEdns0()
	// Family 1 = IPv4: the subnet describes the client, not the record, so AAAA keeps it.
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ip4,
	})

	qctx, cancel := context.WithTimeout(ctx, ecsQueryTimeout)
	defer cancel()

	start := time.Now()
	resp, _, err := s.ask(qctx, m, addr)
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
	// nil, not scope 0, means no client-subnet option came back.
	if sub := ednsOption[*dns.EDNS0_SUBNET](resp); sub != nil {
		a.Echoed = true
		a.Scope = sub.SourceScope
		a.EchoedSubnet = fmt.Sprintf("%s/%d", sub.Address, sub.SourceNetmask)
		// RFC 7871 §7.3: the response echoes our prefix; any other describes a network we never sent.
		a.Mismatch = int(sub.SourceNetmask) != ones || !netw.Contains(sub.Address)
	}
	if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeServerFailure {
		a.Error = "answered " + a.Rcode
	}
	return a
}

// summarise derives the counts, groups and verdict from what the probes saw.
func (e *ECS) summarise() {
	e.Rcode = unanimousRcode(e.Vantages, func(v ECSAnswer) string { return v.Rcode })

	var labels []string
	var sets [][]string
	for _, v := range e.Vantages {
		if v.Error != "" {
			continue
		}
		e.Answered++
		if v.Echoed {
			if v.Mismatch {
				e.Mismatched++
			} else {
				e.Echoed++
				if v.Scope > e.MaxScope {
					e.MaxScope = v.Scope
				}
				if v.Scope != 0 && v.Scope != v.SourceNetmask {
					e.ScopeDistinct = true
				}
			}
		}
		if len(v.Values) > 0 {
			e.WithRecords++
		}
		// Empty sets too: NODATA beside an address is what a region-scoped name looks like.
		labels = append(labels, v.Place)
		sets = append(sets, v.Values)
	}

	for _, g := range answerGroups(labels, sets) {
		if g.Values == nil {
			g.Values = []string{}
		}
		e.Groups = append(e.Groups, ECSGroup{Values: g.Values, Vantages: g.Servers})
	}

	differ := len(e.Groups) > 1
	switch {
	case e.Answered < 2:
		e.Verdict = ECSVerdictInconclusive
	case e.WithRecords == 0:
		// Ahead of the scope verdicts: with no records there is nothing to tailor.
		e.Verdict = ECSVerdictNoRecords
	case e.Echoed == 0:
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

// notes adds what the verdict cannot say; the headline prose lives in templates/ecs.html.
func (e *ECS) notes() {
	add := func(level, text string) { e.Notes = append(e.Notes, Note{Level: level, Text: text}) }

	if missing := e.Asked - e.Answered; missing > 0 {
		add("warn", fmt.Sprintf("%d of %d networks got no usable answer; the comparison is over the rest.", missing, e.Asked))
	}
	if e.Echoed > 0 && e.Echoed < e.Answered {
		add("warn", fmt.Sprintf("Only %d of %d answers carried a client-subnet option, so the rest neither support nor contradict the verdict.", e.Echoed, e.Answered))
	}
	if e.Mismatched > 0 {
		what := "response carried a scope"
		if e.Mismatched > 1 {
			what = "responses carried a scope"
		}
		add("warn", fmt.Sprintf("%d %s for a prefix we never sent, so their scope is excluded: a cached answer keyed to another network, or a middlebox rewriting the option.", e.Mismatched, what))
	}
	if e.WithRecords > 0 && e.WithRecords < e.Answered {
		add("warn", fmt.Sprintf("%d of the %d networks that answered were given no %s record at all, while %d were given records; they are separate groups above.",
			e.Answered-e.WithRecords, e.Answered, e.Type, e.WithRecords))
	}
}
