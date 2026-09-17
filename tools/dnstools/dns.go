// Package dnstools: dns.corpberry.com tool — DNS record lookup against a
// small allowlist of public resolvers. dns.go = domain layer: pure Go
// (miekg/dns), no HTTP.
//
// Scope is deliberately Tier 0 of tools/dnstools/docs/02-build-fit.md:
// one name, one type, one resolver, honest rcode/flags/timing. Multi-resolver
// fan-out, +trace and DNSSEC are Tier 1 and live nowhere in this file yet.
package dnstools

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Record: one answer row, transport layer renders as HTML or JSON.
//
// TTLHuman sits alongside TTL, never instead of it: every tool surveyed that
// humanises TTL keeps the raw integer too (feature inventory §1).
// ASN/ASName/Country are best-effort IP enrichment filled in by the handler
// via iptools, NOT by this package — domain layer stays pure DNS.
// Field: one decoded part of a record whose value is a packed tuple (SOA's
// timers, for instance). Shown under the raw value, never instead of it.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Record struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	TTLHuman string `json:"ttl_human"`

	// Owner: the name this record is really attached to, which is not always
	// the name asked for — a CNAME'd lookup brings the target's records back in
	// the same answer. RFC 1034 forbids them sharing an owner with the alias,
	// so labelling them with the queried name publishes a zone that isn't real.
	Owner string `json:"owner,omitempty"`

	// Label: what this record is for, when its own convention says so — a TXT
	// prefix naming the service that asked for it. Empty when the value speaks
	// for itself.
	Label string `json:"label,omitempty"`
	// Detail: decoded sub-fields for a packed value (SOA).
	Detail []Field `json:"detail,omitempty"`

	ASN     string `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Country string `json:"country,omitempty"`
}

// Result: one record type's answer inside a ResultSet.
//
// Only per-type facts live here. The name, resolver, qname, flags and timing
// are identical for every type in a set, so they live on ResultSet once
// instead of being repeated on every entry. A Result only ever exists for a
// type that answered with records, so it carries no status of its own: the
// honest three-way split of NOERROR-with-records / NODATA / NXDOMAIN is the
// ResultSet's Found / Missing / NXDomain. Conflating those three is called out
// as "the most common bug in this category" in
// reports/dns-concepts-and-query-modes.md.
type Result struct {
	Type    string   `json:"type"`
	Records []Record `json:"records"`
	// Cached: this type's answer came out of our own cache. Per type, because
	// a fan-out routinely mixes fresh and cached answers and the set-wide flag
	// below can only report the all-or-nothing case.
	Cached bool `json:"cached"`

	// meta: response-level facts hoisted onto ResultSet by LookupSet.
	// Unexported, so it never reaches JSON from here.
	meta responseMeta
}

// responseMeta: what a single response says about itself rather than about the
// type asked for. Identical across a fan-out, so LookupSet lifts it to the set.
type responseMeta struct {
	// cached: this answer came from our own cache, so no query left the box.
	// Surfaced because a sub-millisecond "0 ms" reads like a broken timer
	// rather than the cache working.
	cached        bool
	flags         string
	authenticated bool
	signed        bool
	nsid          string
	ede           *EDE
	bogus         bool
	// chain: the CNAMEs the answer came through, which the type filter in
	// exchange drops. A fact about the name rather than the type, so LookupSet
	// lifts it to the set like the rest of this struct.
	chain []Record
}

var (
	// ErrBadType: type outside the supported set.
	ErrBadType = errors.New("unsupported record type")
	// ErrBadResolver: resolver outside the allowlist. Free-form "@server" is
	// deliberately not accepted — that's the SSRF hole
	// reports/abuse-ratelimits-and-ethics.md says to close on day one.
	ErrBadResolver = errors.New("unknown resolver")
	// ErrEmptyName: no name to look up.
	ErrEmptyName = errors.New("no name to look up")
	// ErrBadName: the input cannot be a DNS name at all. Rejected before it
	// costs an upstream query, since nothing downstream can make it one.
	ErrBadName = errors.New("not a domain name")
)

// errPanic stands in for a result a recovered goroutine never produced. A
// blank slot would read as "this type answered with nothing", which is the one
// thing it definitely did not do.
var errPanic = errors.New("internal error while answering this query")

// maxNameLabels bounds how deep a name we will accept. The protocol has no
// such limit; the zone walk in spread.go spends one upstream query per label,
// so a name deeper than any real hostname is a cost we decline to pay.
const maxNameLabels = 10

// validDomain rejects input that cannot be a DNS name before any of it reaches
// an upstream resolver. The size bounds are RFC 1035's own (253 bytes total,
// 63 per label); the label-count bound is ours.
//
// Bytes above 0x7f pass through untouched: a raw Unicode name is a different
// problem (it needs IDNA, not rejection) and belongs to whoever queries it.
func validDomain(name string) error {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return ErrEmptyName
	}
	if len(name) > 253 {
		return fmt.Errorf("%w: longer than 253 bytes", ErrBadName)
	}
	labels := strings.Split(name, ".")
	if len(labels) > maxNameLabels {
		return fmt.Errorf("%w: more than %d labels", ErrBadName, maxNameLabels)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%w: %q is not a usable label", ErrBadName, l)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%w: %q starts or ends with a hyphen", ErrBadName, l)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
				c == '-' || c == '_' || c >= 0x80
			if !ok {
				return fmt.Errorf("%w: %q contains %q", ErrBadName, l, string(c))
			}
		}
	}
	return nil
}

// safe runs f and turns a panic into a log line instead of a dead process.
// echo's Recover middleware only wraps the handler goroutine, and this package
// spawns its own on every route, so without this one malformed upstream answer
// takes down the single binary serving every tool on the box.
func safe(f func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("dnstools: recovered panic in a spawned query",
				"panic", r, "stack", string(debug.Stack()))
		}
	}()
	f()
}

// Resolver: one entry in the allowlist, as offered by the UI + API.
type Resolver struct {
	Key  string // what callers pass: ?resolver=cloudflare
	Name string // display label
	Addr string // where we actually send the query
}

// Resolvers: the whole allowlist. Three well-known public resolvers, no
// free-form target. Order = display order; first entry is the default.
var Resolvers = []Resolver{
	{Key: "cloudflare", Name: "Cloudflare (1.1.1.1)", Addr: "1.1.1.1:53"},
	{Key: "google", Name: "Google (8.8.8.8)", Addr: "8.8.8.8:53"},
	{Key: "quad9", Name: "Quad9 (9.9.9.9)", Addr: "9.9.9.9:53"},
}

// DefaultResolver: used when the caller names none.
const DefaultResolver = "cloudflare"

// Types: what the UI offers — the fan-out set plus PTR, which only makes
// sense for an IP literal and so isn't part of a domain fan-out. Derived, so
// the two lists can't drift. miekg/dns knows ~88 more types
// (reports/record-types-reference.md); Tier 1 grows FanoutTypes.
var Types = append(slices.Clone(FanoutTypes), "PTR")

// FanoutTypes: what a bare lookup asks for — everything worth showing, in one
// go. Making the user pick a type one at a time is the thing this replaces.
//
// It is NOT an ANY query: RFC 8482 lets resolvers answer ANY with a minimal
// stub, so ANY lies (reports/dns-concepts-and-query-modes.md). Asking for each
// type concurrently is the honest version, and per the corpus the single
// highest value-per-line feature available here.
//
// PTR is absent on purpose: it only means something for an IP literal, which
// takes the reverse path instead of a fan-out.
var FanoutTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS"}

// maxTypesPerRequest bounds how wide one request may fan out, so a longer type
// list later can't quietly turn one click into more concurrent queries than we
// mean to send.
//
// It is not the request's query budget, and must not be read as one: a
// SERVFAIL costs a second query on the CD=1 retry, and the dangling-CNAME scan
// adds up to maxDanglingChecks more.
const maxTypesPerRequest = 12

// maxDanglingChecks bounds the follow-up probes the takeover scan may make.
// One sequential query per distinct CNAME target, each with the full timeout,
// is the only fan-out here that used to have no ceiling — and a zone is free
// to point as many names at as many targets as it likes.
const maxDanglingChecks = 5

// EDE: an RFC 8914 Extended DNS Error, i.e. the resolver's own machine-readable
// reason a query failed ("Signature Expired", "Blocked", "Network Error").
//
// This is the single highest-value field in the landscape per
// reports/dns-concepts-and-query-modes.md, and almost no consumer tool renders
// it: the data is sitting in every modern resolver's response and gets thrown
// away in favour of a bare SERVFAIL.
type EDE struct {
	Code  uint16 `json:"code"`
	Text  string `json:"text"`            // the registered label for Code
	Extra string `json:"extra,omitempty"` // free-text detail, resolver's own words
}

// TypeFailure: one type whose query didn't come back usable — a transport
// error, or a resolver rcode that isn't NOERROR/NXDOMAIN (SERVFAIL, REFUSED).
// Kept apart from Missing: "I couldn't find out" is not "it isn't there".
type TypeFailure struct {
	Type  string `json:"type"`
	Rcode string `json:"rcode,omitempty"`
	Error string `json:"error,omitempty"`
	// EDE is the resolver's own explanation, when it sent one.
	EDE *EDE `json:"ede,omitempty"`
	// Bogus: a SERVFAIL that succeeded on retry with checking disabled, which
	// proves the failure is DNSSEC validation rather than a dead server. Two
	// queries, one genuinely diagnostic answer.
	Bogus bool `json:"dnssec_bogus,omitempty"`
}

// ResultSet: the answer to "show me everything", one fan-out over several
// types at once.
//
// Types holding records land in Found, in FanoutTypes order. Types that
// answered NODATA collapse into Missing — one line, not eight empty cards.
// A name that doesn't exist sets NXDomain and leaves both empty: every type
// would say the same thing, so it gets said once.
type ResultSet struct {
	Name         string        `json:"name"`
	QName        string        `json:"qname"`
	Resolver     string        `json:"resolver"`
	ResolverName string        `json:"resolver_name"`
	Flags        string        `json:"flags"`
	Reversed     bool          `json:"reversed,omitempty"`
	NXDomain     bool          `json:"nxdomain"`
	Found        []Result      `json:"found"`
	Missing      []string      `json:"missing"`
	Failed       []TypeFailure `json:"failed,omitempty"`
	// Dangling: a CNAME here points at a name that does not resolve. That is
	// the subdomain-takeover shape: if the target is a deprovisioned bucket or
	// app slot, whoever claims that name next inherits traffic for this one.
	Dangling []string `json:"dangling,omitempty"`
	// Chain: the CNAMEs the resolver followed to reach the answer, for a query
	// whose type isn't CNAME. Without it `?type=A` on an aliased name shows an
	// address and no sign the name is an alias, which is the one fact that
	// explains where that address came from.
	Chain []Record `json:"chain,omitempty"`
	// Provider: who runs this zone's DNS, named from the nameserver suffix.
	// The first thing anyone needs ("where do I log in to change this") and
	// nothing in the raw records says it.
	Provider string `json:"provider,omitempty"`
	// Signed: the zone returned DNSSEC signatures. Authenticated: the resolver
	// set AD, i.e. it actually validated them. Signed-but-not-authenticated is
	// a real state (e.g. the resolver isn't validating); neither is a failure,
	// most names simply aren't signed at all.
	Signed        bool `json:"signed"`
	Authenticated bool `json:"authenticated"`
	// Bogus: at least one type failed validation (proven by the CD=1 retry).
	// Distinct from Signed: a zone whose DNSSEC is broken never gets far enough
	// to return a signature, so it must not be reported as "unsigned" — that is
	// the opposite of what is wrong with it.
	Bogus bool `json:"dnssec_bogus"`
	// NSID identifies the anycast node that answered (RFC 5001), when the
	// resolver is willing to say. Explains why two runs can differ.
	NSID string `json:"nsid,omitempty"`
	// Dig: the exact commands that reproduce this result, one per type.
	//
	// Deliberately NOT a single multi-type line: `dig name A AAAA` warns
	// "extra type option" and silently queries only the last one, so printing
	// that would be a command that doesn't reproduce what we showed.
	// DigWebInterface's equivalent feature is rated the highest trust-per-byte
	// element in the corpus — it makes the result checkable.
	Dig []string `json:"dig"`
	// Zone: the answers in BIND zone-file format, copy-pasteable.
	Zone string `json:"zone,omitempty"`
	// Cached: every type that answered came from this server's cache, so the
	// whole result was assembled without touching a resolver.
	Cached bool `json:"cached"`
	// Asked is how many types were actually queried. A real count, not a sum of
	// the buckets below: on NXDOMAIN every type answers "no such name" and
	// lands in none of them, so deriving it would report zero.
	Asked int `json:"asked"`
	// QueryMS is wall-clock for the whole fan-out, not the sum of its parts:
	// the queries run concurrently.
	QueryMS int64 `json:"query_ms"`
}

// Service queries DNS directly over UDP/53, retrying over TCP when the answer
// comes back truncated. No third-party API in the path.
//
// Stateless: safe to share across request goroutines, same as iptools'
// Service. Built once at startup.
type Service struct {
	udp *dns.Client
	tcp *dns.Client
	// http fetches the one non-DNS thing the domain layer needs: an MTA-STS
	// policy file, which lives behind HTTPS rather than in a record. Checking
	// only the TXT pointer and not the policy is the shortcut most tools take.
	http  *http.Client
	cache *cache
	// inflight collapses concurrent identical questions into one upstream
	// query: a fan-out over 8 types for a popular domain, hit by several
	// visitors at once, still only asks the resolver once per type.
	inflight singleflight.Group
}

// NewService builds a Service with a fixed per-query timeout.
func NewService(timeout time.Duration) *Service {
	return &Service{
		udp:   &dns.Client{Timeout: timeout},
		tcp:   &dns.Client{Net: "tcp", Timeout: timeout},
		http:  &http.Client{Timeout: timeout},
		cache: newCache(),
	}
}

// Looker: handler dependency, anything resolving a name across a set of
// types. *Service satisfies; tests inject a fake so the suite never touches
// the network.
type Looker interface {
	LookupSet(ctx context.Context, name, resolver string, types []string) (*ResultSet, error)
}

// LookupSet queries several types concurrently and folds the answers into one
// ResultSet. Empty types means FanoutTypes (the default "show me everything").
//
// One type failing never cancels the others: a SERVFAIL on CAA must not cost
// you the A records. Failures are reported per type instead.
func (s *Service) LookupSet(ctx context.Context, name, resolver string, types []string) (*ResultSet, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	addr, ok := resolverAddr(resolver)
	if !ok {
		return nil, ErrBadResolver
	}

	// The query name and whether this is a reverse lookup are facts about the
	// input, so they're settled once here rather than per type.
	qname, reversed := reverseName(name)
	if reversed {
		// An IP literal has exactly one interesting question, so don't fan out.
		types = []string{"PTR"}
	} else {
		if err := validDomain(name); err != nil {
			return nil, err
		}
		// Settled once, here: the wire is case-insensitive, so a capitalised
		// name must not become a second cache entry and a second query.
		qname = strings.ToLower(dns.Fqdn(name))
		if len(types) == 0 {
			types = FanoutTypes
		}
	}

	// Normalise and reject an unknown type up front: a typo is the caller's
	// mistake (400), not a per-type failure buried in an otherwise-fine result.
	types = slices.Clone(types)
	for i, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		// Membership of the advertised list, not of the whole RR registry:
		// ANY and AXFR both parse but neither belongs on a lookup page.
		if !slices.Contains(Types, t) {
			return nil, ErrBadType
		}
		types[i] = t
	}
	// R3-6: the fan-out cap belongs here, beside FanoutTypes, not in the
	// handler where `types` was already collapsed to one element.
	if len(types) > maxTypesPerRequest {
		types = types[:maxTypesPerRequest]
	}

	results := make([]Result, len(types))
	errs := make([]error, len(types))

	start := time.Now()
	var wg sync.WaitGroup
	// Bounded: a fan-out is still one user click, and the corpus is explicit
	// that per-request query budget beats trusting a per-IP limiter alone
	// (reports/abuse-ratelimits-and-ethics.md).
	sem := make(chan struct{}, 4)
	for i, t := range types {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			// Stands until the lookup returns, so a recovered panic reports a
			// failed type rather than an empty answer.
			errs[i] = errPanic
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = s.lookup(ctx, qname, t, addr)
		})
	}
	wg.Wait()

	set := &ResultSet{
		Name:         name,
		QName:        qname,
		Resolver:     resolver,
		ResolverName: ResolverName(resolver),
		Reversed:     reversed,
		Asked:        len(types),
		Found:        []Result{},
		Missing:      []string{},
	}

	answered, nx, cached := 0, 0, 0
	for i, t := range types {
		m := results[i].meta
		if m.cached {
			cached++
		}
		// Flags describe one whole response, so first-wins is right. NSID is
		// tracked apart from them: a node that answered without an identifier
		// must not bury the one a later type's response did carry. Signed and
		// Authenticated are per-answer: an unsigned NODATA answer arriving
		// first must not mask a signed one behind it.
		if set.Flags == "" && m.flags != "" {
			set.Flags = m.flags
		}
		if set.NSID == "" {
			set.NSID = m.nsid
		}
		set.Signed = set.Signed || m.signed
		set.Authenticated = set.Authenticated || m.authenticated
		// The chain describes the name, not the type, so any type that saw one
		// has seen all of it.
		if len(set.Chain) == 0 {
			set.Chain = m.chain
		}
		results[i].Cached = m.cached
		var rcode rcodeError
		switch err := errs[i]; {
		case err == nil:
			answered++
			set.Found = append(set.Found, results[i])
		case errors.Is(err, errNXDomain):
			answered++
			if m.ede != nil {
				// The resolver blocked or filtered this name and said so. That
				// is a different fact from "no such name", so it must NOT feed
				// the NXDOMAIN verdict that hides everything else on the page.
				set.Failed = append(set.Failed, TypeFailure{Type: t, Rcode: "NXDOMAIN", EDE: m.ede})
			} else {
				nx++
			}
		case errors.Is(err, errNoData):
			answered++
			set.Missing = append(set.Missing, t)
		case errors.As(err, &rcode):
			set.Failed = append(set.Failed, TypeFailure{
				Type: t, Rcode: string(rcode), EDE: m.ede, Bogus: m.bogus,
			})
		default:
			// Transport failure: "couldn't find out", never "isn't published".
			set.Failed = append(set.Failed, TypeFailure{Type: t, Error: err.Error()})
		}
	}
	// Every type that answered said "no such name" -> say it once, instead of
	// listing eight types as missing from a name that doesn't exist. A SERVFAIL
	// is not an answer, so it no longer counts above; the majority floor then
	// stops one surviving NXDOMAIN from speaking for a fan-out that mostly
	// failed, where "couldn't find out" is the honest verdict.
	set.NXDomain = answered > 0 && nx == answered && answered*2 >= len(types)

	// Dangling-CNAME check. Runs before the timing and cache verdict below,
	// because it issues its own queries and those must be counted honestly.
	//
	// Targets come from the chain as well as from the answers: an explicit
	// ?type=A keeps the CNAME out of Found, and that is exactly the lookup
	// someone runs on a name they already suspect is broken.
	seenTarget := map[string]bool{}
	var targets []string
	collect := func(recs []Record) {
		for _, rec := range recs {
			if rec.Type != "CNAME" {
				continue
			}
			target := strings.TrimSuffix(rec.Value, ".")
			if target == "" || seenTarget[target] {
				continue
			}
			seenTarget[target] = true
			targets = append(targets, target)
		}
	}
	for _, r := range set.Found {
		collect(r.Records)
	}
	collect(set.Chain)
	if len(targets) > maxDanglingChecks {
		targets = targets[:maxDanglingChecks]
	}
	for _, target := range targets {
		res, err := s.lookup(ctx, dns.Fqdn(target), "A", addr)
		// Withdrawn on the query leaving the box, not on it succeeding: the
		// probe this scan exists for is the one that comes back NXDOMAIN, and
		// claiming "served from cache, no upstream query" beside its finding is
		// a straight contradiction.
		if !res.meta.cached {
			cached = -1 << 30
		}
		// errNoData means the target exists but has no A record, which is
		// normal (it may be AAAA-only), so only a missing NAME counts.
		if errors.Is(err, errNXDomain) {
			set.Dangling = append(set.Dangling, target)
		}
	}

	set.Cached = cached > 0 && cached == len(types)

	// Reproduction commands + zone-file rendering of what we found.
	var zone strings.Builder
	// +nsid only when we got one back: the page prints an "Answered by" row
	// off it, and a command that doesn't ask for it can't reproduce that row.
	nsidFlag := ""
	if set.NSID != "" {
		nsidFlag = " +nsid"
	}
	for _, t := range types {
		set.Dig = append(set.Dig, fmt.Sprintf("dig @%s %s %s%s", strings.TrimSuffix(addr, ":53"), qname, t, nsidFlag))
	}
	for _, r := range set.Found {
		for _, rec := range r.Records {
			owner := rec.Owner
			if owner == "" {
				owner = qname
			}
			fmt.Fprintf(&zone, "%s\t%d\tIN\t%s\t%s\n", owner, rec.TTL, rec.Type, rec.Value)
		}
	}
	set.Zone = zone.String()

	for _, f := range set.Failed {
		if f.Bogus {
			set.Bogus = true
			break
		}
	}
	for _, r := range set.Found {
		if set.Provider = providerOf(r.Records); set.Provider != "" {
			break
		}
	}

	// Taken here rather than at the fold above, so the dangling probes' time is
	// counted: they are queries this request made and the user waited for them.
	set.QueryMS = time.Since(start).Milliseconds()
	return set, nil
}

// lookup resolves one type against an already-validated resolver address.
// Internal: LookupSet is the whole public surface, and a single-type query is
// just a set of one. Returns the per-type result plus the response's header
// flags, which describe the response rather than the type.
func (s *Service) lookup(ctx context.Context, qname, qtype, addr string) (Result, error) {
	// Keyed on the lowercased name whatever the caller passed: DNS is
	// case-insensitive, so two spellings are one question.
	key := strings.ToLower(qname) + "|" + qtype + "|" + addr
	now := time.Now()
	if e, ok := s.cache.get(key, now); ok {
		return cloneResult(e.result, true, now.Sub(e.stored)), e.err
	}
	// Shared per key, so N concurrent identical questions make one query and
	// all get the same answer.
	v, _, _ := s.inflight.Do(key, func() (any, error) {
		res, err := s.exchange(ctx, qname, qtype, addr)
		e := cacheEntry{result: res, err: err}
		// A transport failure is not cached: it says nothing about the zone,
		// and the next click should be free to try again.
		if !isTransportErr(err) {
			s.cache.put(key, e, time.Now())
		}
		return e, nil
	})
	e := v.(cacheEntry)
	// singleflight hands the SAME value to every waiter, so each needs its own
	// copy for the same reason a cache hit does. Every waiter here is riding on
	// a query that did go out, so none of them was served from cache.
	return cloneResult(e.result, false, 0), e.err
}

// cloneResult returns a Result whose Records slice is the caller's own, so a
// handler enriching records (ASN, country) can never write into the cache or
// into another request's answer. age is how long the answer has been held.
func cloneResult(r Result, cached bool, age time.Duration) Result {
	out := r
	out.Records = ageRecords(slices.Clone(r.Records), age)
	out.meta.cached = cached
	out.meta.chain = ageRecords(slices.Clone(r.meta.chain), age)
	return out
}

// ageRecords counts each TTL down by how long the answer sat in the cache. A
// TTL replayed unchanged is the wrong number on a tool whose whole question is
// "is my change live yet": it never reaches zero, so the page says to keep
// waiting for a record that expired minutes ago.
func ageRecords(recs []Record, age time.Duration) []Record {
	elapsed := int64(age / time.Second)
	if elapsed <= 0 {
		return recs
	}
	for i := range recs {
		ttl := max(int64(recs[i].TTL)-elapsed, 0)
		recs[i].TTL = uint32(ttl)
		recs[i].TTLHuman = humanizeTTL(recs[i].TTL)
	}
	return recs
}

// isTransportErr reports whether err is a failure to reach the resolver, as
// opposed to a resolver answering with a rcode we partition on.
func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	var rcode rcodeError
	return !errors.Is(err, errNXDomain) && !errors.Is(err, errNoData) && !errors.As(err, &rcode)
}

// exchange performs the actual query. Split from lookup so the cache and
// singleflight wrapper stay readable.
func (s *Service) exchange(ctx context.Context, qname, qtype, addr string) (Result, error) {
	m := newQuery(qname, qtype)

	resp, _, err := s.udp.ExchangeContext(ctx, m, addr)
	// Truncated UDP answer -> ask again over TCP rather than render a partial
	// RRset (dns-concepts-and-query-modes.md: truncation + TCP fallback).
	if err == nil && resp != nil && resp.Truncated {
		tcpResp, _, tcpErr := s.tcp.ExchangeContext(ctx, m, addr)
		if tcpErr != nil {
			// Falling through here would render the truncated RRset as a
			// complete answer and cache it as one for its full lifetime, with
			// the tc bit in Flags as the only trace. A partial RRset is
			// "couldn't find out", so say so.
			return Result{}, fmt.Errorf("truncated answer from %s, TCP retry failed: %w", addr, tcpErr)
		}
		resp = tcpResp
	}
	if err != nil {
		return Result{}, fmt.Errorf("query %s: %w", addr, err)
	}

	meta := responseMeta{
		flags:         flagString(resp),
		authenticated: resp.AuthenticatedData,
		nsid:          nsidOf(resp),
		ede:           edeOf(resp),
	}

	// A SERVFAIL is ambiguous: broken zone, dead server, or DNSSEC validation
	// failure. Asking again with checking disabled resolves it — if the answer
	// arrives once validation is off, the zone is bogus, not down. One extra
	// query, only on failure, and the corpus rates it "genuinely diagnostic".
	if resp.Rcode == dns.RcodeServerFailure {
		cd := newQuery(qname, qtype)
		cd.CheckingDisabled = true
		if cdResp, _, cdErr := s.udp.ExchangeContext(ctx, cd, addr); cdErr == nil && cdResp.Rcode == dns.RcodeSuccess {
			meta.bogus = true
		}
	}

	// Non-nil even when empty, so a caller can iterate without a nil check.
	records := []Record{}
	wantType := dns.StringToType[qtype]
	for _, rr := range resp.Answer {
		// Taken before the type filter, which would otherwise drop every
		// signature unread: we set DO purely to learn whether the resolver
		// validated, so the RRSIGs riding along are the only evidence the zone
		// is signed at all. The base64 itself is noise beside an A record and
		// is dropped below unless the signature is what was asked for.
		if rr.Header().Rrtype == dns.TypeRRSIG {
			meta.signed = true
		}
		// Only the type actually asked for counts. A CNAME'd name returns the
		// CNAME in the answer for EVERY type; without this filter each type
		// looks "found", the CNAME is printed once per type, and NODATA is
		// never reported. The CNAME still shows under its own type.
		if rr.Header().Rrtype != wantType {
			// Except the alias itself, which is kept aside: for an explicit
			// ?type=A this filter is the only thing between the caller and
			// knowing the name is an alias.
			if rr.Header().Rrtype == dns.TypeCNAME {
				meta.chain = append(meta.chain, toRecord(rr))
			}
			continue
		}
		records = append(records, toRecord(rr))
	}
	return Result{Type: qtype, Records: records, meta: meta}, statusErr(resp.Rcode, len(records))
}

// newQuery builds a request with EDNS0 enabled: a 1232-byte buffer (DNS flag
// day 2020, IPv6 minimum MTU minus headers), DO set so the resolver reports
// whether it validated, and an NSID request so it can name the node that
// answered. Costs nothing when the resolver ignores them.
func newQuery(qname, qtype string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.StringToType[qtype])
	m.RecursionDesired = true
	m.SetEdns0(1232, true)
	if opt := m.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	}
	return m
}

// edeOf pulls the resolver's Extended DNS Error out of the OPT record.
func edeOf(m *dns.Msg) *EDE {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		e, ok := o.(*dns.EDNS0_EDE)
		if !ok {
			continue
		}
		text := dns.ExtendedErrorCodeToString[e.InfoCode]
		if text == "" {
			text = "Unknown"
		}
		return &EDE{Code: e.InfoCode, Text: text, Extra: e.ExtraText}
	}
	return nil
}

// nsidOf decodes the answering node's identifier. It is hex on the wire, and
// operators put readable strings in it (e.g. "ams01"), so decode when we can.
func nsidOf(m *dns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		n, ok := o.(*dns.EDNS0_NSID)
		if !ok || n.Nsid == "" {
			continue
		}
		if raw, err := hex.DecodeString(n.Nsid); err == nil && isPrintable(raw) {
			return string(raw)
		}
		return n.Nsid
	}
	return ""
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}

// statusErr maps a response to the sentinel LookupSet partitions on: nil for a
// usable answer, or one of the three "nothing to show" outcomes.
func statusErr(rcode, answers int) error {
	switch {
	case rcode == dns.RcodeNameError:
		return errNXDomain
	case rcode != dns.RcodeSuccess:
		return rcodeError(dns.RcodeToString[rcode])
	case answers == 0:
		return errNoData
	}
	return nil
}

// Partition sentinels. Unexported: callers read ResultSet's Found / Missing /
// Failed / NXDomain instead of matching on these.
var (
	errNXDomain = errors.New("NXDOMAIN")
	errNoData   = errors.New("NODATA")
)

// rcodeError carries a non-NOERROR rcode (SERVFAIL, REFUSED, …) so LookupSet
// can report which one without a second return value.
type rcodeError string

func (e rcodeError) Error() string { return string(e) }

// reverseName returns the in-addr.arpa/ip6.arpa name for an IP literal, plus
// whether the input was an IP at all. Single place that decides "this is a
// reverse lookup" — used both to skip the fan-out and to build the query.
func reverseName(name string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(name))
	if ip == nil {
		return "", false
	}
	rev, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return "", false
	}
	return rev, true
}

// resolverOverride is the seam that lets a test point the domain layer at a DNS
// server on loopback, which the allowlist below exists to forbid. It is nil in
// every shipped build: nothing outside a _test.go file assigns it, it is
// unexported so no other package can, and no request-scoped value reaches it —
// so the set of addresses a visitor can steer a query to is exactly Resolvers.
var resolverOverride func(key string) (string, bool)

func resolverAddr(key string) (string, bool) {
	if resolverOverride != nil {
		if addr, ok := resolverOverride(key); ok {
			return addr, true
		}
	}
	for _, r := range Resolvers {
		if r.Key == key {
			return r.Addr, true
		}
	}
	return "", false
}

// ResolverName maps an allowlist key to its display label, for templates.
// Unknown key returns the key itself rather than blank.
func ResolverName(key string) string {
	for _, r := range Resolvers {
		if r.Key == key {
			return r.Name
		}
	}
	return key
}

func toRecord(rr dns.RR) Record {
	h := rr.Header()
	rec := Record{
		Type:     dns.TypeToString[h.Rrtype],
		Value:    rdata(rr),
		TTL:      h.Ttl,
		TTLHuman: humanizeTTL(h.Ttl),
		// Lowercased for the same reason qname is: a resolver may echo the
		// owner back in whatever case it was asked in, and callers compare this
		// against QName to decide whether it is worth showing.
		Owner: strings.ToLower(h.Name),
	}
	// Decode the types whose raw value is unreadable on its own.
	switch v := rr.(type) {
	case *dns.SOA:
		rec.Detail = soaFields(v)
	case *dns.TXT:
		rec.Label = txtLabel(strings.Join(v.Txt, ""))
	case *dns.CAA:
		rec.Detail = caaFields(v)
	case *dns.HTTPS, *dns.SVCB:
		rec.Detail = svcbFields(rr)
	}
	return rec
}

// rdata renders an RR's data without the header (name/class/ttl/type) that
// dns.RR.String() prefixes — the header's facts already have their own
// columns, so repeating them in the value reads as noise.
func rdata(rr dns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// flagString renders the header bits dig prints, in dig's order. Surfaced
// because "is this answer authoritative / recursive / DNSSEC-validated" is
// unanswerable from the records alone.
func flagString(m *dns.Msg) string {
	var f []string
	for _, b := range []struct {
		on   bool
		name string
	}{
		{m.Response, "qr"},
		{m.Authoritative, "aa"},
		{m.Truncated, "tc"},
		{m.RecursionDesired, "rd"},
		{m.RecursionAvailable, "ra"},
		{m.AuthenticatedData, "ad"},
		{m.CheckingDisabled, "cd"},
	} {
		if b.on {
			f = append(f, b.name)
		}
	}
	return strings.Join(f, " ")
}

// humanizeTTL renders a TTL as a short duration ("45s", "5m", "24h", "7d").
// Shown next to the raw seconds, never replacing them.
func humanizeTTL(seconds uint32) string {
	s := int(seconds)
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm", s/60)
	case s < 86400:
		if m := s % 3600 / 60; m > 0 {
			return fmt.Sprintf("%dh%dm", s/3600, m)
		}
		return fmt.Sprintf("%dh", s/3600)
	default:
		return fmt.Sprintf("%dd", s/86400)
	}
}
