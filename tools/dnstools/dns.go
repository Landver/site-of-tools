// Package dnstools is dns.corpberry.com: DNS lookups against an allowlist of public resolvers.
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

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Field: one decoded part of a packed record value, such as an SOA timer.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Record: one answer row. ASN/ASName/Country are filled only by LookupEnriched.
type Record struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	TTL      uint32 `json:"ttl"`
	TTLHuman string `json:"ttl_human"`

	// Owner can differ from the queried name: a CNAME'd answer carries the target's records too.
	Owner string `json:"owner,omitempty"`

	// Label: what the record is for, e.g. the service a TXT prefix names.
	Label string `json:"label,omitempty"`
	// Target: the host this record points at, without the root dot.
	Target string  `json:"target,omitempty"`
	Detail []Field `json:"detail,omitempty"`

	ASN     string `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Country string `json:"country,omitempty"`
}

// Result: one type's records. NODATA and NXDOMAIN live on ResultSet, never here.
type Result struct {
	Type    string   `json:"type"`
	Records []Record `json:"records"`
	// Cached is per type: one fan-out routinely mixes fresh and cached answers.
	Cached bool `json:"cached"`

	meta responseMeta
}

// responseMeta: facts about the whole response, which LookupSet lifts onto the ResultSet.
type responseMeta struct {
	cached        bool
	flags         string
	authenticated bool
	signed        bool
	nsid          string
	ede           *EDE
	bogus         bool
	chain         []Record // the CNAMEs the answer came through
}

var (
	ErrBadType = errors.New("unsupported record type")
	// ErrBadResolver: there is no free-form "@server"; that would be an SSRF hole.
	ErrBadResolver = errors.New("unknown resolver")
	ErrEmptyName   = errors.New("no name to look up")
	ErrBadName     = errors.New("not a domain name")
	ErrNeedDomain  = errors.New("this check needs a domain name, not an IP address")
)

// errPanic fills the slot of a recovered goroutine; a blank one would read as "no records".
var errPanic = errors.New("internal error while answering this query")

// maxNameLabels is our limit, not DNS's: spread.go's zone walk spends one query per label.
const maxNameLabels = 10

// validDomain rejects input that cannot be a DNS name before it costs an upstream query.
func validDomain(name string) error {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return ErrEmptyName
	}
	if len(name) > 253 {
		return nameError{"that name is longer than the 253 characters DNS allows"}
	}
	labels := strings.Split(name, ".")
	if len(labels) > maxNameLabels {
		return badName(name, fmt.Sprintf("it has more than %d dot-separated parts", maxNameLabels))
	}
	for _, l := range labels {
		if l == "" {
			return badName(name, "it has an empty part (two dots in a row, or a leading dot)")
		}
		if len(l) > 63 {
			return badName(name, fmt.Sprintf("its part %q is longer than the 63 characters a part may have", l))
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return badName(name, fmt.Sprintf("its part %q starts or ends with a hyphen", l))
		}
		// IDNA refused it (NormalizeName converts the rest); sent raw it would be a false NXDOMAIN.
		if !isASCII(l) {
			return badName(name, fmt.Sprintf("its part %q isn't a valid internationalised name", l))
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
				c == '-' || c == '_'
			if !ok {
				what := fmt.Sprintf("%q", string(c))
				if c == ' ' {
					what = "a space"
				}
				return badName(name, "it contains "+what)
			}
		}
	}
	return nil
}

// nameError is ErrBadName to errors.Is, with a message for the person who typed the input.
type nameError struct{ msg string }

func (e nameError) Error() string        { return e.msg }
func (e nameError) Is(target error) bool { return target == ErrBadName }

func badName(input, why string) error {
	return nameError{fmt.Sprintf("%q isn't a domain name: %s", input, why)}
}

// safe logs a goroutine's panic: echo's Recover guards only the handler goroutine, not ours.
func safe(f func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("dnstools: recovered panic in a spawned query",
				"panic", r, "stack", string(debug.Stack()))
		}
	}()
	f()
}

// fanOut runs f(0)..f(n-1), at most limit at once, and waits; a panic in f is logged, not fatal.
func fanOut(n, limit int, f func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, limit)
	for i := range n {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f(i)
		})
	}
	wg.Wait()
}

type Resolver struct {
	Key  string // what callers pass: ?resolver=cloudflare
	Name string
	Addr string
}

// Resolvers is the whole allowlist, in display order.
var Resolvers = []Resolver{
	{Key: "cloudflare", Name: "Cloudflare (1.1.1.1)", Addr: "1.1.1.1:53"},
	{Key: "google", Name: "Google (8.8.8.8)", Addr: "8.8.8.8:53"},
	{Key: "quad9", Name: "Quad9 (9.9.9.9)", Addr: "9.9.9.9:53"},
}

const DefaultResolver = "cloudflare"

// Types: what the UI offers, the fan-out set plus PTR for IP literals.
var Types = append(slices.Clone(FanoutTypes), "PTR")

// FanoutTypes: one query per type, not ANY: RFC 8482 lets resolvers answer ANY with a stub.
var FanoutTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS"}

// maxTypesPerRequest caps fan-out width; CD=1 retries and dangling probes still add queries.
const maxTypesPerRequest = 12

// maxDanglingChecks caps the takeover scan's probes; a zone can alias any number of targets.
const maxDanglingChecks = 5

// EDE: an RFC 8914 Extended DNS Error, the resolver's own reason a query failed.
type EDE struct {
	Code  uint16 `json:"code"`
	Text  string `json:"text"`            // the registered label for Code
	Extra string `json:"extra,omitempty"` // free-text detail, resolver's own words
}

// TypeFailure: a type that couldn't be answered, which is not the same as Missing.
type TypeFailure struct {
	Type  string `json:"type"`
	Rcode string `json:"rcode,omitempty"`
	Error string `json:"error,omitempty"`
	EDE   *EDE   `json:"ede,omitempty"`
	// Bogus: SERVFAIL that a CD=1 retry answered, so DNSSEC validation failed, not the server.
	Bogus bool `json:"dnssec_bogus,omitempty"`
}

// ResultSet: one fan-out. NODATA types go to Missing; NXDOMAIN leaves Found and Missing empty.
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
	// Dangling: CNAME targets that don't resolve, the subdomain-takeover shape.
	Dangling []string `json:"dangling,omitempty"`
	// Chain: the CNAMEs followed to the answer, so ?type=A still shows the name is an alias.
	Chain []Record `json:"chain,omitempty"`
	// Provider: who runs the zone's DNS, named from the nameserver suffix.
	Provider string `json:"provider,omitempty"`
	// Signed: the zone returned RRSIGs. Authenticated: the resolver set AD on every answer.
	Signed        bool `json:"signed"`
	Authenticated bool `json:"authenticated"`
	// Unvalidated: types whose answer lacked AD while another type's had it.
	Unvalidated []string `json:"unvalidated,omitempty"`
	// Bogus: a CD=1 retry proved validation failed. Such a zone returns no RRSIGs,
	// so Signed=false must not be read as "unsigned".
	Bogus bool `json:"dnssec_bogus"`
	// NSID: the anycast node that answered (RFC 5001), which explains why two runs can differ.
	NSID string `json:"nsid,omitempty"`
	// Dig: one command per type, since `dig name A AAAA` silently queries only the last type.
	Dig []string `json:"dig"`
	// Zone: the answers in BIND zone-file format.
	Zone string `json:"zone,omitempty"`
	// Cached: every answer, dangling probes included, came from our cache.
	Cached bool `json:"cached"`
	// Asked: types queried. Not derivable: on NXDOMAIN every type lands in no bucket.
	Asked int `json:"asked"`
	// QueryMS: wall-clock for the whole concurrent fan-out, dangling probes included.
	QueryMS int64 `json:"query_ms"`
}

// Service queries DNS over UDP/53, retrying over TCP on truncation. Safe for concurrent use.
type Service struct {
	udp   *dns.Client
	tcp   *dns.Client
	http  *http.Client // fetches MTA-STS policy files, which live behind HTTPS
	cache *cache
	guard *platform.EgressGuard
	// inflight collapses concurrent identical questions into one upstream query.
	inflight singleflight.Group
}

func NewService(timeout time.Duration) *Service {
	return &Service{
		udp:   &dns.Client{Timeout: timeout},
		tcp:   &dns.Client{Net: "tcp", Timeout: timeout},
		http:  policyClient(timeout, platform.NewEgressGuard([]string{"443"}, nil)),
		cache: newCache(),
	}
}

// Looker is the handler's dependency; tests inject a fake so the suite stays offline.
type Looker interface {
	LookupSet(ctx context.Context, name, resolver string, types []string) (*ResultSet, error)
}

// Checks returns the checks svc also serves; a test fake implements only some.
func Checks(svc Looker) (Spreader, ECSer, Tracer, Mailer, Reputer) {
	spr, _ := svc.(Spreader)
	ecs, _ := svc.(ECSer)
	tra, _ := svc.(Tracer)
	mail, _ := svc.(Mailer)
	rep, _ := svc.(Reputer)
	return spr, ecs, tra, mail, rep
}

// LookupSet queries types concurrently (none = FanoutTypes); a failing type never sinks the rest.
func (s *Service) LookupSet(ctx context.Context, name, resolver string, types []string) (*ResultSet, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrEmptyName
	}
	addr, ok := resolverAddr(resolver)
	if !ok {
		return nil, ErrBadResolver
	}

	qname, reversed := reverseName(name)
	if reversed {
		types = []string{"PTR"}
	} else {
		if err := validDomain(name); err != nil {
			return nil, err
		}
		// Lowercased so a capitalised name isn't a second cache entry and query.
		qname = strings.ToLower(dns.Fqdn(name))
		if len(types) == 0 {
			types = FanoutTypes
		}
	}

	// An unknown type is the caller's mistake (400), not a per-type failure.
	types = slices.Clone(types)
	for i, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		// The advertised list, not the RR registry: ANY and AXFR parse but don't belong here.
		if !slices.Contains(Types, t) {
			return nil, ErrBadType
		}
		types[i] = t
	}
	if len(types) > maxTypesPerRequest {
		types = types[:maxTypesPerRequest]
	}

	results := make([]Result, len(types))
	errs := make([]error, len(types))

	start := time.Now()
	// A per-request query budget; the per-IP limiter alone isn't enough.
	fanOut(len(types), 4, func(i int) {
		errs[i] = errPanic // overwritten unless the lookup panics
		results[i], errs[i] = s.lookup(ctx, qname, types[i], addr)
	})

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

	answered, nx, cached, validated := 0, 0, 0, 0
	for i, t := range types {
		m := results[i].meta
		if m.cached {
			cached++
		}
		// First-wins for Flags only: an earlier answer without NSID or RRSIGs mustn't mask a later one.
		if set.Flags == "" && m.flags != "" {
			set.Flags = m.flags
		}
		if set.NSID == "" {
			set.NSID = m.nsid
		}
		set.Signed = set.Signed || m.signed
		if len(set.Chain) == 0 {
			set.Chain = m.chain
		}
		results[i].Cached = m.cached
		var rcode rcodeError
		err := errs[i]
		if err == nil || errors.Is(err, errNXDomain) || errors.Is(err, errNoData) {
			if m.authenticated {
				validated++
			} else {
				set.Unvalidated = append(set.Unvalidated, t)
			}
		}
		switch {
		case err == nil:
			answered++
			set.Found = append(set.Found, results[i])
		case errors.Is(err, errNXDomain):
			answered++
			if m.ede != nil {
				// Blocked or filtered, not "no such name": keep it out of the NXDOMAIN verdict.
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
	// The majority floor stops one surviving NXDOMAIN speaking for a mostly failed fan-out.
	set.NXDomain = answered > 0 && nx == answered && answered*2 >= len(types)

	set.Authenticated = validated > 0 && len(set.Unvalidated) == 0
	if validated == 0 {
		set.Unvalidated = nil
	}

	// Dangling-CNAME scan. Chain targets count too: ?type=A keeps the CNAME out of Found.
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
	probedUpstream := false
	for _, target := range targets {
		res, err := s.lookup(ctx, dns.Fqdn(target), "A", addr)
		// Any probe that left the box voids Cached, whatever it found.
		if !res.meta.cached {
			probedUpstream = true
		}
		// NODATA is normal (the target may be AAAA-only); only a missing name dangles.
		if errors.Is(err, errNXDomain) {
			set.Dangling = append(set.Dangling, target)
		}
	}

	set.Cached = cached > 0 && cached == len(types) && !probedUpstream

	// SPF first, then labelled TXT records: the page folds long sets.
	for i := range set.Found {
		if set.Found[i].Type == "TXT" {
			slices.SortStableFunc(set.Found[i].Records, func(a, b Record) int {
				return txtRank(a) - txtRank(b)
			})
		}
	}

	var zone strings.Builder
	// +nsid only when we got one, so the command reproduces the page's "Answered by" row.
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

	set.Bogus = slices.ContainsFunc(set.Failed, func(f TypeFailure) bool { return f.Bogus })
	for _, r := range set.Found {
		if set.Provider = providerOf(r.Records); set.Provider != "" {
			break
		}
	}

	// Taken last so the dangling probes' time counts.
	set.QueryMS = time.Since(start).Milliseconds()
	return set, nil
}

// LookupEnriched is GET /'s lookup; geo (nil-able) adds each A/AAAA answer's network.
func LookupEnriched(ctx context.Context, svc Looker, geo iptools.Looker, name, qtype, resolver string) (*ResultSet, error) {
	var types []string
	if t := lookupType(qtype); t != "" {
		types = []string{t}
	}
	set, err := svc.LookupSet(ctx, NormalizeName(name), resolverKey(resolver), types)
	if err != nil {
		return nil, err
	}
	enrichGeo(set, geo)
	return set, nil
}

func lookupType(qtype string) string {
	t := strings.ToUpper(strings.TrimSpace(qtype))
	if t == "ALL" {
		return ""
	}
	return t
}

func resolverKey(resolver string) string {
	if r := strings.ToLower(strings.TrimSpace(resolver)); r != "" {
		return r
	}
	return DefaultResolver
}

func enrichGeo(set *ResultSet, geo iptools.Looker) {
	if geo == nil || set == nil {
		return
	}
	for f := range set.Found {
		for i, r := range set.Found[f].Records {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}
			g, err := geo.Lookup(r.Value)
			if err != nil || g == nil {
				continue
			}
			set.Found[f].Records[i].ASN = g.ASN
			set.Found[f].Records[i].ASName = g.ASName
			set.Found[f].Records[i].Country = g.Country
		}
	}
}

func txtRank(r Record) int {
	switch {
	case strings.HasPrefix(strings.ToLower(strings.TrimLeft(r.Value, `"`)), "v=spf1"):
		return 0
	case r.Label != "":
		return 1
	}
	return 2
}

// AliasTarget: where the alias chain ends, as an owner name, or "" if none.
func (r *ResultSet) AliasTarget() string {
	if len(r.Chain) == 0 {
		return ""
	}
	return dns.Fqdn(r.Chain[len(r.Chain)-1].Target)
}

// The page folds a type with more than foldOver records after foldAfter.
const foldAfter, foldOver = 5, 8

// Folded: how many of this type's records the page folds away.
func (r Result) Folded() int {
	if len(r.Records) > foldOver {
		return len(r.Records) - foldAfter
	}
	return 0
}

func (r Result) FoldsRow(i int) bool { return r.Folded() > 0 && i >= foldAfter }

// FailureGroup: types that failed the same way, shown once.
type FailureGroup struct {
	Types []string
	TypeFailure
}

// FailureGroups folds Failed by failure, in first-seen order (page only).
func (r *ResultSet) FailureGroups() []FailureGroup {
	var out []FailureGroup
	key := func(f TypeFailure) string {
		k := f.Rcode + "|" + f.Error + "|" + fmt.Sprint(f.Bogus)
		if f.EDE != nil {
			k += "|" + fmt.Sprint(f.EDE.Code) + "|" + f.EDE.Extra
		}
		return k
	}
	index := map[string]int{}
	for _, f := range r.Failed {
		k := key(f)
		if i, ok := index[k]; ok {
			out[i].Types = append(out[i].Types, f.Type)
			continue
		}
		index[k] = len(out)
		out = append(out, FailureGroup{Types: []string{f.Type}, TypeFailure: f})
	}
	return out
}

// lookup resolves one type against an allowlisted address, through the cache and singleflight.
func (s *Service) lookup(ctx context.Context, qname, qtype, addr string) (Result, error) {
	// DNS is case-insensitive, so two spellings are one key.
	key := strings.ToLower(qname) + "|" + qtype + "|" + addr
	now := time.Now()
	if e, ok := s.cache.get(key, now); ok {
		return cloneResult(e.result, true, now.Sub(e.stored)), e.err
	}
	v, _, _ := s.inflight.Do(key, func() (any, error) {
		res, err := s.exchange(ctx, qname, qtype, addr)
		e := cacheEntry{result: res, err: err}
		// A transport failure says nothing about the zone, so the next click retries.
		if !isTransportErr(err) {
			s.cache.put(key, e, time.Now())
		}
		return e, nil
	})
	e := v.(cacheEntry)
	// Every waiter gets the same value, so each needs its own copy; none was served from cache.
	return cloneResult(e.result, false, 0), e.err
}

// cloneResult gives the caller its own Records, so enrichment can't write into the cache.
func cloneResult(r Result, cached bool, age time.Duration) Result {
	out := r
	out.Records = ageRecords(slices.Clone(r.Records), age)
	out.meta.cached = cached
	out.meta.chain = ageRecords(slices.Clone(r.meta.chain), age)
	return out
}

// ageRecords counts TTLs down by time spent cached, so a replayed TTL can't outlive the record.
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

// isTransportErr: the resolver wasn't reached, as opposed to answering with a rcode.
func isTransportErr(err error) bool {
	if err == nil {
		return false
	}
	var rcode rcodeError
	return !errors.Is(err, errNXDomain) && !errors.Is(err, errNoData) && !errors.As(err, &rcode)
}

// exchange sends one query, retrying over TCP on truncation and with CD=1 on SERVFAIL.
func (s *Service) exchange(ctx context.Context, qname, qtype, addr string) (Result, error) {
	m := newQuery(qname, qtype)
	resp, tcpErr, err := s.ask(ctx, m, addr)
	if err != nil {
		return Result{}, fmt.Errorf("query %s: %w", addr, err)
	}
	if tcpErr != nil {
		// A partial RRset would render and cache as complete, so it's a failure instead.
		return Result{}, fmt.Errorf("truncated answer from %s, TCP retry failed: %w", addr, tcpErr)
	}

	meta := responseMeta{
		flags:         flagString(resp),
		authenticated: resp.AuthenticatedData,
		nsid:          nsidOf(resp),
		ede:           edeOf(resp),
	}

	// SERVFAIL is ambiguous; if a CD=1 retry succeeds, DNSSEC validation is what failed.
	if resp.Rcode == dns.RcodeServerFailure {
		cd := newQuery(qname, qtype)
		cd.CheckingDisabled = true
		if cdResp, _, cdErr := s.udp.ExchangeContext(ctx, cd, addr); cdErr == nil && cdResp.Rcode == dns.RcodeSuccess {
			meta.bogus = true
		}
	}

	records := []Record{}
	wantType := dns.StringToType[qtype]
	for _, rr := range resp.Answer {
		// Counted before the type filter drops them: RRSIGs are the only sign the zone is signed.
		if rr.Header().Rrtype == dns.TypeRRSIG {
			meta.signed = true
		}
		// Only the asked type: a CNAME'd name returns the CNAME for every type, hiding NODATA.
		if rr.Header().Rrtype != wantType {
			// Kept aside, or ?type=A would never show the name is an alias.
			if rr.Header().Rrtype == dns.TypeCNAME {
				meta.chain = append(meta.chain, toRecord(rr))
			}
			continue
		}
		records = append(records, toRecord(rr))
	}
	return Result{Type: qtype, Records: records, meta: meta}, statusErr(resp.Rcode, len(records))
}

// ask retries a truncated UDP reply over TCP; if that fails it returns the truncated reply and tcpErr.
func (s *Service) ask(ctx context.Context, m *dns.Msg, addr string) (resp *dns.Msg, tcpErr, err error) {
	resp, _, err = s.udp.ExchangeContext(ctx, m, addr)
	if err != nil || resp == nil || !resp.Truncated {
		return resp, nil, err
	}
	full, _, tcpErr := s.tcp.ExchangeContext(ctx, m, addr)
	if tcpErr != nil {
		return resp, tcpErr, nil
	}
	return full, nil, nil
}

// newQuery: EDNS0 with a 1232-byte buffer (DNS flag day 2020), DO for the AD bit, and NSID.
func newQuery(qname, qtype string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.StringToType[qtype])
	m.RecursionDesired = true
	m.SetEdns0(1232, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	return m
}

// ednsOption returns m's first EDNS0 option of type T, or nil.
func ednsOption[T dns.EDNS0](m *dns.Msg) T {
	var none T
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if t, ok := o.(T); ok {
				return t
			}
		}
	}
	return none
}

func edeOf(m *dns.Msg) *EDE {
	e := ednsOption[*dns.EDNS0_EDE](m)
	if e == nil {
		return nil
	}
	text := dns.ExtendedErrorCodeToString[e.InfoCode]
	if text == "" {
		text = "Unknown"
	}
	return &EDE{Code: e.InfoCode, Text: text, Extra: e.ExtraText}
}

// nsidOf decodes the hex NSID when it is printable; operators put names like "ams01" in it.
func nsidOf(m *dns.Msg) string {
	n := ednsOption[*dns.EDNS0_NSID](m)
	if n == nil || n.Nsid == "" {
		return ""
	}
	if raw, err := hex.DecodeString(n.Nsid); err == nil && isPrintable(raw) {
		return string(raw)
	}
	return n.Nsid
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}

// statusErr maps a response to nil or the sentinel LookupSet partitions on.
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

var (
	errNXDomain = errors.New("NXDOMAIN")
	errNoData   = errors.New("NODATA")
)

// rcodeError carries a non-NOERROR rcode (SERVFAIL, REFUSED, …).
type rcodeError string

func (e rcodeError) Error() string { return string(e) }

// reverseName returns the arpa name for an IP literal, and whether the input was one.
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

// resolverOverride lets tests reach a loopback server, which the allowlist forbids.
// Only _test.go files assign it, so a visitor can steer queries only to Resolvers.
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

// ResolverName maps an allowlist key to its label; an unknown key comes back as itself.
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
		// Resolvers echo the asked case, and callers compare Owner against QName.
		Owner: strings.ToLower(h.Name),
	}
	switch v := rr.(type) {
	case *dns.SOA:
		rec.Detail = soaFields(v)
	case *dns.TXT:
		rec.Label = txtLabel(strings.Join(v.Txt, ""))
	case *dns.CAA:
		rec.Detail = caaFields(v)
	case *dns.HTTPS:
		rec.Detail = svcbFields(rr)
		rec.Target = v.Target
	case *dns.SVCB:
		rec.Detail = svcbFields(rr)
		rec.Target = v.Target
	case *dns.NS:
		rec.Target = v.Ns
	case *dns.CNAME:
		rec.Target = v.Target
	case *dns.MX:
		rec.Target = v.Mx
		if v.Mx == "." { // null MX, RFC 7505
			rec.Label = "Null MX: this domain accepts no mail"
		}
	case *dns.PTR:
		rec.Target = v.Ptr
	case *dns.SRV:
		rec.Target = v.Target
	}
	rec.Target = bareName(rec.Target)
	return rec
}

// rdata is rr.String() without the header, whose facts have their own columns.
func rdata(rr dns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// flagString renders the header bits dig prints, in dig's order.
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

// humanizeTTL renders a TTL as "45s", "5m", "1h30m" or "7d".
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
