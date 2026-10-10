package dnstools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

type EmailAuth struct {
	Domain string `json:"domain"`

	SPF       *SPFResult    `json:"spf,omitempty"`
	DMARC     *DMARCResult  `json:"dmarc,omitempty"`
	DKIM      []DKIMKey     `json:"dkim,omitempty"`
	MTASTS    *MTASTSResult `json:"mta_sts,omitempty"`
	TLSRPT    string        `json:"tls_rpt,omitempty"`
	BIMI      string        `json:"bimi,omitempty"`
	HasMX     bool          `json:"has_mx"`
	NXDomain  bool          `json:"nxdomain,omitempty"`
	MailHosts []MailHost    `json:"mail_hosts,omitempty"`
	// MXRep is filled by EmailReport: the blocklist corpus is out of the domain layer's reach.
	MXRep *MXReputation `json:"mx_reputation,omitempty"`
	// MXCount can exceed len(MailHosts): the FCrDNS fan-out stops at maxMailHosts.
	MXCount int `json:"mx_count,omitempty"`
	// NullMX: the only MX is "0 ." (RFC 7505), so the domain takes no mail though HasMX is true.
	NullMX bool `json:"null_mx,omitempty"`
	// DKIMRevoked: selectors with an empty p=, a revoked key (RFC 6376 §3.6.1).
	DKIMRevoked []string `json:"dkim_revoked,omitempty"`
	// DKIMWildcard: every probed selector returned one record, so DKIM is a wildcard TXT.
	DKIMWildcard bool   `json:"dkim_wildcard,omitempty"`
	Notes        []Note `json:"notes,omitempty"`
	QueryMS      int64  `json:"query_ms"`
}

type Note struct {
	Level string `json:"level"` // ok | warn | fail | info
	Text  string `json:"text"`
}

// sortNotes orders findings fail, warn, info, ok; stable within a level.
func sortNotes(notes []Note) {
	slices.SortStableFunc(notes, func(a, b Note) int { return noteRank(a.Level) - noteRank(b.Level) })
}

func noteRank(level string) int {
	switch level {
	case "fail":
		return 0
	case "warn":
		return 1
	case "info":
		return 2
	}
	return 3
}

type SPFResult struct {
	Record string `json:"record"`
	// Lookups: DNS lookups the fully expanded record costs; past Limit (10) SPF permerrors.
	Lookups int `json:"lookups"`
	Limit   int `json:"limit"`
	// Truncated: include resolution hit a cap, so Chain is partial; the verdict still holds.
	Truncated bool     `json:"truncated,omitempty"`
	All       string   `json:"all,omitempty"` // -all, ~all, ?all, +all
	Chain     []string `json:"chain,omitempty"`
	// Extra: further apex v=spf1 records; more than one is a permerror (RFC 7208 §4.5).
	Extra []string `json:"extra_records,omitempty"`
	// Voids: include/redirect targets that resolved to nothing (RFC 7208 §4.6.4). A lower
	// bound: a, mx and exists terms are counted but never resolved.
	Voids     []string `json:"void_lookups,omitempty"`
	VoidLimit int      `json:"void_limit,omitempty"`
}

type DMARCResult struct {
	Record string `json:"record"`
	// Name is where the record was found: a subdomain with none inherits its parent's.
	Name      string `json:"name,omitempty"`
	Inherited bool   `json:"inherited,omitempty"`
	Policy    string `json:"policy"`               // p=
	SubPolicy string `json:"sub_policy,omitempty"` // sp=
	Percent   string `json:"percent,omitempty"`
	Aggregate string `json:"aggregate,omitempty"` // rua=
	Forensic  string `json:"forensic,omitempty"`  // ruf=
	// Extra: further v=DMARC1 records, which make receivers discard all (RFC 7489 §6.6.3).
	Extra []string `json:"extra_records,omitempty"`
}

// Applied is the policy for the asked name: sp= on an inherited record (RFC 7489 §6.6.3).
func (d *DMARCResult) Applied() string {
	if d.Inherited && d.SubPolicy != "" {
		return d.SubPolicy
	}
	return d.Policy
}

// pct reads pct= (100 when absent); false means not a percentage, which may void the record.
func (d *DMARCResult) pct() (int, bool) {
	raw := strings.TrimSpace(d.Percent)
	if raw == "" {
		return 100, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 100 {
		return 0, false
	}
	return n, true
}

// nextLower is the policy RFC 7489 §6.3 applies to mail a partial pct= doesn't select.
func nextLower(policy string) string {
	if policy == "reject" {
		return "quarantine"
	}
	return "none"
}

// MailHost is one MX host and whether IP -> PTR -> forward lands back on the same IP.
type MailHost struct {
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	PTR    string `json:"ptr,omitempty"`
	FCrDNS bool   `json:"fcrdns"`
}

// maxMailHosts bounds the FCrDNS fan-out: each host costs three or four queries.
const maxMailHosts = 5

type DKIMKey struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
}

type MTASTSResult struct {
	Record string `json:"record"`
	// Fetched vs PolicyFound: "file missing" and "file isn't a policy" need different fixes.
	Fetched     bool     `json:"fetched"`
	PolicyFound bool     `json:"policy_found"`
	Mode        string   `json:"mode,omitempty"`
	MX          []string `json:"mx,omitempty"`
	MaxAge      string   `json:"max_age,omitempty"`
	Version     string   `json:"version,omitempty"`
	PolicyError string   `json:"policy_error,omitempty"`
}

func (m *MTASTSResult) MaxAgeHuman() string {
	n, err := strconv.ParseUint(m.MaxAge, 10, 32)
	if err != nil {
		return m.MaxAge
	}
	return humanizeTTL(uint32(n)) + " (" + m.MaxAge + "s)"
}

// commonDKIMSelectors is a short guess list: every entry is one more query per check.
var commonDKIMSelectors = []string{
	"google", "selector1", "selector2", "k1", "k2",
	"dkim", "default", "mail", "s1", "zoho", "sendgrid", "amazonses",
}

const (
	maxSPFIncludes = 15  // past 10 lookups the verdict is settled; stop spending queries
	maxSPFSteps    = 500 // un-memoised re-walks (loops, depth cuts) grow as branching^depth
	maxSPFDepth    = 10
)

type Mailer interface {
	EmailAuth(ctx context.Context, domain string) (*EmailAuth, error)
}

// EmailReport is GET /email: EmailAuth, plus MXRep when rep and bl are wired and answer.
func EmailReport(ctx context.Context, mail Mailer, rep Reputer, bl BlockChecker, name string) (*EmailAuth, error) {
	if mail == nil {
		return nil, ErrDisabled
	}
	name = NormalizeName(name)
	res, err := mail.EmailAuth(ctx, name)
	if err != nil {
		return nil, err
	}
	if rep != nil && bl != nil {
		if mr, err := rep.MXReputation(ctx, name, bl); err == nil {
			res.MXRep = mr
		}
	}
	return res, nil
}

// EmailAuth runs every check concurrently; each goroutine writes its own fields.
func (s *Service) EmailAuth(ctx context.Context, domain string) (*EmailAuth, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, ErrEmptyName
	}
	if _, isIP := reverseName(domain); isIP {
		return nil, ErrNeedDomain
	}
	if err := validDomain(domain); err != nil {
		return nil, err
	}
	addr, _ := resolverAddr(DefaultResolver)
	out := &EmailAuth{Domain: domain}

	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go safe(func() { defer wg.Done(); f() }) }

	var mxErr error
	run(func() {
		r, err := s.lookup(ctx, dnsFqdn(domain), "MX", addr)
		mxErr = err
		hosts, nullMX := s.checkMailHosts(ctx, r.Records, addr)
		out.NXDomain = errors.Is(err, errNXDomain)
		out.HasMX = len(r.Records) > 0
		out.MXCount = len(r.Records)
		out.MailHosts, out.NullMX = hosts, nullMX
	})
	run(func() { out.SPF = s.checkSPF(ctx, domain, addr) })
	run(func() { out.DMARC = s.checkDMARC(ctx, domain, addr) })
	run(func() { out.DKIM, out.DKIMRevoked, out.DKIMWildcard = s.checkDKIM(ctx, domain, addr) })
	run(func() { out.MTASTS = s.checkMTASTS(ctx, domain, addr) })
	run(func() { out.TLSRPT = s.firstTXT(ctx, dnsFqdn("_smtp._tls."+domain), addr, "v=TLSRPTv1") })
	run(func() { out.BIMI = s.firstTXT(ctx, dnsFqdn("default._bimi."+domain), addr, "v=BIMI1") })
	wg.Wait()

	// A failed query is not evidence of absence: never let "missing" read as a fact.
	if mxErr != nil && !errors.Is(mxErr, errNoData) && !errors.Is(mxErr, errNXDomain) {
		out.Notes = append([]Note{{
			Level: "warn",
			Text:  "At least one DNS query failed while checking this domain, so anything reported as missing below may simply not have been reachable. Re-run before acting on it.",
		}}, out.Notes...)
	}
	out.judge()
	return out, nil
}

// checkSPF keeps every apex v=spf1 record: two are a permerror (RFC 7208 §4.5), not a tie.
func (s *Service) checkSPF(ctx context.Context, domain, addr string) *SPFResult {
	recs, _ := s.matchingTXT(ctx, dnsFqdn(domain), addr, "v=spf1")
	if len(recs) == 0 {
		return nil
	}
	rec := recs[0]
	r := &SPFResult{Record: rec, Extra: recs[1:], Limit: 10, VoidLimit: 2}

	w := &spfWalk{
		// The checked domain starts on the path, so a self-include is a loop at once.
		inProgress: map[string]bool{bareName(domain): true},
		memo:       map[string]int{},
		seen:       map[string]bool{},
	}
	r.Lookups, _ = s.countSPFLookups(ctx, rec, addr, w, 0)
	r.Chain, r.Truncated, r.Voids = w.chain, w.truncated, w.voids

	for _, tok := range strings.Fields(rec) {
		switch strings.ToLower(tok) {
		case "all", "+all":
			// Bare `all` carries an implicit "+", i.e. "anyone may send".
			r.All = "+all"
		case "-all", "~all", "?all":
			r.All = strings.ToLower(tok)
		}
	}
	return r
}

// spfWalk is one SPF evaluation; memo holds the cost of sub-trees walked to completion.
type spfWalk struct {
	// inProgress is path-local: RFC 7208 counts evaluations, so a shared include costs twice.
	inProgress map[string]bool
	memo       map[string]int
	seen       map[string]bool // chain de-dup: display, never counting
	chain      []string
	voids      []string
	truncated  bool
	steps      int
}

// spfTerm splits a term into its name (lowercased, CIDR suffix cut) and its target.
func spfTerm(tok string) (name, target string) {
	t := strings.TrimLeft(tok, "+-~?")
	name = t
	if i := strings.IndexAny(t, ":="); i >= 0 {
		name, target = t[:i], t[i+1:]
	}
	name, _, _ = strings.Cut(name, "/")
	return strings.ToLower(name), target
}

// countSPFLookups returns a record's cost, and false when a cut or loop made it path-specific.
func (s *Service) countSPFLookups(ctx context.Context, rec, addr string, w *spfWalk, depth int) (int, bool) {
	w.steps++
	if ctx.Err() != nil || w.steps > maxSPFSteps || depth > maxSPFDepth {
		w.truncated = true
		return 0, false
	}
	toks := strings.Fields(rec)

	// RFC 7208 §6.1: redirect= is ignored when this record has an all mechanism.
	redirectApplies := !slices.ContainsFunc(toks, func(tok string) bool {
		name, _ := spfTerm(tok)
		return name == "all"
	})

	n, exact := 0, true
	for _, tok := range toks {
		name, target := spfTerm(tok)
		switch name {
		case "a", "mx", "ptr", "exists":
			n++
		case "include", "redirect":
			if name == "redirect" && !redirectApplies {
				continue
			}
			n++
			if target == "" {
				continue
			}
			key := bareName(target)
			if w.inProgress[key] {
				// The term is charged; re-entering it would not terminate.
				exact = false
				continue
			}
			if cost, ok := w.memo[key]; ok {
				n += cost
				continue
			}
			if len(w.chain) >= maxSPFIncludes {
				w.truncated, exact = true, false
				continue
			}
			if !w.seen[key] {
				w.seen[key] = true
				w.chain = append(w.chain, target)
			}
			// A macro target (RFC 7208 §7) expands per message; querying it would invent a void.
			if strings.Contains(target, "%{") {
				continue
			}
			subs, void := s.matchingTXT(ctx, dnsFqdn(target), addr, "v=spf1")
			if void {
				w.voids = append(w.voids, target)
			}
			if len(subs) == 0 {
				w.memo[key] = 0
				continue
			}
			w.inProgress[key] = true
			cost, complete := s.countSPFLookups(ctx, subs[0], addr, w, depth+1)
			delete(w.inProgress, key)
			n += cost
			if complete {
				w.memo[key] = cost
			} else {
				exact = false
			}
		}
	}
	return n, exact
}

// checkMailHosts sorts by preference before the cap, so the checked subset doesn't rotate.
func (s *Service) checkMailHosts(ctx context.Context, mx []Record, addr string) (out []MailHost, nullMX bool) {
	byPref := slices.Clone(mx)
	slices.SortStableFunc(byPref, func(a, b Record) int { return mxPref(a.Value) - mxPref(b.Value) })

	for _, rec := range byPref {
		if len(out) >= maxMailHosts {
			break
		}
		switch host := mxHost(rec.Value); host {
		case "":
		case ".":
			nullMX = true
		default:
			out = append(out, s.probeMailHost(ctx, host, addr))
		}
	}
	// RFC 7505 §3: a null MX beside real hosts is a contradiction, not a declaration.
	return out, nullMX && len(mx) == 1
}

func (s *Service) probeMailHost(ctx context.Context, host, addr string) MailHost {
	h := MailHost{Host: host}
	// AAAA only as a fallback, so an IPv6-only MX doesn't read as unresolved.
	fwd, err := s.lookup(ctx, dnsFqdn(host), "A", addr)
	if err != nil || len(fwd.Records) == 0 {
		fwd, err = s.lookup(ctx, dnsFqdn(host), "AAAA", addr)
	}
	if err != nil || len(fwd.Records) == 0 {
		return h
	}
	h.IP = fwd.Records[0].Value

	rev, ok := reverseName(h.IP)
	if !ok {
		return h
	}
	ptr, err := s.lookup(ctx, rev, "PTR", addr)
	if err != nil || len(ptr.Records) == 0 {
		return h
	}
	h.PTR = strings.TrimSuffix(ptr.Records[0].Value, ".")

	fwdType := "A"
	if strings.Contains(h.IP, ":") {
		fwdType = "AAAA"
	}
	back, err := s.lookup(ctx, dnsFqdn(h.PTR), fwdType, addr)
	h.FCrDNS = err == nil && slices.ContainsFunc(back.Records, func(b Record) bool { return b.Value == h.IP })
	return h
}

// maxMXPref sorts an MX whose preference can't be read after every one whose can.
const maxMXPref = 1 << 16

// mxPref reads the preference from MX rdata ("10 mail.example.com.").
func mxPref(rdata string) int {
	f := strings.Fields(rdata)
	if len(f) < 2 {
		return maxMXPref
	}
	n, err := strconv.Atoi(f[0])
	if err != nil || n < 0 {
		return maxMXPref
	}
	return n
}

// mxHost returns the MX target, "." for a null MX and "" when there is no target.
func mxHost(rdata string) string {
	f := strings.Fields(rdata)
	if len(f) == 0 {
		return ""
	}
	if h := strings.TrimSuffix(f[len(f)-1], "."); h != "" {
		return h
	}
	return "."
}

// checkDMARC climbs to a parent when the name publishes no record (RFC 7489 §6.6.3).
func (s *Service) checkDMARC(ctx context.Context, domain, addr string) *DMARCResult {
	name := domain
	for climbed := 0; ; climbed++ {
		at := "_dmarc." + name
		recs, _ := s.matchingTXT(ctx, dnsFqdn(at), addr, "v=DMARC1")
		if len(recs) > 0 {
			d := parseDMARC(recs[0])
			d.Name, d.Inherited, d.Extra = at, name != domain, recs[1:]
			return d
		}
		parent, ok := parentDomain(name)
		if !ok || climbed >= maxDMARCParents {
			return nil
		}
		name = parent
	}
}

const maxDMARCParents = 3

// parentDomain drops the leftmost label, stopping at two labels: with no PSL, the honest floor.
func parentDomain(name string) (string, bool) {
	_, rest, ok := strings.Cut(name, ".")
	if !ok || !strings.Contains(rest, ".") {
		return "", false
	}
	return rest, true
}

func parseDMARC(rec string) *DMARCResult {
	d := &DMARCResult{Record: rec}
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		// Tag names are case-insensitive (RFC 5234 §2.3): "P=reject" is valid.
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "p":
			d.Policy = strings.ToLower(v)
		case "sp":
			d.SubPolicy = strings.ToLower(v)
		case "pct":
			d.Percent = v
		case "rua":
			d.Aggregate = v
		case "ruf":
			d.Forensic = v
		}
	}
	return d
}

// checkDKIM probes common selectors, reporting revoked keys and a wildcard apart from keys.
func (s *Service) checkDKIM(ctx context.Context, domain, addr string) (keys []DKIMKey, revoked []string, wildcard bool) {
	// Indexed, not appended: selector-list order, not goroutine completion order.
	recs := make([]string, len(commonDKIMSelectors))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, sel := range commonDKIMSelectors {
		wg.Add(1)
		go safe(func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			recs[i] = s.firstTXT(ctx, dnsFqdn(sel+"._domainkey."+domain), addr, "v=DKIM1")
		})
	}
	wg.Wait()

	for i, rec := range recs {
		switch {
		case rec == "":
		case dkimHasKey(rec):
			keys = append(keys, DKIMKey{Selector: commonDKIMSelectors[i], Found: true})
		default:
			revoked = append(revoked, commonDKIMSelectors[i])
		}
	}
	// One record under every unrelated selector is a wildcard, not twelve keys.
	wildcard = len(recs) > 1 && recs[0] != "" && !slices.ContainsFunc(recs, func(r string) bool { return r != recs[0] })
	return keys, revoked, wildcard
}

func dkimHasKey(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(strings.TrimSpace(k), "p") {
			return strings.TrimSpace(v) != ""
		}
	}
	return false
}

func (s *Service) checkMTASTS(ctx context.Context, domain, addr string) *MTASTSResult {
	rec := s.firstTXT(ctx, dnsFqdn("_mta-sts."+domain), addr, "v=STSv1")
	if rec == "" {
		return nil
	}
	m := &MTASTSResult{Record: rec}
	body, err := s.fetchPolicy(ctx, "https://mta-sts."+domain+"/.well-known/mta-sts.txt")
	if err != nil {
		m.PolicyError = err.Error()
		return m
	}
	m.Fetched = true
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		// RFC 8461 §3.2 field names are case-insensitive: "Mode: Enforce" is valid.
		switch strings.ToLower(k) {
		case "mode":
			m.Mode = strings.ToLower(v)
		case "mx":
			m.MX = append(m.MX, v)
		case "max_age":
			m.MaxAge = v
		case "version":
			m.Version = v
		}
	}
	// RFC 8461 §3.2 makes all four mandatory; a wildcard vhost serving HTML must not pass.
	age, ageErr := strconv.Atoi(m.MaxAge)
	switch {
	case !strings.EqualFold(m.Version, "STSv1"):
		m.PolicyError = "the file at that URL has no version: STSv1 line, so it is not an MTA-STS policy"
	case m.Mode != "enforce" && m.Mode != "testing" && m.Mode != "none":
		m.PolicyError = "the policy has no usable mode: line"
	case ageErr != nil || age < 1 || age > maxSTSAge:
		m.PolicyError = "the policy's max_age is missing or outside the allowed range"
	case m.Mode != "none" && len(m.MX) == 0:
		m.PolicyError = "the policy lists no mx hosts, so a sender in " + m.Mode + " mode has nothing to match a server against"
	default:
		m.PolicyFound = true
	}
	return m
}

// maxSTSAge is RFC 8461 §3.2's ceiling on max_age, a little over a year.
const maxSTSAge = 31557600

const maxQuotedHeader = 100

// policyClient dials through g: any domain can point mta-sts.<domain> anywhere.
func policyClient(timeout time.Duration, g *platform.EgressGuard) *http.Client {
	tr := g.Transport(5 * time.Second)
	tr.TLSHandshakeTimeout = 5 * time.Second
	return &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// WithEgressGuard sends the MTA-STS fetch and every nameserver probe through g. Nil-safe.
func (s *Service) WithEgressGuard(g *platform.EgressGuard) *Service {
	if s != nil {
		s.http = policyClient(s.http.Timeout, g)
		s.guard = g
	}
	return s
}

func (s *Service) fetchPolicy(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", domainUserAgent)
	resp, err := s.http.Do(req)
	if err != nil {
		return "", errors.New("policy file unreachable")
	}
	defer resp.Body.Close()
	// RFC 8461 §3.3: a redirect MUST NOT be followed.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", fmt.Errorf("policy file redirects (%d), which RFC 8461 forbids", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("policy file returned %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return "", fmt.Errorf("policy file is served as %s, and RFC 8461 requires text/plain", platform.Clip(ct, maxQuotedHeader))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(b), err
}

// policyCovers matches an MTA-STS mx pattern; RFC 8461 §3.2 allows one leading wildcard label.
func policyCovers(pattern, host string) bool {
	pattern, host = bareName(pattern), bareName(host)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		_, rest, found := strings.Cut(host, ".")
		return found && rest == suffix
	}
	return pattern == host
}

// matchingTXT returns every TXT at name starting with prefix, parts joined, and whether the
// name answered nothing at all (void). A SERVFAIL is not void: it means "couldn't find out".
func (s *Service) matchingTXT(ctx context.Context, name, addr, prefix string) (recs []string, void bool) {
	r, err := s.lookup(ctx, name, "TXT", addr)
	switch {
	case errors.Is(err, errNXDomain), errors.Is(err, errNoData):
		return nil, true
	case err != nil:
		return nil, false
	}
	for _, rec := range r.Records {
		v := strings.ReplaceAll(rec.Value, `" "`, "")
		v = strings.Trim(v, `"`)
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			recs = append(recs, v)
		}
	}
	return recs, len(r.Records) == 0
}

// firstTXT is matchingTXT for the checks where a second record changes nothing.
func (s *Service) firstTXT(ctx context.Context, name, addr, prefix string) string {
	if recs, _ := s.matchingTXT(ctx, name, addr, prefix); len(recs) > 0 {
		return recs[0]
	}
	return ""
}

func dnsFqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// bareName lowercases a name and drops its trailing dot, so two spellings compare equal.
func bareName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// judge turns the records into findings; every note says what to do, not just what is wrong.
func (e *EmailAuth) judge() {
	add := func(level, text string) { e.Notes = append(e.Notes, Note{Level: level, Text: text}) }

	if e.NXDomain {
		add("warn", "This name does not exist (NXDOMAIN), so there is no mail setup to check.")
		return
	}

	var dmarcPolicy string
	var dmarcPct int
	var dmarcPctOK, dmarcFull bool
	if e.DMARC != nil {
		dmarcPolicy = e.DMARC.Applied()
		dmarcPct, dmarcPctOK = e.DMARC.pct()
		dmarcFull = dmarcPctOK && dmarcPct == 100
	}

	if e.SPF == nil {
		if e.HasMX {
			add("fail", "No SPF record. Receivers have no way to know which servers may send mail as this domain.")
		}
	} else {
		if len(e.SPF.Extra) > 0 {
			all := append([]string{e.SPF.Record}, e.SPF.Extra...)
			add("fail", fmt.Sprintf("This domain publishes %d SPF records: %s. RFC 7208 makes more than one a permerror, so receivers evaluate none of them and SPF fails for every message. Merge them into one record.", len(all), `"`+strings.Join(all, `" and "`)+`"`))
		}
		if e.SPF.Lookups > e.SPF.Limit {
			add("fail", fmt.Sprintf("SPF needs %d DNS lookups but RFC 7208 allows %d. Over the limit receivers return permerror and SPF fails for every message, silently. Flatten or remove includes.", e.SPF.Lookups, e.SPF.Limit))
		} else if e.SPF.Lookups == e.SPF.Limit {
			add("warn", fmt.Sprintf("SPF uses all %d allowed DNS lookups: any further include will break it.", e.SPF.Limit))
		} else if e.SPF.Lookups >= 8 {
			add("warn", fmt.Sprintf("SPF uses %d of the %d allowed DNS lookups. Adding one more provider is likely to break it.", e.SPF.Lookups, e.SPF.Limit))
		} else {
			add("ok", fmt.Sprintf("SPF uses %d of the %d allowed DNS lookups.", e.SPF.Lookups, e.SPF.Limit))
		}
		if n := len(e.SPF.Voids); n > 0 {
			level, lead := "warn", "SPF points at names that resolve to nothing"
			if n > e.SPF.VoidLimit {
				level = "fail"
				lead = fmt.Sprintf("SPF points at %d names that resolve to nothing, and RFC 7208 lets a receiver give up after %d", n, e.SPF.VoidLimit)
			}
			add(level, lead+": "+strings.Join(e.SPF.Voids, ", ")+". Usually a provider that has been left in the record after it was dropped.")
		}
		switch e.SPF.All {
		case "+all":
			add("fail", "SPF ends in +all, which authorises the entire internet to send as this domain. That is strictly worse than having no SPF at all.")
		case "?all":
			add("warn", "SPF ends in ?all (neutral), which asserts nothing. Receivers treat it much like no policy.")
		case "~all":
			add("ok", "SPF ends in ~all (softfail), the common setting alongside DMARC.")
		case "-all":
			add("ok", "SPF ends in -all (hard fail), the strict setting.")
		}
	}

	if e.DMARC == nil {
		if e.HasMX {
			add("fail", "No DMARC record. Without one, SPF and DKIM results are advisory and nobody is told what to do with failures.")
		}
	} else {
		if len(e.DMARC.Extra) > 0 {
			add("fail", fmt.Sprintf("%s publishes %d DMARC records. RFC 7489 has receivers discard the lot rather than pick one, so the policy is not applied at all.", e.DMARC.Name, len(e.DMARC.Extra)+1))
		}
		if e.DMARC.Inherited {
			add("info", "This name publishes no DMARC record of its own, so receivers apply "+e.DMARC.Name+"'s, as RFC 7489 says they should. The DMARC findings here are about that inherited policy.")
		}
		switch dmarcPolicy {
		case "none":
			add("warn", "DMARC is published but the policy is none, so failing mail is still delivered. It collects reports and protects nothing until you move to quarantine or reject.")
		case "quarantine", "reject":
			landing := "goes to spam"
			if dmarcPolicy == "reject" {
				landing = "is refused outright"
			}
			switch {
			case dmarcFull:
				add("ok", "DMARC p="+dmarcPolicy+": failing mail "+landing+".")
			case dmarcPctOK:
				add("warn", fmt.Sprintf("DMARC is p=%s but pct=%d, so only %d%% of failing mail %s; RFC 7489 gives the other %d%% the next weaker policy (%s). Move to pct=100 once the reports look clean.", dmarcPolicy, dmarcPct, dmarcPct, landing, 100-dmarcPct, nextLower(dmarcPolicy)))
			default:
				add("warn", "DMARC pct= is \""+e.DMARC.Percent+"\", which is not a percentage. Receivers that reject the tag may discard the whole record, so the policy protects nothing.")
			}
		default:
			add("warn", "DMARC record has no usable p= policy tag, so receivers treat it as p=none at best.")
		}
		// On an inherited record sp= is the policy judged above, not an exemption from it.
		if !e.DMARC.Inherited && e.DMARC.SubPolicy == "none" && e.DMARC.Policy != "none" {
			add("warn", "DMARC sets sp=none, so the strong policy above applies to this domain only: every subdomain is unprotected and can still be spoofed.")
		}
		if e.DMARC.Aggregate == "" {
			add("warn", "DMARC has no rua= address, so you receive no aggregate reports and cannot see who is sending as you.")
		}
	}

	if !e.HasMX && (e.SPF == nil || e.DMARC == nil) {
		missing := "SPF or DMARC record"
		switch {
		case e.SPF != nil:
			missing = "DMARC record"
		case e.DMARC != nil:
			missing = "SPF record"
		}
		add("info", "This domain publishes no MX record and no "+missing+", so nothing tells a receiver to refuse mail forged in its name. If it sends no mail, v=spf1 -all and a DMARC record with p=reject say so.")
	}

	if e.NullMX {
		if e.SPF != nil && e.SPF.All == "-all" && dmarcPolicy == "reject" {
			add("ok", "This domain publishes a null MX (RFC 7505), SPF -all and DMARC p=reject: it declares that it neither sends nor receives mail.")
		} else {
			add("info", "This domain publishes a null MX (RFC 7505), so it is telling every sender that it receives no mail. If it sends none either, the matching declarations are v=spf1 -all and DMARC p=reject.")
		}
	}

	var badPTR, unresolved []string
	for _, m := range e.MailHosts {
		switch {
		case m.IP == "":
			unresolved = append(unresolved, m.Host)
		case !m.FCrDNS:
			badPTR = append(badPTR, m.Host)
		}
	}
	if len(unresolved) > 0 {
		add("fail", "These mail hosts don't resolve to an address at all: "+strings.Join(unresolved, ", ")+". Mail to this domain cannot be delivered to them.")
	}
	if len(e.MailHosts) > 0 {
		scope, partial := "every mail host", ""
		if e.MXCount > len(e.MailHosts) {
			scope = fmt.Sprintf("the %d of %d mail hosts a sender tries first", len(e.MailHosts), e.MXCount)
			partial = fmt.Sprintf(" Only %s were checked.", scope)
		}
		if len(badPTR) > 0 {
			add("warn", "Reverse DNS doesn't round-trip for "+strings.Join(badPTR, ", ")+". Receivers weigh forward-confirmed reverse DNS on the address mail arrives from, so this costs deliverability for any mail these servers send, without anything else looking wrong."+partial)
		} else if len(unresolved) == 0 {
			add("ok", "Reverse DNS round-trips (FCrDNS) for "+scope+", checked on each host's first address.")
		}
	}

	switch {
	case e.DKIMWildcard && len(e.DKIM) == 0:
		add("ok", "Every selector probed returns a DKIM record with an empty key: a wildcard under _domainkey that revokes every selector without a record of its own. That is the recommended setup for a domain that sends no mail; a selector you do sign with needs its own record.")
	case e.DKIMWildcard:
		add("warn", "Every selector probed returns the same DKIM record, so there is a wildcard TXT under _domainkey. Any selector a sender invents will appear to be published, which tells a receiver nothing.")
	case len(e.DKIM) > 0:
		var sels []string
		for _, k := range e.DKIM {
			sels = append(sels, k.Selector)
		}
		add("ok", "DKIM keys found at common selectors: "+strings.Join(sels, ", ")+".")
	case e.HasMX:
		add("info", "No DKIM key at the common selectors. DNS can't list selectors, so that is not proof there is none.")
	}
	if len(e.DKIMRevoked) > 0 && !e.DKIMWildcard {
		add("warn", "These selectors publish a revoked key (an empty p=): "+strings.Join(e.DKIMRevoked, ", ")+". Nothing signed with them can verify, so drop the records once no mail still carries those signatures.")
	}

	if e.MTASTS != nil {
		switch {
		case !e.MTASTS.Fetched:
			add("fail", "MTA-STS is advertised in DNS but the policy file could not be fetched ("+e.MTASTS.PolicyError+"). Senders that honour MTA-STS will ignore the policy entirely.")
		case !e.MTASTS.PolicyFound:
			add("fail", "MTA-STS is advertised in DNS and the policy file is served, but it isn't a usable policy: "+e.MTASTS.PolicyError+". Senders that honour MTA-STS will ignore it entirely.")
		case e.MTASTS.Mode == "enforce":
			add("ok", "MTA-STS policy is live and in enforce mode.")
		case e.MTASTS.Mode == "testing":
			add("info", "MTA-STS policy is in testing mode: failures are reported, but senders still deliver when TLS fails, so it protects nothing yet.")
		case e.MTASTS.Mode == "none":
			add("warn", "MTA-STS policy mode is none, which switches the policy off. Senders will not enforce TLS.")
		}
		if e.MTASTS.PolicyFound && e.MTASTS.Mode != "none" {
			var uncovered []string
			for _, h := range e.MailHosts {
				if !slices.ContainsFunc(e.MTASTS.MX, func(p string) bool { return policyCovers(p, h.Host) }) {
					uncovered = append(uncovered, h.Host)
				}
			}
			switch {
			case len(uncovered) == 0 && len(e.MailHosts) > 0:
				add("ok", "Every mail host checked is listed in the MTA-STS policy.")
			case len(uncovered) > 0 && e.MTASTS.Mode == "enforce":
				add("fail", "These MX hosts are not listed in the MTA-STS policy: "+strings.Join(uncovered, ", ")+". A sender in enforce mode refuses to deliver to them.")
			case len(uncovered) > 0:
				add("warn", "These MX hosts are not listed in the MTA-STS policy: "+strings.Join(uncovered, ", ")+". In testing mode that only generates reports, but it would block delivery under enforce.")
			}
		}
	}

	if e.BIMI != "" {
		const noLogo = " so no mailbox provider will ever display the logo. The BIMI record is doing nothing."
		switch {
		case e.DMARC == nil:
			add("fail", "BIMI is published but the domain has no DMARC record at all,"+noLogo)
		case dmarcPolicy != "quarantine" && dmarcPolicy != "reject":
			applied := "p=" + dmarcPolicy
			if dmarcPolicy == "" {
				applied = "not set at all"
			}
			add("fail", "BIMI is published but the DMARC policy that applies here is "+applied+", not quarantine or reject,"+noLogo)
		case e.DMARC.SubPolicy == "none":
			add("fail", "BIMI is published and DMARC is strong, but sp=none exempts every subdomain,"+noLogo+" Set sp= to match p=.")
		case !dmarcFull:
			add("fail", "BIMI is published but DMARC pct="+e.DMARC.Percent+" covers only part of the mail, and BIMI requires the policy to apply to all of it,"+noLogo)
		default:
			add("ok", "BIMI is published and the DMARC policy behind it is strong enough for it to be used.")
		}
	}
	sortNotes(e.Notes)
}

// Score counts findings by level; deliberately not a grade out of 100.
func (e *EmailAuth) Score() (ok, warn, fail int) {
	for _, n := range e.Notes {
		switch n.Level {
		case "ok":
			ok++
		case "warn":
			warn++
		case "fail":
			fail++
		}
	}
	return
}
