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
	// NullMX: every MX targets "." (RFC 7505), so the domain takes no mail though HasMX is true.
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
	rank := func(n Note) int { return slices.Index([]string{"fail", "warn", "info", "ok"}, n.Level) }
	slices.SortStableFunc(notes, func(a, b Note) int { return rank(a) - rank(b) })
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

// MailHost is one MX host and whether IP -> PTR -> forward lands back on the same IP.
type MailHost struct {
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	PTR    string `json:"ptr,omitempty"`
	FCrDNS bool   `json:"fcrdns"`
}

// maxMailHosts bounds the per-host fan-out (3-4 queries each); the reputation card shares it, so both cover the same servers.
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

// maxSPFIncludes caps the include queries; each one is a term already charged, so the cap is past the limit.
const maxSPFIncludes = 15

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
	if err := needDomain(domain); err != nil {
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
		out.NXDomain = errors.Is(err, errNXDomain)
		out.HasMX, out.MXCount = len(r.Records) > 0, len(r.Records)
		out.MailHosts, out.NullMX = s.checkMailHosts(ctx, r.Records, addr)
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
		out.Notes = append(out.Notes, Note{Level: "warn",
			Text: "At least one DNS query failed while checking this domain, so anything reported as missing below may simply not have been reachable. Re-run before acting on it."})
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
	r := &SPFResult{Record: recs[0], Extra: recs[1:], Limit: 10, VoidLimit: 2}
	// The checked domain starts on the path, so a self-include is a loop at once.
	onPath := map[string]bool{bareName(domain): true}
	queries := 0

	// cost charges every evaluation (RFC 7208 §4.6.4): an include reached twice costs twice.
	var cost func(rec string) int
	cost = func(rec string) int {
		toks := strings.Fields(rec)
		// RFC 7208 §6.1: redirect= is ignored when this record has an all mechanism.
		hasAll := slices.ContainsFunc(toks, func(tok string) bool { name, _ := spfTerm(tok); return name == "all" })
		n := 0
		for _, tok := range toks {
			name, target := spfTerm(tok)
			switch {
			case name == "a", name == "mx", name == "ptr", name == "exists":
				n++
			case name == "include", name == "redirect" && !hasAll:
				n++
				key := bareName(target)
				if target == "" || onPath[key] {
					continue
				}
				if queries >= maxSPFIncludes || ctx.Err() != nil {
					r.Truncated = true
					continue
				}
				queries++
				if !slices.Contains(r.Chain, target) {
					r.Chain = append(r.Chain, target)
				}
				// A macro target (RFC 7208 §7) expands per message; querying it would invent a void.
				if strings.Contains(target, "%{") {
					continue
				}
				subs, void := s.matchingTXT(ctx, dnsFqdn(target), addr, "v=spf1")
				if void {
					r.Voids = append(r.Voids, target)
				}
				if len(subs) > 0 {
					onPath[key] = true
					n += cost(subs[0])
					delete(onPath, key)
				}
			}
		}
		return n
	}
	r.Lookups = cost(r.Record)

	for _, tok := range strings.Fields(r.Record) {
		switch strings.ToLower(tok) {
		case "all", "+all":
			r.All = "+all" // a bare all carries an implicit "+": anyone may send
		case "-all", "~all", "?all":
			r.All = strings.ToLower(tok)
		}
	}
	return r
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

func (s *Service) checkMailHosts(ctx context.Context, mx []Record, addr string) ([]MailHost, bool) {
	hosts, nullMX, _ := mailHosts(mx)
	var out []MailHost
	for _, h := range hosts[:min(len(hosts), maxMailHosts)] {
		out = append(out, s.probeMailHost(ctx, h.host, addr))
	}
	return out, nullMX
}

// probeMailHost tries AAAA only as a fallback, so an IPv6-only MX doesn't read as unresolved.
func (s *Service) probeMailHost(ctx context.Context, host, addr string) MailHost {
	h := MailHost{Host: host}
	for _, qtype := range []string{"A", "AAAA"} {
		fwd, err := s.lookup(ctx, dnsFqdn(host), qtype, addr)
		if err != nil || len(fwd.Records) == 0 {
			continue
		}
		h.IP = fwd.Records[0].Value
		rev, _ := reverseName(h.IP)
		ptr, err := s.lookup(ctx, rev, "PTR", addr)
		if err != nil || len(ptr.Records) == 0 {
			return h
		}
		h.PTR = strings.TrimSuffix(ptr.Records[0].Value, ".")
		back, err := s.lookup(ctx, dnsFqdn(h.PTR), qtype, addr)
		h.FCrDNS = err == nil && slices.ContainsFunc(back.Records, func(b Record) bool { return b.Value == h.IP })
		return h
	}
	return h
}

// maxMXPref sorts an MX whose preference can't be read after every one whose can.
const maxMXPref = 1 << 16

// mxPref reads the preference from MX rdata ("10 mail.example.com.").
func mxPref(rdata string) int {
	pref, _, _ := strings.Cut(rdata, " ")
	n, err := strconv.Atoi(pref)
	if err != nil {
		return maxMXPref
	}
	return n
}

type mxTarget struct {
	host string
	pref int
}

// mailHosts sorts by preference before any cap, so the checked subset doesn't rotate.
// nullMX: no target but "." (RFC 7505); conflict: "." beside real hosts, which §3 forbids.
func mailHosts(recs []Record) (hosts []mxTarget, nullMX, conflict bool) {
	byPref := slices.Clone(recs)
	slices.SortStableFunc(byPref, func(a, b Record) int { return mxPref(a.Value) - mxPref(b.Value) })

	var dot bool
	for _, rec := range byPref {
		switch h := mxHost(rec.Value); h {
		case "":
		case ".":
			dot = true
		default:
			hosts = append(hosts, mxTarget{host: h, pref: mxPref(rec.Value)})
		}
	}
	return hosts, dot && len(hosts) == 0, dot && len(hosts) > 0
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

// checkDMARC climbs to a parent when the name publishes no record (RFC 7489 §6.6.3). With no
// PSL it stops at two labels, the honest floor.
func (s *Service) checkDMARC(ctx context.Context, domain, addr string) *DMARCResult {
	name := domain
	for range 4 { // the name, then up to three parents
		at := "_dmarc." + name
		if recs, _ := s.matchingTXT(ctx, dnsFqdn(at), addr, "v=DMARC1"); len(recs) > 0 {
			t := tagList(recs[0])
			return &DMARCResult{Record: recs[0], Name: at, Inherited: name != domain, Extra: recs[1:],
				Policy: strings.ToLower(t["p"]), SubPolicy: strings.ToLower(t["sp"]),
				Percent: t["pct"], Aggregate: t["rua"], Forensic: t["ruf"]}
		}
		_, parent, _ := strings.Cut(name, ".")
		if !strings.Contains(parent, ".") {
			return nil
		}
		name = parent
	}
	return nil
}

// tagList reads a DMARC or DKIM "k=v; k=v" record. Tag names are case-insensitive: "P=reject" is valid.
func tagList(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// checkDKIM probes common selectors, reporting revoked keys and a wildcard apart from keys.
func (s *Service) checkDKIM(ctx context.Context, domain, addr string) (keys []DKIMKey, revoked []string, wildcard bool) {
	// Indexed, not appended: selector-list order, not goroutine completion order.
	recs := make([]string, len(commonDKIMSelectors))
	fanOut(len(commonDKIMSelectors), 6, func(i int) {
		recs[i] = s.firstTXT(ctx, dnsFqdn(commonDKIMSelectors[i]+"._domainkey."+domain), addr, "v=DKIM1")
	})

	for i, rec := range recs {
		switch {
		case rec == "":
		case tagList(rec)["p"] != "":
			keys = append(keys, DKIMKey{Selector: commonDKIMSelectors[i], Found: true})
		default:
			revoked = append(revoked, commonDKIMSelectors[i])
		}
	}
	// One record under every unrelated selector is a wildcard, not twelve keys.
	wildcard = recs[0] != "" && !slices.ContainsFunc(recs, func(r string) bool { return r != recs[0] })
	return keys, revoked, wildcard
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
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		// RFC 8461 §3.2 field names are case-insensitive: "Mode: Enforce" is valid.
		switch strings.ToLower(strings.TrimSpace(k)) {
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
	// RFC 8461 §3.2 makes all four mandatory (max_age at most a year); a wildcard vhost serving HTML must not pass.
	age, ageErr := strconv.Atoi(m.MaxAge)
	switch {
	case !strings.EqualFold(m.Version, "STSv1"):
		m.PolicyError = "the file at that URL has no version: STSv1 line, so it is not an MTA-STS policy"
	case !slices.Contains([]string{"enforce", "testing", "none"}, m.Mode), ageErr != nil, age < 1, age > 31557600:
		m.PolicyError = "the policy's mode: or max_age: line is missing or invalid"
	case m.Mode != "none" && len(m.MX) == 0:
		m.PolicyError = "the policy lists no mx hosts, so a sender in " + m.Mode + " mode has nothing to match a server against"
	default:
		m.PolicyFound = true
	}
	return m
}

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
		return "", fmt.Errorf("policy file is served as %s, and RFC 8461 requires text/plain", platform.Clip(ct, 100))
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
	if errors.Is(err, errNXDomain) || errors.Is(err, errNoData) {
		return nil, true
	}
	for _, rec := range r.Records {
		v := strings.Trim(strings.ReplaceAll(rec.Value, `" "`, ""), `"`)
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			recs = append(recs, v)
		}
	}
	return recs, false
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

// judge turns the records into findings; every note says what to do, not just what is wrong.
func (e *EmailAuth) judge() {
	add := func(level, text string) { e.Notes = append(e.Notes, Note{Level: level, Text: text}) }

	if e.NXDomain {
		add("warn", "This name does not exist (NXDOMAIN), so there is no mail setup to check.")
		return
	}

	// policy is what applies to this name: sp= on an inherited record (RFC 7489 §6.6.3).
	policy, allMail := "", false
	if d := e.DMARC; d != nil {
		policy = d.Policy
		if d.Inherited && d.SubPolicy != "" {
			policy = d.SubPolicy
		}
		pct, err := strconv.Atoi(d.Percent)
		allMail = d.Percent == "" || (err == nil && pct == 100)
	}

	if spf := e.SPF; spf == nil {
		if e.HasMX {
			add("fail", "No SPF record. Receivers have no way to know which servers may send mail as this domain.")
		}
	} else {
		if len(spf.Extra) > 0 {
			all := append([]string{spf.Record}, spf.Extra...)
			add("fail", fmt.Sprintf("This domain publishes %d SPF records: %s. RFC 7208 makes more than one a permerror, so receivers evaluate none of them and SPF fails for every message. Merge them into one record.", len(all), `"`+strings.Join(all, `" and "`)+`"`))
		}
		switch {
		case spf.Lookups > spf.Limit:
			add("fail", fmt.Sprintf("SPF needs %d DNS lookups but RFC 7208 allows %d. Over the limit receivers return permerror and SPF fails for every message, silently. Flatten or remove includes.", spf.Lookups, spf.Limit))
		case spf.Lookups >= 8:
			add("warn", fmt.Sprintf("SPF uses %d of the %d allowed DNS lookups. Adding one more provider is likely to break it.", spf.Lookups, spf.Limit))
		default:
			add("ok", fmt.Sprintf("SPF uses %d of the %d allowed DNS lookups.", spf.Lookups, spf.Limit))
		}
		if len(spf.Voids) > 0 {
			level := "warn"
			if len(spf.Voids) > spf.VoidLimit {
				level = "fail"
			}
			add(level, fmt.Sprintf("SPF points at names that resolve to nothing: %s. RFC 7208 lets a receiver fail SPF past %d of these. Usually a provider left in the record after it was dropped.", strings.Join(spf.Voids, ", "), spf.VoidLimit))
		}
		switch spf.All {
		case "+all":
			add("fail", "SPF ends in +all, which authorises the entire internet to send as this domain. That is strictly worse than having no SPF at all.")
		case "?all":
			add("warn", "SPF ends in ?all (neutral), which asserts nothing. Receivers treat it much like no policy.")
		case "~all", "-all":
			add("ok", "SPF ends in "+spf.All+", so mail from servers it doesn't list fails SPF.")
		}
	}

	if d := e.DMARC; d == nil {
		if e.HasMX {
			add("fail", "No DMARC record. Without one, SPF and DKIM results are advisory and nobody is told what to do with failures.")
		}
	} else {
		if len(d.Extra) > 0 {
			add("fail", fmt.Sprintf("%s publishes %d DMARC records. RFC 7489 has receivers discard the lot rather than pick one, so the policy is not applied at all. Keep one.", d.Name, len(d.Extra)+1))
		}
		if d.Inherited {
			add("info", "This name publishes no DMARC record of its own, so receivers apply "+d.Name+"'s, as RFC 7489 says they should. The DMARC findings here are about that inherited policy.")
		}
		switch {
		case policy == "none":
			add("warn", "DMARC is published but the policy is none, so failing mail is still delivered. It collects reports and protects nothing until you move to quarantine or reject.")
		case policy != "quarantine" && policy != "reject":
			add("warn", "DMARC record has no usable p= policy tag, so receivers treat it as p=none at best.")
		case !allMail:
			add("warn", "DMARC is p="+policy+" but pct="+d.Percent+", so the policy does not cover all failing mail. Move to pct=100 once the reports look clean.")
		default:
			add("ok", "DMARC p="+policy+": receivers keep failing mail out of the inbox.")
		}
		// On an inherited record sp= is the policy judged above, not an exemption from it.
		if !d.Inherited && d.SubPolicy == "none" && d.Policy != "none" {
			add("warn", "DMARC sets sp=none, so the strong policy above applies to this domain only: every subdomain is unprotected and can still be spoofed.")
		}
		if d.Aggregate == "" {
			add("warn", "DMARC has no rua= address, so you receive no aggregate reports and cannot see who is sending as you.")
		}
	}

	if !e.HasMX && (e.SPF == nil || e.DMARC == nil) {
		add("info", "This domain publishes no MX record and lacks SPF or DMARC, so nothing tells a receiver to refuse mail forged in its name. If it sends no mail, v=spf1 -all and a DMARC record with p=reject say so.")
	}
	if e.NullMX {
		add("info", "This domain publishes a null MX (RFC 7505), so it is telling every sender that it receives no mail. If it sends none either, the matching declarations are v=spf1 -all and DMARC p=reject.")
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
	scope := "every mail host"
	if e.MXCount > len(e.MailHosts) {
		scope = fmt.Sprintf("the %d of %d mail hosts a sender tries first", len(e.MailHosts), e.MXCount)
	}
	switch {
	case len(unresolved) > 0:
		add("fail", "These mail hosts don't resolve to an address at all: "+strings.Join(unresolved, ", ")+". Mail to this domain cannot be delivered to them.")
	case len(badPTR) == 0 && len(e.MailHosts) > 0:
		add("ok", "Reverse DNS round-trips (FCrDNS) for "+scope+", checked on each host's first address.")
	}
	if len(badPTR) > 0 {
		add("warn", "Reverse DNS doesn't round-trip for "+strings.Join(badPTR, ", ")+". Receivers weigh forward-confirmed reverse DNS on the address mail arrives from, so this costs deliverability for any mail these servers send, without anything else looking wrong.")
	}

	switch {
	case e.DKIMWildcard && len(e.DKIM) == 0:
		add("ok", "Every selector probed returns a DKIM record with an empty key: a wildcard under _domainkey that revokes every selector without a record of its own. That is the recommended setup for a domain that sends no mail; a selector you do sign with needs its own record.")
	case e.DKIMWildcard:
		add("warn", "Every selector probed returns the same DKIM record, so there is a wildcard TXT under _domainkey. Any selector a sender invents will appear to be published, which tells a receiver nothing.")
	case len(e.DKIM) > 0:
		add("ok", fmt.Sprintf("DKIM keys found at %d of the common selectors tried.", len(e.DKIM)))
	case e.HasMX:
		add("info", "No DKIM key at the common selectors. DNS can't list selectors, so that is not proof there is none.")
	}
	if len(e.DKIMRevoked) > 0 && !e.DKIMWildcard {
		add("warn", "These selectors publish a revoked key (an empty p=): "+strings.Join(e.DKIMRevoked, ", ")+". Nothing signed with them can verify, so drop the records once no mail still carries those signatures.")
	}

	if m := e.MTASTS; m != nil {
		switch {
		case !m.PolicyFound:
			add("fail", "MTA-STS is advertised in DNS but its policy can't be used ("+m.PolicyError+"). Senders that honour MTA-STS will ignore it entirely.")
		case m.Mode == "enforce":
			add("ok", "MTA-STS policy is live and in enforce mode.")
		case m.Mode == "testing":
			add("info", "MTA-STS policy is in testing mode: failures are reported, but senders still deliver when TLS fails, so it protects nothing yet.")
		default:
			add("warn", "MTA-STS policy mode is none, which switches the policy off. Senders will not enforce TLS.")
		}
		var uncovered []string
		for _, h := range e.MailHosts {
			if !slices.ContainsFunc(m.MX, func(p string) bool { return policyCovers(p, h.Host) }) {
				uncovered = append(uncovered, h.Host)
			}
		}
		switch {
		case !m.PolicyFound || m.Mode == "none" || len(e.MailHosts) == 0:
		case len(uncovered) == 0:
			add("ok", "Every mail host checked is listed in the MTA-STS policy.")
		case m.Mode == "enforce":
			add("fail", "These MX hosts are not listed in the MTA-STS policy: "+strings.Join(uncovered, ", ")+". A sender in enforce mode refuses to deliver to them.")
		default:
			add("warn", "These MX hosts are not listed in the MTA-STS policy: "+strings.Join(uncovered, ", ")+". In testing mode that only generates reports, but it would block delivery under enforce.")
		}
	}

	if e.BIMI != "" {
		if (policy == "quarantine" || policy == "reject") && allMail && e.DMARC.SubPolicy != "none" {
			add("ok", "BIMI is published and the DMARC policy behind it is strong enough for it to be used.")
		} else {
			add("fail", "BIMI is published but DMARC does not apply quarantine or reject to all mail (pct=100, no sp=none), so no mailbox provider will display the logo. Strengthen DMARC first.")
		}
	}
	sortNotes(e.Notes)
}

// Score counts findings by level; deliberately not a grade out of 100.
func (e *EmailAuth) Score() (ok, warn, fail int) {
	n := map[string]int{}
	for _, note := range e.Notes {
		n[note.Level]++
	}
	return n["ok"], n["warn"], n["fail"]
}
