package dnstools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Email authentication: SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI.
//
// This is the most common real-world DNS problem and almost all of it is
// TXT records with conventions layered on top, so the value is entirely in
// parsing and judging them, not in fetching them.
//
// The checks here are the ones reports/email-dns-checkers.md rates as the
// silent failure modes: SPF's 10-lookup limit (exceeding it makes SPF fail
// *for everyone*, invisibly), DMARC published but set to do nothing, and BIMI
// that can never display because the DMARC policy behind it is too weak.

// EmailAuth: the whole email-authentication picture for one domain.
type EmailAuth struct {
	Domain string `json:"domain"`

	SPF    *SPFResult    `json:"spf,omitempty"`
	DMARC  *DMARCResult  `json:"dmarc,omitempty"`
	DKIM   []DKIMKey     `json:"dkim,omitempty"`
	MTASTS *MTASTSResult `json:"mta_sts,omitempty"`
	TLSRPT string        `json:"tls_rpt,omitempty"`
	BIMI   string        `json:"bimi,omitempty"`
	HasMX  bool          `json:"has_mx"`
	// MailHosts: the MX hosts with their forward-confirmed reverse DNS result.
	// Receivers weigh FCrDNS heavily, and a mail server whose PTR doesn't
	// round-trip gets scored down without anything in DNS looking wrong.
	MailHosts []MailHost `json:"mail_hosts,omitempty"`
	// MXCount: how many MX records the domain publishes, which is not always
	// len(MailHosts) — the FCrDNS fan-out stops at maxMailHosts, and a verdict
	// that says "every mail host" after checking five of eight is a lie.
	MXCount int `json:"mx_count,omitempty"`
	// DKIMRevoked: selectors answering with an empty p=, i.e. a key that has
	// been revoked (RFC 6376 §3.6.1). Published, and useless for signing.
	DKIMRevoked []string `json:"dkim_revoked,omitempty"`
	// DKIMWildcard: every probed selector returned the same record, so the
	// zone has a wildcard TXT under _domainkey and the selector list below
	// says nothing about which selectors exist.
	DKIMWildcard bool   `json:"dkim_wildcard,omitempty"`
	Notes        []Note `json:"notes,omitempty"`
	QueryMS      int64  `json:"query_ms"`
}

// Note: one finding, severity-tagged. "ok" states a thing is right, because a
// checker that only ever speaks up to complain teaches nothing.
type Note struct {
	Level string `json:"level"` // ok | warn | fail | info
	Text  string `json:"text"`
}

// SPFResult: the record plus the thing that actually breaks in production.
type SPFResult struct {
	Record string `json:"record"`
	// Lookups: how many DNS-lookup-consuming mechanisms this record costs when
	// fully expanded. RFC 7208 caps it at 10; over that, receivers return
	// permerror and SPF fails for every message, silently.
	Lookups int `json:"lookups"`
	Limit   int `json:"limit"`
	// Truncated: we stopped resolving includes at the cap. The verdict still
	// holds (already past the limit), but the chain shown is partial.
	Truncated bool     `json:"truncated,omitempty"`
	All       string   `json:"all,omitempty"` // -all, ~all, ?all, +all
	Chain     []string `json:"chain,omitempty"`
	// Extra: further v=spf1 records at the apex. Two or more is a permerror
	// (RFC 7208 §4.5) whichever of them looks right, so the count is the
	// finding and picking one to grade would hide it.
	Extra []string `json:"extra_records,omitempty"`
	// Voids: include/redirect targets that answered NXDOMAIN or nothing.
	// RFC 7208 §4.6.4 lets a receiver give up after VoidLimit of these. A
	// lower bound: a, mx and exists terms are counted but never resolved.
	Voids     []string `json:"void_lookups,omitempty"`
	VoidLimit int      `json:"void_limit,omitempty"`
}

// DMARCResult: the policy, and whether it does anything.
type DMARCResult struct {
	Record string `json:"record"`
	// Name: where the record was actually published. Not always
	// _dmarc.<domain>: a subdomain with no record of its own inherits its
	// organizational domain's, and saying "no DMARC" there is simply false.
	Name      string `json:"name,omitempty"`
	Inherited bool   `json:"inherited,omitempty"`
	Policy    string `json:"policy"`               // p=
	SubPolicy string `json:"sub_policy,omitempty"` // sp=
	Percent   string `json:"percent,omitempty"`
	Aggregate string `json:"aggregate,omitempty"` // rua=
	Forensic  string `json:"forensic,omitempty"`  // ruf=
	// Extra: further v=DMARC1 records at the same name, which RFC 7489 §6.6.3
	// makes unusable rather than ambiguous — receivers discard the lot.
	Extra []string `json:"extra_records,omitempty"`
}

// Applied is the policy a receiver applies to the name that was asked about.
// An inherited record governs subdomains through sp= when it sets one
// (RFC 7489 §6.6.3), so the p= on the parent is not the answer by itself.
func (d *DMARCResult) Applied() string {
	if d.Inherited && d.SubPolicy != "" {
		return d.SubPolicy
	}
	return d.Policy
}

// pct reads the pct= tag, which is 100 when absent. The second return is
// false for a value that isn't a percentage at all — receivers may drop the
// whole record over it, so it cannot be silently treated as full coverage.
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

// nextLower is what RFC 7489 §6.3 applies to the mail a partial pct= doesn't
// select: the policy one step weaker, not nothing at all.
func nextLower(policy string) string {
	switch policy {
	case "reject":
		return "quarantine"
	case "quarantine":
		return "none"
	}
	return "none"
}

// MailHost: one MX host and whether its reverse DNS round-trips.
//
// Forward-confirmed reverse DNS = IP -> PTR -> forward -> back to the same IP.
// It is the cheapest signal a receiver has that a sending host is what it
// claims, so failing it costs deliverability quietly.
type MailHost struct {
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	PTR    string `json:"ptr,omitempty"`
	FCrDNS bool   `json:"fcrdns"`
}

// maxMailHosts bounds the FCrDNS fan-out: each host costs three queries, four
// when the A lookup comes back empty and the AAAA fallback runs.
const maxMailHosts = 5

// DKIMKey: a selector that actually resolved. Selectors cannot be enumerated
// from DNS, so these come from guessing common ones — always labelled as a
// guess, never as an inventory.
type DKIMKey struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
}

// MTASTSResult: the two-protocol check. The TXT record only says a policy
// exists; the policy itself lives behind HTTPS, and most tools stop at the TXT.
type MTASTSResult struct {
	Record string `json:"record"`
	// Fetched: the policy file came back over HTTPS at all. Separate from
	// PolicyFound because "the file isn't there" and "the file is there and
	// isn't a policy" have different fixes, and one note used to claim both.
	Fetched     bool     `json:"fetched"`
	PolicyFound bool     `json:"policy_found"`
	Mode        string   `json:"mode,omitempty"`
	MX          []string `json:"mx,omitempty"`
	MaxAge      string   `json:"max_age,omitempty"`
	Version     string   `json:"version,omitempty"`
	PolicyError string   `json:"policy_error,omitempty"`
}

// commonDKIMSelectors: what providers actually use. A guess list, not an
// enumeration — DNS gives no way to list selectors.
//
// Kept deliberately short: every entry is one upstream query on every check,
// and one page view already costs a couple of dozen. The long tail of rare
// selectors is not worth the fan-out.
var commonDKIMSelectors = []string{
	"google", "selector1", "selector2", "k1", "k2",
	"dkim", "default", "mail", "s1", "zoho", "sendgrid", "amazonses",
}

// maxSPFIncludes bounds how many includes the counter will resolve.
//
// Correctness is unaffected: the only question is whether the record exceeds
// the RFC 7208 limit of 10, so once we have resolved comfortably past 10 the
// answer is settled and further queries buy nothing. Without this, a record
// with deeply nested includes turns one click into unbounded DNS traffic.
const maxSPFIncludes = 15

// EmailAuth runs every check concurrently.
func (s *Service) EmailAuth(ctx context.Context, domain string) (*EmailAuth, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, ErrEmptyName
	}
	if _, isIP := reverseName(domain); isIP {
		return nil, fmt.Errorf("%w: give a domain name, not an IP", ErrBadType)
	}
	if err := validDomain(domain); err != nil {
		return nil, err
	}
	addr, _ := resolverAddr(DefaultResolver)
	out := &EmailAuth{Domain: domain}

	var wg sync.WaitGroup
	var mu sync.Mutex
	run := func(f func()) { wg.Add(1); go safe(func() { defer wg.Done(); f() }) }

	var mxErr error
	run(func() {
		r, err := s.lookup(ctx, dnsFqdn(domain), "MX", addr)
		mxErr = err
		hosts := s.checkMailHosts(ctx, r.Records, addr)
		mu.Lock()
		out.HasMX = len(r.Records) > 0
		out.MXCount = len(r.Records)
		out.MailHosts = hosts
		mu.Unlock()
	})
	run(func() {
		spf := s.checkSPF(ctx, domain, addr)
		mu.Lock()
		out.SPF = spf
		mu.Unlock()
	})
	run(func() {
		d := s.checkDMARC(ctx, domain, addr)
		mu.Lock()
		out.DMARC = d
		mu.Unlock()
	})
	run(func() {
		keys, revoked, wildcard := s.checkDKIM(ctx, domain, addr)
		mu.Lock()
		out.DKIM, out.DKIMRevoked, out.DKIMWildcard = keys, revoked, wildcard
		mu.Unlock()
	})
	run(func() {
		m := s.checkMTASTS(ctx, domain, addr)
		mu.Lock()
		out.MTASTS = m
		mu.Unlock()
	})
	run(func() {
		v := s.firstTXT(ctx, dnsFqdn("_smtp._tls."+domain), addr, "v=TLSRPTv1")
		mu.Lock()
		out.TLSRPT = v
		mu.Unlock()
	})
	run(func() {
		v := s.firstTXT(ctx, dnsFqdn("default._bimi."+domain), addr, "v=BIMI1")
		mu.Lock()
		out.BIMI = v
		mu.Unlock()
	})
	wg.Wait()

	// A failed query is not evidence of absence. Without this an unreachable
	// resolver rendered as "No SPF record", i.e. a positive factual claim the
	// data does not support — the one thing this tool must never do.
	if mxErr != nil && !errors.Is(mxErr, errNoData) && !errors.Is(mxErr, errNXDomain) {
		out.Notes = append([]Note{{
			Level: "warn",
			Text:  "At least one DNS query failed while checking this domain, so anything reported as missing below may simply not have been reachable. Re-run before acting on it.",
		}}, out.Notes...)
	}
	out.judge()
	return out, nil
}

// checkSPF resolves the record and walks its includes, counting the lookups
// each level costs. The count is the whole point: a record can look perfect
// and still fail for everyone because it needs eleven lookups.
//
// It fetches the apex TXT set itself rather than asking for one match, because
// a second v=spf1 record is not a tie to break: RFC 7208 §4.5 makes it a
// permerror, and grading whichever one came back first hides that.
func (s *Service) checkSPF(ctx context.Context, domain, addr string) *SPFResult {
	recs, _ := s.matchingTXT(ctx, dnsFqdn(domain), addr, "v=spf1")
	if len(recs) == 0 {
		return nil
	}
	rec := recs[0]
	r := &SPFResult{Record: rec, Extra: recs[1:], Limit: 10, VoidLimit: 2}

	w := &spfWalk{
		// The domain being checked starts on the path, so a record that
		// includes itself is a loop from the first term rather than the second.
		inProgress: map[string]bool{spfKey(domain): true},
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

// spfWalk is the state of one SPF evaluation.
//
// inProgress is path-local — a name is added before recursing into it and
// removed afterwards — because RFC 7208 counts *evaluations*, not distinct
// names: the same include reached down two branches is evaluated twice and
// costs twice. Only a name already on the current path is a loop. memo holds
// the cost of a sub-tree that was walked to completion, so paying for it twice
// costs arithmetic rather than a second round of queries.
type spfWalk struct {
	inProgress map[string]bool
	memo       map[string]int
	seen       map[string]bool // chain de-dup: display, never counting
	chain      []string
	voids      []string
	truncated  bool
	// steps counts every entry into the walk, memoised or not, and is the only
	// bound that holds when memoisation cannot help. A sub-tree containing an
	// include loop or a depth cut is deliberately not memoised (its cost is not
	// a fixed number), so without this a crafted include graph is re-walked on
	// every path that reaches it and the cost is branching^depth. A published
	// 9-record graph measured 899 million expansions and 3m40s of CPU on a
	// single request before this existed.
	steps int
}

// maxSPFSteps caps total expansions per evaluation. Far above anything a real
// record needs (the RFC caps the answer at 10 lookups), far below anything
// that costs noticeable CPU.
const maxSPFSteps = 500

// maxSPFDepth stops a chain of includes that is legal but absurd; the RFC's
// own limit of 10 lookups is passed long before this bites.
const maxSPFDepth = 10

// spfKey normalises a target for the walk's maps. DNS is case-insensitive and
// a trailing dot is the same name, so two spellings must not be two entries.
func spfKey(target string) string {
	return strings.ToLower(strings.TrimSuffix(target, "."))
}

// spfTerm splits one term into its mechanism or modifier name and its target.
// RFC 7208 §4.6.1 makes the names case-insensitive, so they are lowercased
// here; the target keeps the case it was published with. A bare a or mx may
// carry a CIDR suffix ("a/24") that is not part of the name.
func spfTerm(tok string) (name, target string) {
	t := strings.TrimLeft(tok, "+-~?")
	name = t
	if i := strings.IndexAny(t, ":="); i >= 0 {
		name, target = t[:i], t[i+1:]
	}
	name, _, _ = strings.Cut(name, "/")
	return strings.ToLower(name), target
}

// countSPFLookups returns what evaluating one record costs, and whether that
// cost is complete enough to memoise: a walk cut short by the budget, the
// depth guard or a loop is only the cost *on this path*.
func (s *Service) countSPFLookups(ctx context.Context, rec, addr string, w *spfWalk, depth int) (int, bool) {
	// Abandon the walk when the caller has gone away: this loop is the most
	// expensive thing one request can ask for, so it must not outlive it.
	if ctx.Err() != nil {
		w.truncated = true
		return 0, false
	}
	w.steps++
	if w.steps > maxSPFSteps {
		w.truncated = true
		return 0, false
	}
	if depth > maxSPFDepth {
		w.truncated = true
		return 0, false
	}
	toks := strings.Fields(rec)

	// RFC 7208 §6.1: redirect= MUST be ignored when the record has an all
	// mechanism. The rule is per record, so it is decided again at every
	// level rather than once for the whole tree.
	redirectApplies := true
	for _, tok := range toks {
		if name, _ := spfTerm(tok); name == "all" {
			redirectApplies = false
			break
		}
	}

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
			key := spfKey(target)
			if w.inProgress[key] {
				// The term is charged; re-entering it would not terminate.
				exact = false
				continue
			}
			if cost, ok := w.memo[key]; ok {
				n += cost
				continue
			}
			// Budget reached: the record is already past the limit, so the
			// verdict cannot change. Stop spending queries to confirm it.
			if len(w.chain) >= maxSPFIncludes {
				w.truncated, exact = true, false
				continue
			}
			if !w.seen[key] {
				w.seen[key] = true
				w.chain = append(w.chain, target)
			}
			// A macro target (RFC 7208 §7) is expanded per message from the
			// sender's identity, so the literal text is a name that cannot
			// resolve. Querying it would invent a void lookup no receiver sees.
			if strings.Contains(target, "%{") {
				continue
			}
			sub, void := s.spfRecord(ctx, target, addr)
			if void {
				w.voids = append(w.voids, target)
			}
			if sub == "" {
				w.memo[key] = 0
				continue
			}
			w.inProgress[key] = true
			cost, complete := s.countSPFLookups(ctx, sub, addr, w, depth+1)
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

// spfRecord fetches the SPF record at target, reporting separately that the
// name resolved to nothing at all — RFC 7208 §4.6.4 counts those against their
// own small limit, and a name with TXT records but no v=spf1 is not one.
func (s *Service) spfRecord(ctx context.Context, target, addr string) (rec string, void bool) {
	recs, void := s.matchingTXT(ctx, dnsFqdn(target), addr, "v=spf1")
	if len(recs) == 0 {
		return "", void
	}
	return recs[0], false
}

// checkMailHosts resolves each MX host and confirms its reverse DNS closes the
// loop: IP -> PTR -> forward -> same IP.
func (s *Service) checkMailHosts(ctx context.Context, mx []Record, addr string) []MailHost {
	var out []MailHost
	for _, rec := range mx {
		if len(out) >= maxMailHosts {
			break
		}
		// MX rdata is "priority host."; the host is the last field.
		parts := strings.Fields(rec.Value)
		if len(parts) == 0 {
			continue
		}
		host := strings.TrimSuffix(parts[len(parts)-1], ".")
		if host == "" || host == "." {
			continue // null MX (RFC 7505): this domain sends/receives no mail
		}
		h := MailHost{Host: host}

		// AAAA is a fallback rather than a second lookup on every host: an
		// IPv6-only MX is rare, but reporting one as unresolved makes the
		// verdict say mail cannot be delivered when it can.
		fwd, err := s.lookup(ctx, dnsFqdn(host), "A", addr)
		if err != nil || len(fwd.Records) == 0 {
			fwd, err = s.lookup(ctx, dnsFqdn(host), "AAAA", addr)
		}
		if err != nil || len(fwd.Records) == 0 {
			out = append(out, h)
			continue
		}
		h.IP = fwd.Records[0].Value

		rev, ok := reverseName(h.IP)
		if !ok {
			out = append(out, h)
			continue
		}
		ptr, err := s.lookup(ctx, rev, "PTR", addr)
		if err != nil || len(ptr.Records) == 0 {
			out = append(out, h)
			continue
		}
		h.PTR = strings.TrimSuffix(ptr.Records[0].Value, ".")

		// Close the loop: the PTR name must resolve back to the same address,
		// asked for the family the address is in.
		fwdType := "A"
		if strings.Contains(h.IP, ":") {
			fwdType = "AAAA"
		}
		back, err := s.lookup(ctx, dnsFqdn(h.PTR), fwdType, addr)
		if err == nil {
			for _, b := range back.Records {
				if b.Value == h.IP {
					h.FCrDNS = true
					break
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// checkDMARC finds the policy a receiver would actually apply to this name.
// RFC 7489 §6.6.3 falls back to the organizational domain when the name itself
// publishes nothing, so a subdomain of a protected domain is protected too and
// answering "no DMARC record" there states the opposite of the truth.
//
// Without a public-suffix list the climb cannot tell an organizational domain
// from a suffix that delegates names to strangers, so the result always says
// which name the record was found at rather than presenting it as this one's.
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

// maxDMARCParents bounds the climb. Two labels above the name asked about is
// well past any organizational domain in practice, and every step is a query.
const maxDMARCParents = 3

// parentDomain drops the leftmost label, refusing to go higher than a name
// with two labels. Without a public-suffix list that is the honest floor:
// climbing further asks a registry suffix for a policy it cannot publish.
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
		// RFC 7489 writes the tag names as ABNF quoted strings, which
		// RFC 5234 §2.3 makes case-insensitive: "P=reject" is a valid record.
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "p":
			d.Policy = strings.ToLower(strings.TrimSpace(v))
		case "sp":
			d.SubPolicy = strings.ToLower(strings.TrimSpace(v))
		case "pct":
			d.Percent = strings.TrimSpace(v)
		case "rua":
			d.Aggregate = strings.TrimSpace(v)
		case "ruf":
			d.Forensic = strings.TrimSpace(v)
		}
	}
	return d
}

// checkDKIM probes common selectors. Explicitly a guess: DNS offers no way to
// list the selectors a domain uses, so absence here proves nothing.
//
// Presence proves less than it looks, too, which is why the two qualifiers
// come back with it: a record with an empty p= is a revoked key, and a zone
// with a wildcard TXT under _domainkey answers for every selector ever probed.
func (s *Service) checkDKIM(ctx context.Context, domain, addr string) (keys []DKIMKey, revoked []string, wildcard bool) {
	// Written at a fixed index rather than appended, so the selector list is
	// the order of commonDKIMSelectors and not the order goroutines finished.
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
	// Twelve unrelated selectors answering with one record is a wildcard, not
	// twelve keys: no zone publishes the same key under every provider's name.
	wildcard = len(recs) > 1 && recs[0] != "" && !slices.ContainsFunc(recs, func(r string) bool { return r != recs[0] })
	return keys, revoked, wildcard
}

// dkimHasKey reports whether a DKIM record carries a public key. An empty p=
// is a revoked key (RFC 6376 §3.6.1): published, and unable to verify anything.
func dkimHasKey(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && strings.EqualFold(strings.TrimSpace(k), "p") {
			return strings.TrimSpace(v) != ""
		}
	}
	return false
}

// checkMTASTS does both halves: the TXT pointer, then the policy file itself
// over HTTPS. Stopping at the TXT is the common shortcut, and it misses a
// policy that is missing, malformed, or listing the wrong MX hosts.
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
		// RFC 8461 §3.2 field names are ABNF quoted strings, so they are
		// case-insensitive; a "Mode: Enforce" policy is valid and used to be
		// reported as unfetchable.
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
	// A policy file is only a policy if it says so, and RFC 8461 §3.2 makes
	// all four of these mandatory. Without the version and mode checks a
	// wildcard vhost returning HTML counted as a valid published policy;
	// without the other two an enforce policy that no sender can satisfy did.
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

// mtaSTSTransport carries the one outbound HTTP request this package makes.
//
// The address is attacker-chosen: any domain can publish a _mta-sts TXT and
// point mta-sts.<domain> wherever it likes, and the reply is reflected back
// into the page. So the dial is gated on the resolved address being publicly
// routable — without that the fetch is a probe into whatever this container
// can reach, and gating at dial time rather than on the hostname closes the
// rebinding window between the two.
var mtaSTSTransport http.RoundTripper = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialPublicOnly,
	}).DialContext,
	MaxIdleConns:        4,
	IdleConnTimeout:     30 * time.Second,
	TLSHandshakeTimeout: 5 * time.Second,
}

func dialPublicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	// Control runs after resolution, so this is always a literal.
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing to connect to %q", address)
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("refusing to fetch a policy from %s: not a public address", ip)
	}
	return nil
}

func (s *Service) fetchPolicy(ctx context.Context, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", domainUserAgent)
	// A copy, so the gated transport and the no-redirect rule apply to this
	// fetch without changing the client the rest of the package shares.
	client := *s.http
	client.Transport = mtaSTSTransport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("policy file unreachable")
	}
	defer resp.Body.Close()
	// RFC 8461 §3.3: a redirect MUST NOT be followed, so it is the reason the
	// policy is unusable rather than a step on the way to fetching it.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", fmt.Errorf("policy file redirects (%d), which RFC 8461 forbids", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("policy file returned %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return "", fmt.Errorf("policy file is served as %s, and RFC 8461 requires text/plain", ct)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return string(b), err
}

// policyCovers reports whether an MTA-STS mx pattern matches a mail host.
// RFC 8461 §3.2 allows a single leading wildcard label, and only that.
func policyCovers(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		_, rest, found := strings.Cut(host, ".")
		return found && rest == suffix
	}
	return pattern == host
}

// matchingTXT returns every TXT record at name starting with prefix, with the
// multi-string parts joined as the spec requires, plus whether the name
// answered nothing at all.
//
// Both extras exist because two callers need more than the first match: a
// second SPF or DMARC record is a permerror rather than a tie to break, and
// names that resolve to nothing have their own limit. A SERVFAIL is neither —
// it means "couldn't find out", not "isn't published".
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

// judge turns the raw records into findings. Every note says what to do, not
// just what is wrong.
func (e *EmailAuth) judge() {
	add := func(level, text string) { e.Notes = append(e.Notes, Note{Level: level, Text: text}) }

	// The DMARC policy that applies here, read once: BIMI is judged against
	// the same answer further down, and the two used to disagree.
	var dmarcPolicy string
	var dmarcPct int
	var dmarcPctOK, dmarcFull bool
	if e.DMARC != nil {
		dmarcPolicy = e.DMARC.Applied()
		dmarcPct, dmarcPctOK = e.DMARC.pct()
		dmarcFull = dmarcPctOK && dmarcPct == 100
	}

	switch {
	case e.SPF == nil && e.HasMX:
		add("fail", "No SPF record. Receivers have no way to know which servers may send mail as this domain.")
	case e.SPF == nil:
		add("info", "No SPF record, and no MX either, so this domain probably isn't used for mail.")
	default:
		if len(e.SPF.Extra) > 0 {
			all := append([]string{e.SPF.Record}, e.SPF.Extra...)
			add("fail", fmt.Sprintf("This domain publishes %d SPF records: %s. RFC 7208 makes more than one a permerror, so receivers evaluate none of them and SPF fails for every message. Merge them into one record.", len(all), `"`+strings.Join(all, `" and "`)+`"`))
		}
		if e.SPF.Lookups > e.SPF.Limit {
			add("fail", fmt.Sprintf("SPF needs %d DNS lookups but RFC 7208 allows %d. Over the limit receivers return permerror and SPF fails for every message, silently. Flatten or remove includes.", e.SPF.Lookups, e.SPF.Limit))
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
			add("ok", "SPF ends in ~all (softfail), the normal setting while you gain confidence.")
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
			add("info", "This name publishes no DMARC record of its own, so receivers apply "+e.DMARC.Name+"'s, as RFC 7489 says they should. The verdict below is that inherited policy.")
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
				add("warn", fmt.Sprintf("DMARC is p=%s but pct=%d, so only that share of failing mail %s. RFC 7489 gives the rest the next weaker policy (%s), which is what most of your spoofed mail actually meets. Move to pct=100 once the reports look clean.", dmarcPolicy, dmarcPct, landing, nextLower(dmarcPolicy)))
			default:
				add("warn", "DMARC pct= is \""+e.DMARC.Percent+"\", which is not a percentage. Receivers that reject the tag may discard the whole record, so the policy protects nothing.")
			}
		default:
			add("warn", "DMARC record has no usable p= policy tag.")
		}
		// Only for a record read at its own name: on an inherited one, sp= is
		// the policy judged above rather than an exemption from it.
		if !e.DMARC.Inherited && e.DMARC.SubPolicy == "none" && e.DMARC.Policy != "none" {
			add("warn", "DMARC sets sp=none, so the strong policy above applies to this domain only: every subdomain is unprotected and can still be spoofed.")
		}
		if e.DMARC.Aggregate == "" {
			add("warn", "DMARC has no rua= address, so you receive no aggregate reports and cannot see who is sending as you.")
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
		// Which hosts the verdict covers, said out loud: the fan-out stops at
		// maxMailHosts, and "every mail host" after five of eight is a lie.
		scope, partial := "every mail host", ""
		if e.MXCount > len(e.MailHosts) {
			scope = fmt.Sprintf("the first %d of %d mail hosts", len(e.MailHosts), e.MXCount)
			partial = fmt.Sprintf(" Only %s were checked.", scope)
		}
		if len(badPTR) > 0 {
			add("warn", "Reverse DNS doesn't round-trip for "+strings.Join(badPTR, ", ")+". Receivers weigh forward-confirmed reverse DNS when scoring mail, so this costs deliverability without anything else looking wrong."+partial)
		} else if len(unresolved) == 0 {
			add("ok", "Reverse DNS round-trips (FCrDNS) for "+scope+", which receivers treat as a trust signal. Only each host's first address is checked.")
		}
	}

	switch {
	case e.DKIMWildcard:
		add("warn", "Every selector probed returns the same DKIM record, so there is a wildcard TXT under _domainkey. Any selector a sender invents will appear to be published, which tells a receiver nothing.")
	case len(e.DKIM) > 0:
		var sels []string
		for _, k := range e.DKIM {
			sels = append(sels, k.Selector)
		}
		add("ok", "DKIM keys found at common selectors: "+strings.Join(sels, ", ")+".")
	case e.HasMX:
		add("info", "No DKIM key found at any common selector. Selectors cannot be listed from DNS, so this is a guess, not proof there is none.")
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
			add("info", "MTA-STS policy is in testing mode: failures are reported but mail still flows unencrypted.")
		case e.MTASTS.Mode == "none":
			add("warn", "MTA-STS policy mode is none, which switches the policy off. Senders will not enforce TLS.")
		}
		// The policy's mx list against the MX the domain actually publishes:
		// a host missing from the policy is refused by every sender honouring
		// it, and nothing in DNS looks wrong.
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

	// One record judged against another, which is the thing plain dig can't do.
	if e.BIMI != "" {
		// BIMI needs the policy to actually apply: a strong p, subdomains not
		// let off via sp=none, and full coverage rather than a partial pct.
		// Which of those failed is the whole content of the finding.
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
}

// Score is a crude readiness count: how many findings are clean versus not.
// Deliberately not a grade out of 100 — the corpus is clear that a single
// number invites arguing with the number instead of fixing the finding.
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
