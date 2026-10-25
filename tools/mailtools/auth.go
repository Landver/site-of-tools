package mailtools

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// SPFAnalysis contains recursive SPF include resolution, 10-lookup limit evaluation, and syntax checks.
type SPFAnalysis struct {
	Record    string   `json:"record"` // empty: no SPF record
	Lookups   int      `json:"lookups"`
	Limit     int      `json:"limit"`
	All       string   `json:"all,omitempty"` // -all, ~all, ?all, +all
	Chain     []string `json:"chain,omitempty"`
	Extra     []string `json:"extra_records,omitempty"`
	Voids     []string `json:"void_lookups,omitempty"`
	Loop      bool     `json:"loop,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Status    string   `json:"status"` // "pass", "warn", "fail"
	StatusMsg string   `json:"status_msg"`
}

// DMARCAnalysis contains DMARC policy parsing, parent inheritance, and alignment directives.
type DMARCAnalysis struct {
	Record    string `json:"record"` // empty: no DMARC record
	Policy    string `json:"policy"`
	SubPolicy string `json:"sub_policy,omitempty"`
	// Effective is the policy receivers apply to the domain checked: sp= on an inherited record that sets it.
	// Empty when no usable record applies.
	Effective string   `json:"effective_policy,omitempty"`
	Percent   string   `json:"percent,omitempty"`
	Aggregate string   `json:"aggregate,omitempty"`
	Forensic  string   `json:"forensic,omitempty"`
	Extra     []string `json:"extra_records,omitempty"`
	Inherited bool     `json:"inherited,omitempty"`
	Status    string   `json:"status"` // "pass", "warn", "fail"
	StatusMsg string   `json:"status_msg"`
}

// DKIMSelectorInfo describes a discovered DKIM key selector.
type DKIMSelectorInfo struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
	Status   string `json:"status"` // "active", "revoked"
}

// DKIMAnalysis holds probed DKIM selectors and wildcard detection.
type DKIMAnalysis struct {
	FoundSelectors []DKIMSelectorInfo `json:"found_selectors,omitempty"`
	Revoked        []string           `json:"revoked,omitempty"`
	Wildcard       bool               `json:"wildcard,omitempty"`
	Status         string             `json:"status"` // "pass", "warn", "info"
	StatusMsg      string             `json:"status_msg"`
}

// MTASTSAnalysis contains MTA-STS and TLSRPT security policy status.
type MTASTSAnalysis struct {
	RecordFound bool     `json:"record_found"`
	Record      string   `json:"record,omitempty"`
	PolicyFound bool     `json:"policy_found"`
	Mode        string   `json:"mode,omitempty"` // enforce, testing, none
	MaxAge      int      `json:"max_age,omitempty"`
	MXPatterns  []string `json:"mx_patterns,omitempty"`
	TLSRPT      string   `json:"tls_rpt,omitempty"`
	PolicyError string   `json:"policy_error,omitempty"`
	Status      string   `json:"status"` // "pass", "warn", "info"
	StatusMsg   string   `json:"status_msg"`
}

// EmailAuthSummary holds the SPF, DMARC, DKIM and MTA-STS/TLSRPT analyses; each is always present.
type EmailAuthSummary struct {
	SPF    *SPFAnalysis    `json:"spf"`
	DMARC  *DMARCAnalysis  `json:"dmarc"`
	DKIM   *DKIMAnalysis   `json:"dkim"`
	MTASTS *MTASTSAnalysis `json:"mta_sts"`
}

// Common DKIM selectors across major ESPs and email suites.
var commonDKIMSelectors = []string{
	"google", "k1", "default", "s1", "mail", "selector1",
	"k2", "s2", "smtp", "dkim", "2023", "2024", "mailjet",
	"mandrill", "zoho", "cm", "scph",
}

// RFC 7208 §4.6.4 limits; maxSPFIncludes bounds our own work on a hostile include tree.
const (
	spfLookupLimit = 10
	spfVoidLimit   = 2
	maxSPFIncludes = 15
)

// AuditEmailAuth performs a comprehensive, concurrent audit of a domain's email authentication.
func (s *Service) AuditEmailAuth(ctx context.Context, domain string) *EmailAuthSummary {
	domain = ExtractDomain(domain)
	summary := &EmailAuthSummary{}
	var wg sync.WaitGroup
	wg.Go(func() { summary.SPF = checkSPF(ctx, domain) })
	wg.Go(func() { summary.DMARC = checkDMARC(ctx, domain) })
	wg.Go(func() { summary.DKIM = checkDKIM(ctx, domain) })
	wg.Go(func() { summary.MTASTS = s.checkMTASTS(ctx, domain) })
	wg.Wait()
	return summary
}

// lookupTXTWithPrefix returns name's TXT records that start with prefix, ignoring case, trimmed.
func lookupTXTWithPrefix(ctx context.Context, name, prefix string) []string {
	txts, err := net.DefaultResolver.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	pfxLower := strings.ToLower(prefix)
	var matches []string
	for _, txt := range txts {
		tr := strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(tr), pfxLower) {
			matches = append(matches, tr)
		}
	}
	return matches
}

// spfTerm is one term of a record: "~include:_spf.example.com" is {'~', "include", "_spf.example.com"}.
type spfTerm struct {
	qualifier    byte
	name, target string
}

func parseSPF(rec string) []spfTerm {
	fields := strings.Fields(rec)
	terms := make([]spfTerm, len(fields))
	for i, f := range fields {
		t := spfTerm{qualifier: '+'}
		if strings.ContainsRune("+-~?", rune(f[0])) {
			t.qualifier, f = f[0], f[1:]
		}
		name := f
		if j := strings.IndexAny(f, ":="); j >= 0 {
			name, t.target = f[:j], f[j+1:]
		}
		name, _, _ = strings.Cut(name, "/") // a/24, mx/24
		t.name = strings.ToLower(name)
		terms[i] = t
	}
	return terms
}

// checkSPF resolves SPF records recursively, tracking the 10-lookup limit (RFC 7208 §4.6.4).
func checkSPF(ctx context.Context, domain string) *SPFAnalysis {
	res := &SPFAnalysis{Limit: spfLookupLimit}
	recs := lookupTXTWithPrefix(ctx, domain, "v=spf1")
	if len(recs) == 0 {
		res.Status, res.StatusMsg = "fail", "No SPF record found: publish v=spf1 to authorize your sending IP addresses"
		return res
	}
	res.Record, res.Extra = recs[0], recs[1:]

	onPath := map[string]bool{strings.ToLower(domain): true}
	queries := 0
	var cost func(terms []spfTerm) int
	cost = func(terms []spfTerm) int {
		// A redirect is ignored when the record has an all mechanism (RFC 7208 §6.1).
		hasAll := slices.ContainsFunc(terms, func(t spfTerm) bool { return t.name == "all" })
		n := 0
		for _, t := range terms {
			switch {
			case t.name == "a", t.name == "mx", t.name == "ptr", t.name == "exists":
				n++
			case t.name == "include", t.name == "redirect" && !hasAll:
				n++
				key := strings.ToLower(t.target)
				switch {
				case t.target == "":
				case onPath[key]:
					res.Loop = true
				case queries >= maxSPFIncludes || ctx.Err() != nil:
					res.Truncated = true
				default:
					queries++
					if !slices.Contains(res.Chain, t.target) {
						res.Chain = append(res.Chain, t.target)
					}
					if strings.Contains(t.target, "%{") {
						continue // a macro expands per message: nothing to look up now
					}
					sub := lookupTXTWithPrefix(ctx, t.target, "v=spf1")
					if len(sub) == 0 {
						res.Voids = append(res.Voids, t.target)
						continue
					}
					onPath[key] = true
					n += cost(parseSPF(sub[0]))
					delete(onPath, key)
				}
			}
		}
		return n
	}

	terms := parseSPF(res.Record)
	res.Lookups = cost(terms)
	redirect := false
	for _, t := range terms {
		switch t.name {
		case "all":
			res.All = string(t.qualifier) + "all"
		case "redirect":
			redirect = true
		}
	}
	res.Status, res.StatusMsg = res.verdict(redirect)
	return res
}

// verdict judges a found record by its worst problem.
func (res *SPFAnalysis) verdict(redirect bool) (status, msg string) {
	switch {
	case res.Loop:
		return "fail", "SPF include loop: an include leads back to a record already being evaluated (permerror)"
	case len(res.Extra) > 0:
		return "fail", "Multiple SPF records published (RFC 7208 permerror): merge them into one v=spf1 record"
	case res.Lookups > res.Limit:
		return "fail", fmt.Sprintf("SPF needs %d DNS lookups, over the RFC 7208 limit of %d: receivers return permerror", res.Lookups, res.Limit)
	case len(res.Voids) > spfVoidLimit:
		return "fail", fmt.Sprintf("Too many void lookups: %d includes publish no SPF record, over the RFC 7208 limit of %d", len(res.Voids), spfVoidLimit)
	case res.Lookups >= res.Limit-2:
		return "warn", fmt.Sprintf("Near the lookup limit (%d of %d used): one more include risks a permerror", res.Lookups, res.Limit)
	case res.All == "+all":
		return "fail", "Permissive '+all' authorizes anyone on the internet to send mail as this domain"
	case res.All == "?all":
		return "warn", "Neutral '?all' does not tell receivers to fail unauthorized mail: end the record with ~all or -all"
	case res.All == "-all":
		return "pass", fmt.Sprintf("Strict fail (-all) with %d of %d DNS lookups used", res.Lookups, res.Limit)
	case res.All == "~all":
		return "pass", fmt.Sprintf("Soft fail (~all) with %d of %d DNS lookups used", res.Lookups, res.Limit)
	case redirect:
		return "pass", fmt.Sprintf("%d of %d DNS lookups used (delegated via redirect)", res.Lookups, res.Limit)
	default:
		return "warn", "No terminal all mechanism (-all/~all) or redirect published: unauthorized mail gets a neutral result"
	}
}

// dmarcVerdicts reads each valid policy; %s is the tag it came from, p or sp.
var dmarcVerdicts = map[string]struct{ status, msg string }{
	"reject":     {"pass", "Reject policy (%s=reject): unauthorized mail is blocked"},
	"quarantine": {"pass", "Quarantine policy (%s=quarantine): unauthorized mail is routed to spam"},
	"none":       {"warn", "Monitoring only (%s=none): unauthorized senders are not blocked; move to quarantine or reject"},
}

// checkDMARC queries _dmarc.<domain> and climbs up to parent domains if missing (RFC 7489 §6.6.3).
func checkDMARC(ctx context.Context, domain string) *DMARCAnalysis {
	name := domain
	for range 4 {
		if recs := lookupTXTWithPrefix(ctx, "_dmarc."+name, "v=DMARC1"); len(recs) > 0 {
			return analyzeDMARC(recs, name != domain)
		}
		_, parent, ok := strings.Cut(name, ".")
		if !ok || !strings.Contains(parent, ".") {
			break
		}
		name = parent
	}
	return &DMARCAnalysis{Status: "fail", StatusMsg: "No DMARC record found at _dmarc." + domain + ": publish a DMARC policy to protect the domain from spoofing"}
}

// analyzeDMARC reads the records at one name; inherited means it is a parent of the domain checked.
func analyzeDMARC(recs []string, inherited bool) *DMARCAnalysis {
	tags := parseTXTTags(recs[0])
	res := &DMARCAnalysis{
		Record:    recs[0],
		Policy:    strings.ToLower(tags["p"]),
		SubPolicy: strings.ToLower(tags["sp"]),
		Percent:   tags["pct"],
		Aggregate: tags["rua"],
		Forensic:  tags["ruf"],
		Extra:     recs[1:],
		Inherited: inherited,
	}
	tag, policy := "p", res.Policy
	if inherited && res.SubPolicy != "" {
		tag, policy = "sp", res.SubPolicy
	}
	verdict, valid := dmarcVerdicts[policy]
	switch {
	case len(res.Extra) > 0:
		res.Status, res.StatusMsg = "fail", "Multiple DMARC records published (RFC 7489 permerror): receivers ignore them all, leaving the domain unprotected"
	case res.Policy == "":
		res.Status, res.StatusMsg = "fail", "Syntax error: DMARC record missing mandatory 'p' tag (RFC 7489 §6.3)"
	case !valid:
		res.Status, res.StatusMsg = "fail", fmt.Sprintf("Invalid DMARC policy %s=%s: must be reject, quarantine, or none", tag, policy)
	default:
		res.Effective = policy
		res.Status, res.StatusMsg = verdict.status, fmt.Sprintf(verdict.msg, tag)
	}
	return res
}

// parseTXTTags reads a "k=v; k=v" record (DMARC, DKIM, BIMI) into lowercase keys and trimmed values.
func parseTXTTags(rec string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// checkDKIM probes common selectors in parallel and detects wildcard DNS configurations.
func checkDKIM(ctx context.Context, domain string) *DKIMAnalysis {
	analysis := &DKIMAnalysis{}
	// A key at a made-up selector means *._domainkey answers for every name.
	canary := fmt.Sprintf("probe-wildcard-%d._domainkey.%s", time.Now().UnixNano()%10000, domain)
	analysis.Wildcard = dkimKey(ctx, canary) != ""

	recs := make([]string, len(commonDKIMSelectors))
	var wg sync.WaitGroup
	for i, sel := range commonDKIMSelectors {
		wg.Go(func() { recs[i] = dkimKey(ctx, sel+"._domainkey."+domain) })
	}
	wg.Wait()

	if !analysis.Wildcard {
		for i, rec := range recs {
			if rec == "" {
				continue
			}
			if parseTXTTags(rec)["p"] != "" {
				analysis.FoundSelectors = append(analysis.FoundSelectors, DKIMSelectorInfo{
					Selector: commonDKIMSelectors[i],
					Record:   rec,
					Status:   "active",
				})
			} else {
				analysis.Revoked = append(analysis.Revoked, commonDKIMSelectors[i])
			}
		}
	}

	if analysis.Wildcard {
		analysis.Status = "warn"
		analysis.StatusMsg = "Wildcard DKIM record detected (*._domainkey): all selectors resolve to wildcard key"
	} else if len(analysis.FoundSelectors) > 0 {
		analysis.Status = "pass"
		names := make([]string, len(analysis.FoundSelectors))
		for i, sel := range analysis.FoundSelectors {
			names[i] = sel.Selector
		}
		analysis.StatusMsg = fmt.Sprintf("%d active selector(s) discovered (%s)", len(analysis.FoundSelectors), strings.Join(names, ", "))
	} else {
		analysis.Status = "info"
		analysis.StatusMsg = "No common public selectors discovered"
	}

	return analysis
}

// dkimKey returns the DKIM key record at name; v=DKIM1 is optional, so p= marks one too.
func dkimKey(ctx context.Context, name string) string {
	for _, txt := range lookupTXTWithPrefix(ctx, name, "") {
		if strings.Contains(txt, "p=") || strings.HasPrefix(txt, "v=DKIM1") {
			return txt
		}
	}
	return ""
}

// checkMTASTS reads _mta-sts and _smtp._tls, then fetches the policy over HTTPS through the guard.
func (s *Service) checkMTASTS(ctx context.Context, domain string) *MTASTSAnalysis {
	res := &MTASTSAnalysis{}
	if recs := lookupTXTWithPrefix(ctx, "_mta-sts."+domain, "v=STSv1"); len(recs) > 0 {
		res.RecordFound = true
		res.Record = recs[0]
	}
	if recs := lookupTXTWithPrefix(ctx, "_smtp._tls."+domain, "v=TLSRPTv1"); len(recs) > 0 {
		res.TLSRPT = recs[0]
	}

	if !res.RecordFound {
		res.Status, res.StatusMsg = "info", "MTA-STS not configured: publish a policy (RFC 8461) to stop SMTP downgrade attacks"
		return res
	}

	policy := &url.URL{Scheme: "https", Host: "mta-sts." + domain, Path: "/.well-known/mta-sts.txt"}
	// RFC 8461 §3.2 caps a policy at 64 KB.
	if body, err := s.fetch(ctx, policy, 64*1024); err != nil {
		res.PolicyError = err.Error()
	} else {
		res.PolicyFound = true
		ParseMTASTSPolicy(string(body), res)
	}

	switch {
	case !res.PolicyFound:
		res.Status, res.StatusMsg = "warn", "MTA-STS DNS record found, but policy file unreachable"
	case res.Mode == "enforce":
		res.Status, res.StatusMsg = "pass", "Strict TLS enforcement enabled (mode=enforce)"
	case res.Mode == "testing":
		res.Status, res.StatusMsg = "warn", "MTA-STS in testing mode: switch to mode=enforce once TLS reports are clean"
	default:
		res.Status, res.StatusMsg = "warn", fmt.Sprintf("MTA-STS mode %q does not enforce TLS", res.Mode)
	}
	return res
}

// ParseMTASTSPolicy parses RFC 8461 key-value pairs into the analysis result.
func ParseMTASTSPolicy(body string, res *MTASTSAnalysis) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, ":"); ok {
			val := strings.TrimSpace(v)
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "mode":
				res.Mode = strings.ToLower(val)
			case "max_age":
				var age int
				fmt.Sscanf(val, "%d", &age)
				res.MaxAge = age
			case "mx":
				res.MXPatterns = append(res.MXPatterns, val)
			}
		}
	}
}
