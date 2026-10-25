package mailtools

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// SPFAnalysis contains recursive SPF include resolution, 10-lookup limit evaluation, and syntax checks.
type SPFAnalysis struct {
	Record    string   `json:"record"`
	Lookups   int      `json:"lookups"`
	Limit     int      `json:"limit"` // RFC 7208 limit: 10
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
	Record    string   `json:"record"`
	Policy    string   `json:"policy"`
	SubPolicy string   `json:"sub_policy,omitempty"`
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

// EmailAuthSummary holds published SPF, DMARC, DKIM, and MTA-STS/TLSRPT intelligence.
type EmailAuthSummary struct {
	HasSPF      bool            `json:"has_spf"`
	SPFRecord   string          `json:"spf_record,omitempty"`
	SPF         *SPFAnalysis    `json:"spf,omitempty"`
	HasDMARC    bool            `json:"has_dmarc"`
	DMARCRecord string          `json:"dmarc_record,omitempty"`
	DMARCPolicy string          `json:"dmarc_policy,omitempty"` // reject, quarantine, none, missing
	DMARC       *DMARCAnalysis  `json:"dmarc,omitempty"`
	DKIM        *DKIMAnalysis   `json:"dkim,omitempty"`
	MTASTS      *MTASTSAnalysis `json:"mta_sts,omitempty"`
}

// Common DKIM selectors across major ESPs and email suites.
var commonDKIMSelectors = []string{
	"google", "k1", "default", "s1", "mail", "selector1",
	"k2", "s2", "smtp", "dkim", "2023", "2024", "mailjet",
	"mandrill", "zoho", "cm", "scph",
}

const maxSPFIncludes = 15

// AuditEmailAuth performs a comprehensive, concurrent audit of a domain's email authentication.
func AuditEmailAuth(ctx context.Context, domain string, guard *platform.EgressGuard) *EmailAuthSummary {
	domain = ExtractDomain(domain)
	summary := &EmailAuthSummary{}

	var wg sync.WaitGroup
	wg.Add(4)

	// 1. SPF Check with deep recursive include resolution & lookup counter
	go func() {
		defer wg.Done()
		summary.SPF = checkSPF(ctx, domain)
		if summary.SPF != nil {
			summary.HasSPF = true
			summary.SPFRecord = summary.SPF.Record
		}
	}()

	// 2. DMARC Check with apex parent climb and tag parsing
	go func() {
		defer wg.Done()
		summary.DMARC = checkDMARC(ctx, domain)
		if summary.DMARC != nil {
			summary.HasDMARC = true
			summary.DMARCRecord = summary.DMARC.Record
			summary.DMARCPolicy = summary.DMARC.Policy
		}
	}()

	// 3. DKIM Selectors Discovery
	go func() {
		defer wg.Done()
		summary.DKIM = checkDKIM(ctx, domain)
	}()

	// 4. MTA-STS & TLSRPT
	go func() {
		defer wg.Done()
		summary.MTASTS = checkMTASTS(ctx, domain, guard)
	}()

	wg.Wait()
	return summary
}

// checkSPF resolves SPF records recursively, tracking the 10-lookup limit (RFC 7208 §4.6.4).
func checkSPF(ctx context.Context, domain string) *SPFAnalysis {
	r := &net.Resolver{}
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		return nil
	}

	var spfRecs []string
	for _, txt := range txts {
		trimmed := strings.TrimSpace(txt)
		if strings.HasPrefix(trimmed, "v=spf1") {
			spfRecs = append(spfRecs, trimmed)
		}
	}

	if len(spfRecs) == 0 {
		return nil
	}

	res := &SPFAnalysis{
		Record: spfRecs[0],
		Limit:  10,
	}
	if len(spfRecs) > 1 {
		res.Extra = spfRecs[1:]
	}

	onPath := map[string]bool{strings.ToLower(domain): true}
	queries := 0

	var cost func(rec string) int
	cost = func(rec string) int {
		toks := strings.Fields(rec)
		hasAll := slices.ContainsFunc(toks, func(tok string) bool {
			name, _ := spfTerm(tok)
			return name == "all"
		})

		n := 0
		for _, tok := range toks {
			name, target := spfTerm(tok)
			switch {
			case name == "a", name == "mx", name == "ptr", name == "exists":
				n++
			case name == "include", name == "redirect" && !hasAll:
				n++
				key := strings.ToLower(target)
				if target == "" {
					continue
				}
				if onPath[key] {
					res.Loop = true
					continue
				}
				if queries >= maxSPFIncludes || ctx.Err() != nil {
					res.Truncated = true
					continue
				}
				queries++
				if !slices.Contains(res.Chain, target) {
					res.Chain = append(res.Chain, target)
				}
				if strings.Contains(target, "%{") {
					continue
				}

				subTxts, subErr := r.LookupTXT(ctx, target)
				var subRecs []string
				if subErr == nil {
					for _, st := range subTxts {
						stTrim := strings.TrimSpace(st)
						if strings.HasPrefix(stTrim, "v=spf1") {
							subRecs = append(subRecs, stTrim)
						}
					}
				}
				if len(subRecs) == 0 {
					res.Voids = append(res.Voids, target)
				} else {
					onPath[key] = true
					n += cost(subRecs[0])
					delete(onPath, key)
				}
			}
		}
		return n
	}

	res.Lookups = cost(res.Record)

	for _, tok := range strings.Fields(res.Record) {
		switch strings.ToLower(tok) {
		case "all", "+all":
			res.All = "+all"
		case "-all", "~all", "?all":
			res.All = strings.ToLower(tok)
		}
	}

	// Status determination
	switch {
	case res.Loop:
		res.Status = "fail"
		res.StatusMsg = "Loop detected in SPF includes"
	case len(res.Extra) > 0:
		res.Status = "fail"
		res.StatusMsg = "Multiple SPF records published (RFC 7208 Permerror)"
	case res.Lookups > 10:
		res.Status = "fail"
		res.StatusMsg = fmt.Sprintf("Exceeds RFC 7208 10 DNS lookup limit (%d lookups) - Permerror", res.Lookups)
	case len(res.Voids) > 2:
		res.Status = "fail"
		res.StatusMsg = fmt.Sprintf("Too many void lookups (%d void domains)", len(res.Voids))
	case res.Lookups >= 8:
		res.Status = "warn"
		res.StatusMsg = fmt.Sprintf("Near 10-lookup limit (%d / 10 lookups used)", res.Lookups)
	case res.All == "+all":
		res.Status = "fail"
		res.StatusMsg = "Permissive '+all' authorizes anyone on the internet to send mail"
	case res.All == "?all":
		res.Status = "warn"
		res.StatusMsg = "Neutral '?all' does not instruct receivers to fail unauthorized mail"
	case res.All == "-all":
		res.Status = "pass"
		res.StatusMsg = fmt.Sprintf("Strict fail (-all) with %d of 10 DNS lookups used", res.Lookups)
	case res.All == "~all":
		res.Status = "pass"
		res.StatusMsg = fmt.Sprintf("Soft fail (~all) with %d of 10 DNS lookups used", res.Lookups)
	default:
		res.Status = "pass"
		res.StatusMsg = fmt.Sprintf("%d of 10 DNS lookups used", res.Lookups)
	}

	return res
}

func spfTerm(tok string) (name, target string) {
	t := strings.TrimLeft(tok, "+-~?")
	name = t
	if i := strings.IndexAny(t, ":="); i >= 0 {
		name, target = t[:i], t[i+1:]
	}
	name, _, _ = strings.Cut(name, "/")
	return strings.ToLower(name), target
}

// checkDMARC queries _dmarc.<domain> and climbs up to parent domains if missing (RFC 7489 §6.6.3).
func checkDMARC(ctx context.Context, domain string) *DMARCAnalysis {
	r := &net.Resolver{}
	name := domain

	for range 4 {
		at := "_dmarc." + name
		txts, err := r.LookupTXT(ctx, at)
		if err == nil {
			var recs []string
			for _, txt := range txts {
				tr := strings.TrimSpace(txt)
				if strings.HasPrefix(tr, "v=DMARC1") {
					recs = append(recs, tr)
				}
			}
			if len(recs) > 0 {
				tags := parseAuthTags(recs[0])
				res := &DMARCAnalysis{
					Record:    recs[0],
					Inherited: name != domain,
					Policy:    strings.ToLower(tags["p"]),
					SubPolicy: strings.ToLower(tags["sp"]),
					Percent:   tags["pct"],
					Aggregate: tags["rua"],
					Forensic:  tags["ruf"],
				}
				if len(recs) > 1 {
					res.Extra = recs[1:]
					res.Status = "fail"
					res.StatusMsg = "Multiple DMARC records published (RFC 7489 Permerror: receivers ignore all)"
					return res
				}

				switch res.Policy {
				case "reject":
					res.Status = "pass"
					res.StatusMsg = "Strict Reject policy (p=reject): unauthorized mail is blocked"
				case "quarantine":
					res.Status = "pass"
					res.StatusMsg = "Quarantine policy (p=quarantine): unauthorized mail is routed to spam"
				case "none":
					res.Status = "warn"
					res.StatusMsg = "Monitoring only (p=none): unauthorized senders are not blocked"
				default:
					res.Status = "warn"
					res.StatusMsg = fmt.Sprintf("DMARC policy: %s", res.Policy)
				}
				return res
			}
		}

		_, parent, ok := strings.Cut(name, ".")
		if !ok || !strings.Contains(parent, ".") {
			break
		}
		name = parent
	}

	return nil
}

func parseAuthTags(rec string) map[string]string {
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
	r := &net.Resolver{}
	analysis := &DKIMAnalysis{}

	recs := make([]string, len(commonDKIMSelectors))
	var wg sync.WaitGroup
	wg.Add(len(commonDKIMSelectors))

	for i, sel := range commonDKIMSelectors {
		go func(idx int, selector string) {
			defer wg.Done()
			qDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
			txts, err := r.LookupTXT(ctx, qDomain)
			if err == nil {
				for _, txt := range txts {
					tr := strings.TrimSpace(txt)
					if strings.Contains(tr, "p=") || strings.HasPrefix(tr, "v=DKIM1") {
						recs[idx] = tr
						break
					}
				}
			}
		}(i, sel)
	}
	wg.Wait()

	for i, rec := range recs {
		if rec == "" {
			continue
		}
		tags := parseAuthTags(rec)
		if tags["p"] != "" {
			analysis.FoundSelectors = append(analysis.FoundSelectors, DKIMSelectorInfo{
				Selector: commonDKIMSelectors[i],
				Record:   rec,
				Status:   "active",
			})
		} else {
			analysis.Revoked = append(analysis.Revoked, commonDKIMSelectors[i])
		}
	}

	if len(recs) > 1 && recs[0] != "" {
		allSame := true
		for _, rec := range recs {
			if rec != recs[0] {
				allSame = false
				break
			}
		}
		if allSame {
			analysis.Wildcard = true
		}
	}

	if len(analysis.FoundSelectors) > 0 {
		analysis.Status = "pass"
		names := make([]string, len(analysis.FoundSelectors))
		for i, sel := range analysis.FoundSelectors {
			names[i] = sel.Selector
		}
		analysis.StatusMsg = fmt.Sprintf("%d active selector(s) discovered (%s)", len(analysis.FoundSelectors), strings.Join(names, ", "))
	} else if analysis.Wildcard {
		analysis.Status = "warn"
		analysis.StatusMsg = "Wildcard DKIM record detected (*._domainkey)"
	} else {
		analysis.Status = "info"
		analysis.StatusMsg = "No common public selectors discovered"
	}

	return analysis
}

// checkMTASTS inspects _mta-sts.<domain> and fetches policy over HTTPS.
func checkMTASTS(ctx context.Context, domain string, guard *platform.EgressGuard) *MTASTSAnalysis {
	r := &net.Resolver{}
	res := &MTASTSAnalysis{}

	txts, err := r.LookupTXT(ctx, "_mta-sts."+domain)
	if err == nil {
		for _, txt := range txts {
			tr := strings.TrimSpace(txt)
			if strings.HasPrefix(tr, "v=STSv1") {
				res.RecordFound = true
				res.Record = tr
				break
			}
		}
	}

	// Also check TLSRPT record
	tlsTxts, tlsErr := r.LookupTXT(ctx, "_smtp._tls."+domain)
	if tlsErr == nil {
		for _, txt := range tlsTxts {
			tr := strings.TrimSpace(txt)
			if strings.HasPrefix(tr, "v=TLSRPTv1") {
				res.TLSRPT = tr
				break
			}
		}
	}

	if !res.RecordFound {
		res.Status = "info"
		res.StatusMsg = "MTA-STS not configured"
		return res
	}

	// Fetch policy over HTTPS
	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 3 * time.Second}
	if guard != nil {
		client.Transport = guard.Transport(3 * time.Second)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, policyURL, nil)
	if err == nil {
		resp, fetchErr := client.Do(req)
		if fetchErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
				res.PolicyFound = true
				for _, line := range strings.Split(string(bodyBytes), "\n") {
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
			} else {
				res.PolicyError = fmt.Sprintf("HTTP %d from policy file", resp.StatusCode)
			}
		} else {
			res.PolicyError = fetchErr.Error()
		}
	}

	if res.PolicyFound {
		if res.Mode == "enforce" {
			res.Status = "pass"
			res.StatusMsg = "Strict TLS enforcement enabled (mode=enforce)"
		} else if res.Mode == "testing" {
			res.Status = "warn"
			res.StatusMsg = "MTA-STS in testing mode"
		} else {
			res.Status = "warn"
			res.StatusMsg = fmt.Sprintf("MTA-STS mode: %s", res.Mode)
		}
	} else {
		res.Status = "warn"
		res.StatusMsg = "MTA-STS DNS record found, but policy file unreachable"
	}

	return res
}
