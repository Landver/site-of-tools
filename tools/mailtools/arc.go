package mailtools

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	maxARCInput = 256 << 10
	maxARCHops  = 50 // RFC 8617 §4.2.1
)

// ARCSummary audits only the structure of an Authenticated Received Chain (RFC 8617): no signature
// is verified, so ChainValid means structurally intact and FinalCV is the last hop's self-reported cv.
type ARCSummary struct {
	ChainValid  bool      `json:"chain_valid"`
	ChainLength int       `json:"chain_length"`
	FinalCV     string    `json:"final_chain_validation"` // "pass", "fail", "none"
	Hops        []ARCHop  `json:"hops"`
	Findings    []ARCNote `json:"findings"`
}

// ARCHop represents a single hop (instance i) in the ARC chain.
type ARCHop struct {
	Index          int    `json:"index"` // i=1, 2, ...
	Domain         string `json:"domain"`
	Selector       string `json:"selector"`
	Algorithm      string `json:"algorithm"`
	CV             string `json:"chain_validation"` // "none", "pass", "fail"
	AuthResults    string `json:"auth_results"`
	SPFResult      string `json:"spf_result,omitempty"`
	DKIMResult     string `json:"dkim_result,omitempty"`
	DMARCResult    string `json:"dmarc_result,omitempty"`
	ARCResult      string `json:"arc_result,omitempty"`
	SealPresent    bool   `json:"seal_present"`
	SigPresent     bool   `json:"signature_present"`
	ResultsPresent bool   `json:"results_present"`
}

// ARCNote represents a finding or observation about the ARC chain.
type ARCNote struct {
	Severity string `json:"severity"` // "ok", "fail", "info"
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

var (
	reAuthVerdicts = map[string]*regexp.Regexp{
		"spf":   regexp.MustCompile(`\bspf\s*=\s*([a-zA-Z0-9_-]+)`),
		"dkim":  regexp.MustCompile(`\bdkim\s*=\s*([a-zA-Z0-9_-]+)`),
		"dmarc": regexp.MustCompile(`\bdmarc\s*=\s*([a-zA-Z0-9_-]+)`),
		"arc":   regexp.MustCompile(`\barc\s*=\s*([a-zA-Z0-9_-]+)`),
	}

	arcHeaderNames = map[string]string{
		"arc-seal":                   "ARC-Seal",
		"arc-message-signature":      "ARC-Message-Signature",
		"arc-authentication-results": "ARC-Authentication-Results",
	}
)

func extractAuthVerdict(val, proto string) string {
	if m := reAuthVerdicts[proto].FindStringSubmatch(strings.ToLower(val)); len(m) > 1 {
		return m[1]
	}
	return ""
}

// AnalyzeARC parses raw email headers and checks the structure of their ARC chain.
func AnalyzeARC(rawHeaders string) (*ARCSummary, error) {
	if len(rawHeaders) > maxARCInput {
		return nil, fmt.Errorf("headers exceed %d KB", maxARCInput>>10)
	}
	if strings.TrimSpace(rawHeaders) == "" {
		return nil, errors.New("empty email headers")
	}

	var slots [maxARCHops + 1]*ARCHop
	var dups [maxARCHops + 1][]string
	for _, line := range unfoldHeaders(rawHeaders) {
		key, val, _ := strings.Cut(line, ":")
		name, ok := arcHeaderNames[strings.ToLower(strings.TrimSpace(key))]
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		tags := parseTXTTags(val)
		i, _ := strconv.Atoi(tags["i"])
		if i <= 0 {
			continue
		}
		if i > maxARCHops {
			return nil, fmt.Errorf("%s has i=%d, past the RFC 8617 limit of %d ARC sets", name, i, maxARCHops)
		}
		if slots[i] == nil {
			slots[i] = &ARCHop{Index: i}
		}
		h := slots[i]

		var present *bool
		switch name {
		case "ARC-Seal":
			present = &h.SealPresent
			h.Domain, h.Selector, h.Algorithm = tags["d"], tags["s"], tags["a"]
			h.CV = strings.ToLower(tags["cv"])
		case "ARC-Message-Signature":
			present = &h.SigPresent
			h.Domain = cmp.Or(h.Domain, tags["d"])
			h.Selector = cmp.Or(h.Selector, tags["s"])
		default:
			present = &h.ResultsPresent
			h.AuthResults = val
			h.SPFResult = extractAuthVerdict(val, "spf")
			h.DKIMResult = extractAuthVerdict(val, "dkim")
			h.DMARCResult = extractAuthVerdict(val, "dmarc")
			h.ARCResult = extractAuthVerdict(val, "arc")
		}
		if *present && !slices.Contains(dups[i], name) {
			dups[i] = append(dups[i], name)
		}
		*present = true
	}

	var hops []ARCHop
	for _, h := range slots {
		if h != nil {
			hops = append(hops, *h)
		}
	}
	if len(hops) == 0 {
		return nil, errors.New("no ARC headers (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results) found in input")
	}

	sum := &ARCSummary{
		ChainValid:  true,
		ChainLength: len(hops),
		FinalCV:     hops[len(hops)-1].CV,
		Hops:        hops,
		Findings: []ARCNote{{
			Severity: "info",
			Title:    "Signatures not verified",
			Detail:   "Only the header structure and the cv= and arc= results each hop wrote about itself were checked, so the final cv is self-reported too. No ARC signature was verified and no DNS key was fetched: a forged chain can look intact.",
		}},
	}
	fail := func(title, detail string) {
		sum.ChainValid = false
		sum.Findings = append(sum.Findings, ARCNote{Severity: "fail", Title: title, Detail: detail})
	}

	for idx, h := range hops {
		if h.Index != idx+1 {
			fail("Broken ARC Sequence", fmt.Sprintf("Expected hop i=%d, but found i=%d. ARC chain must be strictly consecutive without missing hops.", idx+1, h.Index))
		}
		if d := dups[h.Index]; len(d) > 0 {
			fail(fmt.Sprintf("Duplicate ARC Set i=%d", h.Index), fmt.Sprintf("Hop i=%d repeats %s. Each instance must carry exactly one of each ARC header.", h.Index, strings.Join(d, ", ")))
		}
		var missing []string
		if !h.SealPresent {
			missing = append(missing, "ARC-Seal")
		}
		if !h.SigPresent {
			missing = append(missing, "ARC-Message-Signature")
		}
		if !h.ResultsPresent {
			missing = append(missing, "ARC-Authentication-Results")
		}
		if len(missing) > 0 {
			fail(fmt.Sprintf("Incomplete Hop i=%d", h.Index), fmt.Sprintf("Hop i=%d is missing: %s. All three headers are required per hop.", h.Index, strings.Join(missing, " ")))
		}
		switch {
		case h.Index == 1 && h.CV != "none":
			fail("Invalid initial hop cv", fmt.Sprintf("Hop i=1 must specify cv=none, but got cv=%q.", h.CV))
		case h.Index > 1 && h.CV != "pass":
			fail(fmt.Sprintf("Broken chain at hop i=%d", h.Index), fmt.Sprintf("Hop i=%d wrote cv=%q instead of cv=pass: by its own account, the chain it received did not validate.", h.Index, h.CV))
		}
		if h.ARCResult == "fail" {
			fail(fmt.Sprintf("Hop i=%d reported arc=fail", h.Index), fmt.Sprintf("The ARC-Authentication-Results of hop i=%d records arc=fail: the intermediary that added it could not validate the chain it received.", h.Index))
		}
	}

	if sum.ChainValid {
		sum.Findings = append(sum.Findings, ARCNote{
			Severity: "ok",
			Title:    "ARC Chain Structure Intact",
			Detail:   fmt.Sprintf("%d complete, consecutive ARC sets, each reporting a consistent cv= value.", len(hops)),
		})
	}
	return sum, nil
}

// unfoldHeaders joins RFC 5322 continuation lines onto the header they continue.
func unfoldHeaders(s string) []string {
	var out []string
	var cur strings.Builder
	for line := range strings.Lines(s) {
		line = strings.TrimRight(line, "\r\n")
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			cur.WriteByte(' ')
			cur.WriteString(strings.TrimSpace(line))
			continue
		}
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteString(strings.TrimSpace(line))
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
