package mailtools

import (
	"bufio"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ARCSummary represents the audited Authenticated Received Chain (RFC 8617).
type ARCSummary struct {
	ChainValid     bool       `json:"chain_valid"`
	ChainLength    int        `json:"chain_length"`
	FinalCV        string     `json:"final_chain_validation"` // "pass", "fail", "none"
	Hops           []ARCHop   `json:"hops"`
	Findings       []ARCNote  `json:"findings"`
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
	SealPresent    bool   `json:"seal_present"`
	SigPresent     bool   `json:"signature_present"`
	ResultsPresent bool   `json:"results_present"`
}

// ARCNote represents a finding or observation about the ARC chain.
type ARCNote struct {
	Severity string `json:"severity"` // "ok", "warn", "fail", "info"
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

var (
	reTag = regexp.MustCompile(`([a-zA-Z0-9_-]+)\s*=\s*([^;]+)`)

	reAuthVerdicts = map[string]*regexp.Regexp{
		"spf":   regexp.MustCompile(`\bspf\s*=\s*([a-zA-Z0-9_-]+)`),
		"dkim":  regexp.MustCompile(`\bdkim\s*=\s*([a-zA-Z0-9_-]+)`),
		"dmarc": regexp.MustCompile(`\bdmarc\s*=\s*([a-zA-Z0-9_-]+)`),
	}
)

func extractAuthVerdict(val, proto string) string {
	if re, ok := reAuthVerdicts[proto]; ok {
		lower := strings.ToLower(val)
		if m := re.FindStringSubmatch(lower); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func parseTags(val string) map[string]string {
	tags := make(map[string]string)
	for _, m := range reTag.FindAllStringSubmatch(val, -1) {
		if len(m) == 3 {
			k := strings.ToLower(strings.TrimSpace(m[1]))
			v := strings.Trim(strings.TrimSpace(m[2]), "\"")
			tags[k] = v
		}
	}
	return tags
}

// AnalyzeARC parses raw email headers and validates the Authenticated Received Chain.
func AnalyzeARC(rawHeaders string) (*ARCSummary, error) {
	s := strings.TrimSpace(rawHeaders)
	if s == "" {
		return nil, errors.New("empty email headers")
	}

	// Unfold headers (RFC 5322: lines starting with space or tab continue previous line)
	scanner := bufio.NewScanner(strings.NewReader(s))
	var unfolded []string
	var current strings.Builder

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			current.WriteString(" ")
			current.WriteString(strings.TrimSpace(line))
		} else {
			if current.Len() > 0 {
				unfolded = append(unfolded, current.String())
				current.Reset()
			}
			current.WriteString(strings.TrimSpace(line))
		}
	}
	if current.Len() > 0 {
		unfolded = append(unfolded, current.String())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading ARC headers: %w", err)
	}

	hopMap := make(map[int]*ARCHop)

	for _, line := range unfolded {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])

		switch key {
		case "arc-seal":
			tags := parseTags(val)
			i, _ := strconv.Atoi(tags["i"])
			if i > 0 {
				h := getOrCreateHop(hopMap, i)
				h.SealPresent = true
				h.Domain = tags["d"]
				h.Selector = tags["s"]
				h.Algorithm = tags["a"]
				h.CV = strings.ToLower(tags["cv"])
			}
		case "arc-message-signature":
			tags := parseTags(val)
			i, _ := strconv.Atoi(tags["i"])
			if i > 0 {
				h := getOrCreateHop(hopMap, i)
				h.SigPresent = true
				if h.Domain == "" {
					h.Domain = tags["d"]
				}
				if h.Selector == "" {
					h.Selector = tags["s"]
				}
			}
		case "arc-authentication-results":
			// i=1 ... spf=pass ... dkim=pass ...
			tags := parseTags(val)
			i, _ := strconv.Atoi(tags["i"])
			if i > 0 {
				h := getOrCreateHop(hopMap, i)
				h.ResultsPresent = true
				h.AuthResults = val
				h.SPFResult = extractAuthVerdict(val, "spf")
				h.DKIMResult = extractAuthVerdict(val, "dkim")
				h.DMARCResult = extractAuthVerdict(val, "dmarc")
			}
		}
	}

	if len(hopMap) == 0 {
		return nil, errors.New("no ARC headers (ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results) found in input")
	}

	var hops []ARCHop
	for _, h := range hopMap {
		hops = append(hops, *h)
	}
	sort.Slice(hops, func(i, j int) bool {
		return hops[i].Index < hops[j].Index
	})

	summary := &ARCSummary{
		ChainLength: len(hops),
		Hops:        hops,
		ChainValid:  true,
	}

	var notes []ARCNote

	// 1. Verify sequence starts at i=1 and has no gaps
	for idx, h := range hops {
		expectedI := idx + 1
		if h.Index != expectedI {
			summary.ChainValid = false
			notes = append(notes, ARCNote{
				Severity: "fail",
				Title:    "Broken ARC Sequence",
				Detail:   fmt.Sprintf("Expected hop i=%d, but found i=%d. ARC chain must be strictly consecutive without missing hops.", expectedI, h.Index),
			})
		}

		if !h.SealPresent || !h.SigPresent || !h.ResultsPresent {
			summary.ChainValid = false
			missing := ""
			if !h.SealPresent {
				missing += "ARC-Seal "
			}
			if !h.SigPresent {
				missing += "ARC-Message-Signature "
			}
			if !h.ResultsPresent {
				missing += "ARC-Authentication-Results "
			}
			notes = append(notes, ARCNote{
				Severity: "fail",
				Title:    fmt.Sprintf("Incomplete Hop i=%d", h.Index),
				Detail:   fmt.Sprintf("Hop i=%d is missing: %s. All three headers are required per hop.", h.Index, strings.TrimSpace(missing)),
			})
		}

		// 2. Validate chain validation (cv) state
		if h.Index == 1 {
			if h.CV != "none" {
				summary.ChainValid = false
				notes = append(notes, ARCNote{
					Severity: "fail",
					Title:    "Invalid initial hop cv",
					Detail:   fmt.Sprintf("Hop i=1 must specify cv=none, but got cv=%q.", h.CV),
				})
			}
		} else {
			if h.CV != "pass" {
				summary.ChainValid = false
				notes = append(notes, ARCNote{
					Severity: "fail",
					Title:    fmt.Sprintf("Broken chain at hop i=%d", h.Index),
					Detail:   fmt.Sprintf("Hop i=%d reported cv=%q instead of cv=pass. The previous forwarder was not verified.", h.Index, h.CV),
				})
			}
		}
	}

	if len(hops) > 0 {
		lastHop := hops[len(hops)-1]
		summary.FinalCV = lastHop.CV

		if summary.ChainValid {
			notes = append(notes, ARCNote{
				Severity: "ok",
				Title:    "ARC Chain Verified",
				Detail:   fmt.Sprintf("Complete %d-hop ARC chain validated from origin to destination.", len(hops)),
			})
		}
	}

	summary.Findings = notes
	return summary, nil
}

func getOrCreateHop(m map[int]*ARCHop, i int) *ARCHop {
	if h, ok := m[i]; ok {
		return h
	}
	h := &ARCHop{Index: i}
	m[i] = h
	return h
}
