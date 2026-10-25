package mailtools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"path"
	"slices"
	"strings"
	"sync/atomic"
)

// DomainType represents the category of an email domain.
type DomainType string

const (
	DomainTypeCorporate  DomainType = "corporate"
	DomainTypeFreemail   DomainType = "freemail"
	DomainTypeDisposable DomainType = "disposable"
)

// DomainClassification contains classification details for an email or domain.
type DomainClassification struct {
	Domain        string     `json:"domain"`
	Type          DomainType `json:"type"`
	IsDisposable  bool       `json:"is_disposable"`
	IsFreemail    bool       `json:"is_freemail"`
	IsWhitelisted bool       `json:"is_whitelisted"`
	MatchReason   string     `json:"match_reason,omitempty"`
}

// DomainClassifier is an immutable, read-optimized in-memory index.
type DomainClassifier struct {
	disposable, freemail, whitelist map[string]struct{}
}

// The daily sync replaces only the disposable list; wildcards, freemail and the whitelist stay the embedded seed.
var (
	seedWildcards = seedList("data/wildcard.json")
	seedFreemail  = seedList("data/freemail.json")
	seedWhitelist = seedList("data/whitelist.txt")

	active atomic.Pointer[DomainClassifier]
)

func init() {
	active.Store(classifierWith(seedList("data/disposable.txt")))
}

// ActiveClassifier returns the classifier in use: the embedded seed until the first daily sync lands.
func ActiveClassifier() *DomainClassifier { return active.Load() }

func classifierWith(disposable []string) *DomainClassifier {
	return NewDomainClassifier(slices.Concat(disposable, seedWildcards), seedFreemail, seedWhitelist)
}

// NewDomainClassifier indexes the lists; a "*.example.com" wildcard covers what "example.com" does.
func NewDomainClassifier(disposable, freemail, whitelist []string) *DomainClassifier {
	return &DomainClassifier{disposable: domainSet(disposable), freemail: domainSet(freemail), whitelist: domainSet(whitelist)}
}

func domainSet(list []string) map[string]struct{} {
	set := make(map[string]struct{}, len(list))
	for _, d := range list {
		if d = cleanDomain(d); d != "" {
			set[d] = struct{}{}
		}
	}
	return set
}

// seedList reads an embedded list: a JSON array, or one entry per line.
func seedList(name string) []string {
	b, err := Data.ReadFile(name)
	if err != nil {
		panic(err)
	}
	if path.Ext(name) != ".json" {
		return readLines(bytes.NewReader(b))
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		panic(name + ": " + err.Error())
	}
	return list
}

// ExtractDomain normalizes an email address or domain string to lowercase domain.
func ExtractDomain(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	input = strings.Trim(input, "[]")
	if at := strings.LastIndex(input, "@"); at != -1 {
		input = input[at+1:]
	}
	// Strip URI scheme or path if user pasted a URL
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	if slash := strings.Index(input, "/"); slash != -1 {
		input = input[:slash]
	}
	// Only strip port if it's host:port, NOT an IPv6 address
	if strings.Count(input, ":") == 1 {
		if colon := strings.Index(input, ":"); colon != -1 {
			input = input[:colon]
		}
	}
	return cleanDomain(input)
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	return d
}

// firstIn returns the first of domain and its parents that set holds; a bare TLD never matches.
func firstIn(set map[string]struct{}, domain string) string {
	for d := domain; ; {
		if _, ok := set[d]; ok {
			return d
		}
		_, parent, _ := strings.Cut(d, ".")
		if !strings.Contains(parent, ".") {
			return ""
		}
		d = parent
	}
}

// IsWhitelisted checks if a domain, or a parent of it, is in the enterprise whitelist.
func (c *DomainClassifier) IsWhitelisted(domain string) bool {
	domain = cleanDomain(domain)
	return domain != "" && firstIn(c.whitelist, domain) != ""
}

// IsDisposable checks a domain and its parents against the disposable list; the whitelist wins.
func (c *DomainClassifier) IsDisposable(domain string) (bool, string) {
	domain = cleanDomain(domain)
	if domain == "" || c.IsWhitelisted(domain) {
		return false, ""
	}
	switch firstIn(c.disposable, domain) {
	case "":
		return false, ""
	case domain:
		return true, "exact match in canonical blocklist"
	default:
		return true, "parent domain is in disposable blocklist"
	}
}

// IsFreemail checks if a domain belongs to a free public webmail provider.
func (c *DomainClassifier) IsFreemail(domain string) bool {
	_, ok := c.freemail[cleanDomain(domain)]
	return ok
}

// Classify produces a full DomainClassification report.
func (c *DomainClassifier) Classify(input string) DomainClassification {
	dom := ExtractDomain(input)
	res := DomainClassification{
		Domain:        dom,
		Type:          DomainTypeCorporate,
		IsWhitelisted: c.IsWhitelisted(dom),
	}
	if isDisp, reason := c.IsDisposable(dom); isDisp {
		res.Type, res.IsDisposable, res.MatchReason = DomainTypeDisposable, true, reason
	} else if c.IsFreemail(dom) {
		res.Type, res.IsFreemail, res.MatchReason = DomainTypeFreemail, true, "recognized free webmail provider"
	}
	return res
}

func readLines(r io.Reader) []string {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
