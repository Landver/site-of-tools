package mailtools

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"sync"
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
	disposableExact    map[string]struct{}
	disposableWildcard []string
	freemailExact      map[string]struct{}
	whitelist          map[string]struct{}
}

// Global active classifier reference for zero-lock reads.
var (
	globalClassifier atomic.Pointer[DomainClassifier]
	initOnce         sync.Once
)

// SetGlobalClassifier atomically updates the active domain classifier.
func SetGlobalClassifier(c *DomainClassifier) {
	if c != nil {
		globalClassifier.Store(c)
	}
}

// ActiveClassifier returns the current global classifier, lazily initializing from embedded data if needed.
func ActiveClassifier() *DomainClassifier {
	c := globalClassifier.Load()
	if c == nil {
		initOnce.Do(func() {
			_ = InitFromEmbedded()
		})
		c = globalClassifier.Load()
		if c == nil {
			return &DomainClassifier{
				disposableExact: make(map[string]struct{}),
				freemailExact:   make(map[string]struct{}),
				whitelist:       make(map[string]struct{}),
			}
		}
	}
	return c
}

// NewDomainClassifier constructs an index from slice collections.
func NewDomainClassifier(disposable, wildcards, freemail, whitelist []string) *DomainClassifier {
	c := &DomainClassifier{
		disposableExact: make(map[string]struct{}, len(disposable)),
		freemailExact:   make(map[string]struct{}, len(freemail)),
		whitelist:       make(map[string]struct{}, len(whitelist)),
	}

	for _, w := range whitelist {
		w = cleanDomain(w)
		if w != "" {
			c.whitelist[w] = struct{}{}
		}
	}

	for _, d := range disposable {
		d = cleanDomain(d)
		if d != "" {
			// Whitelist protection: skip whitelisted domains from disposable blocklist.
			if _, ok := c.whitelist[d]; !ok {
				c.disposableExact[d] = struct{}{}
			}
		}
	}

	for _, w := range wildcards {
		w = cleanDomain(w)
		if w != "" {
			c.disposableWildcard = append(c.disposableWildcard, w)
		}
	}

	for _, f := range freemail {
		f = cleanDomain(f)
		if f != "" {
			c.freemailExact[f] = struct{}{}
		}
	}

	return c
}

// InitFromEmbedded loads the embedded seed data into the global classifier.
func InitFromEmbedded() error {
	dispFile, err := Data.Open("data/disposable.txt")
	if err != nil {
		return err
	}
	defer dispFile.Close()
	disposable := readLines(dispFile)

	var wildcards []string
	wildFile, err := Data.Open("data/wildcard.json")
	if err == nil {
		defer wildFile.Close()
		_ = json.NewDecoder(wildFile).Decode(&wildcards)
	}

	var freemail []string
	freeFile, err := Data.Open("data/freemail.json")
	if err == nil {
		defer freeFile.Close()
		_ = json.NewDecoder(freeFile).Decode(&freemail)
	}

	var whitelist []string
	whiteFile, err := Data.Open("data/whitelist.txt")
	if err == nil {
		defer whiteFile.Close()
		whitelist = readLines(whiteFile)
	}

	classifier := NewDomainClassifier(disposable, wildcards, freemail, whitelist)
	SetGlobalClassifier(classifier)
	return nil
}

// ExtractDomain normalizes an email address or domain string to lowercase domain.
func ExtractDomain(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	if at := strings.LastIndex(input, "@"); at != -1 {
		input = input[at+1:]
	}
	// Strip URI scheme or path if user pasted a URL
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	if slash := strings.Index(input, "/"); slash != -1 {
		input = input[:slash]
	}
	if colon := strings.Index(input, ":"); colon != -1 {
		input = input[:colon]
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

// IsWhitelisted checks if domain is in the top-tier enterprise whitelist.
func (c *DomainClassifier) IsWhitelisted(domain string) bool {
	domain = cleanDomain(domain)
	if domain == "" {
		return false
	}
	if _, ok := c.whitelist[domain]; ok {
		return true
	}
	// Check parent domains if subdomain (e.g. sub.corpberry.com -> corpberry.com)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := c.whitelist[parent]; ok {
			return true
		}
	}
	return false
}

// IsDisposable checks if a domain matches known disposable domain lists or wildcard suffixes.
func (c *DomainClassifier) IsDisposable(domain string) (bool, string) {
	domain = cleanDomain(domain)
	if domain == "" || c.IsWhitelisted(domain) {
		return false, ""
	}

	if _, ok := c.disposableExact[domain]; ok {
		return true, "exact match in canonical blocklist"
	}

	// Subdomain check: if e.g. "sub.domain.com" and "domain.com" is disposable
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if _, ok := c.disposableExact[parent]; ok {
			return true, "parent domain is in disposable blocklist"
		}
	}

	// Wildcard checks
	for _, w := range c.disposableWildcard {
		if domain == w || strings.HasSuffix(domain, "."+w) {
			return true, "matches wildcard pattern *." + w
		}
	}

	return false, ""
}

// IsFreemail checks if a domain belongs to a free public webmail provider.
func (c *DomainClassifier) IsFreemail(domain string) bool {
	domain = cleanDomain(domain)
	if _, ok := c.freemailExact[domain]; ok {
		return true
	}
	return false
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
		res.Type = DomainTypeDisposable
		res.IsDisposable = true
		res.MatchReason = reason
		return res
	}

	if c.IsFreemail(dom) {
		res.Type = DomainTypeFreemail
		res.IsFreemail = true
		res.MatchReason = "recognized free webmail provider"
		return res
	}

	return res
}

// FreemailDomains returns a copy of all recognized freemail domains.
func (c *DomainClassifier) FreemailDomains() []string {
	if c == nil {
		return nil
	}
	res := make([]string, 0, len(c.freemailExact))
	for d := range c.freemailExact {
		res = append(res, d)
	}
	return res
}

// WhitelistDomains returns a copy of all whitelisted domains.
func (c *DomainClassifier) WhitelistDomains() []string {
	if c == nil {
		return nil
	}
	res := make([]string, 0, len(c.whitelist))
	for d := range c.whitelist {
		res = append(res, d)
	}
	return res
}

// WildcardPatterns returns a copy of all disposable wildcard patterns.
func (c *DomainClassifier) WildcardPatterns() []string {
	if c == nil {
		return nil
	}
	return append([]string(nil), c.disposableWildcard...)
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
