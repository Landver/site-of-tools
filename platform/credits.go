package platform

import (
	"fmt"
	"html/template"
	"strings"
)

// Credit is one third-party data source's attribution, owed wherever its data
// is shown: the footer prints it on pages built from the source, and a result
// served without a page carries it instead.
type Credit struct {
	ID     string `json:"-"`
	Source string `json:"source"`
	Notice string `json:"notice"`
	URL    string `json:"url"`
	// LinkText is the words of Notice the footer links to URL.
	LinkText string `json:"-"`
}

// IDs for CreditFor; the footer names them as literals.
const (
	CreditIP2Location = "ip2location"
	CreditSpamhaus    = "spamhaus"
	CreditShodan      = "shodan"
	CreditCrtSh       = "crtsh"
	CreditRDAP        = "rdap"
)

var credits = []Credit{
	{ID: CreditIP2Location, Source: "IP2Location LITE", URL: "https://lite.ip2location.com", LinkText: "IP geolocation",
		Notice: "corpberry.com uses the IP2Location LITE database for IP geolocation."},
	{ID: CreditSpamhaus, Source: "The Spamhaus Project", URL: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", LinkText: "DROP list",
		Notice: "corpberry.com uses © The Spamhaus Project's DROP list for network abuse detection."},
	{ID: CreditShodan, Source: "Shodan InternetDB", URL: "https://internetdb.shodan.io", LinkText: "InternetDB",
		Notice: "corpberry.com uses © Shodan's InternetDB for open-port data."},
	{ID: CreditCrtSh, Source: "crt.sh", URL: "https://crt.sh", LinkText: "crt.sh",
		Notice: "Subdomain data from crt.sh, the Certificate Transparency log search operated by Sectigo."},
	{ID: CreditRDAP, Source: "rdap.org", URL: "https://rdap.org", LinkText: "rdap.org",
		Notice: "Registration data via rdap.org, which bootstraps to each TLD's own RDAP registry."},
}

// CreditFor returns the credit with that ID.
func CreditFor(id string) (Credit, bool) {
	for _, c := range credits {
		if c.ID == id {
			return c, true
		}
	}
	return Credit{}, false
}

// footerCredit is a Credit cut where the footer's markup goes around it:
// Lead, then the link, then Punct and Tail.
type footerCredit struct {
	URL                         string
	Lead, LinkText, Punct, Tail template.HTML
}

// creditFunc is the "credit" template func. An unknown ID fails the render: a
// credit a licence requires must not vanish over a typo.
func creditFunc(id string) (footerCredit, error) {
	c, ok := CreditFor(id)
	if !ok {
		return footerCredit{}, fmt.Errorf("no credit %q", id)
	}
	lead, after, _ := strings.Cut(c.Notice, c.LinkText)
	punct, tail, _ := strings.Cut(after, " ")
	return footerCredit{
		URL:      c.URL,
		Lead:     textNode(strings.TrimSpace(lead)),
		LinkText: textNode(c.LinkText),
		Punct:    textNode(punct),
		Tail:     textNode(tail),
	}, nil
}

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// textNode escapes s for an HTML text node, where only &, < and > matter.
// html/template would also turn the notices' apostrophes into &#39;.
func textNode(s string) template.HTML { return template.HTML(textEscaper.Replace(s)) }
