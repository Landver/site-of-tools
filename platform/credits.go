package platform

import (
	"fmt"
	"strings"
)

type Credit struct {
	ID     string `json:"-"`
	Source string `json:"source"`
	Notice string `json:"notice"`
	URL    string `json:"url"`
	// LinkText is the words of Notice the footer links to URL.
	LinkText string `json:"-"`
	// Flag is the view-model key that prints this credit in the footer.
	Flag string `json:"-"`
}

const (
	CreditIP2Location = "ip2location"
	CreditSpamhaus    = "spamhaus"
	CreditShodan      = "shodan"
	CreditCrtSh       = "crtsh"
	CreditRDAP        = "rdap"
)

// Licences: IP2Location's notice must be verbatim; Shodan wants a credit wherever its data shows.
var credits = []Credit{
	{ID: CreditIP2Location, Flag: "Attribution", Source: "IP2Location LITE", URL: "https://lite.ip2location.com", LinkText: "IP geolocation",
		Notice: "corpberry.com uses the IP2Location LITE database for IP geolocation."},
	{ID: CreditSpamhaus, Flag: "SpamhausAttribution", Source: "The Spamhaus Project", URL: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/", LinkText: "DROP list",
		Notice: "corpberry.com uses © The Spamhaus Project's DROP list for network abuse detection."},
	{ID: CreditShodan, Flag: "ShodanAttribution", Source: "Shodan InternetDB", URL: "https://internetdb.shodan.io", LinkText: "InternetDB",
		Notice: "corpberry.com uses © Shodan's InternetDB for open-port data."},
	{ID: CreditCrtSh, Flag: "CertsAttribution", Source: "crt.sh", URL: "https://crt.sh", LinkText: "crt.sh",
		Notice: "Subdomain data from crt.sh, the Certificate Transparency log search operated by Sectigo."},
	{ID: CreditRDAP, Flag: "RDAPAttribution", Source: "rdap.org", URL: "https://rdap.org", LinkText: "rdap.org",
		Notice: "Registration data via rdap.org, which bootstraps to each TLD's own RDAP registry."},
}

func CreditFor(id string) (Credit, bool) {
	for _, c := range credits {
		if c.ID == id {
			return c, true
		}
	}
	return Credit{}, false
}

type footerCredit struct{ URL, Lead, LinkText, Rest string }

// An unknown ID fails the render, so a credit a licence requires can't vanish over a typo.
func creditFunc(id string) (footerCredit, error) {
	c, ok := CreditFor(id)
	if !ok {
		return footerCredit{}, fmt.Errorf("no credit %q", id)
	}
	lead, rest, _ := strings.Cut(c.Notice, c.LinkText)
	return footerCredit{URL: c.URL, Lead: strings.TrimSpace(lead), LinkText: c.LinkText, Rest: rest}, nil
}
