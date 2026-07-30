package platform

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// sitemapDate: <lastmod> format. Date-only is valid W3C datetime and matches
// the granularity we actually have (posts carry a date, not a timestamp).
const sitemapDate = "2006-01-02"

// Page: one indexable URL on a host. Path is host-relative ("/cidr"); LastMod
// is optional — the zero time omits the element rather than emitting a lie.
type Page struct {
	Path    string
	LastMod time.Time
}

// RegisterSEO wires /sitemap.xml + /robots.txt onto e for the host rooted at
// base (e.g. "https://ip.corpberry.com").
//
// Per-host by design: the sitemaps.org spec scopes a sitemap to URLs on the
// same host as the sitemap itself, so a crawler ignores cross-host entries.
// One apex sitemap therefore cannot advertise the tool subdomains — each
// *echo.Echo in the vhost map needs its own pair.
//
// pages is evaluated per request so hosts with dynamic content (the blog)
// stay current without a second copy of the load logic.
func RegisterSEO(e *echo.Echo, base string, pages func() ([]Page, error)) {
	e.GET("/sitemap.xml", func(c *echo.Context) error {
		list, err := pages()
		if err != nil {
			return err
		}
		out, err := xml.MarshalIndent(BuildSitemap(base, list), "", "  ")
		if err != nil {
			return err
		}
		return c.Blob(http.StatusOK, "application/xml; charset=utf-8",
			append([]byte(xml.Header), out...))
	})

	// Allow everything and advertise this host's own sitemap. These sites
	// exist to be indexed and cited, so no agent is excluded.
	e.GET("/robots.txt", func(c *echo.Context) error {
		return c.String(http.StatusOK,
			"User-agent: *\nAllow: /\n\nSitemap: "+base+"/sitemap.xml\n")
	})
}

type urlSet struct {
	XMLName xml.Name     `xml:"urlset"`
	Xmlns   string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod,omitempty"`
}

// BuildSitemap renders pages as a urlset, expanding each Path against base.
// Callers pass only URLs they want indexed: POST endpoints, service workers
// and pages of transient user data have no business here.
func BuildSitemap(base string, pages []Page) urlSet {
	set := urlSet{Xmlns: "http://www.sitemaps.org/schemas/sitemap/0.9"}
	for _, p := range pages {
		u := sitemapURL{Loc: base + p.Path}
		if !p.LastMod.IsZero() {
			u.LastMod = p.LastMod.UTC().Format(sitemapDate)
		}
		set.URLs = append(set.URLs, u)
	}
	return set
}
