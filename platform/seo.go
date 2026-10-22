package platform

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// sitemapDate: date-only is valid W3C datetime and all the precision posts have.
const sitemapDate = "2006-01-02"

// Page is one indexable, host-relative URL; a zero LastMod omits <lastmod> rather than emitting a lie.
type Page struct {
	Path    string
	LastMod time.Time
}

// RegisterSEO serves /sitemap.xml and /robots.txt per host: sitemaps.org scopes a sitemap to its own host,
// so every vhost needs its own pair. pages runs per request so the blog stays current.
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

	// These sites exist to be indexed and cited, so no agent is excluded.
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

// BuildSitemap: callers pass only URLs to index, never POST endpoints, workers or transient user data.
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
