package site

import (
	"encoding/json"
	"encoding/xml"
	"html/template"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// Author identity. Single source for the `author` meta tag and the JSON-LD
// Person, so a search engine or an AI answer attributes a post to a stable
// entity rather than to whoever syndicated it. Profile links are the
// `sameAs` anchors that tie this Person to accounts elsewhere.
const (
	authorName    = "Stas"
	authorProfile = "https://www.linkedin.com/in/stanislav-navarici/"
)

// registerSEO wires /sitemap.xml + /robots.txt. posts is the Blog's loader
// (dev reloads per request, prod serves the boot-time slice), so the sitemap
// tracks published posts without a second copy of the load logic.
//
// Note: Cloudflare can inject its own managed robots.txt at the edge, which
// wins over this handler. Disable that in the dashboard for this one to serve.
func registerSEO(e *echo.Echo, base string, posts func() ([]Post, error)) {
	e.GET("/sitemap.xml", func(c *echo.Context) error {
		all, err := posts()
		if err != nil {
			return err
		}
		out, err := xml.MarshalIndent(buildSitemap(base, all), "", "  ")
		if err != nil {
			return err
		}
		return c.Blob(http.StatusOK, "application/xml; charset=utf-8",
			append([]byte(xml.Header), out...))
	})

	// Allow everything and point crawlers at the sitemap: this site exists to
	// be indexed and cited, so no agent is excluded.
	e.GET("/robots.txt", func(c *echo.Context) error {
		return c.String(http.StatusOK,
			"User-agent: *\nAllow: /\n\nSitemap: "+base+"/sitemap.xml\n")
	})
}

// --- sitemap ----------------------------------------------------------------

type urlSet struct {
	XMLName xml.Name     `xml:"urlset"`
	Xmlns   string       `xml:"xmlns,attr"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod,omitempty"`
}

// buildSitemap lists the apex's indexable pages: landing, blog index, and one
// entry per published post. lastmod on the index tracks the newest post, so a
// new post re-dates the page that links to it. Drafts never reach here —
// LoadPosts filters them before this sees them.
func buildSitemap(base string, posts []Post) urlSet {
	set := urlSet{Xmlns: "http://www.sitemaps.org/schemas/sitemap/0.9"}
	newest := ""
	if len(posts) > 0 {
		newest = posts[0].Date.UTC().Format(DateLayout)
	}
	set.URLs = append(set.URLs,
		sitemapURL{Loc: base + "/", LastMod: newest},
		sitemapURL{Loc: base + "/blog", LastMod: newest},
	)
	for _, p := range posts {
		set.URLs = append(set.URLs, sitemapURL{
			Loc:     base + "/blog/" + p.Slug,
			LastMod: p.Date.UTC().Format(DateLayout),
		})
	}
	return set
}

// --- JSON-LD ----------------------------------------------------------------

type ldPerson struct {
	Type   string   `json:"@type"`
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	SameAs []string `json:"sameAs,omitempty"`
}

type ldWebPage struct {
	Type string `json:"@type"`
	ID   string `json:"@id"`
}

type ldBlogPosting struct {
	Context          string    `json:"@context"`
	Type             string    `json:"@type"`
	Headline         string    `json:"headline"`
	Description      string    `json:"description,omitempty"`
	Image            string    `json:"image,omitempty"`
	DatePublished    string    `json:"datePublished"`
	DateModified     string    `json:"dateModified"`
	URL              string    `json:"url"`
	MainEntityOfPage ldWebPage `json:"mainEntityOfPage"`
	Author           ldPerson  `json:"author"`
	Publisher        ldPerson  `json:"publisher"`
	InLanguage       string    `json:"inLanguage"`
}

// articleJSONLD builds the schema.org BlogPosting for one post. Returns
// template.JS so html/template drops it into the ld+json script tag verbatim
// instead of escaping the JSON — safe because every field is our own
// committed content, marshalled by encoding/json.
//
// postURL and imageURL must be absolute; relative URLs are silently ignored
// by consumers, which is the kind of bug that only shows up in a validator.
func articleJSONLD(post Post, postURL, imageURL, base string) (template.JS, error) {
	// Date-only frontmatter → RFC3339 at UTC midnight. Posts are not revised
	// in place, so modified tracks published.
	published := post.Date.UTC().Format(time.RFC3339)
	me := ldPerson{
		Type:   "Person",
		Name:   authorName,
		URL:    base,
		SameAs: []string{authorProfile},
	}
	doc := ldBlogPosting{
		Context:          "https://schema.org",
		Type:             "BlogPosting",
		Headline:         post.Title,
		Description:      post.Desc,
		Image:            imageURL,
		DatePublished:    published,
		DateModified:     published,
		URL:              postURL,
		MainEntityOfPage: ldWebPage{Type: "WebPage", ID: postURL},
		Author:           me,
		Publisher:        me,
		InLanguage:       "en",
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return template.JS(out), nil
}
