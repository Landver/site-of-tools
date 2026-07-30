package site

import (
	"encoding/xml"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// errPostNotFound: slug has no published post → handler maps it to 404.
var errPostNotFound = errors.New("blog: post not found")

// absoluteURL expands a site path ("/static/img/x.png") against base;
// already-absolute URLs pass through. og:image must be absolute.
func absoluteURL(base, u string) string {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return u
	}
	return base + u
}

// Blog serves posts loaded from fsys. Prod loads once at boot (NewBlog);
// dev reloads per request so edits show without restart — same contract as
// the template renderer.
type Blog struct {
	fsys   fs.FS
	dev    bool
	loaded []Post
}

// NewBlog builds the blog. Prod parses posts immediately → a malformed post
// fails boot (caller: log.Fatal) instead of serving a broken page.
func NewBlog(fsys fs.FS, dev bool) (*Blog, error) {
	b := &Blog{fsys: fsys, dev: dev}
	if !dev {
		if err := b.reload(); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// reload loads posts into b.loaded; called only from NewBlog (prod boot).
func (b *Blog) reload() error {
	posts, err := LoadPosts(b.fsys)
	if err != nil {
		return err
	}
	b.loaded = posts
	return nil
}

func (b *Blog) posts() ([]Post, error) {
	if b.dev {
		// Fresh slice per request — no shared mutation under parallel requests.
		return LoadPosts(b.fsys)
	}
	return b.loaded, nil
}

func (b *Blog) post(slug string) (Post, error) {
	posts, err := b.posts()
	if err != nil {
		return Post{}, err
	}
	for _, p := range posts {
		if p.Slug == slug {
			return p, nil
		}
	}
	return Post{}, errPostNotFound
}

// registerRoutes wires /blog, /blog/:slug, /blog/feed.xml onto the apex app.
// base = full apex origin (cfg.URL("")) for absolute canonical + feed URLs.
func (b *Blog) registerRoutes(e *echo.Echo, base string) {
	// Single source for blog URLs — handlers' canonical URLs and the feed's
	// self/entry URLs must match.
	blogURL := base + "/blog"
	feedURL := blogURL + "/feed.xml"
	postURL := func(slug string) string { return blogURL + "/" + slug }

	e.GET("/blog", func(c *echo.Context) error {
		posts, err := b.posts()
		if err != nil {
			return err
		}
		data := map[string]any{
			"Title":     "Blog — corpberry.com",
			"Desc":      "Occasional technical writeups by Stas: bot detection, Go, and the tools on this site.",
			"Posts":     posts,
			"Canonical": blogURL,
			"Feed":      feedURL,
		}
		return platform.Respond(c, http.StatusOK, data, "site/blog-index", "site/blog-index")
	})

	e.GET("/blog/:slug", func(c *echo.Context) error {
		post, err := b.post(c.Param("slug"))
		if errors.Is(err, errPostNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "no such post")
		}
		if err != nil {
			return err
		}
		canonical := postURL(post.Slug)
		data := map[string]any{
			"Title":     post.Title + " — corpberry.com",
			"Desc":      post.Desc,
			"Post":      post,
			"OGType":    "article",
			"Canonical": canonical,
			"Feed":      feedURL,
			// Authorship + publication date, for search engines and for AI
			// answers that need someone to attribute the claims to.
			"Author":    authorName,
			"Published": post.Date.UTC().Format(time.RFC3339),
		}
		var ogImage string
		if post.Image != "" {
			ogImage = absoluteURL(base, post.Image)
			data["OGImage"] = ogImage
		}
		ld, err := articleJSONLD(post, canonical, ogImage, base)
		if err != nil {
			return err
		}
		data["JSONLD"] = ld
		return platform.Respond(c, http.StatusOK, data, "site/blog-post", "site/blog-post")
	})

	// Static path beats /blog/:slug in echo's router — no conflict.
	e.GET("/blog/feed.xml", func(c *echo.Context) error {
		posts, err := b.posts()
		if err != nil {
			return err
		}
		out, err := xml.MarshalIndent(buildFeed(blogURL, feedURL, posts), "", "  ")
		if err != nil {
			return err
		}
		return c.Blob(http.StatusOK, "application/atom+xml; charset=utf-8",
			append([]byte(xml.Header), out...))
	})
}

// --- Atom feed --------------------------------------------------------------

type atomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	Title   string      `xml:"title"`
	ID      string      `xml:"id"`
	Updated string      `xml:"updated"`
	Links   []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type atomEntry struct {
	Title   string   `xml:"title"`
	Link    atomLink `xml:"link"`
	ID      string   `xml:"id"`
	Updated string   `xml:"updated"`
	Summary string   `xml:"summary"`
}

// buildFeed renders posts as an Atom feed from the blog's canonical URLs
// (derived in registerRoutes). posts arrive newest-first from LoadPosts.
func buildFeed(blogURL, feedURL string, posts []Post) atomFeed {
	updated := time.Now().UTC()
	if len(posts) > 0 {
		updated = posts[0].Date.UTC()
	}
	feed := atomFeed{
		Xmlns:   "http://www.w3.org/2005/Atom",
		Title:   "corpberry.com — blog",
		ID:      blogURL,
		Updated: updated.Format(time.RFC3339),
		Links: []atomLink{
			{Rel: "self", Href: feedURL},
			{Rel: "alternate", Href: blogURL},
		},
	}
	for _, p := range posts {
		entryURL := blogURL + "/" + p.Slug
		feed.Entries = append(feed.Entries, atomEntry{
			Title:   p.Title,
			Link:    atomLink{Href: entryURL},
			ID:      entryURL,
			Updated: p.Date.UTC().Format(time.RFC3339),
			Summary: p.Desc,
		})
	}
	return feed
}
