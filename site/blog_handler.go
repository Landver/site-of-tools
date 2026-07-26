package site

import (
	"encoding/xml"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// errPostNotFound: slug has no published post → handler maps it to 404.
var errPostNotFound = errors.New("blog: post not found")

// Blog serves posts loaded from fsys. Prod loads once at boot (NewBlog);
// dev reloads per request so edits show without restart — same contract as
// the template renderer.
type Blog struct {
	fsys   fs.FS
	dev    bool
	loaded []Post
	bySlug map[string]Post
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

func (b *Blog) reload() error {
	posts, err := LoadPosts(b.fsys)
	if err != nil {
		return err
	}
	b.loaded = posts
	b.bySlug = make(map[string]Post, len(posts))
	for _, p := range posts {
		b.bySlug[p.Slug] = p
	}
	return nil
}

func (b *Blog) posts() ([]Post, error) {
	if b.dev {
		if err := b.reload(); err != nil {
			return nil, err
		}
	}
	return b.loaded, nil
}

func (b *Blog) post(slug string) (Post, error) {
	if _, err := b.posts(); err != nil {
		return Post{}, err
	}
	p, ok := b.bySlug[slug]
	if !ok {
		return Post{}, errPostNotFound
	}
	return p, nil
}

// registerRoutes wires /blog, /blog/:slug, /blog/feed.xml onto the apex app.
// base = full apex origin (cfg.URL("")) for absolute canonical + feed URLs.
func (b *Blog) registerRoutes(e *echo.Echo, base string) {
	e.GET("/blog", func(c *echo.Context) error {
		posts, err := b.posts()
		if err != nil {
			return err
		}
		data := map[string]any{
			"Title":     "Blog — corpberry.com",
			"Desc":      "Occasional technical writeups by Stas: bot detection, Go, and the tools on this site.",
			"Posts":     posts,
			"Canonical": base + "/blog",
			"Feed":      base + "/blog/feed.xml",
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
		data := map[string]any{
			"Title":     post.Title + " — corpberry.com",
			"Desc":      post.Desc,
			"Post":      post,
			"OGType":    "article",
			"Canonical": base + "/blog/" + post.Slug,
			"Feed":      base + "/blog/feed.xml",
		}
		return platform.Respond(c, http.StatusOK, data, "site/blog-post", "site/blog-post")
	})

	// Static path beats /blog/:slug in echo's router — no conflict.
	e.GET("/blog/feed.xml", func(c *echo.Context) error {
		posts, err := b.posts()
		if err != nil {
			return err
		}
		out, err := xml.MarshalIndent(buildFeed(base, posts), "", "  ")
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

// buildFeed renders posts as an Atom feed. base = apex origin → every URL
// absolute (feed readers require it). posts arrive newest-first from LoadPosts.
func buildFeed(base string, posts []Post) atomFeed {
	updated := time.Now().UTC()
	if len(posts) > 0 {
		updated = posts[0].Date.UTC()
	}
	feed := atomFeed{
		Xmlns:   "http://www.w3.org/2005/Atom",
		Title:   "corpberry.com — blog",
		ID:      base + "/blog",
		Updated: updated.Format(time.RFC3339),
		Links: []atomLink{
			{Rel: "self", Href: base + "/blog/feed.xml"},
			{Rel: "alternate", Href: base + "/blog"},
		},
	}
	for _, p := range posts {
		feed.Entries = append(feed.Entries, atomEntry{
			Title:   p.Title,
			Link:    atomLink{Href: base + "/blog/" + p.Slug},
			ID:      base + "/blog/" + p.Slug,
			Updated: p.Date.UTC().Format(time.RFC3339),
			Summary: p.Desc,
		})
	}
	return feed
}
