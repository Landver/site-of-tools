package mcptools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
)

type siteBlogArgs struct {
	Slug string `json:"slug,omitempty" jsonschema:"the post to read, e.g. the-bug-is-still-there; leave it out for the list of posts"`
}

type blogPost struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	Date        string `json:"date"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Markdown    string `json:"markdown,omitempty"`
}

type siteTools struct {
	blog *site.Blog
	base string // the apex origin
}

func siteSpecs(d Deps) []toolSpec {
	if d.Blog == nil {
		return nil
	}
	t := siteTools{blog: d.Blog, base: d.ToolURL("")}
	return []toolSpec{{
		toolset: "site",
		tool: &mcp.Tool{
			Name:  "site_blog",
			Title: "corpberry.com blog",
			Description: "Read the corpberry.com blog: technical write-ups by the site's author on bot detection, Go and the tools on the site. " +
				"Without slug it lists every post, newest first, with its slug, title, date, description and url; " +
				"with slug it returns that post as Markdown, its root-relative links and images made absolute. Example: slug the-bug-is-still-there.",
			InputSchema: inputSchema[siteBlogArgs](),
			Annotations: readOnly(false),
		},
		deadline: quickDeadline,
		// The REST blog is static and has no budget to share.
		limiter: platform.NewLimiter(10, 50),
		add:     handle(t.read),
	}}
}

func (t siteTools) read(_ context.Context, a siteBlogArgs) (any, error) {
	slug := strings.TrimSpace(a.Slug)
	if slug == "" {
		posts, err := t.blog.Posts()
		if err != nil {
			return nil, err
		}
		list := make([]blogPost, len(posts))
		for i, p := range posts {
			list[i] = t.entry(p)
		}
		return map[string]any{"posts": list}, nil
	}
	p, err := t.blog.Post(slug)
	switch {
	case errors.Is(err, site.ErrPostNotFound):
		return nil, fmt.Errorf("No post has the slug %q. Call site_blog without a slug to list the posts and their slugs.", slug)
	case err != nil:
		return nil, err
	}
	e := t.entry(p)
	e.Markdown = strings.ReplaceAll(p.Markdown, "](/", "]("+t.base+"/")
	return e, nil
}

func (t siteTools) entry(p site.Post) blogPost {
	return blogPost{Slug: p.Slug, Title: p.Title, Date: p.Date.Format(site.DateLayout), Description: p.Desc,
		URL: t.base + "/blog/" + p.Slug}
}
