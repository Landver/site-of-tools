package mcptools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
)

type siteBlogArgs struct {
	Slug string `json:"slug,omitempty" jsonschema:"the post to read, e.g. the-bug-is-still-there; leave it out for the list of posts"`
}

// blogPost is a post as site_blog returns it; Markdown only when one post
// is asked for.
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
	t := siteTools{blog: d.Blog}
	if d.ToolURL != nil {
		t.base = d.ToolURL("")
	}
	return []toolSpec{{
		toolset: "site",
		tool: &mcp.Tool{
			Name:  "site_blog",
			Title: "corpberry.com blog",
			Description: "Read the corpberry.com blog: technical write-ups by the site's author on bot detection, Go and the tools on the site. " +
				"Without slug it lists every post, newest first, with its slug, title, date, description and url; " +
				"with slug it returns that post as Markdown, its links and images made absolute. Example: slug the-bug-is-still-there.",
			InputSchema: inputSchema[siteBlogArgs](),
			Annotations: readOnly(false),
		},
		deadline: quickDeadline,
		// The REST blog is static and has no budget to share.
		limiter: platform.NewLimiter(10, 50),
		whole:   true,
		add:     handle(t.read),
	}}
}

func (t siteTools) read(_ context.Context, _ *mcp.CallToolRequest, a siteBlogArgs) (any, error) {
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
	e.Markdown = absolutize(p.Markdown, e.URL)
	return e, nil
}

func (t siteTools) entry(p site.Post) blogPost {
	return blogPost{Slug: p.Slug, Title: p.Title, Date: p.Date.Format(site.DateLayout), Description: p.Desc,
		URL: t.base + "/blog/" + p.Slug}
}

// A link or image destination: inline, a reference definition, or an HTML
// attribute. Group 2 is the destination; nothing follows it in the match.
var (
	inlineDest = regexp.MustCompile(`(\]\(\s*<?)([^\s)>]+)`)
	refDest    = regexp.MustCompile(`^( {0,3}\[[^\]]+\]:[ \t]*<?)([^\s>]+)`)
	htmlDest   = regexp.MustCompile(`(\b(?:src|href)=["'])([^"']+)`)
)

// absolutize resolves every relative link and image in a post's Markdown
// against the post's URL, as a browser would: read as source, there is no
// page to resolve /static/… against. Code blocks and spans are left alone.
func absolutize(md, postURL string) string {
	base, err := url.Parse(postURL)
	if err != nil || !base.IsAbs() {
		return md
	}
	resolve := func(re *regexp.Regexp, s string) string {
		return re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			u, err := url.Parse(sub[2])
			if err != nil || u.IsAbs() {
				return m
			}
			return sub[1] + base.ResolveReference(u).String()
		})
	}
	lines := strings.SplitAfter(md, "\n")
	fence := ""
	for i, line := range lines {
		lead := strings.TrimLeft(line, " ")
		switch {
		case fence != "":
			if strings.HasPrefix(lead, fence) {
				fence = ""
			}
			continue
		case fenceOf(lead) != "":
			fence = fenceOf(lead)
			continue
		}
		parts := strings.Split(line, "`") // odd parts are inside code spans
		for j := 0; j < len(parts); j += 2 {
			if j == 0 {
				parts[j] = resolve(refDest, parts[j])
			}
			parts[j] = resolve(htmlDest, resolve(inlineDest, parts[j]))
		}
		lines[i] = strings.Join(parts, "`")
	}
	return strings.Join(lines, "")
}

// fenceOf is the run of three or more backticks or tildes a line opens a
// code block with, or "".
func fenceOf(line string) string {
	for _, c := range []string{"`", "~"} {
		if n := len(line) - len(strings.TrimLeft(line, c)); n >= 3 {
			return strings.Repeat(c, n)
		}
	}
	return ""
}
