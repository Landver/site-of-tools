package tests

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

const firstSteps = "---\n" + `title: "First steps"
description: "Where it started."
date: "2026-09-01"
---

![The first page](/static/img/first.png "First")

Read [the next post](/blog/second-thoughts), the [notes](notes.txt) beside this one,
[the spec](https://example.com/spec), [a mail](mailto:stas@example.com) and [the end](#end).

<img src="/static/img/inline.png" alt="inline">

In code, ` + "`[kept](/as/is)`" + ` stays.

` + "```md\n![kept too](/static/img/raw.png)\n```" + `

[paper]: /static/files/paper.pdf
`

// firstStepsMarkdown is firstSteps as site_blog returns it: no frontmatter,
// every relative link resolved against the post's URL, code untouched.
const firstStepsMarkdown = `![The first page](https://corpberry.test/static/img/first.png "First")

Read [the next post](https://corpberry.test/blog/second-thoughts), the [notes](https://corpberry.test/blog/notes.txt) beside this one,
[the spec](https://example.com/spec), [a mail](mailto:stas@example.com) and [the end](https://corpberry.test/blog/first-steps#end).

<img src="https://corpberry.test/static/img/inline.png" alt="inline">

In code, ` + "`[kept](/as/is)`" + ` stays.

` + "```md\n![kept too](/static/img/raw.png)\n```" + `

[paper]: https://corpberry.test/static/files/paper.pdf
`

// testPosts are two published posts and a draft; the second is over the
// sanitizer's per-string cap, which a post must not be cut at.
var testPosts = fstest.MapFS{
	"2026-09-01-first-steps.md": {Data: []byte(firstSteps)},
	"2026-09-20-second-thoughts.md": {Data: []byte("---\ntitle: \"Second thoughts\"\ndescription: \"Later, and longer.\"\ndate: \"2026-09-20\"\n---\n\n" +
		strings.Repeat("A long paragraph. ", 200) + "\n")},
	"2026-09-25-unfinished.md": {Data: []byte("---\ntitle: \"Unfinished\"\ndate: \"2026-09-25\"\ndraft: true\n---\n\nNot yet.\n")},
}

func TestSiteBlogList(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/site", nil, nil)
	want := map[string]any{"posts": []any{
		map[string]any{"slug": "second-thoughts", "title": "Second thoughts", "date": "2026-09-20",
			"description": "Later, and longer.", "url": apexURL + "/blog/second-thoughts"},
		map[string]any{"slug": "first-steps", "title": "First steps", "date": "2026-09-01",
			"description": "Where it started.", "url": apexURL + "/blog/first-steps"},
	}}
	if diff := cmp.Diff(want, object(t, call(t, cs, "site_blog", map[string]any{}))); diff != "" {
		t.Errorf("list (-want +got):\n%s", diff)
	}
}

func TestSiteBlogPost(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/site", nil, nil)
	got := object(t, call(t, cs, "site_blog", map[string]any{"slug": " first-steps "}))
	if diff := cmp.Diff(firstStepsMarkdown, got["markdown"]); diff != "" {
		t.Errorf("markdown (-want +got):\n%s", diff)
	}
	delete(got, "markdown")
	want := map[string]any{"slug": "first-steps", "title": "First steps", "date": "2026-09-01",
		"description": "Where it started.", "url": apexURL + "/blog/first-steps"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("post (-want +got):\n%s", diff)
	}

	long := object(t, call(t, cs, "site_blog", map[string]any{"slug": "second-thoughts"}))["markdown"].(string)
	if want := strings.Repeat("A long paragraph. ", 200) + "\n"; long != want {
		t.Errorf("second-thoughts came back as %d bytes of %d: a post is never cut", len(long), len(want))
	}

	for _, slug := range []string{"no-such-post", "unfinished"} {
		failsWith(t, call(t, cs, "site_blog", map[string]any{"slug": slug}), "Call site_blog without a slug")
	}
}

// TestSiteBlogParity: the list and a post are the REST view model's posts,
// projected; the Markdown has no REST twin.
func TestSiteBlogParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil, nil)
	entry := func(p map[string]any, url string) map[string]any {
		return map[string]any{"slug": p["Slug"], "title": p["Title"], "date": p["Date"].(string)[:10],
			"description": p["Desc"], "url": url}
	}

	rest := s.rest(t, apexHost, http.MethodGet, "/blog", "")
	var posts []any
	for _, p := range rest["Posts"].([]any) {
		pm := p.(map[string]any)
		posts = append(posts, entry(pm, rest["Canonical"].(string)+"/"+pm["Slug"].(string)))
	}
	if diff := cmp.Diff(map[string]any{"posts": posts}, object(t, call(t, cs, "site_blog", map[string]any{}))); diff != "" {
		t.Errorf("site_blog vs REST GET /blog (-rest +mcp):\n%s", diff)
	}

	one := s.rest(t, apexHost, http.MethodGet, "/blog/first-steps", "")
	got := object(t, call(t, cs, "site_blog", map[string]any{"slug": "first-steps"}))
	delete(got, "markdown")
	if diff := cmp.Diff(entry(one["Post"].(map[string]any), one["Canonical"].(string)), got); diff != "" {
		t.Errorf("site_blog first-steps vs REST GET /blog/first-steps (-rest +mcp):\n%s", diff)
	}
}

// TestSiteBlogLimit: the REST blog has no limiter to share, so MCP has its own.
func TestSiteBlogLimit(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/site", map[string]string{"CF-Connecting-IP": "198.51.100.60"}, nil)
	for i := range 80 {
		if res := call(t, cs, "site_blog", map[string]any{}); res.IsError {
			if !strings.Contains(text(t, res), "Too many requests") || i < 50 {
				t.Errorf("call %d = %q, want limited only past its burst of 50", i+1, text(t, res))
			}
			return
		}
	}
	t.Error("80 site_blog calls in a row were never limited")
}

func TestSiteBlogNeedsTheBlog(t *testing.T) {
	s := newStack(t, stackOpts{bare: true})
	for _, name := range toolNames(t, s.client(t, "/mcp", nil, nil)) {
		if name == "site_blog" {
			t.Error("site_blog is listed without a blog")
		}
	}
	if code := s.do(http.MethodPost, "/mcp/site", listBody, mcpHeaders(nil)).Code; code != http.StatusNotFound {
		t.Errorf("/mcp/site without a blog = %d, want 404", code)
	}
}
