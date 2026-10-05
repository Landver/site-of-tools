package tests

import (
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

const firstStepsMarkdown = `![The first page](https://corpberry.test/static/img/first.png "First")

Read [the next post](https://corpberry.test/blog/second-thoughts), the [notes](https://corpberry.test/blog/notes.txt) beside this one,
[the spec](https://example.com/spec), [a mail](mailto:stas@example.com) and [the end](https://corpberry.test/blog/first-steps#end).

<img src="https://corpberry.test/static/img/inline.png" alt="inline">

In code, ` + "`[kept](/as/is)`" + ` stays.

` + "```md\n![kept too](/static/img/raw.png)\n```" + `

[paper]: https://corpberry.test/static/files/paper.pdf
`

// The second post is over the sanitizer's string cap.
var testPosts = fstest.MapFS{
	"2026-09-01-first-steps.md": {Data: []byte(firstSteps)},
	"2026-09-20-second-thoughts.md": {Data: []byte("---\ntitle: \"Second thoughts\"\ndescription: \"Later, and longer.\"\ndate: \"2026-09-20\"\n---\n\n" +
		strings.Repeat("A long paragraph. ", 200) + "\n")},
	"2026-09-25-unfinished.md": {Data: []byte("---\ntitle: \"Unfinished\"\ndate: \"2026-09-25\"\ndraft: true\n---\n\nNot yet.\n")},
}

func TestSiteBlogParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp/site", nil)
	entry := func(p any, url string) map[string]any {
		m := p.(map[string]any)
		return map[string]any{"slug": m["Slug"], "title": m["Title"], "date": m["Date"].(string)[:10], "description": m["Desc"], "url": url}
	}

	list := s.restOK(t, apexHost, "/blog", "")
	var posts []any
	for _, p := range list["Posts"].([]any) {
		posts = append(posts, entry(p, list["Canonical"].(string)+"/"+p.(map[string]any)["Slug"].(string)))
	}
	if diff := cmp.Diff(map[string]any{"posts": posts}, object(t, call(t, cs, "site_blog", map[string]any{}))); diff != "" {
		t.Errorf("site_blog vs REST GET /blog (-rest +mcp):\n%s", diff)
	}

	one := s.restOK(t, apexHost, "/blog/first-steps", "")
	want := entry(one["Post"], one["Canonical"].(string))
	want["markdown"] = firstStepsMarkdown
	if diff := cmp.Diff(want, object(t, call(t, cs, "site_blog", map[string]any{"slug": " first-steps "}))); diff != "" {
		t.Errorf("site_blog first-steps vs REST GET /blog/first-steps (-rest +mcp):\n%s", diff)
	}

	long := object(t, call(t, cs, "site_blog", map[string]any{"slug": "second-thoughts"}))["markdown"].(string)
	if want := strings.Repeat("A long paragraph. ", 200) + "\n"; long != want {
		t.Errorf("second-thoughts came back as %d bytes of %d", len(long), len(want))
	}
}

// The REST blog has no limiter to share, so site_blog has its own.
func TestSiteBlogLimit(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/site", map[string]string{"CF-Connecting-IP": "198.51.100.60"})
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
