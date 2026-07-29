// Package tests: black-box tests for site package.
package tests

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Landver/site-of-tools/site"
)

func testPostsFS() fstest.MapFS {
	return fstest.MapFS{
		"2026-07-20-first-post.md": &fstest.MapFile{Data: []byte(`---
title: "First Post"
description: "The first test post."
date: "2026-07-20"
image: "https://example.com/first-card.png"
---

Hello **first** body.
`)},
		"2026-07-22-draft-post.md": &fstest.MapFile{Data: []byte(`---
title: "Draft Post"
description: "Not published yet."
date: "2026-07-22"
draft: true
---

Draft body.
`)},
		"2026-07-25-third-post.md": &fstest.MapFile{Data: []byte(`---
title: "Third Post"
description: "The third test post."
date: "2026-07-25"
image: "/static/img/post-card.png"
---

Third body with a [link](https://example.com).
`)},
	}
}

func TestLoadPosts(t *testing.T) {
	posts, err := site.LoadPosts(testPostsFS())
	if err != nil {
		t.Fatalf("LoadPosts: %v", err)
	}
	if len(posts) != 2 {
		t.Fatalf("got %d posts, want 2 (draft filtered)", len(posts))
	}
	// Sorted by date descending.
	if posts[0].Slug != "third-post" || posts[1].Slug != "first-post" {
		t.Errorf("order = [%s %s], want [third-post first-post]", posts[0].Slug, posts[1].Slug)
	}
	// Slug derived from filename minus date prefix.
	if posts[1].Slug != "first-post" {
		t.Errorf("slug = %q, want %q", posts[1].Slug, "first-post")
	}
	// Frontmatter fields.
	if posts[1].Title != "First Post" || posts[1].Desc != "The first test post." {
		t.Errorf("frontmatter = %q / %q", posts[1].Title, posts[1].Desc)
	}
	// Optional og:image frontmatter: site path and absolute URL both kept verbatim.
	if posts[0].Image != "/static/img/post-card.png" {
		t.Errorf("third-post image = %q, want site path", posts[0].Image)
	}
	if posts[1].Image != "https://example.com/first-card.png" {
		t.Errorf("first-post image = %q, want absolute URL", posts[1].Image)
	}
	want := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	if !posts[1].Date.Equal(want) {
		t.Errorf("date = %v, want %v", posts[1].Date, want)
	}
	// Markdown rendered to HTML.
	if !strings.Contains(string(posts[1].HTML), "<strong>first</strong>") {
		t.Errorf("HTML missing bold render, got %q", posts[1].HTML)
	}
}

func TestLoadPostsMissingTitle(t *testing.T) {
	fsys := fstest.MapFS{
		"2026-07-20-broken.md": &fstest.MapFile{Data: []byte(`---
date: "2026-07-20"
---

No title here.
`)},
	}
	if _, err := site.LoadPosts(fsys); err == nil {
		t.Fatal("want error for post without title")
	}
}

func TestLoadPostsBadDate(t *testing.T) {
	fsys := fstest.MapFS{
		"2026-07-20-broken.md": &fstest.MapFile{Data: []byte(`---
title: "Broken"
date: "not-a-date"
---

Body.
`)},
	}
	if _, err := site.LoadPosts(fsys); err == nil {
		t.Fatal("want error for post with unparseable date")
	}
}

func TestLoadPostsAutolinksBareURLs(t *testing.T) {
	fsys := fstest.MapFS{
		"2026-07-20-links.md": &fstest.MapFile{Data: []byte(`---
title: "Links"
date: "2026-07-20"
---

See https://example.com for details.
`)},
	}
	posts, err := site.LoadPosts(fsys)
	if err != nil {
		t.Fatalf("LoadPosts: %v", err)
	}
	want := `<a href="https://example.com">https://example.com</a>`
	if !strings.Contains(string(posts[0].HTML), want) {
		t.Errorf("bare URL not autolinked, want %q in %q", want, posts[0].HTML)
	}
}
