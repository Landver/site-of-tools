package tests

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
)

func TestBlogAccessors(t *testing.T) {
	for _, dev := range []bool{false, true} {
		blog, err := site.NewBlog(testPostsFS(), dev)
		if err != nil {
			t.Fatalf("dev=%v: NewBlog: %v", dev, err)
		}
		posts, err := blog.Posts()
		if err != nil {
			t.Fatalf("dev=%v: Posts: %v", dev, err)
		}
		var slugs []string
		for _, p := range posts {
			slugs = append(slugs, p.Slug)
		}
		if diff := cmp.Diff([]string{"third-post", "first-post"}, slugs); diff != "" {
			t.Errorf("dev=%v: Posts slugs (-want +got):\n%s", dev, diff)
		}

		p, err := blog.Post("first-post")
		if err != nil || p.Title != "First Post" {
			t.Errorf("dev=%v: Post(first-post) = %q, %v", dev, p.Title, err)
		}
		for _, slug := range []string{"draft-post", "no-such-post", ""} {
			if _, err := blog.Post(slug); !errors.Is(err, site.ErrPostNotFound) {
				t.Errorf("dev=%v: Post(%q) err = %v, want ErrPostNotFound", dev, slug, err)
			}
		}
	}
}

func TestBlogPostsIsTheCallersCopy(t *testing.T) {
	blog, err := site.NewBlog(testPostsFS(), false)
	if err != nil {
		t.Fatal(err)
	}
	posts, _ := blog.Posts()
	posts[0].Title, posts[0].Markdown = "changed", "changed"
	again, _ := blog.Post(posts[0].Slug)
	if again.Title == "changed" || again.Markdown == "changed" {
		t.Error("editing the slice Posts returned changed the loaded posts")
	}
}

func TestPostMarkdownDropsFrontmatter(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"plain", "---\ntitle: \"A\"\ndate: \"2026-07-20\"\n---\n\nHello **body**.\n", "Hello **body**.\n"},
		{"crlf", "---\r\ntitle: \"A\"\r\ndate: \"2026-07-20\"\r\n---\r\n\r\nBody.\r\n", "Body.\r\n"},
		{"later rule kept", "---\ntitle: \"A\"\ndate: \"2026-07-20\"\n---\nIntro\n\n---\n\nAfter\n", "Intro\n\n---\n\nAfter\n"},
		{"long separators", "-----\ntitle: \"A\"\ndate: \"2026-07-20\"\n-----\nBody\n", "Body\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			posts, err := site.LoadPosts(fstest.MapFS{"2026-07-20-a.md": &fstest.MapFile{Data: []byte(tc.src)}})
			if err != nil {
				t.Fatalf("LoadPosts: %v", err)
			}
			if posts[0].Markdown != tc.want {
				t.Errorf("Markdown = %q, want %q", posts[0].Markdown, tc.want)
			}
		})
	}
}

func TestRealPostsKeepMarkdownWithoutFrontmatter(t *testing.T) {
	posts, err := site.LoadPosts(site.Posts)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range posts {
		if p.Markdown == "" || strings.HasPrefix(p.Markdown, "---") || strings.Contains(p.Markdown, `date: "`) {
			t.Errorf("%s: Markdown still carries frontmatter or is empty: %.80q", p.Slug, p.Markdown)
		}
	}
}

func TestRegisterReturnsTheServedBlog(t *testing.T) {
	cfg := platform.Config{Env: "prod", BaseDomain: "corpberry.com", ListenAddr: ":8080"}
	blog, err := site.Register(echo.New(), cfg, testPostsFS())
	if err != nil || blog == nil {
		t.Fatalf("Register = %v, %v", blog, err)
	}
	if posts, err := blog.Posts(); err != nil || len(posts) != 2 {
		t.Errorf("blog.Posts() = %d posts, %v; want 2", len(posts), err)
	}
	if _, err := site.Register(echo.New(), cfg, fstest.MapFS{"bad.md": &fstest.MapFile{Data: []byte("no frontmatter")}}); err == nil {
		t.Error("Register with a malformed post: want an error")
	}
}
