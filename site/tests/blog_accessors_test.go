package tests

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
)

func TestRegisterReturnsTheServedBlog(t *testing.T) {
	for _, env := range []string{"prod", "dev"} {
		blog, err := site.Register(echo.New(), platform.Config{Env: env, BaseDomain: "corpberry.com", ListenAddr: ":8080"}, testPostsFS())
		if err != nil {
			t.Fatalf("%s: Register: %v", env, err)
		}
		if p, err := blog.Post("first-post"); err != nil || p.Title != "First Post" {
			t.Errorf("%s: Post(first-post) = %q, %v", env, p.Title, err)
		}
		if _, err := blog.Post("draft-post"); !errors.Is(err, site.ErrPostNotFound) {
			t.Errorf("%s: Post(draft-post) err = %v, want ErrPostNotFound", env, err)
		}
	}
	if _, err := site.Register(echo.New(), platform.Config{Env: "prod"}, fstest.MapFS{"bad.md": &fstest.MapFile{Data: []byte("no frontmatter")}}); err == nil {
		t.Error("Register with a malformed post: want an error")
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
