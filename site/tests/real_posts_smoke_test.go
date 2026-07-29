package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/site"
)

// Temporary smoke test: the shipped posts (embedded FS) must all parse.
func TestRealEmbeddedPostsLoad(t *testing.T) {
	posts, err := site.LoadPosts(site.Posts)
	if err != nil {
		t.Fatalf("LoadPosts(site.Posts): %v", err)
	}
	if len(posts) == 0 {
		t.Fatal("no posts loaded from embedded FS")
	}
	for _, p := range posts {
		t.Logf("%s %q (%s)", p.Date.Format("2006-01-02"), p.Title, p.Slug)
	}
}
