package tests

import (
	"net/http/httptest"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
)

func TestBlogJSONGolden(t *testing.T) {
	app := newTestApp(t)
	got := map[string]*httptest.ResponseRecorder{}
	for name, path := range map[string]string{
		"index":       "/blog",
		"post_third":  "/blog/third-post",
		"post_first":  "/blog/first-post",
		"post_draft":  "/blog/draft-post",
		"post_absent": "/blog/no-such-post",
	} {
		got[name] = get(app, path, "application/json")
	}
	goldentest.JSON(t, "blog", goldentest.Recorded(got))
}
