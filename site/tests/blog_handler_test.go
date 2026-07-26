package tests

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
)

// newBlogTestApp mirrors site/tests/site_test.go's newTestApp but with the
// in-memory posts FS from blog_test.go.
func newBlogTestApp(t *testing.T) *echo.Echo {
	t.Helper()
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
	)
	e := echo.New()
	e.Renderer = r
	cfg := platform.Config{Env: "prod", BaseDomain: "corpberry.com", ListenAddr: ":8080"}
	if err := site.Register(e, cfg, testPostsFS()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return e
}

func blogGet(app *echo.Echo, path, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestBlogIndexHTML(t *testing.T) {
	rec := blogGet(newBlogTestApp(t), "/blog", "text/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Third Post") || !strings.Contains(body, "First Post") {
		t.Errorf("index should list published posts, got:\n%s", body)
	}
	if strings.Contains(body, "Draft Post") {
		t.Error("index must not list drafts")
	}
	// Newest first.
	if strings.Index(body, "Third Post") > strings.Index(body, "First Post") {
		t.Error("index should sort newest first")
	}
	if !strings.Contains(body, `/blog/third-post`) {
		t.Error("index should link to post pages")
	}
}

func TestBlogIndexJSON(t *testing.T) {
	rec := blogGet(newBlogTestApp(t), "/blog", "application/json")
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "third-post") {
		t.Errorf("json should include post metadata, got:\n%s", rec.Body.String())
	}
}

func TestBlogPostHTML(t *testing.T) {
	rec := blogGet(newBlogTestApp(t), "/blog/third-post", "text/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Third Post",
		`<a href="https://example.com">link</a>`, // markdown body rendered
		`<meta property="og:type" content="article">`,
		`<link rel="canonical" href="https://corpberry.com/blog/third-post">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("post page missing %q", want)
		}
	}
}

func TestBlogPostNotFound(t *testing.T) {
	rec := blogGet(newBlogTestApp(t), "/blog/no-such-post", "text/html")
	if rec.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", rec.Code)
	}
}

func TestBlogFeed(t *testing.T) {
	rec := blogGet(newBlogTestApp(t), "/blog/feed.xml", "text/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/atom+xml") {
		t.Errorf("content-type = %q, want application/atom+xml", ct)
	}
	body := rec.Body.String()
	var parsed struct {
		XMLName xml.Name `xml:"feed"`
		Entries []struct {
			Title string `xml:"title"`
		} `xml:"entry"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("feed is not well-formed XML: %v", err)
	}
	if len(parsed.Entries) != 2 {
		t.Errorf("feed has %d entries, want 2 (draft excluded)", len(parsed.Entries))
	}
	if !strings.Contains(body, "https://corpberry.com/blog/third-post") {
		t.Error("feed entries should carry absolute URLs")
	}
}
