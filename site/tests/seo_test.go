package tests

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
)

// Sitemap shape, mirrored here rather than exported from site — a test that
// unmarshals independently catches a field-name change in the real thing.
type sitemap struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"url"`
}

func fetchSitemap(t *testing.T) sitemap {
	t.Helper()
	rec := get(newTestApp(t), "/sitemap.xml", "application/xml")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "xml") {
		t.Errorf("content-type = %q, want xml", ct)
	}
	var got sitemap
	if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("sitemap is not valid XML: %v\n%s", err, rec.Body.String())
	}
	return got
}

func TestSitemapListsPagesAndPosts(t *testing.T) {
	got := fetchSitemap(t)
	locs := make(map[string]string, len(got.URLs))
	for _, u := range got.URLs {
		locs[u.Loc] = u.LastMod
	}
	for _, want := range []string{
		"https://corpberry.com/",
		"https://corpberry.com/blog",
		"https://corpberry.com/blog/third-post",
		"https://corpberry.com/blog/first-post",
	} {
		if _, ok := locs[want]; !ok {
			t.Errorf("sitemap missing %q, got %v", want, locs)
		}
	}
	// Every loc must be absolute — a relative sitemap entry is silently
	// dropped by crawlers, which is invisible until you check a validator.
	for loc := range locs {
		if !strings.HasPrefix(loc, "https://") {
			t.Errorf("loc %q is not absolute", loc)
		}
	}
	if lm := locs["https://corpberry.com/blog/third-post"]; lm == "" {
		t.Error("post entries should carry lastmod")
	}
}

func TestSitemapExcludesDrafts(t *testing.T) {
	for _, u := range fetchSitemap(t).URLs {
		if strings.Contains(u.Loc, "draft") {
			t.Errorf("sitemap must not list drafts, got %q", u.Loc)
		}
	}
}

func TestRobotsAllowsAllAndPointsAtSitemap(t *testing.T) {
	rec := get(newTestApp(t), "/robots.txt", "text/plain")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sitemap: https://corpberry.com/sitemap.xml") {
		t.Errorf("robots.txt should advertise the sitemap, got:\n%s", body)
	}
	// This site wants to be indexed and cited: nothing may be disallowed.
	if strings.Contains(body, "Disallow: /") {
		t.Errorf("robots.txt must not disallow crawling, got:\n%s", body)
	}
}

func TestPostEmitsArticleJSONLD(t *testing.T) {
	body := get(newTestApp(t), "/blog/third-post", "text/html").Body.String()
	const open = `<script type="application/ld+json">`
	i := strings.Index(body, open)
	if i < 0 {
		t.Fatalf("post page should embed ld+json, got:\n%s", body)
	}
	raw := body[i+len(open):]
	raw = raw[:strings.Index(raw, "</script>")]

	// Must survive a real JSON parse: html/template escaping the payload
	// would break every consumer, and only a parse catches it.
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("ld+json is not valid JSON: %v\n%s", err, raw)
	}
	if doc["@type"] != "BlogPosting" {
		t.Errorf("@type = %v, want BlogPosting", doc["@type"])
	}
	if doc["url"] != "https://corpberry.com/blog/third-post" {
		t.Errorf("url = %v, want the canonical post URL", doc["url"])
	}
	if doc["datePublished"] == "" || doc["datePublished"] == nil {
		t.Error("datePublished must be set")
	}
	author, ok := doc["author"].(map[string]any)
	if !ok {
		t.Fatalf("author should be an object, got %T", doc["author"])
	}
	if author["name"] != "Stas" {
		t.Errorf("author.name = %v, want Stas", author["name"])
	}
	if author["@type"] != "Person" {
		t.Errorf("author.@type = %v, want Person", author["@type"])
	}
}

func TestPostEmitsAuthorAndDateMeta(t *testing.T) {
	body := get(newTestApp(t), "/blog/third-post", "text/html").Body.String()
	for _, want := range []string{
		`<meta name="author" content="Stas">`,
		`<meta property="article:published_time" content="`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("post page missing %q", want)
		}
	}
}

// The head partial is shared with every tool, so the article-only tags must
// not leak onto pages that pass no Author/Published/JSONLD.
func TestNonArticlePagesOmitArticleMeta(t *testing.T) {
	for _, path := range []string{"/", "/blog"} {
		body := get(newTestApp(t), path, "text/html").Body.String()
		for _, unwanted := range []string{
			`<meta name="author"`,
			`article:published_time`,
			`application/ld+json`,
		} {
			if strings.Contains(body, unwanted) {
				t.Errorf("%s should not carry %q", path, unwanted)
			}
		}
	}
}
