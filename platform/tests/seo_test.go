package tests

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Independent shape, so a field-name change in the real urlset is caught
// rather than silently round-tripped.
type sitemap struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"url"`
}

func seoApp(base string, pages []platform.Page) *echo.Echo {
	e := echo.New()
	platform.RegisterSEO(e, base, func() ([]platform.Page, error) { return pages, nil })
	return e
}

func hit(app *echo.Echo, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestSitemapExpandsPathsAgainstHost(t *testing.T) {
	when := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	rec := hit(seoApp("https://ip.corpberry.com", []platform.Page{
		{Path: "/"},
		{Path: "/cidr", LastMod: when},
	}), "/sitemap.xml")

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "xml") {
		t.Errorf("content-type = %q, want xml", ct)
	}
	var got sitemap
	if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, rec.Body.String())
	}
	if len(got.URLs) != 2 {
		t.Fatalf("got %d urls, want 2", len(got.URLs))
	}
	// Every loc must be absolute and on this host: a crawler ignores a
	// sitemap entry pointing anywhere else, which is invisible without a
	// validator.
	for _, u := range got.URLs {
		if !strings.HasPrefix(u.Loc, "https://ip.corpberry.com/") {
			t.Errorf("loc %q is not absolute on the sitemap's own host", u.Loc)
		}
	}
	if got.URLs[0].LastMod != "" {
		t.Errorf("zero LastMod should omit the element, got %q", got.URLs[0].LastMod)
	}
	if got.URLs[1].LastMod != "2026-07-30" {
		t.Errorf("lastmod = %q, want 2026-07-30", got.URLs[1].LastMod)
	}
}

func TestRobotsAdvertisesOwnHostSitemap(t *testing.T) {
	body := hit(seoApp("https://botcheck.corpberry.com", nil), "/robots.txt").Body.String()
	if !strings.Contains(body, "Sitemap: https://botcheck.corpberry.com/sitemap.xml") {
		t.Errorf("robots.txt should advertise this host's sitemap, got:\n%s", body)
	}
	// These sites exist to be indexed and cited: nothing may be disallowed.
	if strings.Contains(body, "Disallow: /") {
		t.Errorf("robots.txt must not disallow crawling, got:\n%s", body)
	}
}

func TestEmptySitemapIsStillValidXML(t *testing.T) {
	rec := hit(seoApp("https://corpberry.com", nil), "/sitemap.xml")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var got sitemap
	if err := xml.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("empty sitemap must still parse: %v\n%s", err, rec.Body.String())
	}
	if len(got.URLs) != 0 {
		t.Errorf("got %d urls, want 0", len(got.URLs))
	}
}
