// Package tests: black-box tests for site package.
package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
)

func newTestApp(t *testing.T) *echo.Echo {
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

func get(app *echo.Echo, path, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestHomeHTML(t *testing.T) {
	rec := get(newTestApp(t), "/", "text/html")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<html") {
		t.Error("home should be a full HTML page")
	}
	if !strings.Contains(body, "ip.corpberry.com") {
		t.Errorf("home should link to the ip tool, got:\n%s", body)
	}
}

func TestHomeOmitsIP2LocationCredit(t *testing.T) {
	// Apex uses no IP2Location or blocklist data → neither credit must appear
	// here; both scoped to IP tool + botcheck via .Attribution flag.
	body := get(newTestApp(t), "/", "text/html").Body.String()
	if strings.Contains(body, "lite.ip2location.com") || strings.Contains(body, "IP2Location LITE database") {
		t.Errorf("apex must not show the IP2Location credit (it uses no such data), got:\n%s", body)
	}
	if strings.Contains(body, "Spamhaus") {
		t.Errorf("apex must not show the Spamhaus credit (it uses no such data), got:\n%s", body)
	}
}

func TestHomeJSON(t *testing.T) {
	rec := get(newTestApp(t), "/", "application/json")
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "IP Tools") {
		t.Errorf("json should list the tool, got:\n%s", rec.Body.String())
	}
}

func TestHomeOGTags(t *testing.T) {
	body := get(newTestApp(t), "/", "text/html").Body.String()
	for _, want := range []string{
		`<meta property="og:type" content="website">`,
		`<meta property="og:site_name" content="corpberry.com">`,
		`<meta property="og:title" content="Stas — corpberry.com">`,
		`<meta property="og:image" content="https://corpberry.com/static/img/og-cover.png">`,
		`<meta name="twitter:card" content="summary_large_image">`,
		`content="Open-source web tools by Stas`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("home <head> missing %q", want)
		}
	}
}

func TestThemeScriptCookieSharedDarkDefault(t *testing.T) {
	body := get(newTestApp(t), "/", "text/html").Body.String()
	// Old per-origin / OS-preference logic must be gone entirely.
	for _, gone := range []string{"localStorage", "matchMedia", "prefers-color-scheme"} {
		if strings.Contains(body, gone) {
			t.Errorf("theme script must not reference %q anymore", gone)
		}
	}
	// New contract: validated cookie read, unconditional dark default,
	// parent-Domain write shared across subdomains.
	for _, want := range []string{
		`readTheme() || "dark"`, // no cookie → dark
		`theme=(dark|light)`,    // cookie read validates value
		`"; Domain="`,           // parent-domain scope
		"window.toggleTheme",    // header button hook preserved
	} {
		if !strings.Contains(body, want) {
			t.Errorf("theme script should contain %q, got:\n%s", want, body)
		}
	}
}
