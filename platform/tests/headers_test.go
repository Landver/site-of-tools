package tests

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// headersApp builds the app the way every subdomain gets it: through NewApp, so
// the middleware stack under test is the production one and a header that is
// only set by a tool's own code cannot stand in for one set here.
func headersApp(t *testing.T) *echo.Echo {
	t.Helper()
	e := platform.NewApp(nil, fstest.MapFS{}, false, nil)
	e.GET("/", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })
	e.GET("/boom", func(c *echo.Context) error { return echo.NewHTTPError(http.StatusInternalServerError, "boom") })
	return e
}

func headersFor(t *testing.T, e *echo.Echo, path string) http.Header {
	t.Helper()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Header()
}

// TestSecurityHeadersPresent: these are set in NewApp precisely so a new tool
// cannot forget them, which means nothing else in the repo sets them and
// nothing else would notice if they stopped being set.
func TestSecurityHeadersPresent(t *testing.T) {
	cases := []struct {
		header, want, why string
	}{
		{"X-Content-Type-Options", "nosniff",
			"without it a response whose body is attacker-influenced can be sniffed into something executable regardless of its declared type"},
		{"X-Frame-Options", "DENY",
			"the legacy half of frame-ancestors; browsers that ignore the CSP still honour this, and clickjacking a tool that renders attacker URLs is cheap"},
		{"Referrer-Policy", "strict-origin-when-cross-origin",
			"the request URI on link.corpberry.com carries the visitor's pasted URL, so a full Referer would hand it to whatever the page links to"},
	}

	e := headersApp(t)
	// Every response, not just the happy one: an error response is the one most
	// likely to echo attacker input back, so it needs the headers most.
	for _, path := range []string{"/", "/boom", "/does-not-exist"} {
		h := headersFor(t, e, path)
		for _, c := range cases {
			if got := h.Get(c.header); got != c.want {
				t.Errorf("%s on %s = %q, want %q — %s", c.header, path, got, c.want, c.why)
			}
		}
		if h.Get("Content-Security-Policy") == "" {
			t.Errorf("no Content-Security-Policy on %s — the containment layer is absent on exactly the responses that need it", path)
		}
	}
}

// TestCSPDirectives pins the directives that are load-bearing, one assertion
// each, so deleting any single one fails this test by name rather than being
// absorbed into a whole-string comparison nobody can read.
//
// Two of these are regressions that already happened and were found by loading
// a page rather than by reading the policy: worker-src (botcheck spawns a
// Worker from a blob: URL, and worker-src falls back to script-src, which does
// not allow blob:) and connect-src (the IP tool asks api6.ipify.org from the
// VISITOR's browser, because only the visitor's own connection can answer "do
// you have working IPv6").
func TestCSPDirectives(t *testing.T) {
	csp := headersFor(t, headersApp(t), "/").Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header at all; nothing below can be asserted")
	}

	required := []struct {
		directive, why string
	}{
		{"default-src 'self'",
			"the floor every other directive falls back to"},
		{"worker-src 'self' blob:",
			"botcheck spawns a blob: Worker to time things off the main thread; drop blob: here and that tool silently stops working"},
		{"connect-src 'self' https://api6.ipify.org",
			"the IP tool's live IPv6 check is the single external endpoint the frontend talks to; drop it and the check breaks, widen it and connect-src stops meaning anything"},
		{"frame-ancestors 'none'",
			"no origin may frame these pages"},
		{"base-uri 'none'",
			"a <base> injected into a page that renders attacker-chosen URLs would rewrite every relative link on it"},
		{"object-src 'none'",
			"plugins are a script-execution path that script-src does not cover"},
		{"form-action 'self'",
			"on link.corpberry.com, whose whole job is rendering attacker-chosen URLs, this is what stops an injected form posting off-site"},
		{"style-src 'self' 'unsafe-inline'",
			"Alpine and the vendored CSS need inline styles; asserted so a tightening is a deliberate edit with a test to match"},
		{"img-src 'self' data:",
			"every page's favicon is an inline data: SVG (shared/templates/partials/head.html)"},
	}

	for _, r := range required {
		t.Run(strings.SplitN(r.directive, " ", 2)[0], func(t *testing.T) {
			if !strings.Contains(csp, r.directive) {
				t.Errorf("CSP is missing %q — %s.\nfull policy: %s", r.directive, r.why, csp)
			}
		})
	}

	// script-src is deliberately permissive (Alpine's runtime directives need
	// 'unsafe-eval', three templates carry inline blocks). What must NOT happen
	// is that permissiveness spreading: no wildcard source anywhere, or the
	// policy stops being a containment layer at all.
	if strings.Contains(csp, "*") {
		t.Errorf("CSP contains a wildcard source: %s — that turns the whole policy into decoration", csp)
	}
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("script-src no longer starts from 'self': %s — the one thing it does buy is that no script may be loaded from another origin", csp)
	}
}
