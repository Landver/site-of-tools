package tests

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Bare pages don't count against the rate limit.
func TestBarePagesAreNotRateLimited(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	for i := range 40 {
		req := httptest.NewRequest(http.MethodGet, "/email", nil)
		req.Header.Set("Accept", "text/html")
		req.RemoteAddr = "203.0.113.20:1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("bare page load %d: status %d, want 200", i+1, rec.Code)
		}
	}
}

// The full-page 429 keeps the nav and links the refused request.
func TestRateLimitedPageOffersTheSameRequest(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	var body string
	for range 40 {
		req := httptest.NewRequest(http.MethodGet, "/trace?name=example.com", nil)
		req.Header.Set("Accept", "text/html")
		req.RemoteAddr = "203.0.113.21:1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			body = rec.Body.String()
			break
		}
	}
	if body == "" {
		t.Fatal("never hit the limit")
	}
	for _, want := range []string{`id="dns-nav"`, `href="/trace?name=example.com"`, "Try again"} {
		if !strings.Contains(body, want) {
			t.Errorf("429 page is missing %q", want)
		}
	}
}

// htmx fragments carry nav, title and status out of band, and push the clean URL.
func TestFragmentCarriesNavTitleAndCleanURL(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/?name="+url.QueryEscape("https://Example.com/pricing")+"&type=all",
		map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`hx-swap-oob="true"`, `href="/email?name=example.com"`,
		"<title>example.com · DNS Tools</title>",
		`id="dns-status" hx-swap-oob="innerHTML"`,
		"taken from what you entered",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fragment is missing %q", want)
		}
	}
	if got := rec.Header().Get("HX-Push-Url"); got != "/?name=example.com&type=all" {
		t.Errorf("HX-Push-Url = %q, want the clean URL", got)
	}

	// A full page has no out-of-band copies.
	page := do(t, e, "/?name=example.com", map[string]string{"Accept": "text/html"}).Body.String()
	if n := strings.Count(page, `id="dns-nav"`); n != 1 {
		t.Errorf("full page renders %d navs, want 1", n)
	}
	if strings.Contains(page, "hx-swap-oob") {
		t.Error("full page carries an out-of-band swap")
	}
}
