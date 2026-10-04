package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// TestNegotiation: drives content-negotiation predicates thru real request
// via throwaway route, exported API only.
func TestNegotiation(t *testing.T) {
	e := echo.New()
	e.GET("/n", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]bool{"json": platform.WantsJSON(c), "htmx": platform.IsHTMX(c)})
	})

	tests := []struct {
		name       string
		hdr        map[string]string
		json, htmx bool
	}{
		{"curl default */*", map[string]string{"Accept": "*/*"}, true, false},
		{"no accept header", nil, true, false},
		{"browser text/html", map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}, false, false},
		{"explicit json", map[string]string{"Accept": "application/json"}, true, false},
		{"htmx", map[string]string{"HX-Request": "true", "Accept": "*/*"}, false, true},
		{"htmx overrides json accept", map[string]string{"HX-Request": "true", "Accept": "application/json"}, false, true},
		// Back with htmx's snapshot cache missed: htmx swaps the response in
		// as the whole body, so it must get the page, not a fragment, and
		// not JSON for its */* either.
		{"htmx history restore", map[string]string{"HX-Request": "true", "HX-History-Restore-Request": "true", "Accept": "*/*"}, false, false},
		{"history restore without HX-Request", map[string]string{"HX-History-Restore-Request": "true", "Accept": "*/*"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/n", nil)
			for k, v := range tt.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			var got map[string]bool
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if got["json"] != tt.json || got["htmx"] != tt.htmx {
				t.Errorf("got json=%v htmx=%v, want json=%v htmx=%v", got["json"], got["htmx"], tt.json, tt.htmx)
			}
		})
	}
}

// TestNegotiationHeaders: a URL that answers as page, fragment or JSON says
// so in Vary, never lets a fragment be cached (Back would show it bare), and
// keeps an htmx error out of the history.
func TestNegotiationHeaders(t *testing.T) {
	e := echo.New()
	e.GET("/h", func(c *echo.Context) error {
		code := http.StatusOK
		if c.QueryParam("fail") != "" {
			code = http.StatusBadRequest
		}
		platform.SetNegotiationHeaders(c, code)
		return c.String(code, "x")
	})
	get := func(target string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	browser := map[string]string{"Accept": "text/html"}
	htmx := map[string]string{"Accept": "text/html", "HX-Request": "true"}

	page := get("/h", browser)
	vary := page.Header().Values("Vary")
	for _, want := range []string{"Accept", "HX-Request"} {
		found := false
		for _, v := range vary {
			found = found || v == want
		}
		if !found {
			t.Errorf("Vary = %q, missing %s", vary, want)
		}
	}
	if got := page.Header().Get("Cache-Control"); got != "" {
		t.Errorf("a page got Cache-Control %q; only fragments are kept out of the cache", got)
	}
	if got := get("/h", htmx).Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("fragment Cache-Control = %q, want no-store", got)
	}
	if got := get("/h?fail=1", htmx).Header().Get("HX-Push-Url"); got != "false" {
		t.Errorf("htmx error HX-Push-Url = %q, want false", got)
	}
	if got := get("/h", htmx).Header().Get("HX-Push-Url"); got != "" {
		t.Errorf("a successful fragment carries HX-Push-Url %q; only errors opt out of history", got)
	}
}
