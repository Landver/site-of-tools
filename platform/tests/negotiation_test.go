package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// TestNegotiation drives the content-negotiation predicates through a real
// request via a throwaway route, using only the exported API.
func TestNegotiation(t *testing.T) {
	e := echo.New()
	e.GET("/n", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]bool{
			"json": platform.WantsJSON(c),
			"htmx": platform.IsHTMX(c),
			"text": platform.WantsText(c),
		})
	})

	tests := []struct {
		name             string
		hdr              map[string]string
		json, htmx, text bool
	}{
		{"curl default */*", map[string]string{"Accept": "*/*"}, true, false, false},
		{"no accept header", nil, true, false, false},
		{"browser text/html", map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}, false, false, false},
		{"explicit json", map[string]string{"Accept": "application/json"}, true, false, false},
		{"htmx", map[string]string{"HX-Request": "true", "Accept": "*/*"}, false, true, false},
		{"htmx overrides json accept", map[string]string{"HX-Request": "true", "Accept": "application/json"}, false, true, false},
		{"explicit text/plain", map[string]string{"Accept": "text/plain"}, true, false, true},
		{"text/plain with html present", map[string]string{"Accept": "text/html, text/plain"}, false, false, false},
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
			if got["json"] != tt.json || got["htmx"] != tt.htmx || got["text"] != tt.text {
				t.Errorf("got json=%v htmx=%v text=%v, want json=%v htmx=%v text=%v",
					got["json"], got["htmx"], got["text"], tt.json, tt.htmx, tt.text)
			}
		})
	}
}
