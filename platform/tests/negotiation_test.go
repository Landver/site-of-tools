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
