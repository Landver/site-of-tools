// Package tests holds the black-box tests for the site package.
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

func newTestApp() *echo.Echo {
	r := platform.NewRenderer(false,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
	)
	e := echo.New()
	e.Renderer = r
	site.Register(e, platform.Config{Env: "prod", BaseDomain: "corpberry.com", ListenAddr: ":8080"})
	return e
}

func get(app *echo.Echo, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", accept)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestHomeHTML(t *testing.T) {
	rec := get(newTestApp(), "text/html")
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

func TestHomeJSON(t *testing.T) {
	rec := get(newTestApp(), "application/json")
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), "IP → Location") {
		t.Errorf("json should list the tool, got:\n%s", rec.Body.String())
	}
}
