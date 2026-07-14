package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/iptolocation"
	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
)

// fakeLooker implements iptolocation.Looker so the handler is tested without the
// real databases.
type fakeLooker struct {
	res *iptolocation.Result
	err error
}

func (f fakeLooker) Lookup(string) (*iptolocation.Result, error) { return f.res, f.err }

// newTestApp builds a bare echo with the real (embedded) templates and the given
// Looker. Embedded FS is used so it works regardless of the test's cwd.
func newTestApp(svc iptolocation.Looker) *echo.Echo {
	r := platform.NewRenderer(false,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptolocation.Templates, DevDir: "iptolocation/templates"},
	)
	e := echo.New()
	e.Renderer = r
	iptolocation.Register(e, svc)
	return e
}

func do(app *echo.Echo, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestHandlerJSONRoundTrip(t *testing.T) {
	want := &iptolocation.Result{IP: "8.8.8.8", CountryCode: "US", Country: "United States", ASN: "15169", ASName: "Google LLC"}
	rec := do(newTestApp(fakeLooker{res: want}), "/8.8.8.8", map[string]string{"Accept": "application/json"})

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var got iptolocation.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff := cmp.Diff(want, &got); diff != "" {
		t.Errorf("Result mismatch (-want +got):\n%s", diff)
	}
}

func TestHandlerPlainCurlGetsJSON(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptolocation.Result{IP: "1.1.1.1"}}), "/1.1.1.1", map[string]string{"Accept": "*/*"})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("plain curl content-type = %q, want application/json", ct)
	}
}

func TestHandlerBrowserGetsFullPage(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptolocation.Result{IP: "8.8.8.8"}}), "/8.8.8.8", map[string]string{"Accept": "text/html"})
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("browser response should be a full page, got:\n%s", rec.Body.String())
	}
}

func TestHandlerHTMXGetsFragment(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptolocation.Result{IP: "8.8.8.8"}}), "/?ip=8.8.8.8", map[string]string{"HX-Request": "true"})
	body := rec.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("htmx response should be a fragment, not a full page:\n%s", body)
	}
	if !strings.Contains(body, "8.8.8.8") {
		t.Errorf("fragment missing the IP:\n%s", body)
	}
}

func TestHandlerErrorStatus(t *testing.T) {
	rec := do(newTestApp(fakeLooker{err: iptolocation.ErrUnavailable}), "/1.2.3.4", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ErrUnavailable → code %d, want 503", rec.Code)
	}
}

func TestHandlerDefaultsToVisitorIP(t *testing.T) {
	// Bare "/" with no ?ip looks up the caller's own (routable) IP.
	app := newTestApp(fakeLooker{res: &iptolocation.Result{IP: "203.0.113.7", CountryCode: "US"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	req.RemoteAddr = "203.0.113.7:5555" // TEST-NET-3 — a routable address
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"country_code":"US"`) {
		t.Errorf("bare / should look up the visitor's own IP, got:\n%s", rec.Body.String())
	}
}
