package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// fakeLooker implements iptools.Looker so the handler is tested without the
// real databases.
type fakeLooker struct {
	res *iptools.Result
	err error
}

func (f fakeLooker) Lookup(string) (*iptools.Result, error) { return f.res, f.err }

// newTestApp builds a bare echo with the real (embedded) templates and the given
// Looker. Embedded FS is used so it works regardless of the test's cwd.
func newTestApp(svc iptools.Looker) *echo.Echo {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
	)
	e := echo.New()
	e.Renderer = r
	iptools.Register(e, svc, nil) // nil History: persistence off in handler tests
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
	want := &iptools.Result{IP: "8.8.8.8", CountryCode: "US", Country: "United States", ASN: "15169", ASName: "Google LLC"}
	rec := do(newTestApp(fakeLooker{res: want}), "/?ip=8.8.8.8", map[string]string{"Accept": "application/json"})

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var got iptools.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff := cmp.Diff(want, &got); diff != "" {
		t.Errorf("Result mismatch (-want +got):\n%s", diff)
	}
}

func TestHandlerPlainCurlGetsJSON(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptools.Result{IP: "1.1.1.1"}}), "/?ip=1.1.1.1", map[string]string{"Accept": "*/*"})
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("plain curl content-type = %q, want application/json", ct)
	}
}

func TestHandlerBrowserGetsFullPage(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptools.Result{IP: "8.8.8.8"}}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("browser response should be a full page, got:\n%s", rec.Body.String())
	}
}

func TestHandlerHTMXGetsFragment(t *testing.T) {
	rec := do(newTestApp(fakeLooker{res: &iptools.Result{IP: "8.8.8.8", City: "Mountain View"}}), "/?ip=8.8.8.8", map[string]string{"HX-Request": "true"})
	body := rec.Body.String()
	if strings.Contains(body, "<html") {
		t.Errorf("htmx response should be a fragment, not a full page:\n%s", body)
	}
	if !strings.Contains(body, "Mountain View") {
		t.Errorf("fragment missing the result data:\n%s", body)
	}
}

func TestHandlerBadIPRendersErrorFragment(t *testing.T) {
	// A malformed IP makes the domain Lookup fail with a validation error (not
	// ErrUnavailable). The htmx path must return 400 *and* the error-alert
	// fragment, so the box shows "not a valid IP" instead of silently keeping the
	// previous result. (The client swaps this 400 in via htmx:beforeSwap — see
	// ip/index.html; htmx would otherwise drop a 4xx response.)
	app := newTestApp(fakeLooker{err: errors.New(`"104.253.63." is not a valid IP address`)})
	rec := do(app, "/?ip=104.253.63.", map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad IP code = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "alert-error") || !strings.Contains(body, "not a valid IP address") {
		t.Errorf("bad IP should render the error alert fragment, got:\n%s", body)
	}
}

func TestHandlerErrorStatus(t *testing.T) {
	rec := do(newTestApp(fakeLooker{err: iptools.ErrUnavailable}), "/?ip=1.2.3.4", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ErrUnavailable → code %d, want 503", rec.Code)
	}
}

func TestHandlerDefaultsToVisitorIP(t *testing.T) {
	// Bare "/" with no ?ip looks up the caller's own (routable) IP.
	app := newTestApp(fakeLooker{res: &iptools.Result{IP: "203.0.113.7", CountryCode: "US"}})
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

func TestHandlerJSONWithoutResolvableIPGetsError(t *testing.T) {
	// A JSON caller with no ?ip and a non-routable own address (loopback, as in
	// dev) has nothing to look up: it must get a JSON error, not the HTML page —
	// the same content-negotiation contract /cidr already follows.
	app := newTestApp(fakeLooker{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	req.RemoteAddr = "127.0.0.1:5555" // loopback is not routable
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("body should carry an \"error\" key, got: %s", rec.Body.String())
	}
}

func TestHandlerBrowserWithoutResolvableIPGetsPage(t *testing.T) {
	// Same situation as above but from a browser: the empty lookup page (with the
	// form and the connection inspector) is the right response — only JSON callers
	// get the 400.
	app := newTestApp(fakeLooker{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("browser with no resolvable IP should get the lookup page, got:\n%s", rec.Body.String())
	}
}

func TestHandlerHTMXWithoutResolvableIPGetsFragment(t *testing.T) {
	// An htmx submit with an empty box from a non-routable own IP (dev on
	// loopback) must get the (empty) result fragment — swapping a full page into
	// #result would nest a whole document inside it.
	app := newTestApp(fakeLooker{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("HX-Request", "true")
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("htmx with no resolvable IP should get the fragment, not a full page:\n%s", rec.Body.String())
	}
}

func TestFullPageShowsIP2LocationCredit(t *testing.T) {
	// IP2Location LITE's license requires its exact acknowledgment on any page that
	// uses the data. The full IP-tool page must carry it (the apex must not — see
	// the site package's TestHomeOmitsIP2LocationCredit).
	rec := do(newTestApp(fakeLooker{res: &iptools.Result{IP: "8.8.8.8"}}), "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "uses the IP2Location LITE database") || !strings.Contains(body, "lite.ip2location.com") {
		t.Errorf("full IP-tool page must carry the IP2Location LITE credit, got:\n%s", body)
	}
}

func TestConnectionInspectorCard(t *testing.T) {
	app := newTestApp(fakeLooker{res: &iptools.Result{IP: "198.51.100.7"}})
	req := httptest.NewRequest(http.MethodGet, "/?ip=198.51.100.7", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-For", "198.51.100.7") // drives the default RealIP
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, want := range []string{"your request", "198.51.100.7", "Cloudflare"} {
		if !strings.Contains(body, want) {
			t.Errorf("connection inspector missing %q in:\n%s", want, body)
		}
	}
}

func TestConnectionInspectorHidesSecrets(t *testing.T) {
	// The inspector must never reflect Cookie / Authorization back into the page.
	app := newTestApp(fakeLooker{res: &iptools.Result{IP: "198.51.100.7"}})
	req := httptest.NewRequest(http.MethodGet, "/?ip=198.51.100.7", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Cookie", "session=SUPERSECRETVALUE")
	req.Header.Set("Authorization", "Bearer SUPERSECRETVALUE")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "SUPERSECRETVALUE") {
		t.Errorf("inspector leaked a Cookie/Authorization value:\n%s", rec.Body.String())
	}
}

func TestCIDRCalculatorJSON(t *testing.T) {
	rec := do(newTestApp(fakeLooker{}), "/cidr?cidr=192.168.1.0/24", map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"network":"192.168.1.0"`, `"broadcast":"192.168.1.255"`, `"netmask":"255.255.255.0"`, `"usable_hosts":"254"`} {
		if !strings.Contains(body, want) {
			t.Errorf("cidr JSON missing %s in:\n%s", want, body)
		}
	}
}

func TestCIDRCalculatorPage(t *testing.T) {
	// HTML page renders the form + the suite sub-nav.
	rec := do(newTestApp(fakeLooker{}), "/cidr", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "Subnet calculator") || !strings.Contains(body, "IP lookup") {
		t.Errorf("cidr page missing heading/sub-nav:\n%s", body)
	}
	// Bad input → 400.
	if bad := do(newTestApp(fakeLooker{}), "/cidr?cidr=nope", map[string]string{"Accept": "text/html"}); bad.Code != http.StatusBadRequest {
		t.Errorf("bad CIDR code = %d, want 400", bad.Code)
	}
}

func TestHandlerShowsProxySection(t *testing.T) {
	res := &iptools.Result{
		IP: "1.2.3.4", CountryCode: "US",
		Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN", UsageType: "VPN", ISP: "Acme VPN"},
	}
	// HTML renders a proxy section.
	rec := do(newTestApp(fakeLooker{res: res}), "/?ip=1.2.3.4", map[string]string{"Accept": "text/html"})
	body := rec.Body.String()
	if !strings.Contains(body, "proxy / network") || !strings.Contains(body, "VPN") {
		t.Errorf("expected a proxy section with VPN, got:\n%s", body)
	}
	// JSON includes the nested proxy object.
	recj := do(newTestApp(fakeLooker{res: res}), "/?ip=1.2.3.4", map[string]string{"Accept": "application/json"})
	if !strings.Contains(recj.Body.String(), `"is_proxy":true`) {
		t.Errorf("json missing proxy object: %s", recj.Body.String())
	}
}
