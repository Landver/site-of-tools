package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// fakeLooker stands in for the real resolver so handler tests never touch the
// network.
type fakeLooker struct {
	set       *dnstools.ResultSet
	err       error
	lastName  string
	lastRes   string
	lastTypes []string
}

func (f *fakeLooker) LookupSet(_ context.Context, name, resolver string, types []string) (*dnstools.ResultSet, error) {
	f.lastName, f.lastRes, f.lastTypes = name, resolver, types
	if f.err != nil {
		return nil, f.err
	}
	return f.set, nil
}

// fakeGeo stands in for iptools' geo service.
type fakeGeo struct{ res *iptools.Result }

func (f *fakeGeo) Lookup(string) (*iptools.Result, error) { return f.res, nil }

func newApp(t *testing.T, svc dnstools.Looker, geo iptools.Looker) *echo.Echo {
	t.Helper()
	e := echo.New()
	// Embedded FS for both sources → independent of test cwd, same as the IP
	// tool's handler tests. Shared partials are needed for the full-page render.
	e.Renderer = platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
	)
	dnstools.Register(e, svc, geo, nil) // nil domain client: RDAP/CT off in handler tests
	return e
}

func do(t *testing.T, e *echo.Echo, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func sampleSet() *dnstools.ResultSet {
	return &dnstools.ResultSet{
		Name: "example.com", QName: "example.com.",
		Resolver: "cloudflare", ResolverName: "Cloudflare (1.1.1.1)",
		Flags: "qr rd ra", QueryMS: 12,
		Found: []dnstools.Result{{
			Type:    "A",
			Records: []dnstools.Record{{Type: "A", Value: "93.184.216.34", TTL: 300, TTLHuman: "5m"}},
		}},
		Missing: []string{"CNAME", "CAA"},
	}
}

// A plain curl (no Accept: text/html) gets JSON from the same URL the browser
// renders as a page — golden rule #2.
func TestLookupJSON(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/?name=example.com&type=A", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}

	var got dnstools.ResultSet
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v (body %s)", err, rec.Body)
	}
	if len(got.Found) != 1 || len(got.Found[0].Records) != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.Found[0].Records[0].TTL != 300 || got.Found[0].Records[0].TTLHuman != "5m" {
		t.Errorf("TTL should survive in both forms, got %d / %q",
			got.Found[0].Records[0].TTL, got.Found[0].Records[0].TTLHuman)
	}
	// The empty types collapse into one list rather than vanishing.
	if len(got.Missing) != 2 {
		t.Errorf("missing types = %v, want the two empty ones", got.Missing)
	}
}

func TestLookupHTML(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/?name=example.com", map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"93.184.216.34", "5m", "(300s)", "Cloudflare (1.1.1.1)", "example.com."} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// htmx gets the fragment, not a whole page.
func TestLookupHTMXFragment(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/?name=example.com", map[string]string{"HX-Request": "true"})
	body := rec.Body.String()
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("htmx request got a full page, want just the fragment")
	}
	if !strings.Contains(body, "93.184.216.34") {
		t.Error("fragment is missing the record")
	}
}

// Defaults are applied and passed down, so a bare ?name= works.
func TestDefaultsApplied(t *testing.T) {
	t.Parallel()
	f := &fakeLooker{set: sampleSet()}
	e := newApp(t, f, nil)

	do(t, e, "/?name=example.com", nil)
	if f.lastRes != dnstools.DefaultResolver {
		t.Errorf("default resolver not applied: %q", f.lastRes)
	}
	// No ?type= must mean "everything", not a single default type.
	if f.lastTypes != nil {
		t.Errorf("bare lookup should fan out over all types, got types %v", f.lastTypes)
	}

	do(t, e, "/?name=example.com&type=MX", nil)
	if len(f.lastTypes) != 1 || f.lastTypes[0] != "MX" {
		t.Errorf("explicit type should narrow to it, got %v", f.lastTypes)
	}

	// "all" is the explicit spelling of the default.
	do(t, e, "/?name=example.com&type=all", nil)
	if f.lastTypes != nil {
		t.Errorf("type=all should fan out, got %v", f.lastTypes)
	}
}

// No name: page for browsers, 400 for API callers. Never a full page into an
// htmx slot.
func TestEmptyName(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	if rec := do(t, e, "/", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("JSON caller status = %d, want 400", rec.Code)
	}
	rec := do(t, e, "/", map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Errorf("browser should get the empty form page, got %d", rec.Code)
	}
	frag := do(t, e, "/", map[string]string{"HX-Request": "true"})
	if strings.Contains(frag.Body.String(), "<!DOCTYPE html>") {
		t.Error("htmx got a full page for an empty query")
	}
}

// A caller's mistake is 400; a resolver that failed us is 502.
func TestErrorStatusMapping(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"bad type", dnstools.ErrBadType, http.StatusBadRequest},
		{"bad resolver", dnstools.ErrBadResolver, http.StatusBadRequest},
		{"upstream failure", errUpstream{}, http.StatusBadGateway},
	} {
		e := newApp(t, &fakeLooker{err: tc.err}, nil)
		if rec := do(t, e, "/?name=example.com", nil); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

type errUpstream struct{}

func (errUpstream) Error() string { return "query 1.1.1.1:53: i/o timeout" }

// A and AAAA answers pick up ASN/country from iptools in-process; other record
// types are left alone.
func TestEnrichmentFromIPTools(t *testing.T) {
	t.Parallel()
	set := sampleSet()
	set.Found = append(set.Found, dnstools.Result{
		Type:    "MX",
		Records: []dnstools.Record{{Type: "MX", Value: "mail.example.com.", TTL: 3600, TTLHuman: "1h"}},
	})
	geo := &fakeGeo{res: &iptools.Result{ASN: "15133", ASName: "Edgecast", Country: "United States"}}

	e := newApp(t, &fakeLooker{set: set}, geo)
	rec := do(t, e, "/?name=example.com", nil)

	var got dnstools.ResultSet
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	a := got.Found[0].Records[0]
	if a.ASN != "15133" || a.Country != "United States" {
		t.Errorf("A record was not enriched: %+v", a)
	}
	mx := got.Found[1].Records[0]
	if mx.ASN != "" {
		t.Errorf("MX record should not be enriched, got ASN %q", mx.ASN)
	}
}

// Nil geo service (databases not loaded) must not break the lookup.
func TestNilGeoDegradesGracefully(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	rec := do(t, e, "/?name=example.com", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no geo service", rec.Code)
	}
	var got dnstools.ResultSet
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if got.Found[0].Records[0].ASN != "" {
		t.Errorf("no geo service should mean no ASN, got %q", got.Found[0].Records[0].ASN)
	}
}

// NODATA and NXDOMAIN must read as different answers in the HTML.
func TestEmptyAnswerStatesRenderDistinctly(t *testing.T) {
	t.Parallel()

	// Every empty type is named once, in a single grouped card.
	nodata := &dnstools.ResultSet{
		Name: "example.com", QName: "example.com.", ResolverName: "Cloudflare (1.1.1.1)",
		Found: []dnstools.Result{}, Missing: []string{"MX", "CNAME", "CAA"},
	}
	e := newApp(t, &fakeLooker{set: nodata}, nil)
	body := do(t, e, "/?name=example.com", map[string]string{"Accept": "text/html"}).Body.String()
	if !strings.Contains(body, "nothing published") {
		t.Error("empty types should collapse into one grouped card")
	}
	for _, typ := range []string{"MX", "CNAME", "CAA"} {
		if !strings.Contains(body, typ) {
			t.Errorf("grouped card should name %s", typ)
		}
	}

	// A name that doesn't exist says so once, not once per type.
	nx := &dnstools.ResultSet{
		Name: "nope.example.com", QName: "nope.example.com.", ResolverName: "Cloudflare (1.1.1.1)",
		NXDomain: true, Found: []dnstools.Result{}, Missing: []string{},
	}
	e = newApp(t, &fakeLooker{set: nx}, nil)
	body = do(t, e, "/?name=nope.example.com", map[string]string{"Accept": "text/html"}).Body.String()
	if !strings.Contains(body, "does not exist") {
		t.Error("NXDOMAIN should say the name does not exist")
	}
	if strings.Contains(body, "nothing published") {
		t.Error("NXDOMAIN must not also render the per-type missing card")
	}
}

func TestSitemapPages(t *testing.T) {
	t.Parallel()

	pages, err := dnstools.SitemapPages()
	if err != nil {
		t.Fatalf("SitemapPages: %v", err)
	}
	var paths []string
	for _, p := range pages {
		paths = append(paths, p.Path)
	}
	want := []string{"/", "/consistency", "/domain", "/email"}
	if diff := cmp.Diff(want, paths); diff != "" {
		t.Errorf("sitemap pages differ (-want +got):\n%s", diff)
	}
}

// The endpoint is rate limited: one click fans out to several upstream
// queries, so an unthrottled endpoint is an open DNS proxy.
func TestRateLimited(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	// Burst is generous enough for real use, so push well past it.
	var limited bool
	for range 40 {
		req := httptest.NewRequest(http.MethodGet, "/?name=example.com", nil)
		req.RemoteAddr = "203.0.113.9:1234" // one client
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("no 429 after 40 rapid lookups from one address; endpoint is unthrottled")
	}
}

// A throttled JSON caller gets JSON, not an HTML fragment.
func TestRateLimitIsContentNegotiated(t *testing.T) {
	t.Parallel()
	e := newApp(t, &fakeLooker{set: sampleSet()}, nil)

	var body string
	for range 40 {
		req := httptest.NewRequest(http.MethodGet, "/?name=example.com", nil)
		req.RemoteAddr = "203.0.113.10:1234"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			body = rec.Body.String()
			break
		}
	}
	if body == "" {
		t.Skip("never hit the limit; covered by TestRateLimited")
	}
	if !strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Errorf("JSON caller got a non-JSON 429 body: %s", body)
	}
}
