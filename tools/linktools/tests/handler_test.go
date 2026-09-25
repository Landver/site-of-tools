package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// Handler tests go through the real router with the real templates, per
// docs/07-testing.md §6: one URL, three representations, and the two
// "feature is off" branches that only work because Tracer and Shortener are
// concrete pointers rather than interfaces (docs/03-architecture.md §2).
//
// Each test builds its own app. That is not tidiness: Register installs a
// per-instance rate limiter keyed on the client address, and a shared app would
// let one test's requests spend another's budget.

// newLinkApp wires link.corpberry.com the way main.go does, minus the parts a
// test has no business dialling. A nil tracer or a nil shortener is the real
// production value for "that feature is not configured here", which is what the
// 503 tests below depend on.
func newLinkApp(t *testing.T, tracer *linktools.Tracer, short *linktools.Shortener) *echo.Echo {
	t.Helper()
	// Embedded FS for both sources, so the tests do not depend on the working
	// directory — the same choice dnstools and iptools make.
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{}, false, nil) // nil RequestLog: persistence off
	linktools.Register(e, linktools.NewService(), tracer, short, "https://link.example")
	return e
}

// request drives one call through the whole middleware stack.
func request(t *testing.T, e *echo.Echo, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

var (
	asJSON = map[string]string{"Accept": "*/*"}                             // a plain curl
	asHTML = map[string]string{"Accept": "text/html,application/xhtml+xml"} // a browser
	asHTMX = map[string]string{"Accept": "text/html", "HX-Request": "true"} // a swap
)

const inspectTarget = "/?u=" + "https%3A%2F%2Fexample.com%2F%3Fa%3D1%26a%3D2%26debug"

// TestOneURLThreeRepresentations is golden rule #2, asserted end to end: the
// browser, the htmx swap and the API all read the same route, and none of them
// needs a separate endpoint.
func TestOneURLThreeRepresentations(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	// A plain curl sends Accept: */* and gets the domain struct.
	rec := request(t, e, http.MethodGet, inspectTarget, asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want JSON for Accept: */*", ct)
	}
	var in linktools.Inspection
	if err := json.Unmarshal(rec.Body.Bytes(), &in); err != nil {
		t.Fatalf("response is not an Inspection: %v (body %s)", err, rec.Body)
	}
	if len(in.Params) != 3 {
		t.Errorf("got %d params, want 3 — the repeat and the valueless key must both survive the round trip through HTTP", len(in.Params))
	}

	// A browser gets the whole page.
	rec = request(t, e, http.MethodGet, inspectTarget, asHTML)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTML status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") || !strings.Contains(body, "</html>") {
		t.Errorf("Accept: text/html did not return a whole document:\n%s", truncate(body))
	}
	if !strings.Contains(body, "example.com") {
		t.Error("the rendered page does not contain the host it just parsed")
	}

	// htmx gets the fragment. A full document swapped into a div nests <html>
	// inside <body>, which is the bug this assertion exists to catch.
	rec = request(t, e, http.MethodGet, inspectTarget, asHTMX)
	if rec.Code != http.StatusOK {
		t.Fatalf("htmx status = %d, want 200", rec.Code)
	}
	frag := rec.Body.String()
	for _, forbidden := range []string{"<!DOCTYPE", "<html", "<head", "<body"} {
		if strings.Contains(frag, forbidden) {
			t.Errorf("the htmx fragment contains %q; a whole page swapped into a slot nests a document inside the one already there:\n%s", forbidden, truncate(frag))
		}
	}
	if !strings.Contains(frag, "example.com") {
		t.Errorf("the fragment carries no result:\n%s", truncate(frag))
	}
	if len(frag) >= len(body) {
		t.Errorf("the fragment (%d bytes) is not smaller than the page (%d bytes)", len(frag), len(body))
	}
}

// TestBareHitIsAFormForABrowserAndAnErrorForAnAPI.
//
// The asymmetry is deliberate (needURL's comment): arriving at a page with
// nothing typed yet is the normal first step for a person, and asking for
// nothing is a mistake for a program. Answering 200-with-no-result to a script
// makes the script's own bug invisible.
func TestBareHitIsAFormForABrowserAndAnErrorForAnAPI(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	rec := request(t, e, http.MethodGet, "/", asHTML)
	if rec.Code != http.StatusOK {
		t.Errorf("bare / for a browser = %d, want 200 and an empty form", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Errorf("bare / for a browser rendered no form:\n%s", truncate(rec.Body.String()))
	}

	rec = request(t, e, http.MethodGet, "/", asJSON)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bare / for a JSON caller = %d, want 400 (body %s)", rec.Code, rec.Body)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("400 body is not JSON: %v (%s)", err, rec.Body)
	}
	if body["error"] == "" {
		t.Error("the 400 carries no error message; a caller cannot tell what it got wrong")
	}
	if !strings.Contains(body["error"], "?u=") {
		t.Errorf("the 400 does not name the parameter it wanted: %q", body["error"])
	}
}

// TestNilTracerIsUnavailableNotABadGateway.
//
// 503, never 502: nothing failed, the feature is not running (the note on
// handler.disabled). A 502 says the upstream broke, which sends whoever reads
// the log looking for an outage that does not exist.
//
// This test is valid only because Tracer is a concrete pointer. Held as an
// interface, a nil *Tracer inside it would not be == nil, the branch would be
// dead code, and this test would pass while production panicked
// (docs/03-architecture.md §2).
func TestNilTracerIsUnavailableNotABadGateway(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, headers := range []map[string]string{asJSON, asHTML} {
		rec := request(t, e, http.MethodGet, "/trace?u=http%3A%2F%2Fexample.com%2F", headers)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Accept %q: /trace with no tracer = %d, want 503 (502 would claim an upstream failed)",
				headers["Accept"], rec.Code)
		}
	}
	// And with no ?u= either: still 503, because the feature being off outranks
	// the input being missing.
	if rec := request(t, e, http.MethodGet, "/trace", asJSON); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("bare /trace with no tracer = %d, want 503", rec.Code)
	}
}

// TestNilShortenerIsUnavailable: the write path, the console and the redirect all
// report the same thing. An unset LINK_API_KEY or MONGODB_URI means creation is
// off, which is the fail-closed property that keeps the domain off a blocklist
// (docs/04-short-links.md §5).
func TestNilShortenerIsUnavailable(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/short"},
		{http.MethodGet, "/short"},
		{http.MethodGet, "/s/abc1234"},
	} {
		rec := request(t, e, tc.method, tc.target, asJSON)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s with no shortener = %d, want 503 (body %s)", tc.method, tc.target, rec.Code, rec.Body)
		}
	}
	// Not a 201 by any route: a disabled feature must never report success.
	if rec := request(t, e, http.MethodPost, "/short", asHTML); rec.Code == http.StatusCreated {
		t.Error("POST /short reported 201 with no shortener wired")
	}
}

// TestShortCreateNeedsTheKeyAndSaysNothingElse.
//
// Same status and same body for a missing key and a wrong one: saying which is a
// free hint to anyone probing, and the population that can create links is the
// only thing standing between this domain and a phishing relay.
func TestShortCreateNeedsTheKeyAndSaysNothingElse(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))

	missing := request(t, e, http.MethodPost, "/short", asJSON)
	wrong := request(t, e, http.MethodPost, "/short", map[string]string{
		"Accept": "*/*", "X-Api-Key": "not-the-key",
	})

	for name, rec := range map[string]*httptest.ResponseRecorder{"missing key": missing, "wrong key": wrong} {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: POST /short = %d, want 401 (body %s)", name, rec.Code, rec.Body)
		}
	}
	if missing.Body.String() != wrong.Body.String() {
		t.Errorf("a wrong key and a missing key get different answers, which tells a prober which half they got right:\n missing: %s\n   wrong: %s",
			missing.Body, wrong.Body)
	}
	// Nothing about the key itself comes back either.
	if strings.Contains(strings.ToLower(missing.Body.String()), "not-the-key") {
		t.Error("the rejection echoes the key it was given")
	}
	if len(missing.Body.String()) == 0 {
		t.Error("the 401 has an empty body; a caller cannot tell a rejection from a crash")
	}
}

// TestShortConsoleShowsNoListWithoutTheKey.
//
// A public list hands over the whole corpus with no guessing, which defeats the
// code entropy argument outright and turns hits/last_hit_at into a read-receipt
// oracle (docs/04-short-links.md §8). The page itself stays public; only the list
// is gated.
func TestShortConsoleShowsNoListWithoutTheKey(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))

	rec := request(t, e, http.MethodGet, "/short", asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /short = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body)
	}
	if _, ok := body["links"]; ok {
		t.Errorf("the alias list was served to a caller with no key: %s", rec.Body)
	}
	if auth, _ := body["authorized"].(bool); auth {
		t.Error(`"authorized" is true for a caller that sent no key`)
	}
	if enabled, _ := body["enabled"].(bool); !enabled {
		t.Error(`"enabled" is false although a shortener is wired`)
	}

	// Same for the page: the console renders, the corpus does not.
	page := request(t, e, http.MethodGet, "/short", asHTML)
	if page.Code != http.StatusOK {
		t.Fatalf("GET /short as a browser = %d, want 200", page.Code)
	}
	if strings.Contains(page.Body.String(), "/s/") && strings.Contains(page.Body.String(), "last_hit") {
		t.Errorf("the unauthenticated console page appears to render alias rows:\n%s", truncate(page.Body.String()))
	}
}

// TestJSONNeverCarriesViewModelKeys is why this package has a local reply helper
// instead of calling platform.Respond.
//
// Every page template pulls .Title and .Desc through partials/head, so handing
// Respond a bare domain struct fails the render — and handing it the view-model
// map puts Title, Desc and Active into the API's response body. reply picks one
// per representation, and this test is what keeps anyone from "simplifying" it
// back into the shared helper.
func TestJSONNeverCarriesViewModelKeys(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))

	for _, target := range []string{
		inspectTarget,
		"/clean?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dx",
		"/short",
		"/trace?u=http%3A%2F%2Fexample.com%2F", // 503, and its body is JSON too
		"/",                                    // 400
	} {
		rec := request(t, e, http.MethodGet, target, asJSON)
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s: content-type = %q, want JSON", target, ct)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			continue // an array or a non-object body carries no view-model keys by construction
		}
		for _, leaked := range []string{"Title", "Desc", "Active", "Heading", "Base", "Query"} {
			if _, ok := body[leaked]; ok {
				t.Errorf("%s: the JSON body carries the view-model key %q. That is what platform.Respond would do; reply exists to keep the two representations apart.", target, leaked)
			}
		}
	}
}

// truncate keeps a failure message readable when a whole rendered page would
// otherwise land in the test log.
func truncate(s string) string {
	const max = 600
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n… (" + itoaLocal(len(s)-max) + " more bytes)"
}

func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
