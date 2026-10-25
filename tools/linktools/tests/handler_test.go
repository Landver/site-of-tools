package tests

import (
	"context"
	"encoding/json"
	"errors"
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

// Each test builds its own app: Register's rate limiter is per instance, and a shared one shares budgets.

// A nil tracer or shortener is production's "not configured" value, which the 503 tests rely on.
func newLinkApp(t *testing.T, tracer *linktools.Tracer, short *linktools.Shortener) *echo.Echo {
	t.Helper()
	// Embedded FS for both sources, so the tests do not depend on the working directory.
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{}, false, nil) // nil RequestLog: persistence off
	linktools.Register(e, linktools.NewService(), tracer, short, "https://link.example", nil)
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

// Golden rule #2 end to end: the browser, the htmx swap and the API all read the same route.
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

	// htmx gets the fragment: a full document swapped into a div nests <html> inside <body>.
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

func TestHeadersPageRender(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)
	rec := request(t, e, http.MethodGet, "/headers", asHTML)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /headers HTML status = %d, want 200: body: %s", rec.Code, rec.Body.String())
	}
}

// Nothing typed is a person's normal first step, but a program asking for nothing has a bug to see.
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

// 503, never 502: nothing failed, the feature is off. Valid only because Tracer is a concrete pointer:
// a nil *Tracer inside an interface is not == nil, so the branch would be dead and production panic.
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
	// Still 503 with no ?u=: the feature being off outranks the missing input.
	if rec := request(t, e, http.MethodGet, "/trace", asJSON); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("bare /trace with no tracer = %d, want 503", rec.Code)
	}
}

// No storage (MONGODB_URI unset): the write path, the console and the redirect all report the same.
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

// Storage wired, LINK_API_KEY unset: 503 whatever the key; a request past the gate would get 500.
func TestKeylessServerRefusesEveryKeyGatedRoute(t *testing.T) {
	t.Parallel()
	short := keylessShortener(t, offlineStore())

	for _, h := range []map[string]string{
		asJSON, // no header at all
		{"Accept": "*/*", "X-Api-Key": ""},
		{"Accept": "*/*", "X-Api-Key": testAPIKey}, // a key that worked before it was unset
		{"Accept": "*/*", "X-Api-Key": "anything"},
	} {
		// A fresh app per key: these routes share one per-IP limiter, burst 5.
		e := newLinkApp(t, nil, short)
		for _, tc := range []struct{ method, target string }{
			{http.MethodPost, "/short"},
			{http.MethodGet, "/short"},
			{http.MethodDelete, "/short/abcdefg"},
		} {
			rec := request(t, e, tc.method, tc.target, h)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s with X-Api-Key %q and no key configured = %d, want 503 (body %s)",
					tc.method, tc.target, h["X-Api-Key"], rec.Code, rec.Body)
			}
		}
	}

	e := newLinkApp(t, nil, short)
	page := request(t, e, http.MethodGet, "/short", asHTML)
	if page.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /short as a browser with no key configured = %d, want 503", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"Creating short links is switched off", "keep redirecting"} {
		if !strings.Contains(body, want) {
			t.Errorf("the console does not say %q", want)
		}
	}
	for _, gone := range []string{`id="apikey"`, `hx-post="/short"`} {
		if strings.Contains(body, gone) {
			t.Errorf("the console renders %s although nothing it could send would succeed", gone)
		}
	}

	// The redirect is not key-gated: the offline lookup is a miss, never "short links are off".
	if rec := request(t, e, http.MethodGet, "/s/abc1234", asHTML); rec.Code == http.StatusServiceUnavailable {
		t.Errorf("GET /s/abc1234 with no key configured = 503 (%s); resolving never needs the key", rec.Body)
	}
}

// Links made under a key keep redirecting once LINK_API_KEY is unset; that key no longer writes or lists.
func TestKeylessServerStillRedirects(t *testing.T) {
	ctx := context.Background()
	keyed, store := liveShortener(t, ctx)
	link, err := keyed.Create(ctx, linktools.CreateRequest{URL: "https://example.com/kept", Slug: "made-with-a-key"}, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	e := newLinkApp(t, nil, keylessShortener(t, store))

	rec := request(t, e, http.MethodGet, "/s/"+link.Code, asHTML)
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /s/%s with no key configured = %d, want 302 (body %s)", link.Code, rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != link.Target {
		t.Errorf("Location = %q, want %q", got, link.Target)
	}
	if rec := request(t, e, http.MethodGet, "/s/never-made-here", asHTML); rec.Code != http.StatusNotFound {
		t.Errorf("GET /s/never-made-here with no key configured = %d, want 404", rec.Code)
	}

	oldKey := map[string]string{"Accept": "*/*", "X-Api-Key": testAPIKey}

	req := httptest.NewRequest(http.MethodPost, "/short",
		strings.NewReader(`{"url":"https://example.com/new","slug":"made-without-a-key"}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range oldKey {
		req.Header.Set(k, v)
	}
	created := httptest.NewRecorder()
	e.ServeHTTP(created, req)
	if created.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /short with the old key = %d, want 503 (body %s)", created.Code, created.Body)
	}
	if _, err := keyed.Resolve(ctx, "made-without-a-key"); !errors.Is(err, linktools.ErrLinkNotFound) {
		t.Errorf("a refused create left a link behind (Resolve = %v)", err)
	}

	if rec := request(t, e, http.MethodGet, "/short", oldKey); rec.Code != http.StatusServiceUnavailable ||
		strings.Contains(rec.Body.String(), link.Code) {
		t.Errorf("GET /short with the old key = %d, want 503 and no aliases (body %s)", rec.Code, rec.Body)
	}

	if rec := request(t, e, http.MethodDelete, "/short/"+link.Code, oldKey); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("DELETE /short/%s with the old key = %d, want 503 (body %s)", link.Code, rec.Code, rec.Body)
	}
	if rec := request(t, e, http.MethodGet, "/s/"+link.Code, asHTML); rec.Code != http.StatusFound {
		t.Errorf("after a refused revoke, GET /s/%s = %d, want 302", link.Code, rec.Code)
	}
}

// Same answer for a missing and a wrong key: telling them apart is a free hint to anyone probing.
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

// A public list hands over the corpus and makes hits a read-receipt oracle; only the list is gated.
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

// Why linktools has its own reply helper: the view-model map would put Title/Desc/Active in the API body,
// and a bare struct fails partials/head. Don't "simplify" it back into platform.Respond.
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

// truncate keeps a failure readable when a whole rendered page would land in the test log.
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
