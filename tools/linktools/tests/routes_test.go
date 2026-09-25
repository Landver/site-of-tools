package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// The six routes added after the first handler tests were written — /diff,
// /curl, /extract, /utm, /encode and /clean/rules — had no coverage at all, and
// handler.go was the largest single block of untested code in the tool. These
// go through the real router and the real templates, reusing newLinkApp and
// request from handler_test.go.

// fragmentIsNotADocument is the assertion that caught this bug three times in
// this tool (link/short, GET /short, /clean/rules): a page served as an htmx
// response nests a whole <html> inside the div it is swapped into.
func fragmentIsNotADocument(t *testing.T, e *echo.Echo, target string) {
	t.Helper()
	rec := request(t, e, http.MethodGet, target, asHTMX)
	if rec.Code >= 500 {
		t.Fatalf("%s as htmx = %d (body %s)", target, rec.Code, truncate(rec.Body.String()))
	}
	for _, forbidden := range []string{"<!DOCTYPE", "<html", "<head", "<body"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("%s served a whole document to htmx (found %q)", target, forbidden)
		}
	}
	if strings.TrimSpace(rec.Body.String()) == "" {
		t.Errorf("%s served an EMPTY fragment to htmx — a missing {{define}} renders blank with status 200, which is why this is checked rather than eyeballed", target)
	}
}

// TestEveryContentRouteHonoursNegotiation sweeps the routes added late, so a
// new page cannot quietly skip golden rule #2.
func TestEveryContentRouteHonoursNegotiation(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	targets := []string{
		"/clean?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dx",
		"/diff?a=https%3A%2F%2Fa.com%2F%3Fx%3D1&b=https%3A%2F%2Fa.com%2F%3Fx%3D2",
		"/curl?u=https%3A%2F%2Fexample.com%2F",
		"/utm?u=https%3A%2F%2Fexample.com%2F&utm_source=news",
		"/encode?v=a%20b",
		"/extract?text=see%20https%3A%2F%2Fexample.com",
		"/clean/rules",
	}
	for _, target := range targets {
		t.Run(target[:min(len(target), 22)], func(t *testing.T) {
			if rec := request(t, e, http.MethodGet, target, asJSON); rec.Code != http.StatusOK {
				t.Errorf("JSON = %d, want 200 (body %s)", rec.Code, truncate(rec.Body.String()))
			} else if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Errorf("JSON content-type = %q", ct)
			}
			rec := request(t, e, http.MethodGet, target, asHTML)
			if rec.Code != http.StatusOK {
				t.Errorf("HTML = %d, want 200", rec.Code)
			} else if !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
				t.Error("a browser did not get a whole document")
			}
			fragmentIsNotADocument(t, e, target)
		})
	}
}

// TestDiffSeesOpaqueURLs is a regression guard. DiffInspections compared only
// scheme/host/port/path/fragment/user, so two entirely different non-hierarchical
// URLs — where the whole payload lives in Opaque — came back "identical", with an
// affirmative note saying so. From the one tool whose only job is saying what
// differs.
func TestDiffSeesOpaqueURLs(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, pair := range [][2]string{
		{"javascript:alert(1)", "javascript:fetch('http://evil')"},
		{"mailto:a@example.com", "mailto:b@example.com"},
		{"tel:+15551234", "tel:+19995678"},
	} {
		target := "/diff?a=" + urlEscape(pair[0]) + "&b=" + urlEscape(pair[1])
		rec := request(t, e, http.MethodGet, target, asJSON)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d (body %s)", target, rec.Code, rec.Body)
		}
		var d struct {
			Identical bool `json:"identical"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		if d.Identical {
			t.Errorf("%q vs %q reported IDENTICAL; the payload of an opaque URL is the whole URL", pair[0], pair[1])
		}
	}

	// And genuinely equal URLs still say so, or the fix above would be a
	// different bug wearing the same clothes.
	rec := request(t, e, http.MethodGet, "/diff?a=https%3A%2F%2Fa.com%2F&b=https%3A%2F%2Fa.com%2F", asJSON)
	var same struct {
		Identical bool `json:"identical"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &same)
	if !same.Identical {
		t.Error("two identical URLs were not reported identical")
	}
}

// TestCurlParsesAPastedCommand. Generating a curl line is the easy half; taking
// one apart is the half people actually want, because DevTools' "Copy as cURL"
// is where most of these come from.
func TestCurlParsesAPastedCommand(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	cmd := "curl 'https://example.com/a?b=1' -H 'Accept: application/json' -H 'X-Trace: 42'"
	rec := request(t, e, http.MethodGet, "/curl?curl="+urlEscape(cmd), asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d (body %s)", rec.Code, rec.Body)
	}
	var out struct {
		URL     string                         `json:"url"`
		Headers []struct{ Name, Value string } `json:"headers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, rec.Body)
	}
	if out.URL != "https://example.com/a?b=1" {
		t.Errorf("url = %q, want the one inside the command", out.URL)
	}
	if len(out.Headers) != 2 {
		t.Errorf("got %d headers, want 2 — both -H flags must survive", len(out.Headers))
	}
}

// TestToCurlQuotesAHostileURL. The output is something a human pastes into a
// shell, so a URL carrying quotes or a command substitution must not be able to
// break out of its quoting.
func TestToCurlQuotesAHostileURL(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	hostile := "https://example.com/?a='$(touch /tmp/pwned)'&b=`id`"
	rec := request(t, e, http.MethodGet, "/curl?u="+urlEscape(hostile), asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d (body %s)", rec.Code, rec.Body)
	}
	var out struct {
		Curl string `json:"curl"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	// Every single quote in the URL must be escaped as the '\'' idiom; a bare
	// one would close the quoting and hand the rest to the shell.
	unescaped := strings.ReplaceAll(out.Curl, `'\''`, "")
	if strings.Count(unescaped, "'")%2 != 0 {
		t.Errorf("unbalanced quoting, so the URL can escape its quotes: %s", out.Curl)
	}
	if strings.Contains(unescaped, "$(") && !strings.Contains(out.Curl, `'\''`) {
		t.Errorf("a command substitution survived unquoted: %s", out.Curl)
	}
}

// TestExtractAcceptsPOST, because the whole point is pasting more text than a
// query string will carry.
func TestExtractAcceptsPOST(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	body := strings.NewReader("text=" + urlEscape("see https://a.example and https://b.example and https://a.example again"))
	req := httptest.NewRequest(http.MethodPost, "/extract", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /extract = %d (body %s)", rec.Code, rec.Body)
	}
	var out struct {
		Total  int `json:"total"`
		Unique int `json:"unique"`
		URLs   []struct {
			URL   string `json:"url"`
			Count int    `json:"count"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, rec.Body)
	}
	if out.Unique != 2 {
		t.Errorf("unique = %d, want 2 — the repeated URL must be deduplicated, not listed twice", out.Unique)
	}
	if out.Total <= out.Unique {
		t.Errorf("total (%d) should exceed unique (%d); one URL appears twice", out.Total, out.Unique)
	}
}

// TestUTMReplacesRatherThanAppends. Two utm_source parameters is a real bug, and
// a builder that creates one deliberately would be an odd tool.
func TestUTMReplacesRatherThanAppends(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	rec := request(t, e, http.MethodGet,
		"/utm?u="+urlEscape("https://example.com/?utm_source=old&keep=1")+"&utm_source=new&utm_medium=email", asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d (body %s)", rec.Code, rec.Body)
	}
	var out struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if strings.Count(out.URL, "utm_source=") != 1 {
		t.Errorf("built %q — utm_source appears %d times, want exactly 1", out.URL, strings.Count(out.URL, "utm_source="))
	}
	if !strings.Contains(out.URL, "utm_source=new") {
		t.Errorf("built %q, want the new value to win", out.URL)
	}
	if !strings.Contains(out.URL, "keep=1") {
		t.Errorf("built %q — an unrelated parameter was dropped", out.URL)
	}
}

// TestEncodeShowsQueryAndPathApart is the page's whole reason to exist: "a b" is
// "a+b" after a ? and "a%20b" inside a path, and no surveyed tool makes that
// visible even though it is the most common URL bug there is.
func TestEncodeShowsQueryAndPathApart(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	rec := request(t, e, http.MethodGet, "/encode?v=a%20b", asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d (body %s)", rec.Code, rec.Body)
	}
	var out struct {
		Encoded []struct{ Name, Value string } `json:"encoded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	var query, path string
	for _, e := range out.Encoded {
		switch {
		case strings.Contains(e.Name, "query"):
			query = e.Value
		case strings.Contains(e.Name, "path"):
			path = e.Value
		}
	}
	if query != "a+b" {
		t.Errorf("query encoding = %q, want %q", query, "a+b")
	}
	if path != "a%20b" {
		t.Errorf("path encoding = %q, want %q", path, "a%20b")
	}
	if query == path {
		t.Error("query and path encodings are identical, so the page shows nothing the user could not have guessed")
	}
}

// TestRulesCatalogIsCacheableAndComplete. The extension refreshes this daily and
// caches on the version, so a missing ETag turns every refresh into a full
// re-download of the whole table.
func TestRulesCatalogIsCacheableAndComplete(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	rec := request(t, e, http.MethodGet, "/clean/rules", asJSON)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag; the extension's daily refresh cannot be conditional")
	}
	var cat struct {
		Version  string `json:"version"`
		Scope    string `json:"scope"`
		Tracking []struct {
			Param  string `json:"param"`
			Origin string `json:"origin"`
		} `json:"tracking"`
		NeverStrip []struct{} `json:"never_strip"`
		Wrappers   []struct{} `json:"wrappers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// The field name matters more than it looks: the extension read
	// rules.params for a table the server sends as "tracking", so every server
	// rule was dead and only its hardcoded fallback ever ran.
	if len(cat.Tracking) < 50 {
		t.Errorf(`"tracking" has %d entries; the extension keys off this exact field name`, len(cat.Tracking))
	}
	if len(cat.NeverStrip) == 0 || len(cat.Wrappers) == 0 {
		t.Error("never_strip or wrappers is empty; the extension needs both to match the server")
	}
	if cat.Scope == "" {
		t.Error("no scope sentence; the page promises to say the table is curated rather than exhaustive")
	}

	// A conditional refresh gets 304 rather than the whole table again.
	again := request(t, e, http.MethodGet, "/clean/rules", map[string]string{
		"Accept": "*/*", "If-None-Match": etag,
	})
	if again.Code != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304 (ETag %s)", again.Code, etag)
	}
}

// TestBadInputIsAFourHundredNotACrash across every route that parses something.
func TestBadInputIsAFourHundredNotACrash(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, target := range []string{
		"/?u=" + urlEscape("ht tp://not a url"),
		"/clean?u=" + urlEscape(""),
		"/diff?a=" + urlEscape("https://a.com") + "&b=",
		"/curl?curl=" + urlEscape("curl"),
		"/utm?u=" + urlEscape("   "),
		"/encode?v=",
	} {
		rec := request(t, e, http.MethodGet, target, asJSON)
		if rec.Code >= 500 {
			t.Errorf("%s = %d; bad input must never be a server error (body %s)", target, rec.Code, truncate(rec.Body.String()))
		}
	}
}

func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~", rune(c)) {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// TestStaticPagesRender covers the two routes that deliberately bypass content
// negotiation. They are static documents with no result to negotiate, but they
// still have to render — a missing {{define}} would serve 200 and nothing.
func TestStaticPagesRender(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, nil)

	for _, tc := range []struct{ target, want string }{
		{"/encoding", "percent"},
		{"/extension/privacy", "privacy"},
	} {
		rec := request(t, e, http.MethodGet, tc.target, asHTML)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", tc.target, rec.Code)
			continue
		}
		body := strings.ToLower(rec.Body.String())
		if !strings.Contains(body, "<!doctype html>") {
			t.Errorf("%s rendered no document", tc.target)
		}
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s does not mention %q, so it is probably the wrong template", tc.target, tc.want)
		}
	}
}

// TestSitemapListsOnlyIndexablePages. A redirect, a write endpoint and a legal
// document have no business in a sitemap — and /s/:code additionally carries
// X-Robots-Tag: noindex, so advertising it would be a contradiction.
func TestSitemapListsOnlyIndexablePages(t *testing.T) {
	t.Parallel()
	// RegisterSEO is wired in main.go, not in Register, so the test has to do
	// what main does — which also means this covers that wiring, not just the
	// page list.
	e := newLinkApp(t, nil, nil)
	platform.RegisterSEO(e, "https://link.example", linktools.SitemapPages)

	rec := request(t, e, http.MethodGet, "/sitemap.xml", asHTML)
	if rec.Code != http.StatusOK {
		t.Fatalf("/sitemap.xml = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"/s/", "/extension/privacy"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the sitemap advertises %q", forbidden)
		}
	}
	for _, want := range []string{"/clean", "/diff", "/encoding"} {
		if !strings.Contains(body, want) {
			t.Errorf("the sitemap omits %q", want)
		}
	}
}

// TestStorageFailureIsNotEchoedToTheCaller. A driver error can carry a
// connection string and internal topology, so the caller gets a fixed sentence
// and the detail goes to the log. The offline shortener points at a dead port,
// so every database call fails the way a real outage would.
func TestStorageFailureIsNotEchoedToTheCaller(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))
	keyed := map[string]string{"Accept": "*/*", "X-Api-Key": testAPIKey}

	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/short"},            // Recent -> storage error
		{http.MethodDelete, "/short/abcdefg"}, // Revoke -> storage error
	} {
		rec := request(t, e, tc.method, tc.target, keyed)
		if rec.Code < 400 {
			t.Errorf("%s %s = %d with an unreachable database, want an error", tc.method, tc.target, rec.Code)
		}
		body := strings.ToLower(rec.Body.String())
		for _, leak := range []string{"127.0.0.1", "mongo", "dial tcp", "connection refused", "topology"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s %s leaked %q to the caller: %s", tc.method, tc.target, leak, rec.Body)
			}
		}
	}
}

// TestRevokeNeedsTheKey. The kill switch is a write, gated like every other.
func TestRevokeNeedsTheKey(t *testing.T) {
	t.Parallel()
	e := newLinkApp(t, nil, offlineShortener(t))

	for _, h := range []map[string]string{
		asJSON,
		{"Accept": "*/*", "X-Api-Key": "wrong"},
	} {
		rec := request(t, e, http.MethodDelete, "/short/abcdefg", h)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("DELETE with key %q = %d, want 401", h["X-Api-Key"], rec.Code)
		}
	}
	// And with no shortener at all it is 503, not 401: the feature being off
	// outranks the caller's credentials.
	off := newLinkApp(t, nil, nil)
	if rec := request(t, off, http.MethodDelete, "/short/abcdefg", asJSON); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("DELETE with no shortener = %d, want 503", rec.Code)
	}
}
