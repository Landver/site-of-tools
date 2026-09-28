package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// Server-side tests: the JSON API and the no-JS page path. The browser path is
// covered by render_test.go, which drives the same Render the wasm engine calls.

func newCipherApp(t *testing.T) *echo.Echo {
	t.Helper()
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: ciphertools.Templates, DevDir: "tools/ciphertools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{}, false, nil)
	ciphertools.Register(e, "https://cipher.example")
	return e
}

func do(t *testing.T, e *echo.Echo, method, target, body, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

const form = "application/x-www-form-urlencoded"

var (
	asAPI     = map[string]string{"Accept": "*/*"}
	asBrowser = map[string]string{"Accept": "text/html,application/xhtml+xml"}
)

func TestPagesRender(t *testing.T) {
	e := newCipherApp(t)
	pages, _ := ciphertools.SitemapPages()
	for _, p := range pages {
		rec := do(t, e, http.MethodGet, p.Path, "", "", asBrowser)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", p.Path, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{"data-cipher-engine", "<noscript>", "js/cipher.js"} {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s: page lacks %q", p.Path, want)
			}
		}
	}
}

func TestJWTDecodeAPI(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"token": {jwtioToken}, "key": {"your-256-bit-secret"}}.Encode()
	rec := do(t, e, http.MethodPost, "/jwt/decode", body, form, asAPI)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Alg          string `json:"alg"`
		Verification struct{ State string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Alg != "HS256" || got.Verification.State != "valid" {
		t.Fatalf("got %+v", got)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestJWTSignAPIAcceptsJSONBody(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/jwt/sign",
		`{"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{\"sub\":\"42\"}","now":1700000000}`,
		"application/json", asAPI)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d: %s", rec.Code, rec.Body)
	}
	var got struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if strings.Count(got.Token, ".") != 2 {
		t.Fatalf("token %q", got.Token)
	}
}

// Secrets are read from the body only. A token in the query string must be
// ignored, never quietly used: a URL is logged, cached and sent as Referer.
func TestQueryStringIsIgnored(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/jwt/decode?token="+jwtioToken, "", form, asAPI)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no token") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body)
	}
}

// A browser with JavaScript off posts the form itself and gets the whole page
// back with the result rendered in place.
func TestNoJSFormPostRendersPage(t *testing.T) {
	e := newCipherApp(t)
	body := url.Values{"token": {jwtioToken}}.Encode()
	rec := do(t, e, http.MethodPost, "/jwt/decode", body, form, asBrowser)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	html := rec.Body.String()
	for _, want := range []string{"<!DOCTYPE html>", "Signature not checked", "John Doe"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	rec = do(t, e, http.MethodPost, "/jwt/decode", "token=a.b", form, asBrowser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "only two parts") {
		t.Fatalf("error page: code %d", rec.Code)
	}
}

func TestEngineAssetsAreImmutableWhenVersioned(t *testing.T) {
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: ciphertools.Templates, DevDir: "tools/ciphertools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{"wasm/cipher.wasm": {Data: []byte("\x00asm")}}, false, nil)
	ciphertools.Register(e, "https://cipher.example")

	rec := do(t, e, http.MethodGet, "/static/wasm/cipher.wasm?v=abcd", "", "", nil)
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("versioned: Cache-Control = %q", cc)
	}
	rec = do(t, e, http.MethodGet, "/static/wasm/cipher.wasm", "", "", nil)
	if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "immutable") {
		t.Fatalf("unversioned URL marked immutable: %q", cc)
	}
}

// Every page carries the whole sub-nav, in the suite's fixed order.
func TestNavOrder(t *testing.T) {
	e := newCipherApp(t)
	pages, _ := ciphertools.SitemapPages()
	order := []string{`href="/"`, `href="/hash"`, `href="/hmac"`, `href="/encode"`}
	for _, p := range pages {
		body := do(t, e, http.MethodGet, p.Path, "", "", asBrowser).Body.String()
		nav := body[strings.Index(body, "Cipher Tools sections"):]
		nav = nav[:strings.Index(nav, "</nav>")]
		last := -1
		for _, href := range order {
			i := strings.Index(nav, href)
			if i <= last {
				t.Errorf("GET %s: %s missing or out of order", p.Path, href)
			}
			last = i
		}
	}
}
