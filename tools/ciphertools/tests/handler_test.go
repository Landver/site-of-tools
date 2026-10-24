package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"io/fs"
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

// The JSON API and the no-JS page path; render_test.go covers the browser's.

func newCipherApp(t *testing.T) *echo.Echo {
	t.Helper()
	return engineApp(nil, fstest.MapFS{}, nil)
}

func engineApp(funcs template.FuncMap, static fs.FS, lim *ciphertools.Limits) *echo.Echo {
	r := platform.NewRenderer(false, funcs,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: ciphertools.Templates, DevDir: "tools/ciphertools/templates"},
	)
	e := platform.NewApp(r, static, false, nil)
	ciphertools.Register(e, "https://cipher.example", static, lim)
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

// noJSPage posts body the way a browser with JavaScript off does and checks the whole page holds wants.
func noJSPage(t *testing.T, e *echo.Echo, path, body, contentType string, wants ...string) string {
	t.Helper()
	rec := do(t, e, http.MethodPost, path, body, contentType, asBrowser)
	html := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(html, "<!DOCTYPE html>") {
		t.Fatalf("no-JS POST %s: code %d", path, rec.Code)
	}
	holds(t, "no-JS POST "+path+": page", html, wants...)
	return html
}

func TestPagesRender(t *testing.T) {
	e := newCipherApp(t)
	pages, _ := ciphertools.SitemapPages()
	for _, p := range pages {
		rec := do(t, e, http.MethodGet, p.Path, "", "", asBrowser)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", p.Path, rec.Code)
		}
		holds(t, "GET "+p.Path+": page", rec.Body.String(), "data-cipher-engine", "<noscript>", "js/cipher.js")
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

// JSON numbers reach the op with every digit (1700000000, not "1.7e+09"), and false means off.
func TestJSONBodyNumbersAndBooleans(t *testing.T) {
	e := newCipherApp(t)
	claims := func(body string) map[string]any {
		t.Helper()
		rec := do(t, e, http.MethodPost, "/jwt/sign", body, "application/json", asAPI)
		var got struct{ Token string }
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || strings.Count(got.Token, ".") != 2 {
			t.Fatalf("code %d: %s", rec.Code, rec.Body)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(got.Token, ".")[1])
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		return c
	}
	const base = `"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{}","now":1700000000`
	if c := claims(`{` + base + `,"iat":true}`); c["iat"] != float64(1700000000) {
		t.Errorf("iat = %v, want 1700000000", c["iat"])
	}
	if c := claims(`{` + base + `,"iat":false}`); c["iat"] != nil {
		t.Errorf(`"iat": false still added iat = %v`, c["iat"])
	}
}

// An integer past 2^53 keeps every digit; float64 would round 2^53+1 down to 2^53.
func TestJSONBodyKeepsLargeIntegersExact(t *testing.T) {
	e := newCipherApp(t)
	for counter, want := range map[string]uint64{
		"9007199254740993":    9007199254740993,
		"9223372036854775806": 9223372036854775806,
		"1e6":                 1000000,
	} {
		rec := do(t, e, http.MethodPost, "/totp",
			`{"secret":"JBSWY3DPEHPK3PXP","mode":"hotp","counter":`+counter+`}`, "application/json", asAPI)
		var got struct {
			Counter uint64
			Codes   []struct{ Counter uint64 }
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("counter %s: code %d: %s", counter, rec.Code, rec.Body)
		}
		if got.Counter != want || len(got.Codes) != 3 || got.Codes[2].Counter != want+1 {
			t.Errorf("counter %s: got %d, codes %+v, want %d", counter, got.Counter, got.Codes, want)
		}
	}
}

// A JSON body that isn't a flat object is described in JSON terms, not Go's.
func TestJSONBodyErrorsReadPlainly(t *testing.T) {
	e := newCipherApp(t)
	for body, want := range map[string]string{
		`["alg","HS256"]`: "body: must be an object, found a JSON array",
		`{"alg":"HS256"`:  "body: the JSON ends before it is closed",
		`{"now":1e400}`:   `field "now": 1e400 is out of range`,
	} {
		rec := do(t, e, http.MethodPost, "/jwt/sign", body, "application/json", asAPI)
		var got struct{ Error string }
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusBadRequest || got.Error != want {
			t.Errorf("%s: code %d, error %q, want %q", body, rec.Code, got.Error, want)
		}
	}
}

// A token in the query string is ignored, never used: a URL is logged, cached and sent as Referer.
func TestQueryStringIsIgnored(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/jwt/decode?token="+jwtioToken, "", form, asAPI)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no token") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body)
	}
}

// With JavaScript off the form posts itself and the whole page comes back, result in place.
func TestNoJSFormPostRendersPage(t *testing.T) {
	e := newCipherApp(t)
	noJSPage(t, e, "/jwt/decode", url.Values{"token": {jwtioToken}}.Encode(), form, "Signature not checked", "John Doe")
	rec := do(t, e, http.MethodPost, "/jwt/decode", "token=a.b", form, asBrowser)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "only two parts") {
		t.Fatalf("error page: code %d", rec.Code)
	}
}

func TestEngineAssetsAreImmutableWhenVersioned(t *testing.T) {
	e := engineApp(nil, fstest.MapFS{"wasm/cipher.wasm": {Data: []byte("\x00asm")}}, nil)
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
	order := []string{`href="/"`, `href="/hash"`, `href="/hmac"`, `href="/password"`, `href="/encrypt"`, `href="/keys"`,
		`href="/cert"`, `href="/totp"`, `href="/random"`, `href="/encode"`, `href="/identify"`, `href="/dpop"`, `href="/pkce"`}
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

// The ~12 MB engine is gzipped once and reused (per request it costs ~0.25 s of CPU), never twice by
// the app's gzip middleware, and sent raw to a client without gzip.
func TestEngineServedPrecompressed(t *testing.T) {
	wasm := bytes.Repeat([]byte("\x00asm engine bytes "), 4096)
	e := engineApp(nil, fstest.MapFS{"wasm/cipher.wasm": {Data: wasm}}, nil)
	var first []byte
	for i := 0; i < 2; i++ {
		rec := do(t, e, http.MethodGet, "/static/wasm/cipher.wasm?v=abcd", "", "", map[string]string{"Accept-Encoding": "gzip, br"})
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Content-Type") != "application/wasm" {
			t.Fatalf("code %d, encoding %q, type %q", rec.Code, rec.Header().Get("Content-Encoding"), rec.Header().Get("Content-Type"))
		}
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(zr)
		if !bytes.Equal(got, wasm) {
			t.Fatalf("one gunzip gives %d bytes, want the %d-byte engine (compressed twice?)", len(got), len(wasm))
		}
		if i == 0 {
			first = rec.Body.Bytes()
		} else if !bytes.Equal(first, rec.Body.Bytes()) {
			t.Fatal("second response compressed again instead of reusing the first")
		}
	}

	rec := do(t, e, http.MethodGet, "/static/wasm/cipher.wasm", "", "", nil)
	if rec.Header().Get("Content-Encoding") != "" || !bytes.Equal(rec.Body.Bytes(), wasm) {
		t.Fatalf("no-gzip client: encoding %q, %d bytes", rec.Header().Get("Content-Encoding"), rec.Body.Len())
	}
}
