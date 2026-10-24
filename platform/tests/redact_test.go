package tests

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// TestRedactURI: a pasted URL's token must reach neither the Mongo corpus nor the TTL-less stdout log.
func TestRedactURI(t *testing.T) {
	cases := []struct {
		name, in string
		mustNot  string
	}{
		{"inspect", "/?u=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3DSECRET", "SECRET"},
		{"inspect unencoded", "/?u=https://app.example.com/reset?token=SECRET&extra=123", "SECRET"},
		{"diff a", "/diff?a=https%3A%2F%2Fx%2F%3Fk%3DSECRET&b=https%3A%2F%2Fy", "SECRET"},
		{"curl", "/curl?curl=curl%20-H%20%27Authorization%3A%20SECRET%27%20https%3A%2F%2Fx", "SECRET"},
		{"extract", "/extract?text=see%20https%3A%2F%2Fx%3Ft%3DSECRET", "SECRET"},
		{"encode", "/encode?v=eyJhbGciOiJIUzI1NiJ9.SECRET.sig", "SECRET"},
		// A pasted URL or email in the DNS box.
		{"dns pasted url", "/email?name=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3DSECRET", "SECRET"},
		{"dns pasted email", "/email?name=SECRET%40example.com", "SECRET"},
	}
	for _, c := range cases {
		got := platform.RedactURI(c.in)
		if strings.Contains(got, c.mustNot) {
			t.Errorf("%s: RedactURI(%q) = %q, still contains %q", c.name, c.in, got, c.mustNot)
		}
		if !strings.Contains(got, "redacted") {
			t.Errorf("%s: no redaction marker in %q", c.name, got)
		}
	}
}

// TestRedactURIKeepsShape: paths, key names and other params survive, so the log still shows the endpoint.
func TestRedactURIKeepsShape(t *testing.T) {
	got := platform.RedactURI("/trace?u=https%3A%2F%2Fsecret.example&ua=googlebot")
	for _, want := range []string{"/trace", "u=", "ua=googlebot"} {
		if !strings.Contains(got, want) {
			t.Errorf("RedactURI dropped %q; got %q", want, got)
		}
	}
}

// TestRedactURILeavesOthersAlone: it runs on every subdomain, so ?ip= and a plain DNS ?name= stay intact.
func TestRedactURILeavesOthersAlone(t *testing.T) {
	for _, in := range []string{
		"/?ip=8.8.8.8", "/?name=example.com&type=MX", "/cidr?cidr=10.0.0.0%2F8", "/",
		"/static/js/app.js",
		// "v" is /encode's redacted key but also every static asset's cache-buster, which must stay readable.
		"/static/css/styles.css?v=1a2b3c4d",
	} {
		if got := platform.RedactURI(in); got != in {
			t.Errorf("RedactURI(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestRedactURIUnparseable: a malformed URI is where a naive logger leaks the most.
func TestRedactURIUnparseable(t *testing.T) {
	got := platform.RedactURI("/?u=%zz%SECRET{]|")
	if strings.Contains(got, "SECRET") {
		t.Errorf("unparseable URI logged whole: %q", got)
	}
}

// TestRedactionIsWiredIntoTheRequestLogger reads what NewApp's real middleware logs: every test above
// passes even if requestLogger logs v.URI raw, so deleting the RedactURI call must fail here.
func TestRedactionIsWiredIntoTheRequestLogger(t *testing.T) {
	// The realistic case: an inspected password-reset link carries its token in OUR request's query string.
	const secret = "reset-token-DO-NOT-LOG"

	cases := []struct {
		name   string
		target string
		why    string
	}{
		{"inspect", "/?u=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3D" + secret,
			"every linktools page's input arrives as ?u="},
		{"diff", "/diff?a=https%3A%2F%2Fx%2F%3Fk%3D" + secret + "&b=https%3A%2F%2Fy",
			"/diff takes two pasted URLs, and both are redacted keys"},
		{"encode", "/encode?v=" + secret,
			"/encode is the likeliest place someone pastes a JWT"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logged bytes.Buffer
			e := platform.NewApp(nil, fstest.MapFS{}, false, nil)
			// c.Logger() resolves e.Logger at call time, so swapping it after NewApp still captures the log.
			e.Logger = slog.New(slog.NewTextHandler(&logged, nil))
			e.GET("/*", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })

			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.target, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 — the request never reached the logger, so this test proves nothing", rec.Code)
			}

			line := logged.String()
			if line == "" {
				t.Fatal("the request logger wrote nothing; this test cannot see what is logged, so it is not testing the wiring")
			}
			if strings.Contains(line, secret) {
				t.Errorf("%s: the pasted secret reached the log line %q — redaction is not wired into requestLogger, and this copy goes to stdout, which Docker keeps on the host with no TTL", c.why, line)
			}
			if !strings.Contains(line, "redacted") {
				t.Errorf("no redaction marker in the log line %q; the URI was logged verbatim", line)
			}
			// The log must still show which endpoint was hit, or it is safe and useless.
			if !strings.Contains(line, "status=200") {
				t.Errorf("log line lost the status field: %q", line)
			}
		})
	}
}

// TestRedactionLeavesOrdinaryRequestsLegible: on ip/dns the query string is the log's whole analytic value.
func TestRedactionLeavesOrdinaryRequestsLegible(t *testing.T) {
	var logged bytes.Buffer
	e := platform.NewApp(nil, fstest.MapFS{}, false, nil)
	e.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	e.GET("/*", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?name=example.com&type=MX", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, want := range []string{"name=example.com", "type=MX"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("log line dropped %q: %q — over-redaction makes the corpus useless for the tools whose input is not a URL", want, logged.String())
		}
	}
}

// A plain domain or IP in the DNS ?name= stays readable.
func TestRedactURIKeepsAPlainDNSName(t *testing.T) {
	for _, in := range []string{"/?name=example.com&type=A", "/?name=8.8.8.8", "/?name=2001%3Adb8%3A%3A1"} {
		if got := platform.RedactURI(in); got != in {
			t.Errorf("RedactURI(%q) = %q, want it unchanged", in, got)
		}
	}
}

// An unencoded pasted URL's tail ("&token=…") is redacted; DNS params stay.
func TestRedactURIDropsAnUnencodedURLsTail(t *testing.T) {
	got := platform.RedactURI("/email?name=https://app.example.com/reset?a=b&token=SECRET&type=MX")
	if strings.Contains(got, "SECRET") {
		t.Errorf("RedactURI kept the pasted URL's tail: %q", got)
	}
	if !strings.Contains(got, "type=MX") {
		t.Errorf("RedactURI dropped the tool's own parameter: %q", got)
	}
}
