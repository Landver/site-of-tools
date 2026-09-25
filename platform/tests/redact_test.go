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

// TestRedactURI: on link.corpberry.com the request URI IS the visitor's pasted
// input, which routinely carries a session token or a password-reset link. It
// must not reach the 30-day Mongo corpus, and — more importantly — must not
// reach the stdout log, which Docker keeps on the host with no TTL at all.
func TestRedactURI(t *testing.T) {
	cases := []struct {
		name, in string
		mustNot  string
	}{
		{"inspect", "/?u=https%3A%2F%2Fapp.example.com%2Freset%3Ftoken%3DSECRET", "SECRET"},
		{"diff a", "/diff?a=https%3A%2F%2Fx%2F%3Fk%3DSECRET&b=https%3A%2F%2Fy", "SECRET"},
		{"curl", "/curl?curl=curl%20-H%20%27Authorization%3A%20SECRET%27%20https%3A%2F%2Fx", "SECRET"},
		{"extract", "/extract?text=see%20https%3A%2F%2Fx%3Ft%3DSECRET", "SECRET"},
		{"encode", "/encode?v=eyJhbGciOiJIUzI1NiJ9.SECRET.sig", "SECRET"},
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

// TestRedactURIKeepsShape: the corpus still has to show which endpoint was hit
// and with what shape of request, so paths, key names and other parameters all
// survive.
func TestRedactURIKeepsShape(t *testing.T) {
	got := platform.RedactURI("/trace?u=https%3A%2F%2Fsecret.example&ua=googlebot")
	for _, want := range []string{"/trace", "u=", "ua=googlebot"} {
		if !strings.Contains(got, want) {
			t.Errorf("RedactURI dropped %q; got %q", want, got)
		}
	}
}

// TestRedactURILeavesOthersAlone: this runs on every request to every subdomain,
// so it must not touch ip.corpberry.com's ?ip= or dns.corpberry.com's ?name=.
func TestRedactURILeavesOthersAlone(t *testing.T) {
	for _, in := range []string{
		"/?ip=8.8.8.8", "/?name=example.com&type=MX", "/cidr?cidr=10.0.0.0%2F8", "/",
		"/static/js/app.js",
		// "v" is a redacted key (/encode's input) but it is also every static
		// asset's cache-buster, and rewriting those would make the whole site's
		// asset log lines unreadable for nothing.
		"/static/css/styles.css?v=1a2b3c4d",
	} {
		if got := platform.RedactURI(in); got != in {
			t.Errorf("RedactURI(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestRedactURIUnparseable: an unparseable URI is exactly when a naive logger
// leaks the most, so it is truncated rather than logged whole.
func TestRedactURIUnparseable(t *testing.T) {
	got := platform.RedactURI("/?u=%zz%SECRET{]|")
	if strings.Contains(got, "SECRET") {
		t.Errorf("unparseable URI logged whole: %q", got)
	}
}

// TestRedactionIsWiredIntoTheRequestLogger is the integration half, and it is
// the half that matters. Every test above passes with RedactURI never called:
// the unit can be perfect while app.go logs v.URI raw, and the leak the
// function exists to prevent happens on every request anyway.
//
// So this drives a real request through a real app built by NewApp, with the
// app's slog logger pointed at a buffer, and reads what the middleware actually
// wrote. Deleting the RedactURI call from requestLogger fails it.
func TestRedactionIsWiredIntoTheRequestLogger(t *testing.T) {
	// A token in the pasted URL: the realistic case from docs — someone
	// inspects a password-reset link and the reset token rides along in the
	// query string of OUR request, straight into a log Docker keeps forever.
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
			// Echo resolves c.Logger() to e.Logger at call time, so pointing it
			// at a buffer after NewApp still captures what the middleware writes.
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
			// The corpus still has to show which endpoint was hit, or the log
			// is safe and useless.
			if !strings.Contains(line, "status=200") {
				t.Errorf("log line lost the status field: %q", line)
			}
		})
	}
}

// TestRedactionLeavesOrdinaryRequestsLegible: the same middleware runs on
// ip.corpberry.com and dns.corpberry.com, where the query string is the whole
// analytic value of the log. Redaction that over-reaches costs that.
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
