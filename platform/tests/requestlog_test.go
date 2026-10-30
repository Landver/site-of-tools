package tests

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// TestNewRequestLogDisabled: a nil db yields a nil store whose no-op methods need no guards.
func TestNewRequestLogDisabled(t *testing.T) {
	if rl := platform.NewRequestLog(context.Background(), nil, nil); rl != nil {
		t.Fatalf("NewRequestLog(nil db) = %v, want nil (disabled)", rl)
	}
}

// TestNilRequestLogIsSafe: a nil *RequestLog is how "Mongo disabled" reaches the middleware.
func TestNilRequestLogIsSafe(t *testing.T) {
	var rl *platform.RequestLog
	rl.Record(platform.RequestEntry{Method: "GET", URI: "/"}) // must not panic
	if err := rl.Close(context.Background()); err != nil {
		t.Errorf("nil RequestLog Close() = %v, want nil", err)
	}
}

// TestShouldRecord: pages are persisted; static assets and the /mcp messages mcptools records itself are not.
func TestShouldRecord(t *testing.T) {
	cases := []struct {
		method, path string
		status       int
		want         bool
	}{
		{"GET", "/", 200, true},
		{"GET", "/cidr", 200, true},
		{"GET", "/history", 200, true},
		{"GET", "/static/css/app.css", 200, false},
		{"GET", "/static/js/htmx.js", 404, false},
		{"POST", "/mcp", 200, false},
		{"POST", "/mcp/ip", 202, false},
		{"GET", "/mcpx", 200, true},
		// Refused before the SDK, so no message hook saw them: rate limit, owner key, batch, body size.
		{"POST", "/mcp", 429, true},
		{"POST", "/mcp/owner", 403, true},
		{"POST", "/mcp/dns", 400, true},
		{"POST", "/mcp", 413, true},
		// GETs carry no message: the landing page and a refused JSON GET.
		{"GET", "/mcp", 200, true},
		{"GET", "/mcp/ip", 405, true},
	}
	for _, c := range cases {
		if got := platform.ShouldRecord(c.method, c.path, c.status); got != c.want {
			t.Errorf("ShouldRecord(%s %s %d) = %v, want %v", c.method, c.path, c.status, got, c.want)
		}
	}
}

// TestIsProbe: a 404 on a dotfile or .php path counts, unless a browser or a Cloudflare Worker sent it.
func TestIsProbe(t *testing.T) {
	cases := []struct {
		target string
		status int
		header string // set to "x" when non-empty
		want   bool
	}{
		{"/.env", 404, "", true},
		{"/packages/api/.env", 404, "", true},
		{"/.git/config", 404, "", true},
		{"/.AWS/credentials", 404, "", true},
		{"/wp-login.php", 404, "", true},
		{"/.well-known/x.php", 404, "", true},
		{"/../etc/passwd", 404, "", true},
		{"/.well-known/security.txt", 404, "", false},
		{"/mcp/.well-known/openid-configuration", 404, "", false},
		{"/admin", 404, "", false},
		{"/favicon.ico", 404, "", false},
		{"/?u=https://x.test/.env", 404, "", false}, // the query is someone using a tool
		{"/.env", 200, "", false},
		{"/.env", 429, "", false},
		{"/.env", 404, "Sec-Fetch-Site", false}, // a hostile page's <img> makes its visitors send this
		{"/.env", 404, "CF-Worker", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.target, nil)
		if c.header != "" {
			r.Header.Set(c.header, "x")
		}
		if got := platform.IsProbe(r, c.status); got != c.want {
			t.Errorf("IsProbe(%s, %d, %q) = %v, want %v", c.target, c.status, c.header, got, c.want)
		}
	}
}

// TestRequestLogProbeHookLive: a real 404 on a probe path reaches the hook once; dev never flags.
func TestRequestLogProbeHookLive(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping live request-log test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m, err := platform.OpenMongo(ctx, uri, "site-of-tools-test")
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	t.Cleanup(func() { _ = m.DB().Collection("request_logs").Drop(ctx); _ = m.Close(ctx) })

	var got []string // written by the writer goroutine, read after Close has drained it
	rl := platform.NewRequestLog(ctx, m.DB(), func(_ context.Context, e platform.RequestEntry) { got = append(got, e.URI) })
	prod, dev := platform.NewApp(nil, fstest.MapFS{}, false, rl), platform.NewApp(nil, fstest.MapFS{}, true, rl)
	for _, hit := range []struct {
		app  *echo.Echo
		path string
	}{{prod, "/.env"}, {prod, "/"}, {dev, "/.git/config"}} {
		hit.app.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", hit.path, nil))
	}
	if err := rl.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if diff := cmp.Diff([]string{"/.env"}, got); diff != "" {
		t.Errorf("hook calls (-want +got):\n%s", diff)
	}
}
