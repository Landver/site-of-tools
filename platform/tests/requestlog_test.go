package tests

import (
	"context"
	"testing"

	"github.com/Landver/site-of-tools/platform"
)

// TestNewRequestLogDisabled: a nil db yields a nil store whose no-op methods need no guards.
func TestNewRequestLogDisabled(t *testing.T) {
	if rl := platform.NewRequestLog(context.Background(), nil); rl != nil {
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
