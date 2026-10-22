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

// TestShouldRecord: pages are persisted; static assets and /mcp (which records itself) are not.
func TestShouldRecord(t *testing.T) {
	cases := map[string]bool{
		"/":                   true,
		"/cidr":               true,
		"/history":            true,
		"/static/css/app.css": false,
		"/static/js/htmx.js":  false,
		"/mcp":                false,
		"/mcp/ip":             false,
		"/mcpx":               true,
	}
	for path, want := range cases {
		if got := platform.ShouldRecord(path); got != want {
			t.Errorf("ShouldRecord(%q) = %v, want %v", path, got, want)
		}
	}
}
