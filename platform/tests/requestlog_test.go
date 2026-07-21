package tests

import (
	"context"
	"testing"

	"github.com/Landver/site-of-tools/platform"
)

// TestNewRequestLogDisabled: nil db (Mongo off) → nil store, valid "disabled"
// value w/ no-op methods → Mongo-less boot needs no guards.
func TestNewRequestLogDisabled(t *testing.T) {
	if rl := platform.NewRequestLog(context.Background(), nil); rl != nil {
		t.Fatalf("NewRequestLog(nil db) = %v, want nil (disabled)", rl)
	}
}

// TestNilRequestLogIsSafe: Record + Close must be nil-safe — nil *RequestLog =
// how "Mongo disabled" propagates through NewApp into middleware.
func TestNilRequestLogIsSafe(t *testing.T) {
	var rl *platform.RequestLog
	rl.Record(platform.RequestEntry{Method: "GET", URI: "/"}) // must not panic
	if err := rl.Close(context.Background()); err != nil {
		t.Errorf("nil RequestLog Close() = %v, want nil", err)
	}
}

// TestShouldRecord: page requests persisted, static assets not — high volume,
// no analytic value.
func TestShouldRecord(t *testing.T) {
	cases := map[string]bool{
		"/":                   true,
		"/cidr":               true,
		"/history":            true,
		"/static/css/app.css": false,
		"/static/js/htmx.js":  false,
	}
	for path, want := range cases {
		if got := platform.ShouldRecord(path); got != want {
			t.Errorf("ShouldRecord(%q) = %v, want %v", path, got, want)
		}
	}
}
