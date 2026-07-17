package tests

import (
	"context"
	"testing"

	"github.com/Landver/site-of-tools/platform"
)

// TestNewRequestLogDisabled: a nil db (Mongo off) yields a nil store — the valid
// "disabled" value whose methods no-op, so a Mongo-less boot needs no guards.
func TestNewRequestLogDisabled(t *testing.T) {
	if rl := platform.NewRequestLog(context.Background(), nil); rl != nil {
		t.Fatalf("NewRequestLog(nil db) = %v, want nil (disabled)", rl)
	}
}

// TestNilRequestLogIsSafe: Record and Close must be nil-safe (a nil *RequestLog is
// how "Mongo disabled" propagates through NewApp into the middleware).
func TestNilRequestLogIsSafe(t *testing.T) {
	var rl *platform.RequestLog
	rl.Record(platform.RequestEntry{Method: "GET", URI: "/"}) // must not panic
	if err := rl.Close(context.Background()); err != nil {
		t.Errorf("nil RequestLog Close() = %v, want nil", err)
	}
}

// TestShouldRecord: page requests are persisted, static assets are not (high
// volume, no analytic value).
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
