package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

var asJSON = map[string]string{"Accept": "application/json"}

func limitsApp(lim *iptools.Limits) *echo.Echo {
	return newAppWith(fakeLooker{res: &iptools.Result{IP: "8.8.8.8"}}, nil, lim)
}

// spend keeps asking past the burst: a slow run may refill a token or two meanwhile.
func spend(t *testing.T, e *echo.Echo, target string, burst int, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	for i := range burst {
		if rec := do(e, target, hdr); rec.Code != http.StatusOK {
			t.Fatalf("%s request %d = %d, want 200 inside the burst of %d", target, i+1, rec.Code, burst)
		}
	}
	for range burst {
		if rec := do(e, target, hdr); rec.Code != http.StatusOK {
			return rec
		}
	}
	t.Fatalf("%s was never refused past its burst of %d", target, burst)
	return nil
}

func TestEveryRouteIsRateLimited(t *testing.T) {
	cases := []struct {
		target string
		burst  int
		hdr    map[string]string
		want   string // in the 429 body
	}{
		{"/?ip=8.8.8.8", 10, asJSON, `"error":"Too many requests`},
		{"/?ip=8.8.8.8", 10, map[string]string{"Accept": "text/html"}, "<html"},
		{"/?ip=8.8.8.8", 10, map[string]string{"HX-Request": "true"}, `class="alert-error`},
		{"/cidr?cidr=10.0.0.0/8", 50, map[string]string{"Accept": "text/html"}, "Subnet calculator"},
		{"/history", 10, map[string]string{"Accept": "text/html"}, "Lookup history"},
	}
	for _, tc := range cases {
		rec := spend(t, limitsApp(nil), tc.target, tc.burst, tc.hdr)
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), tc.want) ||
			!strings.Contains(rec.Body.String(), "Too many requests") {
			t.Errorf("%s %v past the burst = %d, want 429 with %q:\n%s", tc.target, tc.hdr, rec.Code, tc.want, rec.Body)
		}
	}
}

func TestOneLimitsIsOneBudgetAcrossApps(t *testing.T) {
	lim := iptools.NewLimits()
	spend(t, limitsApp(lim), "/?ip=8.8.8.8", 10, asJSON)
	if rec := do(limitsApp(lim), "/?ip=1.1.1.1", asJSON); rec.Code != http.StatusTooManyRequests {
		t.Errorf("the other app on the same Limits = %d, want 429", rec.Code)
	}
	if rec := do(limitsApp(lim), "/cidr?cidr=10.0.0.0/8", asJSON); rec.Code != http.StatusOK {
		t.Errorf("/cidr after the lookup budget ran out = %d, want 200: separate classes", rec.Code)
	}
}

func TestFullLookupCapAnswersBusy(t *testing.T) {
	lim := iptools.NewLimits()
	const otherClient = "198.51.100.250"
	if !lim.LookupCap.TryAcquire(otherClient, 8) {
		t.Fatal("a fresh lookup cap is not 8")
	}
	e := limitsApp(lim)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- do(e, "/?ip=8.8.8.8", asJSON) }()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the lookup waited on a full cap instead of answering busy")
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusServiceUnavailable ||
		body["error"] != platform.BusyMessage || body["ip"] != "8.8.8.8" {
		t.Errorf("full cap = %d %s, want 503 {ip, error: %q}", rec.Code, rec.Body, platform.BusyMessage)
	}
	if page := do(e, "/?ip=8.8.8.8", map[string]string{"Accept": "text/html"}); page.Code != http.StatusServiceUnavailable ||
		!strings.Contains(page.Body.String(), platform.BusyMessage) {
		t.Errorf("browser with a full cap = %d, want the page saying busy", page.Code)
	}
	lim.LookupCap.Release(otherClient, 8)
	if rec := do(e, "/?ip=8.8.8.8", asJSON); rec.Code != http.StatusOK {
		t.Errorf("lookup after the cap freed = %d, want 200", rec.Code)
	}
}
