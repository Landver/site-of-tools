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
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/dnstools"
)

// limitsApp is one door onto lim, the way main.go hands one Limits value to
// REST and to MCP.
func limitsApp(t *testing.T, lim *dnstools.Limits) *echo.Echo {
	t.Helper()
	e := echo.New()
	e.Renderer = platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
	)
	dnstools.Register(e, &goldenDNS{}, nil, nil, nil, lim)
	return e
}

func from(e *echo.Echo, target, remote string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// within fails the test if f waits instead of answering: a full cap must
// refuse, never queue.
func within(t *testing.T, f func() *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f() }()
	select {
	case rec := <-done:
		return rec
	case <-time.After(2 * time.Second):
		t.Fatal("the request waited on a full cap instead of answering busy")
		return nil
	}
}

// A walk costs 50 to 100 upstream queries, so /consistency and /trace share
// one class, 1 per 2 s with burst 3, apart from the lookup budget.
func TestWalksHaveTheirOwnStricterBudget(t *testing.T) {
	t.Parallel()
	e := limitsApp(t, nil)
	const client = "203.0.113.30:1234"
	for i, target := range []string{"/consistency?name=example.com", "/trace?name=example.com", "/consistency?name=example.com"} {
		if rec := from(e, target, client, nil); rec.Code != http.StatusOK {
			t.Fatalf("walk %d (%s) = %d, want 200 inside the burst of 3", i+1, target, rec.Code)
		}
	}
	rec := from(e, "/trace?name=example.com", client, nil)
	if rec.Code != http.StatusTooManyRequests || !strings.HasPrefix(rec.Body.String(), "{") {
		t.Errorf("fourth walk = %d %s, want a JSON 429", rec.Code, rec.Body)
	}
	if rec := from(e, "/?name=example.com", client, nil); rec.Code != http.StatusOK {
		t.Errorf("a lookup after the walk budget ran out = %d, want 200: the classes are separate", rec.Code)
	}
}

// One Limits value is one budget, whichever app spends it, and an IPv6 client
// is one client across its /64 (dnstools used to key on the bare address).
func TestOneLimitsIsOneBudgetAcrossApps(t *testing.T) {
	t.Parallel()
	lim := dnstools.NewLimits()
	rest, other := limitsApp(t, lim), limitsApp(t, lim)
	for range 3 {
		from(rest, "/trace?name=example.com", "[2001:db8:5:6::1]:1234", nil)
	}
	if rec := from(other, "/consistency?name=example.com", "[2001:db8:5:6:ffff::9]:1234", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("same /64 on the other app = %d, want 429", rec.Code)
	}
	if rec := from(limitsApp(t, nil), "/consistency?name=example.com", "[2001:db8:5:6::1]:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("an app with its own Limits = %d, want 200", rec.Code)
	}
}

func TestFullCapAnswersBusyWithoutQueueing(t *testing.T) {
	t.Parallel()
	lim := dnstools.NewLimits()
	if !lim.WalkCap.TryAcquire(4) || !lim.LookupCap.TryAcquire(8) {
		t.Fatal("fresh caps are not 4 walks and 8 lookups")
	}
	e := limitsApp(t, lim)

	for _, target := range []string{"/trace?name=example.com", "/consistency?name=example.com", "/?name=example.com", "/email?name=example.com", "/domain?name=example.com"} {
		rec := within(t, func() *httptest.ResponseRecorder { return from(e, target, "203.0.113.32:1234", nil) })
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusServiceUnavailable || body["error"] != platform.BusyMessage {
			t.Errorf("%s with its cap full = %d %s, want 503 {error: %q}", target, rec.Code, rec.Body, platform.BusyMessage)
		}
	}
	page := within(t, func() *httptest.ResponseRecorder {
		return from(e, "/trace?name=example.com", "203.0.113.33:1234", map[string]string{"Accept": "text/html"})
	})
	if page.Code != http.StatusServiceUnavailable || !strings.Contains(page.Body.String(), platform.BusyMessage) ||
		!strings.Contains(page.Body.String(), `id="dns-nav"`) {
		t.Errorf("browser with the walk cap full = %d, want the trace page saying busy", page.Code)
	}

	lim.WalkCap.Release(4)
	if rec := from(e, "/trace?name=example.com", "203.0.113.34:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("walk after the cap freed = %d, want 200", rec.Code)
	}
}
