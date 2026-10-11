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
	"github.com/Landver/site-of-tools/tools/dnstools"
)

// limitsApp is one door onto lim, as main.go hands one Limits to REST and MCP.
func limitsApp(lim *dnstools.Limits) *echo.Echo {
	return registerApp(&goldenDNS{}, nil, nil, nil, lim)
}

// within fails the test if f waits: a full cap must refuse, never queue.
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

// A walk costs 50 to 100 upstream queries, so walks have a budget apart from lookups.
func TestWalksHaveTheirOwnStricterBudget(t *testing.T) {
	t.Parallel()
	e := limitsApp(nil)
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

// One Limits value is one budget, whichever app spends it, an IPv6 client's by its /64.
func TestOneLimitsIsOneBudgetAcrossApps(t *testing.T) {
	t.Parallel()
	lim := dnstools.NewLimits()
	rest, other := limitsApp(lim), limitsApp(lim)
	for range 3 {
		from(rest, "/trace?name=example.com", "[2001:db8:5:6::1]:1234", nil)
	}
	if rec := from(other, "/consistency?name=example.com", "[2001:db8:5:6:ffff::9]:1234", nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("same /64 on the other app = %d, want 429", rec.Code)
	}
	if rec := from(limitsApp(nil), "/consistency?name=example.com", "[2001:db8:5:6::1]:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("an app with its own Limits = %d, want 200", rec.Code)
	}
}

// /domain waits on RDAP and crt.sh, so it has a cap of its own.
func TestDomainReportsHaveTheirOwnCap(t *testing.T) {
	t.Parallel()
	lim := dnstools.NewLimits()
	dom, _ := canned(t, rdapBody(time.Now().AddDate(1, 0, 0)), http.StatusOK, "[]", http.StatusOK)
	e := registerApp(&goldenDNS{}, nil, dom, nil, lim)
	const holder, client = "198.51.100.250", "203.0.113.35:1234"

	lim.LookupCap.TryAcquire(holder, 8)
	if rec := from(e, "/domain?name=example.com", client, nil); rec.Code != http.StatusOK {
		t.Errorf("/domain with every lookup slot held = %d %s, want 200", rec.Code, rec.Body)
	}
	lim.LookupCap.Release(holder, 8)

	lim.DomainCap.TryAcquire(holder, 4)
	if rec := from(e, "/?name=example.com", client, nil); rec.Code != http.StatusOK {
		t.Errorf("a lookup with the /domain cap full = %d, want 200", rec.Code)
	}
	if rec := from(e, "/domain?name=example.com", client, nil); rec.Code != http.StatusServiceUnavailable ||
		!strings.Contains(rec.Body.String(), platform.BusyMessage) {
		t.Errorf("/domain with its own cap full = %d %s, want 503 busy", rec.Code, rec.Body)
	}
}

func TestFullCapAnswersBusyWithoutQueueing(t *testing.T) {
	t.Parallel()
	lim := dnstools.NewLimits()
	const otherClient = "198.51.100.250"
	if !lim.WalkCap.TryAcquire(otherClient, 4) || !lim.LookupCap.TryAcquire(otherClient, 8) || !lim.DomainCap.TryAcquire(otherClient, 4) {
		t.Fatal("fresh caps are not 4 walks, 8 lookups and 4 domain reports")
	}
	e := limitsApp(lim)

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

	lim.WalkCap.Release(otherClient, 4)
	if rec := from(e, "/trace?name=example.com", "203.0.113.34:1234", nil); rec.Code != http.StatusOK {
		t.Errorf("walk after the cap freed = %d, want 200", rec.Code)
	}
}
