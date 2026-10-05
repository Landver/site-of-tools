package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// limitedApp is one door onto l. The deny answer is 429 with no body, so a
// refused request can't be mistaken for an allowed one.
func limitedApp(l platform.Limiter, skip func(*echo.Context) bool) *echo.Echo {
	e := platform.NewApp(nil, fstest.MapFS{}, false, nil)
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) },
		platform.RateLimit(l, skip, func(c *echo.Context) error { return c.NoContent(http.StatusTooManyRequests) }))
	return e
}

func hitAs(e *echo.Echo, client string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("CF-Connecting-IP", client)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code
}

func TestRateLimitBudgetIsSharedAcrossApps(t *testing.T) {
	l := platform.NewLimiter(0.001, 3)
	a, b := limitedApp(l, nil), limitedApp(l, nil)
	for i := range 3 {
		if code := hitAs(a, "203.0.113.5"); code != http.StatusOK {
			t.Fatalf("request %d on the first app = %d, want 200 inside the burst", i+1, code)
		}
	}
	if code := hitAs(b, "203.0.113.5"); code != http.StatusTooManyRequests {
		t.Errorf("second app after the budget was spent on the first = %d, want 429", code)
	}
	if code := hitAs(b, "203.0.113.6"); code != http.StatusOK {
		t.Errorf("another client = %d, want 200: budgets are per client", code)
	}
}

func TestRateLimitIPv6ClientIsOneBucketPerSlash64(t *testing.T) {
	l := platform.NewLimiter(0.001, 2)
	a, b := limitedApp(l, nil), limitedApp(l, nil)
	hitAs(a, "2001:db8:1:2::1")
	hitAs(a, "2001:db8:1:2::2")
	if code := hitAs(b, "2001:db8:1:2:ffff::9"); code != http.StatusTooManyRequests {
		t.Errorf("third address in the same /64 = %d, want 429", code)
	}
	if code := hitAs(b, "2001:db8:1:3::1"); code != http.StatusOK {
		t.Errorf("an address in the next /64 = %d, want 200", code)
	}
}

func TestRateLimitUnparseableClientsShareOneBucket(t *testing.T) {
	e := limitedApp(platform.NewLimiter(0.001, 2), nil)
	hitAs(e, "junk-1")
	hitAs(e, "junk-2")
	if code := hitAs(e, "junk-3"); code != http.StatusTooManyRequests {
		t.Errorf("a third forged value = %d, want 429: unparseable clients must not each get a budget", code)
	}
	if code := hitAs(e, "203.0.113.5"); code != http.StatusOK {
		t.Errorf("a real client after the junk bucket emptied = %d, want 200", code)
	}
}

func TestRateLimitSkipSpendsNothing(t *testing.T) {
	e := limitedApp(platform.NewLimiter(0.001, 1), func(c *echo.Context) bool { return c.QueryParam("q") == "" })
	for range 3 {
		if code := hitAs(e, "203.0.113.5"); code != http.StatusOK {
			t.Fatalf("skipped request = %d, want 200", code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/?q=x", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.5")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first counted request = %d, want 200: skipped ones spent the budget", rec.Code)
	}
}

// AllowKey is the MCP door: it must spend the very bucket the middleware
// spends, whether it is handed the raw IP or the key.
func TestAllowKeySpendsTheMiddlewaresBucket(t *testing.T) {
	l := platform.NewLimiter(0.001, 3)
	e := limitedApp(l, nil)
	if !platform.AllowKey(l, "2001:db8:1:2::1") || !platform.AllowKey(l, platform.RateLimitKey("2001:db8:1:2::2")) {
		t.Fatal("AllowKey refused inside the burst")
	}
	hitAs(e, "2001:db8:1:2::3")
	if platform.AllowKey(l, "2001:db8:1:2::4") {
		t.Error("AllowKey allowed a fourth call although REST and AllowKey together spent the burst of 3")
	}
	if code := hitAs(e, "2001:db8:1:2::5"); code != http.StatusTooManyRequests {
		t.Errorf("REST after the shared budget was spent = %d, want 429", code)
	}
}

func TestGlobalLimiterIsOneBucketForEveryone(t *testing.T) {
	l := platform.NewGlobalLimiter(0.001, 2)
	e := limitedApp(l, nil)
	if !platform.AllowKey(l, "198.51.100.1") {
		t.Fatal("first call refused")
	}
	if code := hitAs(e, "203.0.113.5"); code != http.StatusOK {
		t.Fatalf("second caller = %d, want 200", code)
	}
	if code := hitAs(e, "192.0.2.77"); code != http.StatusTooManyRequests {
		t.Errorf("third distinct caller = %d, want 429: the global bucket is shared", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	limitedApp(platform.NewGlobalLimiter(1, 5), nil).ServeHTTP(rec, req)
	if rec.Header().Get("X-RateLimit-Limit") != "5" {
		t.Errorf("X-RateLimit-Limit = %q, want the store's burst: Echo's headers must survive the wrapper",
			rec.Header().Get("X-RateLimit-Limit"))
	}
}

func TestCapRefusesAtOnceWhenFull(t *testing.T) {
	c := platform.NewCap(10)
	done := make(chan []bool, 1)
	go func() {
		done <- []bool{c.TryAcquire("192.0.2.1", 7), c.TryAcquire("192.0.2.2", 4), c.TryAcquire("192.0.2.3", 3), c.TryAcquire("192.0.2.4", 1)}
	}()
	select {
	case got := <-done:
		want := []bool{true, false, true, false}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("TryAcquire #%d = %v, want %v (sequence 7, 4, 3, 1 against 10)", i+1, got[i], want[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TryAcquire blocked on a full cap; it must refuse at once")
	}
	c.Release("192.0.2.1", 7)
	if !c.TryAcquire("192.0.2.5", 5) {
		t.Error("Release did not return the units")
	}

	var unbounded *platform.Cap
	if !unbounded.TryAcquire("192.0.2.1", 1<<40) {
		t.Error("a nil Cap refused; nil means no cap")
	}
	unbounded.Release("192.0.2.1", 1<<40)
}

// One client may hold a quarter of a cap, its IPv6 /64 counting as one
// client, so the rest stays free for everyone else.
func TestCapSharePerClient(t *testing.T) {
	c := platform.NewCap(8)
	for i := range 2 {
		if !c.TryAcquire("2001:db8:1:2::1", 1) {
			t.Fatalf("unit %d of the client's share of 2 refused", i+1)
		}
	}
	if c.TryAcquire(platform.RateLimitKey("2001:db8:1:2::77"), 1) {
		t.Error("a third unit for the same /64, by its key, was granted past the share")
	}
	for i := range 6 {
		if !c.TryAcquire(fmt.Sprintf("198.51.100.%d", i+1), 1) {
			t.Errorf("another client was refused with %d of 8 units held", 2+i)
		}
	}
	c.Release("2001:db8:1:2::2", 1)
	if c.TryAcquire("203.0.113.1", 2) {
		t.Error("granted 2 units with 1 free")
	}
	if !c.TryAcquire("2001:db8:1:2::3", 1) {
		t.Error("the /64 was refused after releasing a unit back to its share")
	}

	// A call bigger than any share still runs, alone, when the cap has room.
	big := platform.NewCap(256)
	if !big.TryAcquire("192.0.2.1", 128) {
		t.Error("a client holding nothing was refused a call over its share")
	}
	if big.TryAcquire("192.0.2.1", 1) {
		t.Error("a client over its share was granted more")
	}
}
