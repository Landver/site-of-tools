package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

func limitedApp(l platform.Limiter) *echo.Echo {
	e := platform.NewApp(nil, fstest.MapFS{}, false, nil)
	e.GET("/", func(c *echo.Context) error { return c.NoContent(http.StatusOK) },
		platform.RateLimit(l, nil, func(c *echo.Context) error { return c.NoContent(http.StatusTooManyRequests) }))
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
	a, b := limitedApp(l), limitedApp(l)
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
	a, b := limitedApp(l), limitedApp(l)
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
	e := limitedApp(platform.NewLimiter(0.001, 2))
	hitAs(e, "junk-1")
	hitAs(e, "junk-2")
	if code := hitAs(e, "junk-3"); code != http.StatusTooManyRequests {
		t.Errorf("a third forged value = %d, want 429: unparseable clients must not each get a budget", code)
	}
	if code := hitAs(e, "203.0.113.5"); code != http.StatusOK {
		t.Errorf("a real client after the junk bucket emptied = %d, want 200", code)
	}
}

// AllowKey, the MCP door, must spend the middleware's bucket, by raw IP or key.
func TestAllowKeySpendsTheMiddlewaresBucket(t *testing.T) {
	l := platform.NewLimiter(0.001, 3)
	e := limitedApp(l)
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
	if r, b := l.Rate(); r != 0.001 || b != 2 {
		t.Errorf("Rate() = %g, %d, want what it was built with", r, b)
	}
	e := limitedApp(l)
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
	limitedApp(platform.NewGlobalLimiter(1, 5)).ServeHTTP(rec, req)
	if rec.Header().Get("X-RateLimit-Limit") != "5" {
		t.Errorf("X-RateLimit-Limit = %q, want the store's burst: Echo's headers must survive the wrapper",
			rec.Header().Get("X-RateLimit-Limit"))
	}
}

// One client, an IPv6 /64 counting as one, may hold a quarter of a cap.
func TestCapSharePerClient(t *testing.T) {
	var unbounded *platform.Cap
	if !unbounded.TryAcquire("192.0.2.1", 1<<40) {
		t.Error("a nil Cap refused")
	}
	unbounded.Release("192.0.2.1", 1<<40)

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
