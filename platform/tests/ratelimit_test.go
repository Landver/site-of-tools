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

func hitAs(e *echo.Echo, client string) *httptest.ResponseRecorder {
	return hit(e, "/", map[string]string{"CF-Connecting-IP": client})
}

func TestLimiterIsOneBudgetPerClientAcrossDoors(t *testing.T) {
	l := platform.NewLimiter(0.001, 3)
	a, b := limitedApp(l), limitedApp(l)
	if hitAs(a, "2001:db8:1:2::1").Code != http.StatusOK || !platform.AllowKey(l, "2001:db8:1:2::2") ||
		hitAs(b, "2001:db8:1:2::3").Code != http.StatusOK {
		t.Fatal("refused inside the burst of 3")
	}
	if platform.AllowKey(l, "2001:db8:1:2::4") {
		t.Error("AllowKey passed a fourth call from the /64 after two apps and AllowKey spent its burst")
	}
	if code := hitAs(a, "2001:db8:1:2:ffff::9").Code; code != http.StatusTooManyRequests {
		t.Errorf("the same /64 after its burst = %d, want 429", code)
	}
	for _, other := range []string{"2001:db8:1:3::1", "203.0.113.6"} {
		if code := hitAs(b, other).Code; code != http.StatusOK {
			t.Errorf("another client %s = %d, want 200: budgets are per client", other, code)
		}
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
	if rec := hitAs(e, "203.0.113.5"); rec.Code != http.StatusOK || rec.Header().Get("X-RateLimit-Limit") != "2" {
		t.Fatalf("second caller = %d with X-RateLimit-Limit %q, want 200 and the burst: Echo's headers must survive the wrapper",
			rec.Code, rec.Header().Get("X-RateLimit-Limit"))
	}
	if code := hitAs(e, "192.0.2.77").Code; code != http.StatusTooManyRequests {
		t.Errorf("third distinct caller = %d, want 429: the global bucket is shared", code)
	}
}

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
	if c.TryAcquire("2001:db8:1:2::77", 1) {
		t.Error("a third unit for the same /64 was granted past the share")
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

	big := platform.NewCap(256)
	if !big.TryAcquire("192.0.2.1", 128) {
		t.Error("a client holding nothing was refused a call over its share")
	}
	if big.TryAcquire("192.0.2.1", 1) {
		t.Error("a client over its share was granted more")
	}
}
