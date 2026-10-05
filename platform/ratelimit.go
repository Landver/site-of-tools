package platform

import (
	"errors"
	"sync"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"golang.org/x/sync/semaphore"
)

// Limiter: build one per tool and hand it to REST and MCP alike, so a client has one budget.
type Limiter interface {
	middleware.RateLimiterStore
	Rate() (perSecond float64, burst int)
}

const (
	LimitedMessage = "Too many requests from your address. Try again in a few seconds."
	BusyMessage    = "Busy, try again in a few seconds."
)

var ErrBusy = errors.New(BusyMessage)

func NewLimiter(rate float64, burst int) Limiter { return newStore(rate, burst) }

func NewGlobalLimiter(rate float64, burst int) Limiter {
	return globalLimiter{newStore(rate, burst)}
}

type memStore struct {
	*middleware.RateLimiterMemoryStore
	perSecond float64
	burst     int
}

func newStore(rate float64, burst int) memStore {
	return memStore{middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate: rate, Burst: burst,
	}), rate, burst}
}

func (s memStore) Rate() (float64, int) { return s.perSecond, s.burst }

type globalLimiter struct{ memStore }

func (g globalLimiter) Allow(string) (bool, error) { return g.memStore.Allow("") }

// Echo calls AllowContext when a store has it, so it too must drop the client key.
func (g globalLimiter) AllowContext(c *echo.Context, _ string) (bool, error) {
	return g.memStore.AllowContext(c, "")
}

func RateLimit(l Limiter, skip func(*echo.Context) bool, deny func(*echo.Context) error) echo.MiddlewareFunc {
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: skip,
		Store:   l,
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return RateLimitKey(c.RealIP()), nil
		},
		DenyHandler: func(c *echo.Context, _ string, _ error) error { return deny(c) },
	})
}

// AllowKey is RateLimit outside Echo; client may be the raw IP or its key.
func AllowKey(l Limiter, client string) bool {
	ok, err := l.Allow(RateLimitKey(client))
	return ok && err == nil
}

// Cap bounds work in flight and never queues. A client may hold a quarter: one
// stuck on a slow upstream can't make everyone busy. A nil Cap is unbounded.
type Cap struct {
	sem   *semaphore.Weighted
	share int64
	mu    sync.Mutex
	held  map[string]int64
}

func NewCap(n int64) *Cap {
	return &Cap{sem: semaphore.NewWeighted(n), share: max(1, n/4), held: map[string]int64{}}
}

// TryAcquire lets a client holding nothing exceed its share, so no call is refused forever.
func (c *Cap) TryAcquire(client string, w int64) bool {
	if c == nil {
		return true
	}
	key := RateLimitKey(client)
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.held[key]; h > 0 && h+w > c.share {
		return false
	}
	if !c.sem.TryAcquire(w) {
		return false
	}
	c.held[key] += w
	return true
}

func (c *Cap) Release(client string, w int64) {
	if c == nil {
		return
	}
	key := RateLimitKey(client)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.held[key] -= w
	if c.held[key] <= 0 {
		delete(c.held, key)
	}
	c.sem.Release(w)
}
