package platform

import (
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"golang.org/x/sync/semaphore"
)

// Limiter is a token-bucket store keyed by client. A tool package builds its
// stores once and hands the same values to every door (REST, MCP), so a client
// has one budget whichever it uses.
type Limiter = middleware.RateLimiterStore

// BusyMessage answers a request refused because a Cap is full.
const BusyMessage = "Busy, try again in a few seconds."

const limiterExpiry = 3 * time.Minute

// NewLimiter returns a per-client store refilling rate tokens a second, up to
// burst.
func NewLimiter(rate float64, burst int) Limiter {
	return newStore(rate, burst)
}

// NewGlobalLimiter returns a store with one bucket for every caller, whatever
// key it is asked about: a breaker for a resource all clients share, which
// per-client buckets cannot protect.
func NewGlobalLimiter(rate float64, burst int) Limiter {
	return globalLimiter{newStore(rate, burst)}
}

func newStore(rate float64, burst int) *middleware.RateLimiterMemoryStore {
	return middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate: rate, Burst: burst, ExpiresIn: limiterExpiry,
	})
}

type globalLimiter struct {
	s *middleware.RateLimiterMemoryStore
}

func (g globalLimiter) Allow(string) (bool, error) { return g.s.Allow("") }

// AllowContext keeps the X-RateLimit-* headers the memory store sets in Echo.
func (g globalLimiter) AllowContext(c *echo.Context, _ string) (bool, error) {
	return g.s.AllowContext(c, "")
}

// RateLimit spends one token of the client's bucket in l per request, keyed by
// RateLimitKey(c.RealIP()) exactly as AllowKey keys it, and answers with deny
// once the bucket is empty. skip (nil for none) exempts requests that do no work.
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

// AllowKey spends one token of a client's bucket in l, for callers outside
// Echo. client is the raw IP or its RateLimitKey; both reach the bucket
// RateLimit uses. A store error refuses.
func AllowKey(l Limiter, client string) bool {
	ok, err := l.Allow(RateLimitKey(client))
	return ok && err == nil
}

// Cap bounds work in flight and never queues: TryAcquire fails at once when
// the budget is spent, so the caller answers busy. Each client's share is a
// quarter of it, so one client held up by a slow upstream can't make everyone
// else busy. A nil Cap is unbounded.
type Cap struct {
	sem   *semaphore.Weighted
	share int64
	mu    sync.Mutex
	held  map[string]int64
}

// NewCap returns a Cap of n units, shared by every door like a Limiter.
func NewCap(n int64) *Cap {
	return &Cap{sem: semaphore.NewWeighted(n), share: max(1, n/4), held: map[string]int64{}}
}

// TryAcquire takes w units for client, the raw IP or its RateLimitKey, if
// they are free now and within the client's share. A client holding nothing
// may exceed its share, so no single call is refused forever.
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

// Release returns w units client took with TryAcquire.
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
