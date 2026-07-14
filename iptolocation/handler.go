package iptolocation

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Looker is the handler's dependency: anything that can resolve an IP. *Service
// satisfies it; tests inject a fake. (A nil *Service is a valid Looker and
// returns ErrUnavailable.)
type Looker interface {
	Lookup(ip string) (*Result, error)
}

// Register wires the ip.corpberry.com routes onto e.
//
//	GET /        landing page with the lookup form (?ip= prefills / runs a lookup)
//	GET /:ip     look up a specific IP (pretty URL for browsers and `curl`)
func Register(e *echo.Echo, svc Looker) {
	e.GET("/", func(c *echo.Context) error {
		if ip := strings.TrimSpace(c.QueryParam("ip")); ip != "" {
			return lookup(c, svc, ip)
		}
		return c.Render(http.StatusOK, "ip/index", map[string]any{"Title": "IP → Location"})
	})

	e.GET("/:ip", func(c *echo.Context) error {
		return lookup(c, svc, strings.TrimSpace(c.Param("ip")))
	})
}

// lookup performs the lookup and responds in the caller's preferred format.
func lookup(c *echo.Context, svc Looker, ip string) error {
	res, err := svc.Lookup(ip)

	// API / CLI: raw JSON (result or error).
	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	}

	// Browser / htmx: a view model rendered as a full page or a fragment.
	vm := map[string]any{"Title": "IP → Location", "Query": ip, "Result": res}
	code := http.StatusOK
	if err != nil {
		vm["Result"] = nil
		vm["Error"] = err.Error()
		code = statusFor(err)
	}
	if platform.IsHTMX(c) {
		return c.Render(code, "ip/result", vm)
	}
	return c.Render(code, "ip/index", vm)
}

func statusFor(err error) int {
	if err == ErrUnavailable {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}
