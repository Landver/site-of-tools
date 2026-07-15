package iptools

import (
	"errors"
	"net"
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
//	GET /        the visitor's own IP by default (or ?ip= to look one up)
//	GET /:ip     look up a specific IP (pretty URL for browsers and `curl`)
func Register(e *echo.Echo, svc Looker) {
	e.GET("/", func(c *echo.Context) error {
		ip := strings.TrimSpace(c.QueryParam("ip"))
		self := false
		if ip == "" {
			// Default to the caller's own IP when it's a routable public address
			// (skips 127.0.0.1 in dev, private ranges, etc.).
			if own := c.RealIP(); routable(own) {
				ip, self = own, true
			}
		}
		if ip == "" {
			return c.Render(http.StatusOK, "ip/index", map[string]any{"Title": "IP Tools", "Query": "", "Attribution": true})
		}
		return show(c, svc, ip, self)
	})

	e.GET("/:ip", func(c *echo.Context) error {
		return show(c, svc, strings.TrimSpace(c.Param("ip")), false)
	})
}

// show looks up ip and responds in the caller's preferred format. self marks the
// result as the visitor's own IP (for a small label in the HTML view).
func show(c *echo.Context, svc Looker, ip string, self bool) error {
	res, err := svc.Lookup(ip)

	// API / CLI: raw JSON (result or error).
	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	}

	// Browser / htmx: a view model rendered as a full page or a fragment.
	// Attribution: IP2Location LITE's license requires the credit on any page that
	// uses the databases (see shared/templates/partials/footer.html). It's scoped
	// to this tool via the VM flag, so the apex — which uses no such data — omits it.
	vm := map[string]any{"Title": "IP Tools", "Query": ip, "Result": res, "Self": self, "Attribution": true}
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
	if errors.Is(err, ErrUnavailable) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// routable reports whether ipStr is a public address worth geolocating — not
// loopback / private / link-local / unspecified.
func routable(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
