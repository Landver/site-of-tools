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

// handler holds the transport-layer dependencies for the ip.corpberry.com routes.
type handler struct {
	svc Looker
}

// Register wires the ip.corpberry.com routes onto e. Lookups are query-param only
// (?ip=…), consistent with /cidr?cidr=… — there is no /:ip pretty route.
//
//	GET /        an IP's geo/ASN/proxy — the caller's own by default, or ?ip= to look one up
//	GET /cidr    subnet / CIDR calculator (?cidr=…)
func Register(e *echo.Echo, svc Looker) {
	h := &handler{svc: svc}
	e.GET("/", h.index)
	e.GET("/cidr", h.cidr)
}

// index serves the visitor's own IP by default, or ?ip= to look one up. A bare hit
// with no resolvable IP renders the empty lookup page.
func (h *handler) index(c *echo.Context) error {
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
		return c.Render(http.StatusOK, "ip/index", map[string]any{
			"Title": "IP Tools", "Active": "lookup", "Query": "", "Attribution": true, "Conn": conn(c),
		})
	}
	return h.show(c, ip, self)
}

// cidr serves the subnet / CIDR calculator (GET /cidr, ?cidr=…). Pure math, no
// databases — so this page carries no IP2Location attribution.
func (h *handler) cidr(c *echo.Context) error {
	input := strings.TrimSpace(c.QueryParam("cidr"))
	if input == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "provide a CIDR, e.g. /cidr?cidr=192.168.1.0/24"})
		}
		return c.Render(http.StatusOK, "ip/cidr", map[string]any{"Title": "Subnet calculator", "Active": "cidr", "Query": ""})
	}
	sub, err := ParseSubnet(input)
	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"cidr": input, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, sub)
	}
	vm := map[string]any{"Title": "Subnet calculator", "Active": "cidr", "Query": input, "Subnet": sub}
	code := http.StatusOK
	if err != nil {
		vm["Subnet"] = nil
		vm["Error"] = err.Error()
		code = http.StatusBadRequest
	}
	return c.Render(code, "ip/cidr", vm)
}

// show looks up ip and responds in the caller's preferred format. self marks the
// result as the visitor's own IP (for a small label in the HTML view).
func (h *handler) show(c *echo.Context, ip string, self bool) error {
	res, err := h.svc.Lookup(ip)

	// API / CLI: raw JSON — the geolocation result, or an error.
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
	vm := map[string]any{"Title": "IP Tools", "Active": "lookup", "Query": ip, "Result": res, "Self": self, "Attribution": true}
	code := http.StatusOK
	if err != nil {
		vm["Result"] = nil
		vm["Error"] = err.Error()
		code = statusFor(err)
	}
	if platform.IsHTMX(c) {
		return c.Render(code, "ip/result", vm)
	}
	vm["Conn"] = conn(c) // full page only — the "your request" card
	return c.Render(code, "ip/index", vm)
}

// ConnInfo is the "your request" inspector's view of the current request — pure
// transport metadata, no domain lookup. TLS and the visitor's HTTP version are
// absent: they terminate at Cloudflare/nginx and aren't knowable here. Cookie and
// Authorization are deliberately never read.
type ConnInfo struct {
	IP       string // resolved client IP (c.RealIP())
	Via      string // how the IP was derived: Cloudflare / X-Forwarded-For / direct
	Scheme   string // http or https (from X-Forwarded-Proto, else the local conn)
	Host     string // Host header the visitor hit
	Browser  string // User-Agent
	Language string // first Accept-Language token
}

// conn builds the connection inspector's data from the current request.
func conn(c *echo.Context) ConnInfo {
	r := c.Request()

	via := "direct"
	switch {
	case r.Header.Get("CF-Connecting-IP") != "":
		via = "Cloudflare"
	case r.Header.Get("X-Forwarded-For") != "":
		via = "X-Forwarded-For"
	}

	// Browser-facing scheme: X-Forwarded-Proto is the reliable signal (TLS
	// terminates upstream); fall back to the local connection in dev.
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}

	lang := r.Header.Get("Accept-Language")
	if i := strings.IndexAny(lang, ",;"); i >= 0 {
		lang = lang[:i]
	}

	return ConnInfo{
		IP:       c.RealIP(),
		Via:      via,
		Scheme:   scheme,
		Host:     r.Host,
		Browser:  r.UserAgent(),
		Language: strings.TrimSpace(lang),
	}
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
