package iptools

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Page descriptions feed <meta name="description"> and og:description via the "Desc" VM key.
const (
	lookupDesc  = "Look up any IP: geolocation, ASN, VPN/proxy/Tor and blocklist reputation, and open ports. Or inspect your own connection. Free, open source, with a curl-able JSON API."
	cidrDesc    = "CIDR subnet calculator: network range, broadcast address, netmask, and host counts for any CIDR. Free, open source, JSON API included."
	historyDesc = "Recent IP lookups made from this browser."
)

// Looker is satisfied by *Service (a nil one returns ErrUnavailable) and by test fakes.
type Looker interface {
	Lookup(ctx context.Context, ip string) (*Result, error)
}

type handler struct {
	svc Looker
	chk Checker // nil when Mongo is off, so no blocklist row
	lim *Limits
}

// Limits are built once and shared by REST and MCP, so both spend one budget.
type Limits struct {
	Lookup, CIDR platform.Limiter
	LookupCap    *platform.Cap
}

func NewLimits() *Limits {
	return &Limits{
		Lookup:    platform.NewLimiter(2, 10),
		CIDR:      platform.NewLimiter(10, 50),
		LookupCap: platform.NewCap(8),
	}
}

// Register: lookups take ?ip= only, matching /cidr?cidr=; there is no /:ip route.
func Register(e *echo.Echo, svc Looker, chk Checker, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{svc: svc, chk: chk, lim: lim}
	e.GET("/", h.index, platform.RateLimit(lim.Lookup, nil, h.limited))
	e.GET("/cidr", h.cidr, platform.RateLimit(lim.CIDR, nil, h.limited))
	e.GET("/history", history)
}

func (h *handler) limited(c *echo.Context) error {
	const code = http.StatusTooManyRequests
	platform.SetNegotiationHeaders(c, code)
	if platform.WantsJSON(c) {
		return c.JSON(code, map[string]string{"error": platform.LimitedMessage})
	}
	var page string
	var vm map[string]any
	switch c.Path() {
	case "/cidr":
		page, vm = "ip/cidr", cidrVM(strings.TrimSpace(c.QueryParam("cidr")))
	default:
		page, vm = "ip/index", lookupVM(strings.TrimSpace(c.QueryParam("ip")))
		if platform.IsHTMX(c) {
			page = "ip/result"
		} else {
			vm["Conn"] = platform.Conn(c)
		}
	}
	vm["Error"] = platform.LimitedMessage
	return c.Render(code, page, vm)
}

func lookupVM(query string) map[string]any {
	return map[string]any{"Title": "IP Tools", "Desc": lookupDesc, "Active": "lookup", "Query": query,
		"Attribution": true, "SpamhausAttribution": true, "Subdomain": "ip"}
}

func cidrVM(query string) map[string]any {
	return map[string]any{"Title": "Subnet calculator", "Desc": cidrDesc, "Active": "cidr", "Query": query, "Subdomain": "ip"}
}

// No routable IP: browsers get the empty page, htmx an empty fragment (never the full page), JSON a 400.
func (h *handler) index(c *echo.Context) error {
	ip := strings.TrimSpace(c.QueryParam("ip"))
	self := false
	if ip == "" {
		if own := c.RealIP(); Routable(own) {
			ip, self = own, true
		}
	}
	if ip == "" {
		platform.SetNegotiationHeaders(c, http.StatusOK)
		switch {
		case platform.WantsJSON(c):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no routable IP to look up; pass ?ip=, e.g. /?ip=8.8.8.8"})
		case platform.IsHTMX(c):
			return c.Render(http.StatusOK, "ip/result", map[string]any{})
		}
		vm := lookupVM("")
		vm["Conn"] = platform.Conn(c)
		return c.Render(http.StatusOK, "ip/index", vm)
	}
	return h.show(c, ip, self)
}

// cidr uses no databases, so its page carries no IP2Location attribution.
func (h *handler) cidr(c *echo.Context) error {
	platform.SetNegotiationHeaders(c, http.StatusOK)
	input := strings.TrimSpace(c.QueryParam("cidr"))
	if input == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "provide a CIDR, e.g. /cidr?cidr=192.168.1.0/24"})
		}
		return c.Render(http.StatusOK, "ip/cidr", cidrVM(""))
	}
	sub, err := ParseSubnet(input)
	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"cidr": input, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, sub)
	}
	vm := cidrVM(input)
	code := http.StatusOK
	if err != nil {
		vm["Error"] = err.Error()
		code = http.StatusBadRequest
	} else {
		vm["Subnet"] = sub
	}
	return c.Render(code, "ip/cidr", vm)
}

// history renders past lookups from this browser's localStorage; the server keeps none, so it has no JSON.
// The rows are database results, so the page carries the IP2Location credit.
func history(c *echo.Context) error {
	return c.Render(http.StatusOK, "ip/history", map[string]any{"Title": "Lookup history", "Desc": historyDesc,
		"Active": "history", "Attribution": true, "SpamhausAttribution": true, "Subdomain": "ip"})
}

func (h *handler) show(c *echo.Context, ip string, self bool) error {
	res, err := h.lookup(c, ip)
	wantsJSON := platform.WantsJSON(c)

	code := http.StatusOK
	if err != nil {
		code = statusFor(err)
	}
	platform.SetNegotiationHeaders(c, code)

	if wantsJSON {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	}

	vm := lookupVM(ip)
	vm["Self"] = self
	if err != nil {
		vm["Error"] = pageError(err)
	} else {
		vm["Result"] = res
		vm["ShodanAttribution"] = res.ShodanConsulted()
	}
	if platform.IsHTMX(c) {
		return c.Render(code, "ip/result", vm)
	}
	// Only a self-lookup enriches the conn card: someone else's IP says nothing about this connection.
	conn := platform.Conn(c)
	if self && err == nil {
		conn = conn.WithNetwork(res.ConnNetwork())
	}
	vm["Conn"] = conn
	return c.Render(code, "ip/index", vm)
}

func (h *handler) lookup(c *echo.Context, ip string) (*Result, error) {
	if !h.lim.LookupCap.TryAcquire(c.RealIP(), 1) {
		return nil, platform.ErrBusy
	}
	defer h.lim.LookupCap.Release(c.RealIP(), 1)
	return LookupWithReputation(c.Request().Context(), h.svc, h.chk, ip)
}

// pageError is a lookup error for the page; the JSON keeps the Go string.
func pageError(err error) string {
	if errors.Is(err, ErrUnavailable) {
		return "IP lookups are unavailable right now: this server's geolocation databases are not loaded. Try again later."
	}
	return err.Error()
}

func statusFor(err error) int {
	if errors.Is(err, ErrUnavailable) || errors.Is(err, platform.ErrBusy) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// ConnNetwork is the one Result-to-conn-card mapping, shared with botcheck so the two can't drift.
func (r *Result) ConnNetwork() platform.ConnNetwork {
	if r == nil {
		return platform.ConnNetwork{}
	}
	n := platform.ConnNetwork{ASN: r.ASN, ASName: r.ASName}
	if p := r.Proxy; p != nil && p.IsProxy {
		n.ProxyType, n.Provider = p.ProxyType, p.Provider
	}
	return n
}

// SitemapPages leaves out /history: transient third-party IPs with no search value.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}, {Path: "/cidr"}}, nil
}
