package iptools

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Looker: handler's dependency, anything that can resolve an IP. *Service
// satisfies it; tests inject a fake. (nil *Service = valid Looker → returns
// ErrUnavailable.)
type Looker interface {
	Lookup(ip string) (*Result, error)
}

// handler: transport-layer deps for the ip.corpberry.com routes.
type handler struct {
	svc  Looker
	hist *History // nil when Mongo disabled — Record/Recent are nil-safe
}

// Register wires ip.corpberry.com routes onto e. Lookups query-param only
// (?ip=…), consistent w/ /cidr?cidr=… — no /:ip pretty route. hist may be nil
// (Mongo off) → /history view simply empty.
//
//	GET /         an IP's geo/ASN/proxy — the caller's own by default, or ?ip= to look one up
//	GET /cidr     subnet / CIDR calculator (?cidr=…)
//	GET /history  the most recent user-initiated lookups
func Register(e *echo.Echo, svc Looker, hist *History) {
	h := &handler{svc: svc, hist: hist}
	e.GET("/", h.index)
	e.GET("/cidr", h.cidr)
	e.GET("/history", h.history)
}

// index serves the visitor's own IP by default, or ?ip= to look one up. Bare
// hit w/ no resolvable IP renders empty lookup page to browser, (empty) result
// fragment to htmx — never a full page into #result slot — and 400 to JSON
// caller (same contract /cidr follows).
func (h *handler) index(c *echo.Context) error {
	ip := strings.TrimSpace(c.QueryParam("ip"))
	self := false
	if ip == "" {
		// Default to caller's own IP when it's a routable public address
		// (skips 127.0.0.1 in dev, private ranges, etc.).
		if own := c.RealIP(); routable(own) {
			ip, self = own, true
		}
	}
	if ip == "" {
		switch {
		case platform.WantsJSON(c):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no routable IP to look up; pass ?ip=, e.g. /?ip=8.8.8.8"})
		case platform.IsHTMX(c):
			return c.Render(http.StatusOK, "ip/result", map[string]any{})
		}
		return c.Render(http.StatusOK, "ip/index", map[string]any{
			"Title": "IP Tools", "Active": "lookup", "Query": "", "Attribution": true, "Conn": platform.Conn(c),
		})
	}
	return h.show(c, ip, self)
}

// cidr serves the subnet / CIDR calculator (GET /cidr, ?cidr=…). Pure math, no
// databases → no IP2Location attribution on this page.
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
	vm := map[string]any{"Title": "Subnet calculator", "Active": "cidr", "Query": input}
	code := http.StatusOK
	if err != nil {
		vm["Error"] = err.Error()
		code = http.StatusBadRequest
	} else {
		vm["Subnet"] = sub
	}
	return c.Render(code, "ip/cidr", vm)
}

// history lists the most recent user-initiated lookups. Content-negotiated like
// rest of tool: JSON for API/CLI, page for browsers. Mongo disabled → repo nil
// → simply shows empty history. HTML view carries IP2Location credit (displays
// geo/ASN data from the databases).
func (h *handler) history(c *echo.Context) error {
	const limit = 50
	entries, err := h.hist.Recent(c.Request().Context(), limit)

	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if entries == nil {
			entries = []HistoryEntry{} // render [] not null
		}
		return c.JSON(http.StatusOK, map[string]any{"lookups": entries})
	}

	vm := map[string]any{
		"Title": "Lookup history", "Active": "history",
		"Entries": entries, "Enabled": h.hist != nil, "Attribution": true,
	}
	if err != nil {
		vm["Error"] = err.Error()
	}
	return c.Render(http.StatusOK, "ip/history", vm)
}

// show looks up ip and responds in the caller's preferred format. self marks
// result as visitor's own IP (small label in HTML view).
func (h *handler) show(c *echo.Context, ip string, self bool) error {
	res, err := h.svc.Lookup(ip)
	wantsJSON := platform.WantsJSON(c)

	// Record real, user-initiated web lookups for /history view: successful,
	// not visitor's own auto-looked-up IP (self), from browser UI not JSON
	// caller — also excludes page's own IPv6 self-probe (requests JSON) + CLI
	// calls. Record is fire-and-forget + nil-safe → no added latency, no-ops
	// when Mongo off.
	if err == nil && !self && !wantsJSON {
		h.hist.Record(res)
	}

	// API / CLI: raw JSON — geolocation result, or error.
	if wantsJSON {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	}

	// Browser / htmx: view model rendered as full page or fragment.
	// Attribution: IP2Location LITE's license requires credit on any page using
	// the databases (see shared/templates/partials/footer.html). Scoped to this
	// tool via VM flag → apex (no such data) omits it.
	vm := map[string]any{"Title": "IP Tools", "Active": "lookup", "Query": ip, "Self": self, "Attribution": true}
	code := http.StatusOK
	if err != nil {
		vm["Error"] = err.Error()
		code = statusFor(err)
	} else {
		vm["Result"] = res
	}
	if platform.IsHTMX(c) {
		return c.Render(code, "ip/result", vm)
	}
	// Full page only — the "your request" card. G38/G44: when visitor looked at
	// OWN IP, same lookup also enriches card w/ ASN/proxy attribution the shared
	// conn partial renders (lookup of someone else's IP says nothing about this
	// connection → only self-lookups enrich).
	conn := platform.Conn(c)
	if self && err == nil {
		conn = conn.WithNetwork(res.ConnNetwork())
	}
	vm["Conn"] = conn
	return c.Render(code, "ip/index", vm)
}

func statusFor(err error) int {
	if errors.Is(err, ErrUnavailable) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// ConnNetwork maps a lookup result into the shared conn-card network
// attribution (G38/G44): ASN/AS-name plus proxy type/provider, as the plain
// strings platform.ConnInfo.WithNetwork expects. THE Result → ConnNetwork
// mapping, shared by iptools' own handler + botcheck's (whose conn card
// enriches from same lookup) → two tools can't drift apart.
// Lookup already blanks databases' "-" placeholders via clean(); runs again
// here so a hand-built Result (tests, fakes) maps same way. nil Result →
// zero value — no enrichment, card renders plain transport rows.
func (r *Result) ConnNetwork() platform.ConnNetwork {
	if r == nil {
		return platform.ConnNetwork{}
	}
	n := platform.ConnNetwork{ASN: clean(r.ASN), ASName: clean(r.ASName)}
	if p := r.Proxy; p != nil && p.IsProxy {
		n.ProxyType = p.ProxyType
		n.Provider = clean(p.Provider)
	}
	return n
}

// routable reports whether ipStr is public address worth geolocating — not
// loopback / private / link-local / unspecified.
func routable(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
