package iptools

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
)

// Page descriptions, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" VM key.
const (
	lookupDesc  = "Look up any IP: geolocation, ASN, VPN/proxy/Tor and blocklist reputation, and open ports. Or inspect your own connection. Free, open source, with a curl-able JSON API."
	cidrDesc    = "CIDR subnet calculator: network range, broadcast address, netmask, and host counts for any CIDR. Free, open source, JSON API included."
	historyDesc = "Recent IP lookups made from this browser."
)

// Looker: handler dependency, anything resolving IP. *Service satisfies;
// tests inject fake. (nil *Service = valid Looker → returns ErrUnavailable.)
type Looker interface {
	Lookup(ip string) (*Result, error)
}

// handler: transport-layer deps for ip.corpberry.com routes.
type handler struct {
	svc  Looker
	hist *History // nil when Mongo disabled — Record/Recent nil-safe
	chk  Checker  // nil when Mongo disabled → no blocklist row (G37)
	lim  *Limits
}

// Limits are this tool's budgets, built once and shared by every door.
type Limits struct {
	Lookup, CIDR, History platform.Limiter
	LookupCap             *platform.Cap
}

func NewLimits() *Limits {
	return &Limits{
		Lookup:    platform.NewLimiter(2, 10),
		CIDR:      platform.NewLimiter(10, 50),
		History:   platform.NewLimiter(2, 10),
		LookupCap: platform.NewCap(8),
	}
}

// Register wires ip.corpberry.com routes onto e. Lookups query-param only
// (?ip=…), consistent w/ /cidr?cidr=… — no /:ip pretty route. hist may be nil
// (Mongo off) → /history view empty.
// chk (from CheckerFrom) may be nil too; lim nil means fresh limits.
//
//	GET /         IP's geo/ASN/proxy — caller's own by default, or ?ip= to look one up
//	GET /cidr     subnet / CIDR calculator (?cidr=…)
//	GET /history  most recent user-initiated lookups
func Register(e *echo.Echo, svc Looker, hist *History, chk Checker, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{svc: svc, hist: hist, chk: chk, lim: lim}
	e.GET("/", h.index, platform.RateLimit(lim.Lookup, nil, h.limited))
	e.GET("/cidr", h.cidr, platform.RateLimit(lim.CIDR, nil, h.limited))
	e.GET("/history", h.history, platform.RateLimit(lim.History, nil, h.limited))
}

// limited answers a spent budget the way each route answers its own errors.
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
	case "/history":
		page, vm = "ip/history", h.historyVM()
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
		"Attribution": true, "SpamhausAttribution": true}
}

func cidrVM(query string) map[string]any {
	return map[string]any{"Title": "Subnet calculator", "Desc": cidrDesc, "Active": "cidr", "Query": query}
}

func (h *handler) historyVM() map[string]any {
	return map[string]any{"Title": "Lookup history", "Desc": historyDesc, "Active": "history",
		"Enabled": h.hist != nil, "Attribution": true, "SpamhausAttribution": true}
}

// index serves visitor's own IP by default, or ?ip= to look one up. Bare hit
// w/ no resolvable IP renders empty lookup page to browser, (empty) result
// fragment to htmx — never full page into #result slot — & 400 to JSON caller
// (same contract /cidr follows).
func (h *handler) index(c *echo.Context) error {
	ip := strings.TrimSpace(c.QueryParam("ip"))
	self := false
	if ip == "" {
		// Default to caller's own IP when routable public address
		// (skips 127.0.0.1 in dev, private ranges, etc.).
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

// cidr serves subnet / CIDR calculator (GET /cidr, ?cidr=…). Pure math, no
// databases → no IP2Location attribution on this page.
func (h *handler) cidr(c *echo.Context) error {
	platform.SetNegotiationHeaders(c, http.StatusOK) // HTML or JSON from one URL
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

// history lists most recent user-initiated lookups. Content-negotiated like
// rest of tool: JSON for API/CLI, page for browsers. Mongo disabled → repo nil
// → shows empty history. HTML view carries IP2Location credit (displays
// geo/ASN data from databases).
func (h *handler) history(c *echo.Context) error {
	const limit = 50
	entries, err := h.hist.Recent(c.Request().Context(), limit)
	platform.SetNegotiationHeaders(c, http.StatusOK) // HTML or JSON from one URL

	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		if entries == nil {
			entries = []HistoryEntry{} // render [] not null
		}
		return c.JSON(http.StatusOK, map[string]any{"lookups": entries})
	}

	vm := h.historyVM()
	vm["Entries"] = entries
	if err != nil {
		vm["Error"] = err.Error()
	}
	return c.Render(http.StatusOK, "ip/history", vm)
}

// show looks up ip & responds in caller's preferred format. self marks result
// as visitor's own IP (small label in HTML view).
func (h *handler) show(c *echo.Context, ip string, self bool) error {
	res, err := h.lookup(c, ip)
	wantsJSON := platform.WantsJSON(c)

	// Record real user-initiated web lookups for /history view: successful,
	// not visitor's own auto-looked-up IP (self), from browser UI not JSON
	// caller — also excludes page's own IPv6 self-probe (requests JSON) + CLI
	// calls. Record fire-and-forget + nil-safe → no added latency, no-ops when
	// Mongo off.
	if err == nil && !self && !wantsJSON {
		h.hist.Record(res)
	}

	code := http.StatusOK
	if err != nil {
		code = statusFor(err)
	}
	platform.SetNegotiationHeaders(c, code)

	// API / CLI: raw JSON — geolocation result or error.
	if wantsJSON {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		return c.JSON(http.StatusOK, res)
	}

	// Browser / htmx: view model rendered as full page or fragment.
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
	// Full page only — "your request" card. G38/G44: when visitor looked at
	// OWN IP, same lookup also enriches card w/ ASN/proxy attribution shared
	// conn partial renders (lookup of someone else's IP says nothing about this
	// connection → only self-lookups enrich).
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

// ConnNetwork maps lookup result into shared conn-card network attribution
// (G38/G44): ASN/AS-name plus proxy type/provider, as plain strings
// platform.ConnInfo.WithNetwork expects. THE Result → ConnNetwork mapping,
// shared by iptools' own handler + botcheck's (whose conn card enriches from
// same lookup) → two tools can't drift apart.
// Lookup already blanks databases' "-" placeholders via clean(); runs again
// here so hand-built Result (tests, fakes) maps same way. Exported method on
// exported type, so nil-safe on principle even though neither current caller
// (this file, botcheck's handler) ever passes nil: nil Result → zero value, no
// enrichment, card renders plain transport rows — not a live path today, just
// same public-API nil-safety this package's other exported methods keep.
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

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
// Deliberately excludes /history — it lists recently looked-up IP addresses,
// which is transient third-party data with no search value.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}, {Path: "/cidr"}}, nil
}
