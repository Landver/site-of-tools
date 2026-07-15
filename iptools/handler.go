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

// handler holds the transport-layer dependencies for the ip.corpberry.com routes:
// the IP resolver and a best-effort reverse-DNS function. reverse is injectable so
// the black-box tests stay hermetic (no real DNS on test addresses).
type handler struct {
	svc     Looker
	reverse func(ip string) string
}

// Option customises the handler wiring.
type Option func(*handler)

// WithReverseDNS overrides the reverse-DNS resolver (default: ReverseDNS). Tests
// pass a canned function so the connection inspector never does a live lookup.
func WithReverseDNS(fn func(ip string) string) Option {
	return func(h *handler) { h.reverse = fn }
}

// Register wires the ip.corpberry.com routes onto e. Lookups are query-param only
// (?ip=…), consistent with /cidr?cidr=… — there is no /:ip pretty route.
//
//	GET /        an IP's geo/ASN/proxy — the caller's own by default, or ?ip= to look one up
//	GET /cidr    subnet / CIDR calculator (?cidr=…)
func Register(e *echo.Echo, svc Looker, opts ...Option) {
	h := &handler{svc: svc, reverse: ReverseDNS}
	for _, o := range opts {
		o(h)
	}
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
			"Title": "IP Tools", "Active": "lookup", "Query": "", "Attribution": true, "Conn": h.conn(c),
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

	// API / CLI: raw JSON. The bare-"/" self view adds a connection block (parity
	// with the "your request" card); explicit /{ip} lookups stay pure geo.
	if platform.WantsJSON(c) {
		if err != nil {
			return c.JSON(statusFor(err), map[string]string{"ip": ip, "error": err.Error()})
		}
		if self {
			return c.JSON(http.StatusOK, selfView{Result: res, Connection: h.conn(c)})
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
	// Full page only: attach the connection inspector (does a bounded PTR, so we
	// skip it for the htmx fragment and the JSON/text paths above).
	vm["Conn"] = h.conn(c)
	return c.Render(code, "ip/index", vm)
}

// ConnInfo is the "your request" inspector's view of the current request — pure
// transport metadata built from headers the edge sets, no domain lookup. TLS
// cipher/version and the visitor's HTTP version are intentionally absent: they
// terminate at Cloudflare/nginx and aren't knowable here. Cookie and
// Authorization are deliberately never read.
type ConnInfo struct {
	IP       string `json:"ip"`                    // resolved client IP (c.RealIP())
	Hostname string `json:"reverse_dns,omitempty"` // best-effort reverse DNS ("" if none)
	Via      string `json:"detected_via"`          // Cloudflare / X-Forwarded-For / direct
	Scheme   string `json:"scheme"`                // http or https (from X-Forwarded-Proto)
	Host     string `json:"host"`                  // Host header the visitor hit
	Browser  string `json:"user_agent"`            // User-Agent
	Language string `json:"language,omitempty"`    // first Accept-Language token

	// Curated forwarding headers for the "how your IP was detected" disclosure —
	// template-only, deliberately kept out of the JSON.
	CFConnectingIP string `json:"-"`
	ForwardedFor   string `json:"-"`
	RealIP         string `json:"-"` // nginx's immediate peer (a Cloudflare edge only when proxied)
	ForwardedProto string `json:"-"`
	// Proxied: request arrived via Cloudflare (CF-Connecting-IP set). Drives the
	// X-Real-IP "(Cloudflare edge)" label; when false the host is DNS-only.
	Proxied bool `json:"-"`
}

// selfView is the JSON for the bare "/" self lookup: the geolocation Result plus a
// connection block describing the current request. Other IP lookups return a bare
// *Result — the connection is about the caller, not the looked-up address.
type selfView struct {
	*Result
	Connection ConnInfo `json:"connection"`
}

// conn builds the connection inspector's data from the current request.
func (h *handler) conn(c *echo.Context) ConnInfo {
	r := c.Request()
	ip := c.RealIP()

	// Describe how the IP was derived, mirroring cfIPExtractor's precedence.
	proxied := r.Header.Get("CF-Connecting-IP") != ""
	via := "direct"
	switch {
	case proxied:
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
		IP:             ip,
		Hostname:       h.reverse(ip),
		Via:            via,
		Scheme:         scheme,
		Host:           r.Host,
		Browser:        r.UserAgent(),
		Language:       strings.TrimSpace(lang),
		CFConnectingIP: r.Header.Get("CF-Connecting-IP"),
		ForwardedFor:   r.Header.Get("X-Forwarded-For"),
		RealIP:         r.Header.Get("X-Real-IP"),
		ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
		Proxied:        proxied,
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
