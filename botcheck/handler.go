package botcheck

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/iptools"
	"github.com/Landver/site-of-tools/platform"
)

// Looker is the handler's dependency on IP intelligence: anything that resolves
// an IP to geolocation + proxy facts. *iptools.Service satisfies it (a nil one
// returns ErrUnavailable), and tests inject a fake — so this package needs no
// databases to test the transport layer. The domain scorer (botcheck.go) never
// sees this interface; the handler maps its result into plain Signals fields.
type Looker interface {
	Lookup(ip string) (*iptools.Result, error)
}

// handler holds the transport-layer dependencies for botcheck.corpberry.com.
type handler struct {
	svc Looker
}

// Register wires the botcheck.corpberry.com routes onto e.
//
//	GET  /        the check page (browser) — or a server-only score (curl/JSON)
//	POST /check   accepts the collected client fingerprint, returns the full score
func Register(e *echo.Echo, svc Looker) {
	h := &handler{svc: svc}
	e.GET("/", h.index)
	e.POST("/check", h.check)
}

// index serves the page shell to browsers; the vendored collector then gathers
// client signals and POSTs them to /check. A non-browser caller (curl, an API
// client) gets an immediate JSON score built from server-only signals — the same
// content-negotiation contract as the IP tool.
func (h *handler) index(c *echo.Context) error {
	if platform.WantsJSON(c) {
		var sig Signals
		h.addServerSignals(c, &sig)
		return c.JSON(http.StatusOK, Evaluate(sig))
	}
	// Opt in to Sec-CH-UA-Platform so the follow-up POST /check reliably carries the
	// header side of the platform cross-check (a spoofing client keeps the header and
	// the JS userAgentData.platform out of sync). It's a low-entropy hint Chromium
	// already sends by default on secure origins; the explicit opt-in just makes the
	// dependency clear. We request only what the scorer reads — nothing more.
	c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform")
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title": "Bot check", "Conn": platform.Conn(c),
	})
}

// check fuses the POSTed client fingerprint with server-observed signals, scores
// it, and replies with JSON (API/CLI) or an HTML results fragment (browser). It
// has no full-page representation: the page is served by index and this only ever
// fills the #result slot, so — unlike the IP tool's show — it never renders a page
// template even when Accept says text/html.
func (h *handler) check(c *echo.Context) error {
	var sig Signals // client half binds straight from the JSON body (json tags on Signals)
	if err := c.Bind(&sig); err != nil {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid fingerprint payload"})
		}
		return c.Render(http.StatusBadRequest, "botcheck/result",
			Report{Verdict: "error", Checks: []Check{{Label: "Invalid fingerprint payload"}}})
	}
	sig.ClientCollected = true
	h.addServerSignals(c, &sig)
	report := Evaluate(sig)

	if platform.WantsJSON(c) {
		return c.JSON(http.StatusOK, report)
	}
	return c.Render(http.StatusOK, "botcheck/result", report)
}

// addServerSignals fills the half of Signals that Go sees without any JS: request
// headers plus IP reputation/geo from the shared iptools service. The IP lookup
// is best-effort — a missing/failed database just leaves those fields zero (the
// scorer treats that as "no server IP signal"), exactly as the IP tool degrades.
func (h *handler) addServerSignals(c *echo.Context, sig *Signals) {
	r := c.Request()
	sig.Now = time.Now()
	sig.HTTPUserAgent = r.UserAgent()
	sig.SecCHUAPlatform = r.Header.Get("Sec-CH-UA-Platform")
	sig.SecCHUA = r.Header.Get("Sec-CH-UA")
	sig.SecFetchMode = r.Header.Get("Sec-Fetch-Mode")
	sig.AcceptLanguage = r.Header.Get("Accept-Language")

	if h.svc == nil {
		return
	}
	res, err := h.svc.Lookup(c.RealIP())
	if err != nil || res == nil {
		return
	}
	// "-" is IP2Location's unknown placeholder (e.g. localhost); treat it as no
	// signal so the timezone cross-check doesn't fire against it.
	sig.IPTimezone = cleanPlaceholder(res.Timezone)
	if p := res.Proxy; p != nil && p.IsProxy {
		sig.IsProxy = true
		switch p.ProxyType {
		case "DCH": // data center / hosting
			sig.IsDatacenter = true
		case "VPN":
			sig.IsVPN = true
		case "TOR":
			sig.IsTor = true
		}
	}
}

// cleanPlaceholder maps IP2Location/IP2Proxy's "-" (unknown) placeholder to an
// empty string, so an unknown IP timezone/country is treated as "no signal"
// rather than a real value the cross-checks could spuriously trip on. It lives
// here with its sole caller (addServerSignals) — the domain scorer never uses it.
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
