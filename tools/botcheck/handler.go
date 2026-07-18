package botcheck

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
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
	svc    Looker
	corpus *Corpus // nil-safe: a disabled Mongo turns the fingerprint corpus into a no-op
}

// Register wires the botcheck.corpberry.com routes onto e.
//
//	GET  /                  the check page (browser) — or a server-only score (curl/JSON)
//	POST /check             accepts the collected client fingerprint, returns the full score
//	GET  /botcheck-sw.js    the tiny Service Worker the collector registers (G03)
func Register(e *echo.Echo, svc Looker, corpus *Corpus) {
	h := &handler{svc: svc, corpus: corpus}
	e.GET("/", h.index)
	e.POST("/check", h.check)
	e.GET("/botcheck-sw.js", h.serviceWorker)
}

// swScript is the Service Worker source the collector registers as a fourth JS
// context for the cross-context checks (G03) plus the G14 additions: it reports
// its navigator.webdriver (a top-frame-only webdriver patch forgets this context)
// and runs the same CDP Error.stack trap the worker probe uses. It answers one
// message (over the posted MessageChannel port) and has NO fetch handler —
// deliberately, so it can never intercept or modify a single request on the
// origin. Served as a constant: it reads nothing from the request and never
// changes. The trap must NOT touch `.stack` itself, or it would self-trigger.
const swScript = `self.onmessage=(ev)=>{` +
	`const p=ev.ports&&ev.ports[0];` +
	`if(p){` +
	`let c=false;` +
	`const e=new Error();` +
	`try{Object.defineProperty(e,'stack',{configurable:true,get(){c=true;return 'x';}});}catch(_){}` +
	`try{console.debug(e);}catch(_){}` +
	`p.postMessage({` +
	`ua:navigator.userAgent,` +
	`languages:[...(navigator.languages||[])],` +
	`cores:navigator.hardwareConcurrency||0,` +
	`platform:(navigator.userAgentData&&navigator.userAgentData.platform)||"",` +
	`webdriver:navigator.webdriver===true,` +
	`cdp:c` +
	`});}};`

// serviceWorker serves swScript with a JavaScript MIME type (Service Worker
// registration refuses anything else). It sits at the root so the registration
// gets the widest default scope; the script never uses it.
func (h *handler) serviceWorker(c *echo.Context) error {
	return c.Blob(http.StatusOK, "application/javascript", []byte(swScript))
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
		// G38/G44: enrich the "your request" card with the ASN/proxy attribution
		// the shared conn partial renders when present (best-effort, like the IP
		// signals — a failed lookup renders the six transport rows unchanged).
		"Title": "Bot check", "Conn": platform.Conn(c).WithNetwork(h.network(c)),
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
	// G41/G42: fold the fingerprint into the rolling corpus, then count how many
	// distinct IPs presented this exact one — the scraping-farm tell. Best-effort:
	// a disabled corpus or a Mongo error leaves FingerprintIPs 0 ("no corpus
	// data"), the fingerprint_reuse rule stays silent, and the score is unchanged.
	hash := sig.FingerprintHash()
	_ = h.corpus.Record(c.Request().Context(), hash, c.RealIP())
	if n, err := h.corpus.DistinctIPs(c.Request().Context(), hash); err == nil {
		sig.FingerprintIPs = n
	}
	report := Evaluate(sig)
	report.ClientPayload = &sig // G54: echo the raw fingerprint for the dump + JSON API

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
	sig.EgressIP = c.RealIP() // G09: the server-observed IP the WebRTC candidates are compared against
	sig.SecCHUAPlatform = r.Header.Get("Sec-CH-UA-Platform")
	sig.SecCHUA = r.Header.Get("Sec-CH-UA")
	sig.SecFetchMode = r.Header.Get("Sec-Fetch-Mode")
	sig.AcceptLanguage = r.Header.Get("Accept-Language")
	// G06: the content-negotiation headers the header-consistency rules read. All
	// three are soft signals only — a proxy (CF/nginx) on the path can strip or
	// rewrite them, the same caveat that made sec_fetch_missing soft.
	sig.HTTPAccept = r.Header.Get("Accept")
	sig.HTTPAcceptEncoding = r.Header.Get("Accept-Encoding")
	// Collected for completeness but deliberately UNUSED in rules: Safari never
	// sends Upgrade-Insecure-Requests, so any rule requiring it would
	// false-positive every real Safari user.
	sig.HTTPUpgradeInsecureRequests = r.Header.Get("Upgrade-Insecure-Requests")

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
	sig.ASN = cleanPlaceholder(res.ASN) // egress ASN number, for good-bot corroboration
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
// here with its caller (addServerSignals) — the domain scorer never uses it.
// (The conn-card enrichment uses the shared mapping on iptools.Result instead.)
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// network resolves the G38/G44 conn-card enrichment: the ASN and proxy
// attribution the shared conn partial renders when present. It follows the
// addServerSignals degradation contract — a nil service or a failed lookup
// yields a zero ConnNetwork, and the card renders its six transport rows
// unchanged. The Result → ConnNetwork mapping itself lives on iptools.Result
// (ConnNetwork) so both tools share one implementation.
func (h *handler) network(c *echo.Context) platform.ConnNetwork {
	if h.svc == nil {
		return platform.ConnNetwork{}
	}
	res, err := h.svc.Lookup(c.RealIP())
	if err != nil {
		return platform.ConnNetwork{}
	}
	return res.ConnNetwork() // nil-safe: no result ⇒ no enrichment
}
