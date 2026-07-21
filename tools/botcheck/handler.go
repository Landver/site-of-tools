package botcheck

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Looker is handler's dep on IP intel: anything that resolves an IP to
// geolocation + proxy facts. *iptools.Service satisfies it (nil one returns
// ErrUnavailable), tests inject fake → package needs no DBs to test
// transport layer. Domain scorer (botcheck.go) never sees this interface;
// handler maps its result into plain Signals fields.
type Looker interface {
	Lookup(ip string) (*iptools.Result, error)
}

// handler holds transport-layer deps for botcheck.corpberry.com.
type handler struct {
	svc    Looker
	corpus *Corpus // nil-safe: disabled Mongo → fingerprint corpus no-ops
}

// Register wires botcheck.corpberry.com routes onto e.
//
//	GET  /                  check page (browser) — or server-only score (curl/JSON)
//	POST /check             accepts collected client fingerprint, returns full score
//	GET  /botcheck-sw.js    tiny Service Worker collector registers (G03)
func Register(e *echo.Echo, svc Looker, corpus *Corpus) {
	h := &handler{svc: svc, corpus: corpus}
	e.GET("/", h.index)
	e.POST("/check", h.check)
	e.GET("/botcheck-sw.js", h.serviceWorker)
}

// swScript: Service Worker source collector registers as 4th JS context for
// cross-context checks (G03) plus G14 additions: reports its
// navigator.webdriver (top-frame-only webdriver patch forgets this context)
// and runs same CDP Error.stack trap the worker probe uses. Answers one
// message (over posted MessageChannel port), has NO fetch handler —
// deliberate, so it can never intercept or modify a single request on the
// origin. Served as a constant: reads nothing from request, never changes.
// Trap must NOT touch `.stack` itself, or it'd self-trigger.
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

// serviceWorker serves swScript w/ JS MIME type (Service Worker registration
// refuses anything else). Sits at root → registration gets widest default
// scope; script never uses it.
func (h *handler) serviceWorker(c *echo.Context) error {
	return c.Blob(http.StatusOK, "application/javascript", []byte(swScript))
}

// index serves page shell to browsers; vendored collector then gathers
// client signals and POSTs them to /check. Non-browser caller (curl, API
// client) gets immediate JSON score built from server-only signals — same
// content-negotiation contract as IP tool.
func (h *handler) index(c *echo.Context) error {
	if platform.WantsJSON(c) {
		var sig Signals
		h.addServerSignals(c, &sig)
		return c.JSON(http.StatusOK, Evaluate(sig))
	}
	// Opt in to Sec-CH-UA-Platform → follow-up POST /check reliably carries the
	// header side of the platform cross-check (spoofing client keeps header +
	// JS userAgentData.platform out of sync). Low-entropy hint Chromium already
	// sends by default on secure origins; explicit opt-in just makes the
	// dependency clear. Request only what scorer reads — nothing more.
	c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform")
	// Attribution: IP2Location LITE's license requires credit on any page that
	// uses or mentions the data — botcheck's IP reputation checks do (see iptools.Looker).
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title": "Bot check", "Attribution": true,
	})
}

// check fuses POSTed client fingerprint w/ server-observed signals, scores
// it, and replies w/ JSON (API/CLI) or an HTML results fragment (browser). It
// has no full-page representation: page is served by index and this only ever
// fills the #result slot, so — unlike IP tool's show — it never renders a page
// template even when Accept says text/html.
func (h *handler) check(c *echo.Context) error {
	var sig Signals // client half binds straight from JSON body (json tags on Signals)
	if err := c.Bind(&sig); err != nil {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid fingerprint payload"})
		}
		return c.Render(http.StatusBadRequest, "botcheck/result",
			Report{Verdict: "error", Checks: []Check{{Label: "Invalid fingerprint payload"}}})
	}
	sig.ClientCollected = true
	connNet := h.addServerSignals(c, &sig)
	// G41/G42: fold fingerprint into rolling corpus, then count how many
	// distinct IPs presented this exact one — scraping-farm tell. Best-effort:
	// disabled corpus or Mongo error leaves FingerprintIPs 0 ("no corpus
	// data"), fingerprint_reuse rule stays silent, score unchanged.
	hash := sig.FingerprintHash()
	_ = h.corpus.Record(c.Request().Context(), hash, c.RealIP())
	if n, err := h.corpus.DistinctIPs(c.Request().Context(), hash); err == nil {
		sig.FingerprintIPs = n
	}
	// G43: count how many distinct fingerprints this IP has cycled through in
	// churn window — fingerprint-rotation tell. Same best-effort contract:
	// disabled corpus or Mongo error leaves FingerprintChurn 0 ("no corpus
	// data"), ip_fingerprint_churn rule stays silent, score unchanged.
	if n, err := h.corpus.DistinctHashesByIP(c.Request().Context(), c.RealIP(), churnWindow); err == nil {
		sig.FingerprintChurn = n
	}
	report := Evaluate(sig)
	report.ClientPayload = &sig // G54: echo raw fingerprint for dump + JSON API

	if platform.WantsJSON(c) {
		return c.JSON(http.StatusOK, report)
	}
	return c.Render(http.StatusOK, "botcheck/result", map[string]any{
		"Report": report,
		"Conn":   platform.Conn(c).WithNetwork(connNet),
	})
}

// addServerSignals fills the half of Signals Go sees w/o any JS: request
// headers plus IP reputation/geo from shared iptools service. IP lookup is
// best-effort — a missing/failed database just leaves those fields zero (the
// scorer treats that as "no server IP signal"), same as IP tool degrades.
// Returns the conn-card network attribution from the same lookup so the check
// handler can enrich the "your request" pane w/o a second IP lookup.
func (h *handler) addServerSignals(c *echo.Context, sig *Signals) platform.ConnNetwork {
	var net platform.ConnNetwork
	r := c.Request()
	sig.Now = time.Now()
	sig.HTTPUserAgent = r.UserAgent()
	sig.EgressIP = c.RealIP() // G09: server-observed IP the WebRTC candidates are compared against
	sig.SecCHUAPlatform = r.Header.Get("Sec-CH-UA-Platform")
	sig.SecCHUA = r.Header.Get("Sec-CH-UA")
	sig.SecFetchMode = r.Header.Get("Sec-Fetch-Mode")
	sig.AcceptLanguage = r.Header.Get("Accept-Language")
	// G06: content-negotiation headers the header-consistency rules read. All
	// three are soft signals only — a proxy (CF/nginx) on the path can strip or
	// rewrite them, same caveat that made sec_fetch_missing soft.
	sig.HTTPAccept = r.Header.Get("Accept")
	sig.HTTPAcceptEncoding = r.Header.Get("Accept-Encoding")
	// Collected for completeness but deliberately UNUSED in rules: Safari never
	// sends Upgrade-Insecure-Requests, so any rule requiring it would
	// false-positive every real Safari user.
	sig.HTTPUpgradeInsecureRequests = r.Header.Get("Upgrade-Insecure-Requests")

	if h.svc == nil {
		return net
	}
	res, err := h.svc.Lookup(c.RealIP())
	if err != nil || res == nil {
		return net
	}
	// "-" is IP2Location's unknown placeholder (e.g. localhost); treat as no
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
	return res.ConnNetwork()
}

// cleanPlaceholder maps IP2Location/IP2Proxy's "-" (unknown) placeholder to
// an empty string, so an unknown IP timezone/country is treated as "no
// signal" rather than a real value the cross-checks could spuriously trip
// on. Lives here w/ its caller (addServerSignals) — domain scorer never uses
// it. (Conn-card enrichment uses the shared mapping on iptools.Result instead.)
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
