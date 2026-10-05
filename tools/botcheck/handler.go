package botcheck

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// handler holds transport-layer deps for botcheck.corpberry.com.
type handler struct {
	svc       Looker
	corpus    *Corpus         // nil-safe: Mongo disabled → fingerprint corpus no-ops
	blocklist iptools.Checker // nil when Mongo off → ip_blocklisted silent (G37)
	lim       *Limits
}

// Limits are this tool's budgets, built once and shared by every door. A
// score looks the caller's IP up (Shodan included) and reads the corpus.
type Limits struct {
	Check    platform.Limiter
	CheckCap *platform.Cap
}

// NewLimits returns fresh budgets: 2 scores/s (burst 10), 8 in flight.
func NewLimits() *Limits {
	return &Limits{Check: platform.NewLimiter(2, 10), CheckCap: platform.NewCap(8)}
}

// Register wires botcheck.corpberry.com routes onto e. blocklist may be nil
// (build it with iptools.CheckerFrom); lim nil means fresh limits.
//
//	GET  /                  check page (browser) — or server-only score (curl/JSON)
//	POST /check             accepts collected client fingerprint, returns full score
//	GET  /botcheck-sw.js    tiny Service Worker collector registers (G03)
func Register(e *echo.Echo, svc Looker, corpus *Corpus, blocklist iptools.Checker, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{svc: svc, corpus: corpus, blocklist: blocklist, lim: lim}
	// The page shell scores nothing, so only the JSON GET spends the budget.
	page := func(c *echo.Context) bool { return !platform.WantsJSON(c) }
	e.GET("/", h.index, platform.RateLimit(lim.Check, page, limited))
	e.POST("/check", h.check, platform.RateLimit(lim.Check, nil, limited))
	e.GET("/botcheck-sw.js", h.serviceWorker)
}

func limited(c *echo.Context) error {
	return refuse(c, http.StatusTooManyRequests, "Too many checks from your address. Try again in a few seconds.")
}

// refuse answers a request turned away before scoring: JSON for an API caller,
// the result slot's error fragment for the page.
func refuse(c *echo.Context, code int, msg string) error {
	if platform.WantsJSON(c) {
		return c.JSON(code, map[string]string{"error": msg})
	}
	return c.Render(code, "botcheck/result", map[string]any{"Report": Report{Verdict: "error", Checks: []Check{{Label: msg}}}})
}

// swScript: Service Worker source collector registers as 4th JS context for
// cross-context checks (G03) plus G14 additions: reports its
// navigator.webdriver (top-frame-only webdriver patch forgets this context)
// & runs same CDP Error.stack trap worker probe uses. Answers one
// message (over posted MessageChannel port), has NO fetch handler —
// deliberate, so can never intercept or modify any request on origin.
// Served as constant: reads nothing from req, never changes.
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
// client signals & POSTs them to /check. Non-browser caller (curl, API
// client) gets immediate JSON score built from server-only signals — same
// content-negotiation contract as IP tool.
func (h *handler) index(c *echo.Context) error {
	if platform.WantsJSON(c) {
		if !h.lim.CheckCap.TryAcquire(1) {
			return refuse(c, http.StatusServiceUnavailable, platform.BusyMessage)
		}
		defer h.lim.CheckCap.Release(1)
		var sig Signals
		h.addServerSignals(c, &sig)
		return c.JSON(http.StatusOK, Evaluate(sig))
	}
	// Opt in to Sec-CH-UA-Platform → follow-up POST /check reliably carries
	// header side of platform cross-check (spoofing client keeps header +
	// JS userAgentData.platform out of sync). Low-entropy hint Chromium already
	// sends by default on secure origins; explicit opt-in makes dependency
	// clear. Request only what scorer reads — nothing more.
	c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform")
	// Attribution: IP2Location LITE license requires credit on any page that
	// uses or mentions data — botcheck's IP reputation checks do (see iptools.Looker).
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title":               "Bot check",
		"Desc":                "Open-source bot-detection self-test: see which of 68 signals give your browser away. Client fingerprint, HTTP headers, and IP reputation, cross-checked. Every signal shown, nothing blocked.",
		"Attribution":         true,
		"SpamhausAttribution": true,
	})
}

// check fuses POSTed client fingerprint w/ server-observed signals, scores
// it, & replies w/ JSON (API/CLI) or HTML results fragment (browser). Has
// no full-page representation: page served by index & this only ever
// fills #result slot, so — unlike IP tool's show — never renders a page
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
	if !h.lim.CheckCap.TryAcquire(1) {
		return refuse(c, http.StatusServiceUnavailable, platform.BusyMessage)
	}
	defer h.lim.CheckCap.Release(1)
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
	// G43: count how many distinct fingerprints this IP cycled through in
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

// addServerSignals fills the half of sig Go sees without JS: the request's
// headers and its IP's reputation/geo, both best-effort. Returns the conn-card
// network from the same lookup, so the check handler needs no second one.
func (h *handler) addServerSignals(c *echo.Context, sig *Signals) platform.ConnNetwork {
	sig.Now = time.Now()
	AddHTTPSignals(sig, requestHeaders(c.Request()))
	return AddIPSignals(c.Request().Context(), sig, c.RealIP(), h.svc, h.blocklist).ConnNetwork()
}

func requestHeaders(r *http.Request) HTTPSignals {
	return HTTPSignals{
		UserAgent:               r.UserAgent(),
		Accept:                  r.Header.Get("Accept"),
		AcceptLanguage:          r.Header.Get("Accept-Language"),
		AcceptEncoding:          r.Header.Get("Accept-Encoding"),
		SecCHUA:                 r.Header.Get("Sec-CH-UA"),
		SecCHUAPlatform:         r.Header.Get("Sec-CH-UA-Platform"),
		SecFetchMode:            r.Header.Get("Sec-Fetch-Mode"),
		UpgradeInsecureRequests: r.Header.Get("Upgrade-Insecure-Requests"),
	}
}

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
// /check is POST-only and botcheck-sw.js is a service worker, so neither
// belongs in a sitemap.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}}, nil
}
