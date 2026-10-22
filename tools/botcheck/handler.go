package botcheck

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

type handler struct {
	svc       Looker
	corpus    *Corpus         // nil-safe: Mongo disabled → fingerprint corpus no-ops
	blocklist iptools.Checker // nil when Mongo off → ip_blocklisted silent
	lim       *Limits
}

// Limits are shared by REST and MCP; a score looks the IP up and reads the corpus.
type Limits struct {
	Check    platform.Limiter
	CheckCap *platform.Cap
}

func NewLimits() *Limits {
	return &Limits{Check: platform.NewLimiter(2, 10), CheckCap: platform.NewCap(8)}
}

// Register wires botcheck.corpberry.com routes onto e.
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

func refuse(c *echo.Context, code int, msg string) error {
	if platform.WantsJSON(c) {
		return c.JSON(code, map[string]string{"error": msg})
	}
	return c.Render(code, "botcheck/result", map[string]any{"Report": Report{Verdict: "error", Checks: []Check{{Label: msg}}}})
}

// swScript has no fetch handler on purpose, so it can never intercept a request on the origin.
// The CDP trap must not read .stack itself, or it would trigger itself.
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

// Service Worker registration refuses any non-JS MIME type; serving from root gives the widest scope.
func (h *handler) serviceWorker(c *echo.Context) error {
	return c.Blob(http.StatusOK, "application/javascript", []byte(swScript))
}

// index: browsers get the page shell (the collector POSTs to /check); other clients get a JSON score.
func (h *handler) index(c *echo.Context) error {
	if platform.WantsJSON(c) {
		if !h.lim.CheckCap.TryAcquire(c.RealIP(), 1) {
			return refuse(c, http.StatusServiceUnavailable, platform.BusyMessage)
		}
		defer h.lim.CheckCap.Release(c.RealIP(), 1)
		var sig Signals
		h.addServerSignals(c, &sig)
		return c.JSON(http.StatusOK, Evaluate(sig))
	}
	// Opt in so the follow-up POST /check carries Sec-CH-UA-Platform for the platform cross-check.
	c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform")
	// The IP2Location LITE licence requires credit on any page that uses its data.
	return c.Render(http.StatusOK, "botcheck/index", map[string]any{
		"Title":               "Bot check",
		"Desc":                "Open-source bot-detection self-test: see which of 68 signals give your browser away. Client fingerprint, HTTP headers, and IP reputation, cross-checked. Every signal shown, nothing blocked.",
		"Attribution":         true,
		"SpamhausAttribution": true,
	})
}

// check only ever fills #result, so unlike the IP tool's show it never renders a full page.
func (h *handler) check(c *echo.Context) error {
	var sig Signals // client half binds straight from JSON body (json tags on Signals)
	if err := c.Bind(&sig); err != nil {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid fingerprint payload"})
		}
		return refuse(c, http.StatusBadRequest, "Invalid fingerprint payload")
	}
	if !h.lim.CheckCap.TryAcquire(c.RealIP(), 1) {
		return refuse(c, http.StatusServiceUnavailable, platform.BusyMessage)
	}
	defer h.lim.CheckCap.Release(c.RealIP(), 1)
	sig.ClientCollected = true
	connNet := h.addServerSignals(c, &sig)
	// Best-effort: a disabled corpus or Mongo error leaves the count at 0, which the rule reads as no data.
	hash := sig.FingerprintHash()
	_ = h.corpus.Record(c.Request().Context(), hash, c.RealIP())
	if n, err := h.corpus.DistinctIPs(c.Request().Context(), hash); err == nil {
		sig.FingerprintIPs = n
	}
	// Same best-effort contract for the per-IP churn count.
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

func (h *handler) addServerSignals(c *echo.Context, sig *Signals) platform.ConnNetwork {
	sig.Now = time.Now()
	AddHTTPSignals(sig, requestHeaders(c.Request()))
	return AddIPSignals(c.Request().Context(), sig, c.RealIP(), h.svc, h.blocklist).ConnNetwork()
}

func requestHeaders(r *http.Request) HTTPSignals {
	return HTTPSignals{
		UserAgent:       r.UserAgent(),
		Accept:          r.Header.Get("Accept"),
		AcceptLanguage:  r.Header.Get("Accept-Language"),
		AcceptEncoding:  r.Header.Get("Accept-Encoding"),
		SecCHUA:         r.Header.Get("Sec-CH-UA"),
		SecCHUAPlatform: r.Header.Get("Sec-CH-UA-Platform"),
		SecFetchMode:    r.Header.Get("Sec-Fetch-Mode"),
	}
}

// SitemapPages lists only /: /check is POST-only and botcheck-sw.js is a service worker.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}}, nil
}
