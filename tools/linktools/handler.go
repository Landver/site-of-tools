package linktools

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Landver/site-of-tools/platform"
)

// Page descriptions, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" view-model key.
const (
	inspectDesc  = "Take a URL apart: every query parameter decoded and kept in order, repeated keys shown as repeats, comma-lists split and counted, double-encoded values peeled layer by layer, and the fragment parsed instead of thrown away. Nothing is fetched. Free, open source, JSON API included."
	cleanDesc    = "Remove tracking parameters from a URL and see exactly which rule removed what. Unwraps Safe Links, urldefense and the other mail-gateway wrappers with no network request at all. Free, open source, JSON API included."
	traceDesc    = "Follow a link hop by hop without opening it: every redirect with its status, timing and cookies, and an honest answer when the chain continues somewhere an HTTP client cannot follow. Ask as Googlebot, Slackbot or a browser."
	shortDesc    = "Short links on a domain I own. Not a public shortener: creating one needs a key, deliberately and permanently."
	diffDesc     = "Compare two URLs part by part and parameter by parameter: what was added, removed, changed or only moved. The tool for 'why does staging behave differently from production'."
	encodingDesc = "What percent-encoding actually reserves, and why the same characters mean different things in a path, a query and a fragment. Including the '+' that is a space in one and a literal plus in the other."
	rulesDesc    = "Every tracking parameter this tool removes, who sets it, and what it identifies. Curated and hand-maintained, not exhaustive, and here in full so you can check it."
	privacyDesc  = "What the Corpberry Link browser extension sends, stores and does not collect."
)

// Rate limits. Parsing is pure CPU with no upstream, so it is generous; the
// routes that cost someone else bandwidth are not
// (docs/06-security-and-abuse.md §4).
const (
	pureRatePerSecond  = 10
	pureRateBurst      = 50
	fetchRatePerSecond = 1
	fetchRateBurst     = 5
	rateLimitExpiry    = 3 * time.Minute

	// The redirect breaker is deliberately high: it exists to stop one client
	// saturating the shared Mongo, not to police ordinary use. A personal link
	// shortener that legitimately serves 200 redirects a second does not exist.
	redirectGlobalPerSecond = 200
	redirectGlobalBurst     = 400

	// Per-IP as well as global. The global breaker alone lets ONE source drain
	// the shared bucket and 503 every other visitor, and it does not bound the
	// case the resolve cache was written for either: a scanner walking RANDOM
	// codes misses the cache every time, so each request is still a database
	// round trip. These numbers are far above any human — a person following
	// links does about one a second — and far below a scanner.
	redirectPerIPPerSecond = 20
	redirectPerIPBurst     = 60
)

// recentLimit bounds the key-gated console list.
const recentLimit = 50

const minTTL = time.Minute

// handler: transport-layer dependencies for link.corpberry.com.
//
// svc is required — a nil one can only be a wiring mistake, and left to be
// discovered per request it surfaces as a panic-recovered 500 rather than an
// error at startup. trace and short are CONCRETE POINTERS, never interfaces, so
// the "nil means the feature is off" check actually works: a nil pointer stored
// in an interface is not == nil, which would make every 503 branch dead code.
type handler struct {
	svc   *Service
	trace *Tracer
	short *Shortener
	base  string
}

// Register wires link.corpberry.com routes onto e. Query-param only and
// GET-shaped wherever the operation is a read, so every result is a shareable
// URL — the one convention every tool surveyed agrees on
// (docs/reports/firsthand-ui-observations.md).
//
//	GET  /                  Inspect a URL
//	GET  /clean             Strip trackers, unwrap wrappers
//	GET  /clean/rules       The rule table, content-negotiated
//	GET  /diff              Compare two URLs
//	GET  /trace             Follow the redirect chain
//	GET  /short             Console (list is key-gated)
//	POST /short             Create an alias (key required)
//	GET  /s/:code           The redirect itself
//	GET  /curl              URL <-> curl command, both directions
//	POST /curl              The paste direction, from the page's form
//	GET  /extract           Pull every URL out of pasted text
//	GET  /utm               Campaign URL builder
//	GET  /encode            Encode / decode playground
//	GET  /encoding          Percent-encoding reference
//	GET  /extension/privacy Extension privacy policy
func Register(e *echo.Echo, svc *Service, trace *Tracer, short *Shortener, base string) {
	if svc == nil {
		panic("linktools.Register: svc is nil")
	}
	h := &handler{svc: svc, trace: trace, short: short, base: base}

	pure := rateLimiter(pureRatePerSecond, pureRateBurst)
	fetch := rateLimiter(fetchRatePerSecond, fetchRateBurst)

	e.GET("/", h.inspect, pure)
	e.GET("/clean", h.clean, pure)
	e.GET("/clean/rules", h.rules, pure)
	e.GET("/diff", h.diff, pure)
	e.GET("/curl", h.curl, pure)
	// POST keeps a pasted command's cookies and tokens out of URLs, history and
	// proxy logs, which the request-log redactor never sees. GET ?curl= stays.
	e.POST("/curl", h.curl, pure)
	e.GET("/extract", h.extract, pure)
	e.POST("/extract", h.extract, pure)
	e.GET("/utm", h.utm, pure)
	e.GET("/encode", h.encode, pure)
	e.GET("/encoding", h.encoding)
	e.GET("/extension/privacy", h.privacy)

	// An empty form dials nothing, so it does not spend the trace budget.
	e.GET("/trace", h.traceRoute, rateLimiterExcept(fetchRatePerSecond, fetchRateBurst, func(c *echo.Context) bool {
		return strings.TrimSpace(c.QueryParam("u")) == ""
	}))

	// Both /short routes are on the strict limiter, not the pure one: the console
	// is key-gated and reads the corpus, so it is not a cheap page (doc 06 §4).
	e.GET("/short", h.shortConsole, fetch)
	e.POST("/short", h.shortCreate, fetch)
	// Two limiters, deliberately. A generous per-IP bound (20/s, burst 60 — far
	// above any human following links, far below a scanner) stops one source
	// walking random codes straight through the resolve cache into the shared
	// database, which the negative cache alone cannot prevent because every
	// random code is a miss. The coarse global breaker then stops the aggregate
	// from hurting the other subdomains (docs/04-short-links.md §7).
	e.GET("/s/:code", h.redirect,
		rateLimiter(redirectPerIPPerSecond, redirectPerIPBurst),
		globalLimiter(redirectGlobalPerSecond, redirectGlobalBurst))

	// Revoking an alias. Without this Revoke had no caller at all, so the
	// "kill switch" §10 promises did not exist: a leaked key's links could not
	// be taken down by any means short of editing the database by hand.
	// Soft-delete only — the document stays so the code is never reissued.
	e.DELETE("/short/:code", h.shortRevoke, fetch)
}

// reply picks the representation, and is the only place in this file that does.
//
// platform.Respond cannot stand in for it: every page template pulls .Title and
// .Desc through partials/head, so handing it a bare domain struct makes
// html/template fail the render, while handing it the view-model map would leak
// Title/Desc into the JSON body. Same split dnstools uses.
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	platform.SetNegotiationHeaders(c, code)
	switch {
	case platform.WantsJSON(c):
		return c.JSON(code, body)
	case platform.IsHTMX(c):
		return c.Render(code, frag, vm)
	}
	return c.Render(code, page, vm)
}

// vm builds the view-model keys every page needs.
func (h *handler) vm(active, heading, desc, query string) map[string]any {
	return map[string]any{
		"Active": active, "Title": heading + " — Link Tools", "Desc": desc,
		"Heading": heading, "Query": query, "Base": h.base,
		"Examples": examples[active],
	}
}

func listChanged(c *echo.Context) {
	if platform.IsHTMX(c) {
		c.Response().Header().Set("HX-Trigger", "link-list-changed")
	}
}

// needURL answers the bare hit: the empty form to a browser, an empty result to
// htmx, and 400 to a JSON caller, for whom asking nothing is a mistake rather
// than a starting point. Reports whether it has already answered.
func (h *handler) needURL(c *echo.Context, raw string, vm map[string]any, page, frag, example string) (bool, error) {
	if raw != "" {
		return false, nil
	}
	if platform.WantsJSON(c) {
		return true, apiError(c, http.StatusBadRequest, "no URL; pass ?u=, e.g. "+example)
	}
	return true, reply(c, http.StatusOK, nil, vm, page, frag)
}

func apiError(c *echo.Context, code int, msg string) error {
	platform.SetNegotiationHeaders(c, code)
	return c.JSON(code, map[string]string{"error": msg})
}

type suggestion struct {
	Label, Action, Field, Value string
}

// wrongTool answers input that belongs on another page with a 400 and a POST
// button there, so a curl command's cookies never ride in a URL. Reports
// whether it answered.
func (h *handler) wrongTool(c *echo.Context, vm map[string]any, raw, page string) (bool, error) {
	var msg string
	switch WrongTool(raw) {
	case ToolCurl:
		msg = "That looks like a curl command, not a URL."
		label := "Take it apart on the curl page"
		if page == "link/curl" {
			label = "Take it apart instead"
		}
		vm["Suggest"] = suggestion{Label: label, Action: "/curl", Field: "curl", Value: raw}
	case ToolExtract:
		msg = "That looks like text with links in it, not one URL."
		vm["Suggest"] = suggestion{Label: "Pull the links out on the Extract page", Action: "/extract", Field: "text", Value: raw}
	default:
		return false, nil
	}
	vm["Error"] = msg
	return true, reply(c, http.StatusBadRequest, map[string]string{"error": msg}, vm, page, "link/error")
}

// --- inspect ---------------------------------------------------------------

func (h *handler) inspect(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	vm := h.vm("inspect", "Inspect a URL", inspectDesc, raw)

	if done, err := h.needURL(c, raw, vm, "link/index", "link/inspect",
		"?u=https%3A%2F%2Fexample.com%2F%3Fa%3D1"); done {
		return err
	}

	if done, err := h.wrongTool(c, vm, raw, "link/index"); done {
		return err
	}
	res, err := h.svc.Parse(raw)
	if err != nil {
		return h.badRequest(c, vm, err, "link/index")
	}
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/index", "link/inspect")
}

// --- clean -----------------------------------------------------------------

func (h *handler) clean(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	opt := CleanOptions{
		Sort:           c.QueryParam("sort") == "true",
		StripAffiliate: c.QueryParam("affiliate") == "true",
		Unwrap:         c.QueryParam("unwrap") != "false", // on by default: it is the whole point
	}
	vm := h.vm("clean", "Clean a URL", cleanDesc, raw)
	vm["Sort"], vm["Affiliate"], vm["Unwrap"] = opt.Sort, opt.StripAffiliate, opt.Unwrap

	if done, err := h.needURL(c, raw, vm, "link/clean", "link/cleaned",
		"?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dx"); done {
		return err
	}

	if done, err := h.wrongTool(c, vm, raw, "link/clean"); done {
		return err
	}
	res, err := h.svc.Clean(raw, opt)
	if err != nil {
		return h.badRequest(c, vm, err, "link/clean")
	}
	vm["Result"], vm["Groups"] = res, groupRemovals(res.Removed)
	return reply(c, http.StatusOK, res, vm, "link/clean", "link/cleaned")
}

// removalGroup is one rule's removals, so the page prints its reason once.
// The JSON keeps the flat list.
type removalGroup struct {
	Pattern string // the rule's parameter pattern, e.g. "utm_*"
	Why     string
	Params  []Removal
}

// groupRemovals folds Removals by rule, in order of first appearance.
func groupRemovals(rs []Removal) []removalGroup {
	var out []removalGroup
	at := map[string]int{}
	for _, r := range rs {
		i, ok := at[r.Rule]
		if !ok {
			pattern, _, _ := strings.Cut(r.Rule, " · ")
			i = len(out)
			at[r.Rule] = i
			out = append(out, removalGroup{Pattern: pattern, Why: r.Why})
		}
		out[i].Params = append(out[i].Params, r)
	}
	return out
}

// rules serves the rule table. Content-negotiated rather than a ".json"
// endpoint: golden rule #2 says every feature speaks HTML and JSON from one URL,
// and a .json suffix would be the only route in the repo hard-coding one
// representation. JSON is what the extension caches; the HTML view is also what
// discharges the promise to state the catalog's scope rather than being magic.
func (h *handler) rules(c *echo.Context) error {
	cat := Rules()
	vm := h.vm("clean", "Tracking rules", rulesDesc, "")
	vm["Catalog"] = cat
	// Cheap validator for the extension's daily refresh. JSON only: the
	// catalog version says nothing about the page template around it.
	if platform.WantsJSON(c) {
		c.Response().Header().Set("ETag", `"`+cat.Version+`"`)
		if match := c.Request().Header.Get("If-None-Match"); match != "" && strings.Contains(match, cat.Version) {
			// A 304 carries the Vary its 200 would have (RFC 9110 §15.4.5).
			platform.SetNegotiationHeaders(c, http.StatusNotModified)
			return c.NoContent(http.StatusNotModified)
		}
	}
	// Page and fragment differ, as on /short: serving the page to htmx would
	// swap a whole <html> document into a div.
	return reply(c, http.StatusOK, cat, vm, "link/rules", "link/rulestable")
}

// --- diff ------------------------------------------------------------------

// diff is A13: a second view over two Inspections, not new logic.
func (h *handler) diff(c *echo.Context) error {
	a := strings.TrimSpace(c.QueryParam("a"))
	b := strings.TrimSpace(c.QueryParam("b"))
	vm := h.vm("diff", "Compare two URLs", diffDesc, "")
	vm["A"], vm["B"] = a, b

	if a == "" || b == "" {
		if platform.WantsJSON(c) {
			return apiError(c, http.StatusBadRequest, "pass both ?a= and ?b=")
		}
		return reply(c, http.StatusOK, nil, vm, "link/diff", "link/diffed")
	}
	for _, side := range []string{a, b} {
		if done, err := h.wrongTool(c, vm, side, "link/diff"); done {
			return err
		}
	}
	ia, err := h.svc.Parse(a)
	if err != nil {
		return h.badRequest(c, vm, sideError("A", err), "link/diff")
	}
	ib, err := h.svc.Parse(b)
	if err != nil {
		return h.badRequest(c, vm, sideError("B", err), "link/diff")
	}
	res := DiffInspections(ia, ib)
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/diff", "link/diffed")
}

func sideError(side string, err error) error {
	return fmt.Errorf("URL %s is not valid: %s", side, strings.TrimPrefix(err.Error(), "not a valid URL: "))
}

// --- trace -----------------------------------------------------------------

func (h *handler) traceRoute(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	persona := strings.TrimSpace(c.QueryParam("ua"))
	vm := h.vm("trace", "Trace a redirect chain", traceDesc, raw)
	vm["Personas"], vm["Persona"] = Personas(), persona
	vm["Disabled"] = h.trace == nil

	if h.trace == nil {
		return h.disabled(c, vm, "link/trace",
			"Tracing is not enabled on this server.")
	}
	if done, err := h.needURL(c, raw, vm, "link/trace", "link/chain",
		"?u=http%3A%2F%2Fexample.com%2F"); done {
		return err
	}

	if done, err := h.wrongTool(c, vm, raw, "link/trace"); done {
		return err
	}
	ch, err := h.trace.Trace(c.Request().Context(), raw, persona)
	if err != nil {
		if errors.Is(err, ErrDisabled) {
			return h.disabled(c, vm, "link/trace", "Tracing is not enabled on this server.")
		}
		return h.badRequest(c, vm, err, "link/trace")
	}
	vm["Result"] = ch
	return reply(c, http.StatusOK, ch, vm, "link/trace", "link/chain")
}

// --- short links -----------------------------------------------------------

// shortOff answers a key-gated route when no key is configured: 503 before any
// credential is read, because no key can work and a 401 would say otherwise.
// Nil short also means no storage, so the redirect is down too.
func (h *handler) shortOff(c *echo.Context, vm map[string]any) error {
	vm["Disabled"] = true
	msg := "Creating short links is switched off on this server: no API key is set, so links cannot be created, listed or revoked. Links that already exist keep redirecting."
	if h.short == nil {
		msg = "Short links are switched off on this server: no storage is configured, so links can be neither created nor followed."
	}
	return h.disabled(c, vm, "link/short", msg)
}

// shortConsole renders the create form, and the recent list ONLY to a caller
// holding the key. A public list hands over the whole corpus with no guessing,
// which defeats the code entropy outright and turns the hit counter into a
// read-receipt oracle (docs/04-short-links.md §8).
func (h *handler) shortConsole(c *echo.Context) error {
	vm := h.vm("short", "Short links", shortDesc, "")
	if !h.short.HasKey() {
		return h.shortOff(c, vm)
	}
	authed := h.short.Authorized(c.Request().Header.Get("X-Api-Key"))
	vm["Authed"] = authed
	body := map[string]any{"enabled": true, "authorized": authed}
	if authed {
		links, err := h.short.Recent(c.Request().Context(), recentLimit)
		if err != nil {
			return h.storageError(c, vm, err, "link/short")
		}
		// Project before rendering. CreatedIP is json:"-" so the API is safe,
		// but a struct tag means NOTHING to html/template — the HTML side would
		// be protected only by nobody having typed {{.CreatedIP}} yet (§8).
		vm["Links"] = consoleRows(h.short, links)
		body["links"] = links
	}
	// Page vs fragment differ here, unlike most routes: the browser gets the
	// whole console, while an htmx request (the "Load aliases" button, which is
	// the only thing that can send the X-Api-Key header) gets just the list.
	// Returning the page to htmx would inject a full <html> document into a div.
	return reply(c, http.StatusOK, body, vm, "link/short", "link/shortlist")
}

// createRequest is a TYPED struct with string fields only. Decoding into a
// map or bson.M would let {"slug":{"$ne":null}} reach a Mongo filter as an
// operator (docs/04-short-links.md §3).
type createRequest struct {
	URL   string `json:"url" form:"url"`
	Slug  string `json:"slug" form:"slug"`
	TTL   string `json:"ttl" form:"ttl"`
	Note  string `json:"note" form:"note"`
	Clean bool   `json:"clean" form:"clean"`
}

func (h *handler) shortCreate(c *echo.Context) error {
	vm := h.vm("short", "Short links", shortDesc, "")
	if !h.short.HasKey() {
		return h.shortOff(c, vm)
	}
	if !h.short.Authorized(c.Request().Header.Get("X-Api-Key")) {
		// Same body for a missing key and a wrong one: saying which is a free
		// hint to anyone probing.
		const msg = "Creating a short link needs a valid API key."
		vm["Error"] = msg
		return reply(c, http.StatusUnauthorized, map[string]string{"error": msg}, vm, "link/short", "link/error")
	}

	var req createRequest
	if err := c.Bind(&req); err != nil {
		return h.badRequest(c, vm, errors.New("could not read the request body"), "link/short")
	}
	opt := CreateOptions{Slug: req.Slug, Note: req.Note, Clean: req.Clean, CreatedIP: c.RealIP()}
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil {
			return h.badRequest(c, vm, errors.New("ttl is not a duration, e.g. 720h"), "link/short")
		}
		// CreateOptions reads <= 0 as permanent; leaving ttl out asks for that.
		if d < minTTL {
			return h.badRequest(c, vm, errors.New("ttl must be at least 1m; leave it out for a link that never expires"), "link/short")
		}
		opt.TTL = d
	}

	link, err := h.short.Create(c.Request().Context(), req.URL, opt)
	if err != nil {
		return h.createError(c, vm, err)
	}
	out := map[string]any{
		"code": link.Code, "short": h.short.ShortURL(link.Code),
		"target": link.Target, "created_at": link.CreatedAt,
		"expires_at": link.ExpiresAt, "hits": link.Hits,
	}
	if link.Original != "" {
		out["original"] = link.Original
	}
	if len(link.Cleaned) > 0 {
		out["cleaned"] = link.Cleaned
	}
	vm["Created"] = map[string]any{
		"Short": h.short.ShortURL(link.Code), "Target": link.Target, "Cleaned": link.Cleaned,
		"Note": link.Note, "ExpiresAt": link.ExpiresAt,
	}
	listChanged(c)
	return reply(c, http.StatusCreated, out, vm, "link/short", "link/created")
}

// createError maps the domain's sentinels onto status codes. 409 for a taken
// slug is the one that matters: guessing what the caller meant and silently
// appending a suffix is how "my-link-2" ends up in someone's slide deck.
func (h *handler) createError(c *echo.Context, vm map[string]any, err error) error {
	switch {
	case errors.Is(err, ErrSlugTaken):
		// 409, never a silently-suffixed slug: guessing what the caller meant
		// is how "my-link-2" ends up in someone's slide deck.
		return h.failErr(c, vm, http.StatusConflict, err, "link/short")
	case errors.Is(err, ErrDisabled):
		return h.failErr(c, vm, http.StatusServiceUnavailable, err, "link/short")
	case errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrInvalidSlug), errors.Is(err, ErrInvalidNote):
		return h.failErr(c, vm, http.StatusBadRequest, err, "link/short")
	}
	// Anything else is a storage or driver failure. Those messages can carry
	// connection strings and internal topology, so the client gets a fixed
	// sentence and the detail goes to the log.
	return h.storageError(c, vm, err, "link/short")
}

// storageError logs the real error and returns a fixed 500 to the caller.
func (h *handler) storageError(c *echo.Context, vm map[string]any, err error, page string) error {
	c.Logger().Error("linktools storage error", "err", err, "path", c.Request().URL.Path)
	const msg = "Something went wrong on our side. Nothing was changed."
	return h.fail(c, vm, http.StatusInternalServerError, msg, page)
}

func (h *handler) fail(c *echo.Context, vm map[string]any, code int, msg, page string) error {
	vm["Error"] = msg
	return reply(c, code, map[string]string{"error": msg}, vm, page, "link/error")
}

// failErr gives JSON the Go error string, as the API always has, and the page
// a sentence.
func (h *handler) failErr(c *echo.Context, vm map[string]any, code int, err error, page string) error {
	vm["Error"] = sentence(err.Error())
	return reply(c, code, map[string]string{"error": err.Error()}, vm, page, "link/error")
}

// consoleRow is the console's view of a Link: everything the page renders and
// nothing it does not. Exists so CreatedIP cannot reach a template at all.
type consoleRow struct {
	Code string
	// Short is the full public URL, rendered here rather than assembled in the
	// template: ShortURL owns the /s/ prefix, and a template that pasted base
	// and code together would be a second copy of that rule waiting to drift
	// (it already minted /s/s/ once when the prefix was added twice).
	Short     string
	Target    string
	Note      string
	Hits      int64
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
	// Expires carries the time only within two days of the expiry.
	Expired bool
	Expires string
}

func consoleRows(s *Shortener, links []Link) []consoleRow {
	now := time.Now()
	out := make([]consoleRow, 0, len(links))
	for _, l := range links {
		row := consoleRow{
			Code: l.Code, Short: s.ShortURL(l.Code), Target: l.Target, Note: l.Note, Hits: l.Hits,
			CreatedAt: l.CreatedAt, ExpiresAt: l.ExpiresAt, RevokedAt: l.RevokedAt, Expires: "Never",
		}
		if e := l.ExpiresAt; e != nil {
			row.Expired = !e.After(now)
			row.Expires = e.UTC().Format("2 Jan 2006")
			if d := e.Sub(now); d > -48*time.Hour && d < 48*time.Hour {
				row.Expires = e.UTC().Format("2 Jan 2006, 15:04 UTC")
			}
		}
		out = append(out, row)
	}
	return out
}

// shortRevoke soft-deletes an alias. Key-gated like every other write.
//
// Soft, never hard: deleting the row frees the code, and a custom slug
// re-registered to a different target silently changes where every existing
// copy of that link goes (docs/04-short-links.md §4).
func (h *handler) shortRevoke(c *echo.Context) error {
	vm := h.vm("short", "Short links", shortDesc, "")
	if !h.short.HasKey() {
		return h.shortOff(c, vm)
	}
	if !h.short.Authorized(c.Request().Header.Get("X-Api-Key")) {
		const msg = "Revoking a short link needs a valid API key."
		return h.fail(c, vm, http.StatusUnauthorized, msg, "link/short")
	}
	if err := h.short.Revoke(c.Request().Context(), c.Param("code")); err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			return h.fail(c, vm, http.StatusNotFound, "No such short link.", "link/short")
		}
		return h.storageError(c, vm, err, "link/short")
	}
	vm["Revoked"] = c.Param("code")
	listChanged(c)
	return reply(c, http.StatusOK, map[string]string{"status": "revoked", "code": c.Param("code")},
		vm, "link/short", "link/revoked")
}

// redirect resolves an alias. Not content-negotiated: it is a redirect for every
// caller, including one sending Accept: application/json, because an extension
// resolving a link wants the behaviour and not a description of it.
func (h *handler) redirect(c *echo.Context) error {
	if h.short == nil {
		return c.String(http.StatusServiceUnavailable, "short links are not enabled here")
	}
	code := c.Param("code")
	// Set on every answer, hit or miss: a 404 that omits them is still a URL
	// Googlebot crawled and an intermediary may cache.
	hdr := c.Response().Header()
	// The global breaker's own headers would publish the whole site's redirect
	// volume to anyone who fetches one short link, which is a traffic figure
	// nobody outside needs. The per-IP limiter's numbers are about the caller
	// and are equally uninteresting to publish here.
	hdr.Del("X-RateLimit-Limit")
	hdr.Del("X-RateLimit-Remaining")
	hdr.Del("X-RateLimit-Reset")
	hdr.Del("Retry-After")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Robots-Tag", "noindex, nofollow")
	hdr.Set("Referrer-Policy", "no-referrer")

	link, err := h.short.Resolve(c.Request().Context(), code)
	if err != nil {
		// One status for expired, revoked and never-existed. Telling them apart
		// is an existence oracle over the guessable custom-slug namespace.
		if !platform.WantsJSON(c) {
			return c.Render(http.StatusNotFound, "link/gone", h.vm("", "Short link not found", shortDesc, ""))
		}
		return c.String(http.StatusNotFound, "no such link")
	}

	// The headers above are already set, which matters: Echo v5's c.Redirect
	// sets Location and calls WriteHeader in the SAME call, so anything written
	// after it never reaches the wire. 302 not 301, because a 301 is cached by
	// browsers effectively forever and an alias that can never be repointed or
	// retired is a liability. X-Robots-Tag because Googlebot follows short
	// links, and would otherwise associate this domain with whatever they point
	// at — the blocklisting threat arriving by a route the API key does not cover.
	h.short.RecordHit(link.Code) // async; the redirect never waits on the write
	return c.Redirect(http.StatusFound, link.Target)
}

// --- curl ------------------------------------------------------------------

const curlDesc = "Paste a curl command, including Chrome's Copy as cURL, and get its URL, method and headers taken apart. Or turn a URL into a safely quoted curl command."

// curl runs both ways. The inverse — pasting a command and getting the URL
// parsed — is the genuinely useful half: people copy curl lines out of
// documentation and DevTools constantly and nothing takes one apart.
func (h *handler) curl(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	cmd := strings.TrimSpace(c.QueryParam("curl"))
	if cmd == "" && c.Request().Method == http.MethodPost {
		cmd = strings.TrimSpace(c.FormValue("curl"))
	}
	vm := h.vm("curl", "Take apart or build a curl command", curlDesc, raw)
	vm["Cmd"] = cmd
	var paste, build []Example
	for _, e := range examples["curl"] {
		if strings.Contains(e.Href, "?curl=") {
			paste = append(paste, e)
		} else {
			build = append(build, e)
		}
	}
	vm["Examples"], vm["BuildExamples"], vm["EmptyExamples"] = paste, build, build
	if c.Request().Method == http.MethodPost {
		vm["EmptyExamples"] = paste
	}
	// Set before the empty-input branch below, not only on the ?u= path: the
	// bare page renders the form too, and without these the "Ask as" select had
	// nothing to list, so the persona feature was unreachable until after a
	// first conversion.
	vm["Personas"], vm["Persona"] = Personas(), c.QueryParam("ua")

	postReset(c, "/curl")
	if cmd != "" {
		req, err := h.svc.FromCurlRequest(cmd)
		if err != nil {
			return h.badRequest(c, vm, err, "link/curl")
		}
		in, perr := h.svc.Parse(req.URL)
		if perr != nil {
			return h.badRequest(c, vm, perr, "link/curl")
		}
		out := map[string]any{
			"url": req.URL, "headers": req.Headers, "inspection": in,
			"method": req.Method, "method_why": req.MethodWhy,
		}
		if req.BodyBytes > 0 {
			out["body_bytes"] = req.BodyBytes
		}
		if len(req.Notes) > 0 {
			out["notes"] = req.Notes
		}
		vm["FromCurl"], vm["Headers"], vm["Result"], vm["Request"] = req.URL, req.Headers, in, req
		return reply(c, http.StatusOK, out, vm, "link/curl", "link/curled")
	}

	if done, err := h.needURL(c, raw, vm, "link/curl", "link/curled",
		"?u=https%3A%2F%2Fexample.com%2F"); done {
		return err
	}
	if done, err := h.wrongTool(c, vm, raw, "link/curl"); done {
		return err
	}
	opt := CurlOptions{
		Persona:         c.QueryParam("ua"),
		FollowRedirects: c.QueryParam("follow") == "true",
		ShowHeaders:     c.QueryParam("headers") == "true",
	}
	line, err := h.svc.ToCurl(raw, opt)
	if err != nil {
		return h.badRequest(c, vm, err, "link/curl")
	}
	vm["Curl"], vm["Personas"], vm["Persona"] = line, Personas(), opt.Persona
	vm["Follow"], vm["ShowHeaders"] = opt.FollowRedirects, opt.ShowHeaders
	return reply(c, http.StatusOK, map[string]any{"curl": line}, vm, "link/curl", "link/curled")
}

// postReset drops an example chip's ?curl= or ?text= from the address bar
// after an htmx POST, so a reload doesn't bring the example back.
func postReset(c *echo.Context, path string) {
	if c.Request().Method == http.MethodPost && platform.IsHTMX(c) {
		c.Response().Header().Set("HX-Replace-Url", path)
	}
}

// --- extract ---------------------------------------------------------------

const extractDesc = "Paste HTML, Markdown or an email and get every link out, deduplicated and counted, with its anchor text. Nothing is fetched: this is for auditing links before they go out, not for checking whether they work."

// extract accepts GET for a shareable result and POST for anything large.
// The text parameter is redacted from the request log like every other input
// on this host (platform/redact.go).
func (h *handler) extract(c *echo.Context) error {
	text := c.QueryParam("text")
	if text == "" {
		text = c.FormValue("text")
	}
	text = strings.TrimSpace(text)
	vm := h.vm("extract", "Extract links", extractDesc, "")
	vm["Text"] = text
	postReset(c, "/extract")

	if text == "" {
		if platform.WantsJSON(c) {
			return apiError(c, http.StatusBadRequest, "no text; pass ?text= or POST a text field")
		}
		return reply(c, http.StatusOK, nil, vm, "link/extract", "link/extracted")
	}
	res, err := h.svc.Extract(text)
	if err != nil {
		return h.badRequest(c, vm, err, "link/extract")
	}
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/extract", "link/extracted")
}

// --- utm -------------------------------------------------------------------

const utmDesc = "Add UTM campaign tags to a URL: the utm_ parameters Google Analytics and most analytics tools read to credit a visit to a campaign. Tags already on the URL are kept unless you replace them."

type utmField struct {
	Name, Placeholder, Hint, Value string
}

var utmHelp = map[string][2]string{
	"utm_source":   {"newsletter", "Where the traffic comes from. The one most analytics tools require."},
	"utm_medium":   {"email", "How it arrives: email, cpc, social, referral."},
	"utm_campaign": {"spring-launch", "Which campaign the link belongs to."},
	"utm_term":     {"running-shoes", "The paid keyword, for search ads."},
	"utm_content":  {"header-button", "Which link it was, when a campaign has several. The A/B field."},
}

// utmCommon fields show unfolded; term and content are for paid search and A/B tests.
const utmCommon = 3

func (h *handler) utm(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	vm := h.vm("utm", "Build a campaign URL", utmDesc, raw)

	fields := make([]utmField, len(UTMKeys))
	typed := map[string]string{}
	rare, anyTag := false, false // a folded field has a value / any field does
	for i, key := range UTMKeys {
		v := strings.TrimSpace(c.QueryParam(key))
		fields[i] = utmField{Name: key, Placeholder: utmHelp[key][0], Hint: utmHelp[key][1], Value: v}
		typed[key] = v
		rare = rare || (i >= utmCommon && v != "")
		anyTag = anyTag || v != ""
	}
	vm["Common"], vm["Rare"], vm["RareOpen"], vm["AnyTag"] = fields[:utmCommon], fields[utmCommon:], rare, anyTag

	if done, err := h.needURL(c, raw, vm, "link/utm", "link/utmbuilt",
		"?u=https%3A%2F%2Fexample.com%2F&utm_source=newsletter"); done {
		return err
	}

	if done, err := h.wrongTool(c, vm, raw, "link/utm"); done {
		return err
	}
	res, err := h.svc.BuildUTM(raw, typed)
	if err != nil {
		return h.badRequest(c, vm, err, "link/utm")
	}
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/utm", "link/utmbuilt")
}

// --- encode ----------------------------------------------------------------

const encodeDesc = "Percent-encode and decode with the right rules for where the value goes: a query and a path escape differently, and the difference is what breaks base64 values. Plus base64, base64url and multi-layer decoding."

func (h *handler) encode(c *echo.Context) error {
	v := c.QueryParam("v")
	vm := h.vm("encode", "Encode and decode", encodeDesc, "")
	vm["Value"] = v
	if v == "" {
		if platform.WantsJSON(c) {
			return apiError(c, http.StatusBadRequest, "no value; pass ?v=")
		}
		return reply(c, http.StatusOK, nil, vm, "link/encode", "link/encoded")
	}
	res := EncodeAll(v)
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/encode", "link/encoded")
}

// --- static pages ----------------------------------------------------------

// encoding and privacy render directly rather than through reply, and that is
// deliberate: both are static documents with no result to negotiate and no
// fragment to swap, so a JSON representation would be an empty promise and an
// htmx representation would be the whole page. Nothing links to either with
// hx-get — adding one would need a fragment first (golden rule #2).
func (h *handler) encoding(c *echo.Context) error {
	return c.Render(http.StatusOK, "link/encoding",
		h.vm("encoding", "Percent-encoding reference", encodingDesc, ""))
}

func (h *handler) privacy(c *echo.Context) error {
	return c.Render(http.StatusOK, "link/privacy",
		h.vm("", "Extension privacy", privacyDesc, ""))
}

// --- shared error paths ----------------------------------------------------

func (h *handler) badRequest(c *echo.Context, vm map[string]any, err error, page string) error {
	return h.failErr(c, vm, http.StatusBadRequest, err, page)
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// curl is a command's name, and keeps its case at the start of one too.
	if r, size := utf8.DecodeRuneInString(s); unicode.IsLower(r) && !strings.HasPrefix(s, "curl ") {
		s = string(unicode.ToUpper(r)) + s[size:]
	}
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "!") {
		s += "."
	}
	return s
}

// disabled answers 503, never 502: nothing failed, the feature is not running.
func (h *handler) disabled(c *echo.Context, vm map[string]any, page, msg string) error {
	vm["Error"] = msg
	return reply(c, http.StatusServiceUnavailable, map[string]string{"error": msg}, vm, page, "link/error")
}

// --- middleware ------------------------------------------------------------

func rateLimiter(rate float64, burst int) echo.MiddlewareFunc {
	return rateLimiterExcept(rate, burst, nil)
}

func rateLimiterExcept(rate float64, burst int, skip func(*echo.Context) bool) echo.MiddlewareFunc {
	store := middleware.NewRateLimiterMemoryStoreWithConfig(
		middleware.RateLimiterMemoryStoreConfig{Rate: rate, Burst: burst, ExpiresIn: rateLimitExpiry},
	)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Skipper: skip,
		Store:   store,
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			// Normalised, not the bare IP: an ordinary IPv6 client holds a /64,
			// so a per-address bucket is not a limit at all.
			return platform.RateLimitKey(c.RealIP()), nil
		},
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			const msg = "Too many requests from your address. Try again in a few seconds."
			// A link back to the refused page; a POST can't be replayed by one.
			retry := c.Request().URL.Path
			if c.Request().Method == http.MethodGet {
				retry = c.Request().URL.RequestURI()
			}
			return reply(c, http.StatusTooManyRequests,
				map[string]string{"error": msg},
				map[string]any{"Title": "Slow down — Link Tools", "Desc": msg, "Error": msg, "Active": "", "Retry": retry},
				"link/ratelimited", "link/error")
		},
	})
}

// globalLimiter buckets every caller together, deliberately. Per-IP limiting
// cannot protect a shared resource from a distributed source, and the thing
// being protected here is a database other subdomains depend on.
func globalLimiter(rate float64, burst int) echo.MiddlewareFunc {
	store := middleware.NewRateLimiterMemoryStoreWithConfig(
		middleware.RateLimiterMemoryStoreConfig{Rate: rate, Burst: burst, ExpiresIn: rateLimitExpiry},
	)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store:               store,
		IdentifierExtractor: func(*echo.Context) (string, error) { return "global", nil },
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			return c.String(http.StatusServiceUnavailable, "busy, try again shortly")
		},
	})
}

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
//
// Tool pages only. /s/:code is a redirect carrying X-Robots-Tag: noindex,
// /short is the owner's console, and the privacy policy is a document nobody
// searches for — platform.BuildSitemap's own comment says transient and
// non-page URLs have no business here.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/"}, {Path: "/clean"}, {Path: "/clean/rules"}, {Path: "/trace"},
		{Path: "/diff"}, {Path: "/extract"}, {Path: "/utm"}, {Path: "/curl"},
		{Path: "/encode"}, {Path: "/encoding"},
	}, nil
}
