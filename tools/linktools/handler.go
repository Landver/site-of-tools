package linktools

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Landver/site-of-tools/platform"
)

// Page descriptions, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" view-model key.
const (
	inspectDesc  = "Take a URL apart: every query parameter decoded and kept in order, repeated keys shown as repeats, comma-lists split and counted, double-encoded values peeled layer by layer, and the fragment parsed instead of thrown away. Nothing is fetched. Free, open source, JSON API included."
	cleanDesc    = "Strip tracking parameters from a URL and see exactly which rule removed what. Unwraps Safe Links, urldefense and the other mail-gateway wrappers with no network request at all. Free, open source, JSON API included."
	traceDesc    = "Follow a link hop by hop without opening it: every redirect with its status, timing and cookies, and an honest answer when the chain continues somewhere an HTTP client cannot follow. Ask as Googlebot, Slackbot or a browser."
	shortDesc    = "Short links on a domain I own. Not a public shortener: creating one needs a key, deliberately and permanently."
	diffDesc     = "Compare two URLs parameter by parameter: what was added, removed, changed or merely reordered. The tool for 'why does staging behave differently from production'."
	encodingDesc = "What percent-encoding actually reserves, and why the same characters mean different things in a path, a query and a fragment. Including the '+' that is a space in one and a literal plus in the other."
	rulesDesc    = "Every tracking parameter this tool strips, who sets it, and what it identifies. Curated and hand-maintained, not exhaustive, and here in full so you can check it."
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
)

// recentLimit bounds the key-gated console list.
const recentLimit = 50

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
	e.GET("/extract", h.extract, pure)
	e.POST("/extract", h.extract, pure)
	e.GET("/utm", h.utm, pure)
	e.GET("/encode", h.encode, pure)
	e.GET("/encoding", h.encoding)
	e.GET("/extension/privacy", h.privacy)

	e.GET("/trace", h.traceRoute, fetch)

	// Both /short routes are on the strict limiter, not the pure one: the console
	// is key-gated and reads the corpus, so it is not a cheap page (doc 06 §4).
	e.GET("/short", h.shortConsole, fetch)
	e.POST("/short", h.shortCreate, fetch)
	// The redirect stays unlimited PER IP — it must be fast and public — but it
	// is the only unauthenticated route touching the shared database, so it
	// carries a coarse global breaker as well as the resolve cache behind it
	// (docs/04-short-links.md §7).
	e.GET("/s/:code", h.redirect, globalLimiter(redirectGlobalPerSecond, redirectGlobalBurst))
}

// reply picks the representation, and is the only place in this file that does.
//
// platform.Respond cannot stand in for it: every page template pulls .Title and
// .Desc through partials/head, so handing it a bare domain struct makes
// html/template fail the render, while handing it the view-model map would leak
// Title/Desc into the JSON body. Same split dnstools uses.
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	switch {
	case platform.WantsJSON(c):
		return c.JSON(code, body)
	case platform.IsHTMX(c):
		return c.Render(code, frag, vm)
	}
	return c.Render(code, page, vm)
}

// vm builds the view-model keys every page needs.
func (h *handler) vm(active, title, desc, query string) map[string]any {
	return map[string]any{
		"Active": active, "Title": title, "Desc": desc,
		"Heading": title, "Query": query, "Base": h.base,
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
		return true, c.JSON(http.StatusBadRequest, map[string]string{
			"error": "no URL; pass ?u=, e.g. " + example,
		})
	}
	return true, reply(c, http.StatusOK, nil, vm, page, frag)
}

// --- inspect ---------------------------------------------------------------

func (h *handler) inspect(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	vm := h.vm("inspect", "Inspect a URL — Link Tools", inspectDesc, raw)

	if done, err := h.needURL(c, raw, vm, "link/index", "link/inspect",
		"?u=https%3A%2F%2Fexample.com%2F%3Fa%3D1"); done {
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
	vm := h.vm("clean", "Clean a URL — Link Tools", cleanDesc, raw)
	vm["Sort"], vm["Affiliate"], vm["Unwrap"] = opt.Sort, opt.StripAffiliate, opt.Unwrap

	if done, err := h.needURL(c, raw, vm, "link/clean", "link/cleaned",
		"?u=https%3A%2F%2Fexample.com%2F%3Futm_source%3Dx"); done {
		return err
	}

	res, err := h.svc.Clean(raw, opt)
	if err != nil {
		return h.badRequest(c, vm, err, "link/clean")
	}
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/clean", "link/cleaned")
}

// rules serves the rule table. Content-negotiated rather than a ".json"
// endpoint: golden rule #2 says every feature speaks HTML and JSON from one URL,
// and a .json suffix would be the only route in the repo hard-coding one
// representation. JSON is what the extension caches; the HTML view is also what
// discharges the promise to state the catalog's scope rather than being magic.
func (h *handler) rules(c *echo.Context) error {
	cat := Rules()
	vm := h.vm("clean", "Tracking rules — Link Tools", rulesDesc, "")
	vm["Catalog"] = cat
	// Cheap validator for the extension's daily refresh.
	c.Response().Header().Set("ETag", `"`+cat.Version+`"`)
	if match := c.Request().Header.Get("If-None-Match"); match != "" && strings.Contains(match, cat.Version) {
		return c.NoContent(http.StatusNotModified)
	}
	return reply(c, http.StatusOK, cat, vm, "link/rules", "link/rules")
}

// --- diff ------------------------------------------------------------------

// diff is A13: a second view over two Inspections, not new logic.
func (h *handler) diff(c *echo.Context) error {
	a := strings.TrimSpace(c.QueryParam("a"))
	b := strings.TrimSpace(c.QueryParam("b"))
	vm := h.vm("diff", "Compare two URLs — Link Tools", diffDesc, "")
	vm["A"], vm["B"] = a, b

	if a == "" || b == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "pass both ?a= and ?b="})
		}
		return reply(c, http.StatusOK, nil, vm, "link/diff", "link/diffed")
	}
	ia, err := h.svc.Parse(a)
	if err != nil {
		return h.badRequest(c, vm, err, "link/diff")
	}
	ib, err := h.svc.Parse(b)
	if err != nil {
		return h.badRequest(c, vm, err, "link/diff")
	}
	res := DiffInspections(ia, ib)
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/diff", "link/diffed")
}

// --- trace -----------------------------------------------------------------

func (h *handler) traceRoute(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	persona := strings.TrimSpace(c.QueryParam("ua"))
	vm := h.vm("trace", "Trace a redirect chain — Link Tools", traceDesc, raw)
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

// shortConsole renders the create form, and the recent list ONLY to a caller
// holding the key. A public list hands over the whole corpus with no guessing,
// which defeats the code entropy outright and turns the hit counter into a
// read-receipt oracle (docs/04-short-links.md §8).
func (h *handler) shortConsole(c *echo.Context) error {
	vm := h.vm("short", "Short links — Link Tools", shortDesc, "")
	vm["Disabled"] = h.short == nil
	authed := h.short != nil && h.short.Authorized(c.Request().Header.Get("X-Api-Key"))
	vm["Authed"] = authed

	if h.short == nil {
		return h.disabled(c, vm, "link/short", "Short links are not enabled on this server.")
	}
	body := map[string]any{"enabled": true, "authorized": authed}
	if authed {
		links, err := h.short.Recent(c.Request().Context(), recentLimit)
		if err != nil {
			return h.storageError(c, vm, err, "link/short")
		}
		// Project before rendering. CreatedIP is json:"-" so the API is safe,
		// but a struct tag means NOTHING to html/template — the HTML side would
		// be protected only by nobody having typed {{.CreatedIP}} yet (§8).
		vm["Links"] = consoleRows(links)
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
	vm := h.vm("short", "Short links — Link Tools", shortDesc, "")
	if h.short == nil {
		return h.disabled(c, vm, "link/short", "Short links are not enabled on this server.")
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
	vm["Created"] = map[string]any{"Short": h.short.ShortURL(link.Code), "Cleaned": link.Cleaned}
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
		return h.fail(c, vm, http.StatusConflict, err.Error(), "link/short")
	case errors.Is(err, ErrDisabled):
		return h.fail(c, vm, http.StatusServiceUnavailable, err.Error(), "link/short")
	case errors.Is(err, ErrInvalidTarget), errors.Is(err, ErrInvalidSlug), errors.Is(err, ErrInvalidNote):
		return h.fail(c, vm, http.StatusBadRequest, err.Error(), "link/short")
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

// consoleRow is the console's view of a Link: everything the page renders and
// nothing it does not. Exists so CreatedIP cannot reach a template at all.
type consoleRow struct {
	Code      string
	Target    string
	Note      string
	Hits      int64
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

func consoleRows(links []Link) []consoleRow {
	out := make([]consoleRow, 0, len(links))
	for _, l := range links {
		out = append(out, consoleRow{
			Code: l.Code, Target: l.Target, Note: l.Note, Hits: l.Hits,
			CreatedAt: l.CreatedAt, ExpiresAt: l.ExpiresAt, RevokedAt: l.RevokedAt,
		})
	}
	return out
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
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Robots-Tag", "noindex, nofollow")
	hdr.Set("Referrer-Policy", "no-referrer")

	link, err := h.short.Resolve(c.Request().Context(), code)
	if err != nil {
		// One status for expired, revoked and never-existed. Telling them apart
		// is an existence oracle over the guessable custom-slug namespace.
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

const curlDesc = "Turn a URL into a runnable curl command, or paste a curl command (including Chrome's Copy as cURL) and get the URL and headers taken apart. The second direction is the useful one."

// curl runs both ways. The inverse — pasting a command and getting the URL
// parsed — is the genuinely useful half: people copy curl lines out of
// documentation and DevTools constantly and nothing takes one apart.
func (h *handler) curl(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	cmd := strings.TrimSpace(c.QueryParam("curl"))
	vm := h.vm("curl", "URL and curl — Link Tools", curlDesc, raw)
	vm["Cmd"] = cmd

	if cmd != "" {
		u, headers, err := h.svc.FromCurl(cmd)
		if err != nil {
			return h.badRequest(c, vm, err, "link/curl")
		}
		in, perr := h.svc.Parse(u)
		if perr != nil {
			return h.badRequest(c, vm, perr, "link/curl")
		}
		out := map[string]any{"url": u, "headers": headers, "inspection": in}
		vm["FromCurl"], vm["Headers"], vm["Result"] = u, headers, in
		return reply(c, http.StatusOK, out, vm, "link/curl", "link/curled")
	}

	if done, err := h.needURL(c, raw, vm, "link/curl", "link/curled",
		"?u=https%3A%2F%2Fexample.com%2F"); done {
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
	vm := h.vm("extract", "Extract links — Link Tools", extractDesc, "")
	vm["Text"] = text

	if text == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no text; pass ?text= or POST a text field"})
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

const utmDesc = "Build a campaign-tagged URL from its parts. The inverse of the Clean page, on the same rule table, so the parameters it adds are exactly the ones Clean knows how to remove."

// utmFields are the five standard campaign parameters, in the order Google
// documents them.
var utmFields = []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"}

func (h *handler) utm(c *echo.Context) error {
	raw := strings.TrimSpace(c.QueryParam("u"))
	vm := h.vm("utm", "Campaign URL builder — Link Tools", utmDesc, raw)
	vm["Fields"] = utmFields

	values := map[string]string{}
	for _, f := range utmFields {
		values[f] = strings.TrimSpace(c.QueryParam(f))
	}
	vm["Values"] = values

	if done, err := h.needURL(c, raw, vm, "link/utm", "link/utmbuilt",
		"?u=https%3A%2F%2Fexample.com%2F&utm_source=newsletter"); done {
		return err
	}

	in, err := h.svc.Parse(raw)
	if err != nil {
		return h.badRequest(c, vm, err, "link/utm")
	}
	// Replace an existing value rather than appending a second copy: two
	// utm_source parameters is a real bug and building one deliberately would
	// be an odd thing for this page to do.
	for _, f := range utmFields {
		v := values[f]
		in.Params = upsertParam(in.Params, f, v)
	}
	built, err := h.svc.Rebuild(in)
	if err != nil {
		return h.badRequest(c, vm, err, "link/utm")
	}
	vm["Built"] = built
	return reply(c, http.StatusOK, map[string]any{"url": built}, vm, "link/utm", "link/utmbuilt")
}

// upsertParam sets key to value, replacing the first occurrence and dropping
// the rest; an empty value removes the key entirely.
func upsertParam(ps []Param, key, value string) []Param {
	out := make([]Param, 0, len(ps)+1)
	done := false
	for _, p := range ps {
		if p.Key != key {
			out = append(out, p)
			continue
		}
		if done || value == "" {
			continue
		}
		p.Value, p.RawValue, p.Layers, p.List, p.Delimiter = value, "", nil, nil, ""
		p.Valueless, p.Warn, p.AltValue = false, "", ""
		out = append(out, p)
		done = true
	}
	if !done && value != "" {
		out = append(out, Param{Index: len(out) + 1, Key: key, Value: value})
	}
	for i := range out {
		out[i].Index = i + 1
	}
	return out
}

// --- encode ----------------------------------------------------------------

const encodeDesc = "Percent-encode and decode with the right rules for where the value goes: a query and a path escape differently, and the difference is what breaks base64 values. Plus base64, base64url and the decode ladder."

func (h *handler) encode(c *echo.Context) error {
	v := c.QueryParam("v")
	vm := h.vm("encode", "Encode and decode — Link Tools", encodeDesc, "")
	vm["Value"] = v
	if v == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no value; pass ?v="})
		}
		return reply(c, http.StatusOK, nil, vm, "link/encode", "link/encoded")
	}
	res := EncodeAll(v)
	vm["Result"] = res
	return reply(c, http.StatusOK, res, vm, "link/encode", "link/encoded")
}

// --- static pages ----------------------------------------------------------

func (h *handler) encoding(c *echo.Context) error {
	return c.Render(http.StatusOK, "link/encoding",
		h.vm("encoding", "Percent-encoding reference — Link Tools", encodingDesc, ""))
}

func (h *handler) privacy(c *echo.Context) error {
	return c.Render(http.StatusOK, "link/privacy",
		h.vm("", "Extension privacy — Link Tools", privacyDesc, ""))
}

// --- shared error paths ----------------------------------------------------

func (h *handler) badRequest(c *echo.Context, vm map[string]any, err error, page string) error {
	vm["Error"] = err.Error()
	return reply(c, http.StatusBadRequest, map[string]string{"error": err.Error()}, vm, page, "link/error")
}

// disabled answers 503, never 502: nothing failed, the feature is not running.
func (h *handler) disabled(c *echo.Context, vm map[string]any, page, msg string) error {
	vm["Error"] = msg
	return reply(c, http.StatusServiceUnavailable, map[string]string{"error": msg}, vm, page, "link/error")
}

// --- middleware ------------------------------------------------------------

func rateLimiter(rate float64, burst int) echo.MiddlewareFunc {
	store := middleware.NewRateLimiterMemoryStoreWithConfig(
		middleware.RateLimiterMemoryStoreConfig{Rate: rate, Burst: burst, ExpiresIn: rateLimitExpiry},
	)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: store,
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			// Normalised, not the bare IP: an ordinary IPv6 client holds a /64,
			// so a per-address bucket is not a limit at all.
			return platform.RateLimitKey(c.RealIP()), nil
		},
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			const msg = "Too many requests from your address. Try again in a few seconds."
			return reply(c, http.StatusTooManyRequests,
				map[string]string{"error": msg},
				map[string]any{"Title": "Slow down", "Desc": msg, "Error": msg},
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
// POST /short is not a page, and the privacy policy is a document nobody
// searches for — platform.BuildSitemap's own comment says transient and
// non-page URLs have no business here.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/"}, {Path: "/clean"}, {Path: "/clean/rules"},
		{Path: "/diff"}, {Path: "/trace"}, {Path: "/short"}, {Path: "/encoding"},
	}, nil
}
