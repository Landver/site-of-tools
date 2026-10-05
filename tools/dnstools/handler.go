package dnstools

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Page description, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" VM key.
const emailDesc = "Check a domain's email authentication: SPF (including the 10-lookup limit that silently breaks it), DMARC policy strength, DKIM keys at common selectors, MTA-STS policy fetched over HTTPS not just its DNS pointer, TLS-RPT and BIMI. Free, open source, JSON API included."

const domainDesc = "Who registered this domain, when it expires, what its registry lock status actually means, and every subdomain Certificate Transparency has seen under it. Registration via RDAP, subdomains via CT logs: both public, both free, and neither sends a packet at the domain itself."

const consistencyDesc = "Is your DNS change live yet? Asks every one of the zone's own authoritative nameservers directly, with recursion off, and compares them against the public resolvers. Shows which servers disagree, whether their SOA serials match, and how long the cached copies have left."

const traceDesc = "Walk the DNS delegation for any name from a root server down, one zone cut at a time, with recursion off. Every hop is shown: the server that answered, its round-trip time, the nameservers it handed back and whether the referral carried glue. The DNSSEC chain of trust is verified here against the IANA root trust anchors, not read off a resolver's AD bit. Free, open source, JSON API included."

const lookupDesc = "Look up DNS records for any domain: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, against Cloudflare, Google or Quad9. Shows TTL as seconds and as a duration, plus rcode, header flags and query time. Free, open source, with a curl-able JSON API."

// Tracer: handler dependency for the delegation walk. Separate from Looker and
// Spreader so a test can fake one half on its own. *Service satisfies all.
type Tracer interface {
	Trace(ctx context.Context, name, qtype string) (*Trace, error)
}

// handler: transport-layer deps for dns.corpberry.com routes.
type handler struct {
	svc  Looker
	spr  Spreader
	mail Mailer
	tra  Tracer
	// ecs: the EDNS-client-subnet steering card on /consistency. A Looker that
	// does not implement ECSer simply leaves the card off the page.
	ecs ECSer
	// rep / block: mail-server reputation on /email. block is the shared
	// blocklist corpus, which dnstools never opens itself. Either one nil
	// means the card is not rendered — golden rule #5.
	rep   Reputer
	block BlockChecker
	// dom: RDAP + Certificate Transparency. Best-effort and nil-safe; when it
	// is off or an upstream is down, the page says so rather than implying the
	// domain has no registration or no subdomains.
	dom *DomainClient
	// geo: best-effort ASN/country enrichment for resolved addresses, reusing
	// iptools' already-open IP2Location handles in-process. Same binary, no
	// new dependency, no HTTP hop (02-build-fit.md §2). nil (or nil *Service
	// behind it) degrades to plain records.
	geo iptools.Looker
	lim *Limits
}

// Limits are this tool's budgets, built once and shared by every door. One
// lookup fans out to up to 8 upstream queries, which is the difference between
// a tool and an open DNS proxy (reports/abuse-ratelimits-and-ethics.md); a walk
// (/consistency, /trace) costs 50 to 100.
type Limits struct {
	Lookup, Walk       platform.Limiter
	LookupCap, WalkCap *platform.Cap
}

// NewLimits returns fresh budgets: lookups 2/s (burst 10), walks one per 2 s
// (burst 3); 8 lookups and 4 walks in flight.
func NewLimits() *Limits {
	return &Limits{
		Lookup:    platform.NewLimiter(2, 10),
		Walk:      platform.NewLimiter(0.5, 3),
		LookupCap: platform.NewCap(8),
		WalkCap:   platform.NewCap(4),
	}
}

// Register wires dns.corpberry.com routes onto e. Query-param only
// (?name=&type=&resolver=), matching iptools' convention — no /:name route.
// lim nil means fresh limits.
//
//	GET /             DNS record lookup
//	GET /consistency  the zone's own nameservers vs the public resolvers
//	GET /trace        the delegation walk from the root, chain of trust checked here
//	GET /domain       registration (RDAP) + subdomains (Certificate Transparency)
//	GET /email        SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI
func Register(e *echo.Echo, svc Looker, geo iptools.Looker, dom *DomainClient, bl BlockChecker, lim *Limits) {
	// Every other dependency here is optional and degrades to a 503 or to a
	// thinner page. svc is not: a nil one can only be a wiring mistake, and
	// left to be discovered per request it surfaces as a panic-recovered 500
	// instead of an error at startup.
	if svc == nil {
		panic("dnstools.Register: svc is nil")
	}
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{svc: svc, geo: geo, dom: dom, block: bl, lim: lim}
	// The same *Service satisfies both interfaces; a test can pass a fake that
	// only implements one.
	h.spr, _ = svc.(Spreader)
	h.mail, _ = svc.(Mailer)
	h.tra, _ = svc.(Tracer)
	h.ecs, _ = svc.(ECSer)
	h.rep, _ = svc.(Reputer)
	lookup := platform.RateLimit(lim.Lookup, bare, limited)
	walk := platform.RateLimit(lim.Walk, bare, limited)
	e.GET("/", h.index, lookup)
	e.GET("/consistency", h.consistency, walk)
	e.GET("/trace", h.trace, walk)
	e.GET("/domain", h.domain, lookup)
	e.GET("/email", h.email, lookup)
}

// reply picks the representation, and is the only place in this file that
// does. Every route serves its domain struct as JSON and a view model as HTML,
// so platform.Respond — one value shared by all three — cannot stand in for it.
//
// page is the whole document a browser gets; frag is the slot htmx swaps.
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	platform.SetNegotiationHeaders(c, code)
	switch {
	case platform.WantsJSON(c):
		return c.JSON(code, body)
	case platform.IsHTMX(c):
		// Fragments also carry the nav, title and status line (dns/oob).
		vm["OOB"] = true
		return c.Render(code, frag, vm)
	}
	return c.Render(code, page, vm)
}

// readName normalises ?name= and returns what was typed when reading it took
// more than trimming. For htmx, history gets the clean URL (HX-Push-Url).
func readName(c *echo.Context) (name, typed string) {
	raw := c.QueryParam("name")
	name = NormalizeName(raw)
	if name == "" || raw == name {
		return name, ""
	}
	if platform.IsHTMX(c) {
		u := *c.Request().URL
		q := u.Query()
		q.Set("name", name)
		u.RawQuery = q.Encode()
		c.Response().Header().Set("HX-Push-Url", u.RequestURI())
	}
	if t := strings.TrimSpace(raw); !strings.EqualFold(strings.TrimSuffix(t, "."), name) {
		typed = t
	}
	return name, typed
}

// withName adds the view-model keys every page derives from the name.
func withName(vm map[string]any, name, typed string) map[string]any {
	if needDomain(name) == nil {
		vm["NavName"] = name
	}
	vm["Typed"] = typed
	vm["Unicode"] = UnicodeName(name)
	return vm
}

// needName answers the bare hit: the empty form to a browser, an empty result
// slot to htmx, and 400 to a JSON caller, for whom asking nothing is a mistake
// rather than a starting point. Reports whether it has already answered.
func needName(c *echo.Context, name string, vm map[string]any, page, frag, example string) (bool, error) {
	if name != "" {
		return false, nil
	}
	if platform.WantsJSON(c) {
		return true, c.JSON(http.StatusBadRequest, map[string]string{
			"error": "no name; pass ?name=, e.g. " + example,
		})
	}
	if platform.IsHTMX(c) {
		// A blank submit changes nothing but the status line.
		c.Response().Header().Set("HX-Reswap", "none")
		c.Response().Header().Set("HX-Push-Url", "false")
		return true, c.HTML(http.StatusOK, `<p id="dns-status" hx-swap-oob="innerHTML"></p>`)
	}
	return true, c.Render(http.StatusOK, page, vm)
}

// unavailable answers a route whose dependency is switched off. 503, not 400
// or 502: the caller asked correctly and no upstream failed us, the feature
// simply is not running.
func unavailable(c *echo.Context, vm map[string]any, page, frag string) error {
	const msg = "This check isn't available right now."
	vm["Error"] = msg
	return reply(c, http.StatusServiceUnavailable, map[string]string{"error": msg}, vm, page, frag)
}

// answered renders the outcome of a domain-layer call: the struct on success,
// the mapped status and the named error on failure. Callers attach their own
// view-model keys first, and only when err is nil.
func answered(c *echo.Context, name string, body any, err error, vm map[string]any, page, frag string) error {
	if err != nil {
		vm["Error"] = sentence(err.Error())
		vm["ErrIP"] = errors.Is(err, ErrNeedDomain)
		vm["TitleName"] = "Error"
		return reply(c, statusFor(err), map[string]string{"name": name, "error": err.Error()}, vm, page, frag)
	}
	vm["TitleName"] = displayName(name)
	return reply(c, http.StatusOK, body, vm, page, frag)
}

// displayName: the Unicode spelling of a punycode name, else the name.
func displayName(name string) string {
	if u := UnicodeName(name); u != "" {
		return u
	}
	return name
}

// sentence capitalises a Go-style error for the page; the JSON keeps the Go form.
func sentence(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[size:]
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "!") {
		s += "."
	}
	return s
}

// email serves the SPF / DMARC / DKIM / MTA-STS / BIMI check.
func (h *handler) email(c *echo.Context) error {
	name, typed := readName(c)
	// Page-scoped, like every other credit here: the footer sits outside the
	// htmx target, so a per-result flag never reaches the DOM on a form submit.
	// Spamhaus only — the reputation card reads the blocklist corpus, and
	// nothing on this page consults IP2Location.
	vm := withName(map[string]any{
		"Title": "Email DNS", "Desc": emailDesc, "Active": "email", "Query": name,
		"SpamhausAttribution": true,
	}, name, typed)

	if done, err := needName(c, name, vm, "dns/email", "dns/emailauth", "/email?name=example.com"); done {
		return err
	}
	if h.mail == nil {
		return unavailable(c, vm, "dns/email", "dns/emailauth")
	}
	if !h.lim.LookupCap.TryAcquire(1) {
		return busy(c, vm, "dns/email", "dns/emailauth")
	}
	defer h.lim.LookupCap.Release(1)

	res, err := EmailReport(c.Request().Context(), h.mail, h.rep, h.block, c.QueryParam("name"))
	if err == nil {
		vm["Email"] = res
		vm["OK"], vm["Warn"], vm["Fail"] = res.Score()
		if res.MXRep != nil {
			vm["MXRep"] = res.MXRep
		}
	}
	return answered(c, name, res, err, vm, "dns/email", "dns/emailauth")
}

// domain serves the two questions DNS itself cannot answer: who registered
// this name, and what subdomains exist under it. Both halves are independent
// and best-effort, so one upstream failing still leaves the other rendered.
func (h *handler) domain(c *echo.Context) error {
	name, typed := readName(c)
	// Credits ride on the PAGE, not the result: the footer lives outside the
	// htmx target, so a per-result flag never reaches the DOM on a form
	// submit — which is how these pages are actually used. iptools does the
	// same. IP2Location's licence makes this an obligation, not a nicety.
	vm := withName(map[string]any{
		"Title": "Domain info", "Desc": domainDesc, "Active": "domain", "Query": name,
		"CertsAttribution": true, "RDAPAttribution": true,
	}, name, typed)

	if done, err := needName(c, name, vm, "dns/domain", "dns/domaininfo", "/domain?name=example.com"); done {
		return err
	}
	if !h.lim.LookupCap.TryAcquire(1) {
		return busy(c, vm, "dns/domain", "dns/domaininfo")
	}
	defer h.lim.LookupCap.Release(1)
	rep, err := DomainInfo(c.Request().Context(), h.svc, h.dom, c.QueryParam("name"))
	if err != nil {
		return answered(c, name, nil, err, vm, "dns/domain", "dns/domaininfo")
	}
	if rep.RegistrableDomain != "" {
		vm["RegFor"] = rep.RegistrableDomain
	}

	// Partial success stays 200; total failure must not.
	code := http.StatusOK
	switch err := rep.Err(); {
	case errors.Is(err, ErrDisabled):
		return unavailable(c, vm, "dns/domain", "dns/domaininfo")
	case err != nil:
		code = http.StatusBadGateway
	default:
		vm["TitleName"] = displayName(name)
	}
	if rep.RegErr == nil {
		vm["Registration"] = rep.Registration
	} else {
		vm["RegError"] = rep.RegErr.Error()
		// "The registry holds nothing for this name" is an answer; only a
		// failed lookup deserves the disclaimer.
		vm["RegAbsent"] = errors.Is(rep.RegErr, errNoRDAPRecord)
		if rep.Delegated {
			vm["RegHasNS"] = true
		}
	}
	if rep.CertErr == nil {
		vm["Certs"] = rep.CertNames
	} else {
		vm["CertError"] = rep.CertErr.Error()
	}
	return reply(c, code, rep, vm, "dns/domain", "dns/domaininfo")
}

// consistency serves the "is my change live yet" check: the zone's own
// nameservers asked directly, plus the public resolvers, grouped by what they
// actually returned.
func (h *handler) consistency(c *echo.Context) error {
	name, typed := readName(c)
	qtype := walkType(c.QueryParam("type"))

	vm := withName(map[string]any{
		"Title": "DNS consistency", "Desc": consistencyDesc, "Active": "consistency",
		"Query": name, "QType": qtype, "Types": Types,
		// Page-scoped credits, same reason as /domain above.
		"Attribution": true, "RDAPAttribution": true,
	}, name, typed)
	if done, err := needName(c, name, vm, "dns/consistency", "dns/spread", "/consistency?name=example.com"); done {
		return err
	}
	if h.spr == nil {
		return unavailable(c, vm, "dns/consistency", "dns/spread")
	}
	if !h.lim.WalkCap.TryAcquire(1) {
		return busy(c, vm, "dns/consistency", "dns/spread")
	}
	defer h.lim.WalkCap.Release(1)

	env, err := Consistency(c.Request().Context(), h.spr, h.ecs, h.geo, h.dom, c.QueryParam("name"), c.QueryParam("type"))
	if err == nil {
		// A nil ECS is falsy to {{with}}, so the card renders nothing when the
		// check did not run.
		vm["Spread"], vm["ECS"] = env.Spread, env.ECS
	}
	return answered(c, name, env, err, vm, "dns/consistency", "dns/spread")
}

// trace serves the delegation walk from the root, with the chain of trust
// validated in the domain layer rather than taken from a resolver's AD bit.
func (h *handler) trace(c *echo.Context) error {
	name, typed := readName(c)
	qtype := walkType(c.QueryParam("type"))

	vm := withName(map[string]any{
		"Title": "DNS trace", "Desc": traceDesc, "Active": "trace",
		"Query": name, "QType": qtype, "Types": Types,
	}, name, typed)
	if done, err := needName(c, name, vm, "dns/trace", "dns/tracewalk", "/trace?name=example.com"); done {
		return err
	}
	if h.tra == nil {
		return unavailable(c, vm, "dns/trace", "dns/tracewalk")
	}
	if !h.lim.WalkCap.TryAcquire(1) {
		return busy(c, vm, "dns/trace", "dns/tracewalk")
	}
	defer h.lim.WalkCap.Release(1)

	// No attribution flags: this walk uses neither IP2Location nor RDAP.
	res, err := h.tra.Trace(c.Request().Context(), name, qtype)
	if err == nil {
		vm["Trace"] = res
	}
	return answered(c, name, res, err, vm, "dns/trace", "dns/tracewalk")
}

// bare pages query nothing, so they don't count.
func bare(c *echo.Context) bool { return strings.TrimSpace(c.QueryParam("name")) == "" }

// limited answers a spent budget, negotiated three ways like every other
// response here. Rendering one route's fragment to everyone gave browsers an
// unstyled partial and htmx nothing it would swap.
func limited(c *echo.Context) error {
	const msg = "Too many lookups from your IP address. One lookup asks several upstream servers, so this tool is rate limited. Try again in a second."
	active := strings.TrimPrefix(c.Request().URL.Path, "/")
	if active == "" {
		active = "lookup"
	}
	name := NormalizeName(c.QueryParam("name"))
	vm := withName(map[string]any{"Title": "Slow down · DNS Tools", "Desc": msg, "Error": msg,
		"Active": active, "Query": name, "Retry": c.Request().URL.RequestURI()}, name, "")
	if platform.IsHTMX(c) {
		// Not a history entry.
		c.Response().Header().Set("HX-Push-Url", "false")
		// Above the last result, not over it.
		c.Response().Header().Set("HX-Reswap", "afterbegin")
	}
	return reply(c, http.StatusTooManyRequests,
		map[string]string{"error": msg}, vm,
		"dns/ratelimited", "dns/slowdown")
}

// busy answers a full cap: 503 like unavailable, but only for now.
func busy(c *echo.Context, vm map[string]any, page, frag string) error {
	vm["Error"] = platform.BusyMessage
	return reply(c, http.StatusServiceUnavailable, map[string]string{"error": platform.BusyMessage}, vm, page, frag)
}

// index serves the lookup page, and the lookup itself when ?name= is present.
// Bare hit renders the empty form to a browser, an empty result fragment to
// htmx, and 400 to a JSON caller — same contract iptools' /cidr follows.
func (h *handler) index(c *echo.Context) error {
	name, typed := readName(c)
	// Blank or "all" = the default fan-out. Naming one type narrows to it, so
	// a ?type= permalink still works, but nobody has to click through nine
	// types to find out what a domain publishes.
	qtype := lookupType(c.QueryParam("type"))
	resolver := resolverKey(c.QueryParam("resolver"))

	vm := withName(h.vm(name, qtype, resolver), name, typed)
	if done, err := needName(c, name, vm, "dns/index", "dns/result", "/?name=example.com&type=A"); done {
		return err
	}
	// No "your request" connection card here, unlike iptools/botcheck: this
	// tool answers questions about someone else's domain, so the visitor's own
	// connection is a non-sequitur. The DNS-relevant version of that idea is
	// resolver identity ("which resolver do YOU use"), which needs a delegated
	// beacon zone and is Tier 2 (02-build-fit.md §4).
	if !h.lim.LookupCap.TryAcquire(1) {
		return busy(c, vm, "dns/index", "dns/result")
	}
	defer h.lim.LookupCap.Release(1)
	res, err := LookupEnriched(c.Request().Context(), h.svc, h.geo,
		c.QueryParam("name"), c.QueryParam("type"), c.QueryParam("resolver"))
	if err == nil {
		vm["Result"] = res
	}
	return answered(c, name, res, err, vm, "dns/index", "dns/result")
}

// vm builds the shared view model every render of this page needs.
func (h *handler) vm(name, qtype, resolver string) map[string]any {
	return map[string]any{
		"Title":       "DNS Tools",
		"Desc":        lookupDesc,
		"Active":      "lookup", // which sub-nav entry is current
		"Attribution": true,
		"Query":       name,
		"QType":       qtype, // "" = the all-types fan-out
		"AllTypes":    qtype == "",
		"Resolver":    resolver,
		"Types":       Types,
		"Resolvers":   Resolvers,
	}
}

// statusFor maps domain errors to HTTP status: caller's fault (bad type,
// unknown resolver, empty or malformed name) is 400, a failed upstream query
// is 502 — the resolver failed us, the request itself was fine.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrBadType), errors.Is(err, ErrBadResolver),
		errors.Is(err, ErrEmptyName), errors.Is(err, ErrBadName), errors.Is(err, ErrNeedDomain):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/"}, {Path: "/consistency"}, {Path: "/trace"}, {Path: "/domain"}, {Path: "/email"},
	}, nil
}
