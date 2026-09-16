package dnstools

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/iptools"
)

// Page description, surfaced as <meta name="description"> + og:description by
// shared/templates/partials/head.html via the "Desc" VM key.
const emailDesc = "Check a domain's email authentication: SPF (including the 10-lookup limit that silently breaks it), DMARC policy strength, DKIM keys at common selectors, MTA-STS policy fetched over HTTPS not just its DNS pointer, TLS-RPT and BIMI. Free, open source, JSON API included."

const domainDesc = "Who registered this domain, when it expires, what its registry lock status actually means, and every subdomain Certificate Transparency has seen under it. Registration via RDAP, subdomains via CT logs: both public, both free, and neither sends a packet at the domain itself."

const consistencyDesc = "Is your DNS change live yet? Asks every one of the zone's own authoritative nameservers directly, with recursion off, and compares them against the public resolvers. Shows which servers disagree, whether their SOA serials match, and how long the cached copies have left."

const lookupDesc = "Look up DNS records for any domain: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, against Cloudflare, Google or Quad9. Shows TTL as seconds and as a duration, plus rcode, header flags and query time. Free, open source, with a curl-able JSON API."

// Mailer: handler dependency for the email-auth page.
type Mailer interface {
	EmailAuth(ctx context.Context, domain string) (*EmailAuth, error)
}

// Spreader: handler dependency for the consistency check. Separate from Looker
// so a test can fake either half on its own. *Service satisfies both.
type Spreader interface {
	Spread(ctx context.Context, name, qtype string) (*Spread, error)
}

// handler: transport-layer deps for dns.corpberry.com routes.
type handler struct {
	svc  Looker
	spr  Spreader
	mail Mailer
	// dom: RDAP + Certificate Transparency. Best-effort and nil-safe; when it
	// is off or an upstream is down, the page says so rather than implying the
	// domain has no registration or no subdomains.
	dom *DomainClient
	// geo: best-effort ASN/country enrichment for resolved addresses, reusing
	// iptools' already-open IP2Location handles in-process. Same binary, no
	// new dependency, no HTTP hop (02-build-fit.md §2). nil (or nil *Service
	// behind it) degrades to plain records.
	geo iptools.Looker
}

// Rate limit for the lookup endpoint. One click is a fan-out of up to 8
// upstream queries, so this is the difference between a tool and an open DNS
// proxy someone else points at a target (reports/abuse-ratelimits-and-ethics.md).
//
// Burst covers ordinary use — a few lookups while you fix a record, plus the
// htmx request per submit — while the sustained rate is well under anything
// that would matter to a public resolver.
const (
	rateLimitPerSecond = 2
	rateLimitBurst     = 10
	rateLimitExpiry    = 3 * time.Minute
)

// Register wires dns.corpberry.com routes onto e. Query-param only
// (?name=&type=&resolver=), matching iptools' convention — no /:name route.
//
//	GET /             DNS record lookup
//	GET /consistency  the zone's own nameservers vs the public resolvers
//	GET /domain       registration (RDAP) + subdomains (Certificate Transparency)
//	GET /email        SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI
func Register(e *echo.Echo, svc Looker, geo iptools.Looker, dom *DomainClient) {
	h := &handler{svc: svc, geo: geo, dom: dom}
	// The same *Service satisfies both interfaces; a test can pass a fake that
	// only implements one.
	h.spr, _ = svc.(Spreader)
	h.mail, _ = svc.(Mailer)
	limit := rateLimiter()
	e.GET("/", h.index, limit)
	e.GET("/consistency", h.consistency, limit)
	e.GET("/domain", h.domain, limit)
	e.GET("/email", h.email, limit)
}

// reply picks the representation, and is the only place in this file that
// does. Every route serves its domain struct as JSON and a view model as HTML,
// so platform.Respond — one value shared by all three — cannot stand in for it.
//
// page is the whole document a browser gets; frag is the slot htmx swaps.
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	switch {
	case platform.WantsJSON(c):
		return c.JSON(code, body)
	case platform.IsHTMX(c):
		return c.Render(code, frag, vm)
	}
	return c.Render(code, page, vm)
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
		return true, c.Render(http.StatusOK, frag, vm)
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
		vm["Error"] = err.Error()
		return reply(c, statusFor(err), map[string]string{"name": name, "error": err.Error()}, vm, page, frag)
	}
	return reply(c, http.StatusOK, body, vm, page, frag)
}

// email serves the SPF / DMARC / DKIM / MTA-STS / BIMI check.
func (h *handler) email(c *echo.Context) error {
	name := strings.TrimSpace(strings.ToLower(c.QueryParam("name")))
	vm := map[string]any{"Title": "Email DNS", "Desc": emailDesc, "Active": "email", "Query": name}

	if done, err := needName(c, name, vm, "dns/email", "dns/emailauth", "/email?name=example.com"); done {
		return err
	}
	if h.mail == nil {
		return unavailable(c, vm, "dns/email", "dns/emailauth")
	}

	res, err := h.mail.EmailAuth(c.Request().Context(), name)
	if err == nil {
		vm["Email"] = res
		vm["OK"], vm["Warn"], vm["Fail"] = res.Score()
	}
	return answered(c, name, res, err, vm, "dns/email", "dns/emailauth")
}

// delegationHealth supplies the two inputs Spread's own probes cannot reach:
// an ASN per nameserver address, from iptools in-process, and the registry's
// delegation, over RDAP. The judgement itself lives in the domain layer.
//
// Reports whether IP2Location and RDAP data each made it onto the page, which
// is what the two footer credits key off.
func (h *handler) delegationHealth(ctx context.Context, sp *Spread) (usedGeo, usedRDAP bool) {
	var asnOf func(string) string
	if h.geo != nil {
		asnOf = func(ip string) string {
			g, err := h.geo.Lookup(ip)
			if err != nil || g == nil {
				return ""
			}
			return g.ASN
		}
	}

	// The registry knows the zone apex and nothing below it, so this asks
	// about the zone Spread walked up to find, not the name that was typed.
	var registryNS []string
	if h.dom != nil && sp.Zone != "" {
		if reg, err := h.dom.Registration(ctx, strings.TrimSuffix(sp.Zone, ".")); err == nil {
			registryNS = reg.Nameservers
		}
	}
	return sp.AddDelegationHealth(asnOf, registryNS), len(registryNS) > 0
}

// domain serves the two questions DNS itself cannot answer: who registered
// this name, and what subdomains exist under it. Both halves are independent
// and best-effort, so one upstream failing still leaves the other rendered.
func (h *handler) domain(c *echo.Context) error {
	name := strings.TrimSpace(strings.ToLower(c.QueryParam("name")))
	// Credits ride on the PAGE, not the result: the footer lives outside the
	// htmx target, so a per-result flag never reaches the DOM on a form
	// submit — which is how these pages are actually used. iptools does the
	// same. IP2Location's licence makes this an obligation, not a nicety.
	vm := map[string]any{
		"Title": "Domain info", "Desc": domainDesc, "Active": "domain", "Query": name,
		"CertsAttribution": true, "RDAPAttribution": true,
	}

	if done, err := needName(c, name, vm, "dns/domain", "dns/domaininfo", "/domain?name=example.com"); done {
		return err
	}
	// The other three routes are validated inside the domain layer; this one
	// reaches HTTP upstreams directly, so it does its own check first.
	if err := validDomain(name); err != nil {
		return answered(c, name, nil, err, vm, "dns/domain", "dns/domaininfo")
	}

	// Two independent upstreams, fetched concurrently: neither should wait on
	// the other, and either failing must not cost the other's result.
	ctx := c.Request().Context()
	var (
		wg     sync.WaitGroup
		reg    *Registration
		regErr error
		ct     *CertNames
		ctErr  error
	)
	wg.Add(2)
	go safe(func() {
		defer wg.Done()
		regErr = errPanic
		reg, regErr = h.dom.Registration(ctx, name)
	})
	go safe(func() {
		defer wg.Done()
		ctErr = errPanic
		ct, ctErr = h.dom.CertNames(ctx, name)
	})
	wg.Wait()

	// A nil client answers ErrDisabled from both halves, and so does one whose
	// URLs were blanked in config — the same page either way, which is why
	// this is one branch rather than a nil check that would miss the second.
	if errors.Is(regErr, ErrDisabled) && errors.Is(ctErr, ErrDisabled) {
		return unavailable(c, vm, "dns/domain", "dns/domaininfo")
	}

	// Partial success stays 200; total failure must not.
	code := http.StatusOK
	if regErr != nil && ctErr != nil {
		code = http.StatusBadGateway
	}

	out := map[string]any{"name": name}
	if regErr == nil {
		out["registration"] = reg
		vm["Registration"] = reg
		// Credit each upstream only when its data is actually on the page, and
		// only on this page — same rule the Shodan credit follows in iptools.
	} else {
		out["registration_error"] = regErr.Error()
		vm["RegError"] = regErr.Error()
		// Distinguish "the registry answered, and holds nothing for this name"
		// from "the lookup failed". Only the latter deserves the disclaimer.
		vm["RegAbsent"] = errors.Is(regErr, errNoRDAPRecord)
	}
	if ctErr == nil {
		out["certificate_names"] = ct
		vm["Certs"] = ct
	} else {
		out["certificate_names_error"] = ctErr.Error()
		vm["CertError"] = ctErr.Error()
	}
	return reply(c, code, out, vm, "dns/domain", "dns/domaininfo")
}

// consistency serves the "is my change live yet" check: the zone's own
// nameservers asked directly, plus the public resolvers, grouped by what they
// actually returned.
func (h *handler) consistency(c *echo.Context) error {
	name := strings.TrimSpace(c.QueryParam("name"))
	qtype := strings.ToUpper(strings.TrimSpace(c.QueryParam("type")))
	if qtype == "" {
		qtype = "A"
	}

	vm := map[string]any{
		"Title": "DNS consistency", "Desc": consistencyDesc, "Active": "consistency",
		"Query": name, "QType": qtype, "Types": Types,
		// Page-scoped credits, same reason as /domain above.
		"Attribution": true, "RDAPAttribution": true,
	}
	if done, err := needName(c, name, vm, "dns/consistency", "dns/spread", "/consistency?name=example.com"); done {
		return err
	}
	if h.spr == nil {
		return unavailable(c, vm, "dns/consistency", "dns/spread")
	}

	ctx := c.Request().Context()
	sp, err := h.spr.Spread(ctx, name, qtype)
	if err == nil {
		vm["Spread"] = sp
		// Both credits are asserted from what the findings actually used, not
		// from the page having been requested.
		// Flags are already set on the page VM; delegationHealth's return
		// values would only ever narrow them, and narrowing loses the credit
		// on the htmx path.
		h.delegationHealth(ctx, sp)
	}
	return answered(c, name, sp, err, vm, "dns/consistency", "dns/spread")
}

// rateLimiter throttles per client IP, keyed on the same Cloudflare-aware
// c.RealIP() the request log uses. In-process only: one box, one binary, so a
// shared store would be infrastructure for no gain.
func rateLimiter() echo.MiddlewareFunc {
	store := middleware.NewRateLimiterMemoryStoreWithConfig(
		middleware.RateLimiterMemoryStoreConfig{
			Rate:      rateLimitPerSecond,
			Burst:     rateLimitBurst,
			ExpiresIn: rateLimitExpiry,
		},
	)
	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: store,
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return c.RealIP(), nil
		},
		DenyHandler: func(c *echo.Context, _ string, _ error) error {
			// Negotiated three ways like every other response here. Rendering
			// one route's fragment to everyone gave browsers an unstyled
			// partial and htmx nothing it would swap.
			const msg = "Too many lookups from your address. One lookup asks several upstream resolvers, so this endpoint is rate limited. Try again in a few seconds."
			return reply(c, http.StatusTooManyRequests,
				map[string]string{"error": msg},
				map[string]any{"Title": "Slow down", "Desc": msg, "Error": msg},
				"dns/ratelimited", "dns/error")
		},
	})
}

// index serves the lookup page, and the lookup itself when ?name= is present.
// Bare hit renders the empty form to a browser, an empty result fragment to
// htmx, and 400 to a JSON caller — same contract iptools' /cidr follows.
func (h *handler) index(c *echo.Context) error {
	name := strings.TrimSpace(c.QueryParam("name"))
	// Blank or "all" = the default fan-out. Naming one type narrows to it, so
	// a ?type= permalink still works, but nobody has to click through nine
	// types to find out what a domain publishes.
	qtype := strings.ToUpper(strings.TrimSpace(c.QueryParam("type")))
	if qtype == "ALL" {
		qtype = ""
	}
	resolver := strings.ToLower(strings.TrimSpace(c.QueryParam("resolver")))
	if resolver == "" {
		resolver = DefaultResolver
	}

	vm := h.vm(name, qtype, resolver)
	if done, err := needName(c, name, vm, "dns/index", "dns/result", "/?name=example.com&type=A"); done {
		return err
	}
	return h.show(c, vm, name, qtype, resolver)
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

// show runs the lookup and responds in the caller's preferred format.
func (h *handler) show(c *echo.Context, vm map[string]any, name, qtype, resolver string) error {
	var types []string
	if qtype != "" {
		types = []string{qtype}
	}
	res, err := h.svc.LookupSet(c.Request().Context(), name, resolver, types)
	if err == nil {
		vm["Result"] = res
		// IP2Location's licence requires the credit wherever their data shows
		// (shared/templates/partials/footer.html), so it is claimed only once
		// enrichment has actually attached something.
		h.enrich(res)
	}
	// No "your request" connection card here, unlike iptools/botcheck: this
	// tool answers questions about someone else's domain, so the visitor's own
	// connection is a non-sequitur. The DNS-relevant version of that idea is
	// resolver identity ("which resolver do YOU use"), which needs a delegated
	// beacon zone and is Tier 2 (02-build-fit.md §4).
	return answered(c, name, res, err, vm, "dns/index", "dns/result")
}

// enrich attaches ASN / AS-name / country to each A and AAAA answer by calling
// iptools' geo service directly, in-process. Best-effort throughout: no geo
// service, unloaded databases or a failed lookup just leaves the fields blank
// and the DNS result stands on its own.
// Returns whether it actually attached anything, which drives the
// IP2Location credit: the footer shows exactly when their data is on screen.
func (h *handler) enrich(set *ResultSet) bool {
	if h.geo == nil || set == nil {
		return false
	}
	attached := false
	for f := range set.Found {
		for i, r := range set.Found[f].Records {
			if r.Type != "A" && r.Type != "AAAA" {
				continue
			}
			geo, err := h.geo.Lookup(r.Value)
			if err != nil || geo == nil {
				continue
			}
			set.Found[f].Records[i].ASN = geo.ASN
			set.Found[f].Records[i].ASName = geo.ASName
			set.Found[f].Records[i].Country = geo.Country
			attached = attached || geo.ASN != "" || geo.ASName != "" || geo.Country != ""
		}
	}
	return attached
}

// statusFor maps domain errors to HTTP status: caller's fault (bad type,
// unknown resolver, empty or malformed name) is 400, a failed upstream query
// is 502 — the resolver failed us, the request itself was fine.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrBadType), errors.Is(err, ErrBadResolver),
		errors.Is(err, ErrEmptyName), errors.Is(err, ErrBadName):
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

// SitemapPages: this tool's indexable URLs, for platform.RegisterSEO.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{
		{Path: "/"}, {Path: "/consistency"}, {Path: "/domain"}, {Path: "/email"},
	}, nil
}
