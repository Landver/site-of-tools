package dnstools

import (
	"cmp"
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

// Page descriptions, rendered as <meta name="description"> and og:description via the "Desc" key.
const (
	emailDesc = "Check a domain's email authentication: SPF (including the 10-lookup limit that silently breaks it), DMARC policy strength, DKIM keys at common selectors, MTA-STS policy fetched over HTTPS not just its DNS pointer, TLS-RPT and BIMI. Free, open source, JSON API included."

	domainDesc = "Who registered this domain, when it expires, what its registry lock status actually means, and every subdomain Certificate Transparency has seen under it. Registration via RDAP, subdomains via CT logs: both public, both free, and neither sends a packet at the domain itself."

	consistencyDesc = "Is your DNS change live yet? Asks every one of the zone's own authoritative nameservers directly, with recursion off, and compares them against the public resolvers. Shows which servers disagree, whether their SOA serials match, and how long the cached copies have left."

	traceDesc = "Walk the DNS delegation for any name from a root server down, one zone cut at a time, with recursion off. Every hop is shown: the server that answered, its round-trip time, the nameservers it handed back and whether the referral carried glue. The DNSSEC chain of trust is verified here against the IANA root trust anchors, not read off a resolver's AD bit. Free, open source, JSON API included."

	lookupDesc = "Look up DNS records for any domain: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, against Cloudflare, Google or Quad9. Shows TTL as seconds and as a duration, plus rcode, header flags and query time. Free, open source, with a curl-able JSON API."
)

const UnavailableMessage = "This check isn't available right now."

// Tracer is the handler's dependency for the delegation walk; *Service satisfies it.
type Tracer interface {
	Trace(ctx context.Context, name, qtype string) (*Trace, error)
}

// handler holds the routes' deps; all but svc may be nil, which leaves that card or page off.
type handler struct {
	svc   Looker
	spr   Spreader
	mail  Mailer
	tra   Tracer
	ecs   ECSer
	rep   Reputer
	block BlockChecker // the shared blocklist corpus, which dnstools never opens itself
	dom   *DomainClient
	geo   iptools.Looker // iptools' open IP2Location handles, in-process: no HTTP hop
	lim   *Limits
}

// Limits are shared by REST and MCP; a walk costs 50 to 100 upstream queries.
type Limits struct {
	Lookup, Walk       platform.Limiter
	LookupCap, WalkCap *platform.Cap
	// DomainCap is apart: RDAP and crt.sh can hold a slot for 20 s.
	DomainCap *platform.Cap
}

func NewLimits() *Limits {
	return &Limits{
		Lookup:    platform.NewLimiter(2, 10),
		Walk:      platform.NewLimiter(0.5, 3),
		LookupCap: platform.NewCap(8),
		WalkCap:   platform.NewCap(4),
		DomainCap: platform.NewCap(4),
	}
}

// Register wires dns.corpberry.com's routes onto e; all take ?name= (and ?type=, ?resolver=).
func Register(e *echo.Echo, svc Looker, geo iptools.Looker, dom *DomainClient, bl BlockChecker, lim *Limits) {
	if lim == nil {
		lim = NewLimits()
	}
	h := &handler{svc: svc, geo: geo, dom: dom, block: bl, lim: lim}
	h.spr, h.ecs, h.tra, h.mail, h.rep = Checks(svc)
	lookup := platform.RateLimit(lim.Lookup, bare, limited)
	walk := platform.RateLimit(lim.Walk, bare, limited)
	e.GET("/", h.index, lookup)
	e.GET("/consistency", h.consistency, walk)
	e.GET("/trace", h.trace, walk)
	e.GET("/domain", h.domain, lookup)
	e.GET("/email", h.email, lookup)
}

// navPages is the sub-nav, in order; Key is the page's "Active".
var navPages = []struct{ Key, Path, Label, Hint string }{
	{"lookup", "/", "DNS lookup", "Nine record types for a name, at once"},
	{"consistency", "/consistency", "Consistency", "Is a DNS change live yet? The zone's own nameservers against the public resolvers"},
	{"trace", "/trace", "Trace", "Walk the delegation down from the root and check the DNSSEC chain"},
	{"domain", "/domain", "Domain", "Who registered it, when it expires, and its subdomains"},
	{"email", "/email", "Email", "SPF, DMARC, DKIM, MTA-STS and inbound mail-server blocklists"},
}

// view starts a page's view model from ?name=, and returns the name as read.
func view(c *echo.Context, active, title, desc string) (string, map[string]any) {
	raw := c.QueryParam("name")
	name := NormalizeName(raw)
	vm := map[string]any{
		"Active": active, "Title": title, "Desc": desc, "Nav": navPages,
		"Query": name, "Unicode": UnicodeName(name), "OOB": platform.IsHTMX(c),
	}
	if needDomain(name) == nil {
		vm["NavName"] = name
	}
	if name == "" || raw == name {
		return name, vm
	}
	if platform.IsHTMX(c) {
		u := *c.Request().URL
		q := u.Query()
		q.Set("name", name)
		u.RawQuery = q.Encode()
		c.Response().Header().Set("HX-Push-Url", u.RequestURI())
	}
	// What was typed, when reading it took more than trimming.
	if t := strings.TrimSpace(raw); !strings.EqualFold(strings.TrimSuffix(t, "."), name) {
		vm["Typed"] = t
	}
	return name, vm
}

// serve answers a bare hit and a full cap the same on every route; run answers the rest.
func serve(c *echo.Context, name string, vm map[string]any, cap *platform.Cap, run func(ctx context.Context) error) error {
	if name == "" {
		if platform.WantsJSON(c) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "no name; pass ?name=, e.g. " + c.Request().URL.Path + "?name=example.com"})
		}
		if platform.IsHTMX(c) {
			// A blank submit changes nothing but the status line.
			c.Response().Header().Set("HX-Reswap", "none")
			c.Response().Header().Set("HX-Push-Url", "false")
			return c.HTML(http.StatusOK, `<p id="dns-status" hx-swap-oob="innerHTML"></p>`)
		}
		return c.Render(http.StatusOK, "dns/page", vm)
	}
	if !cap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm)
	}
	defer cap.Release(c.RealIP(), 1)
	return run(c.Request().Context())
}

// unavailable answers 503: the request was fine, the check is just off or busy.
func unavailable(c *echo.Context, msg string, vm map[string]any) error {
	vm["Error"] = msg
	return platform.Reply(c, http.StatusServiceUnavailable, map[string]string{"error": msg}, vm, "dns/page", "dns/frag")
}

// answered renders a domain-layer result, or its error with the mapped status.
func answered(c *echo.Context, name string, body any, err error, vm map[string]any) error {
	switch {
	case errors.Is(err, ErrDisabled):
		return unavailable(c, UnavailableMessage, vm)
	case err != nil:
		vm["Error"], vm["ErrIP"], vm["TitleName"] = sentence(err.Error()), errors.Is(err, ErrNeedDomain), "Error"
		return platform.Reply(c, statusFor(err), map[string]string{"name": name, "error": err.Error()}, vm, "dns/page", "dns/frag")
	}
	vm["TitleName"] = cmp.Or(UnicodeName(name), name)
	return platform.Reply(c, http.StatusOK, body, vm, "dns/page", "dns/frag")
}

// sentence capitalises a Go-style error for the page; the JSON keeps the Go form.
func sentence(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[size:]
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "!") {
		s += "."
	}
	return s
}

// email serves the SPF / DMARC / DKIM / MTA-STS / BIMI check.
func (h *handler) email(c *echo.Context) error {
	name, vm := view(c, "email", "Email DNS", emailDesc)
	// Credits are page-scoped: the footer sits outside the htmx target.
	vm["SpamhausAttribution"] = true
	return serve(c, name, vm, h.lim.LookupCap, func(ctx context.Context) error {
		res, err := EmailReport(ctx, h.mail, h.rep, h.block, c.QueryParam("name"))
		if err == nil {
			vm["Email"] = res
			vm["OK"], vm["Warn"], vm["Fail"] = res.Score()
		}
		return answered(c, name, res, err, vm)
	})
}

// domain serves registration (RDAP) and CT subdomains; each half degrades on its own.
func (h *handler) domain(c *echo.Context) error {
	name, vm := view(c, "domain", "Domain info", domainDesc)
	vm["CertsAttribution"], vm["RDAPAttribution"] = true, true
	return serve(c, name, vm, h.lim.DomainCap, func(ctx context.Context) error {
		rep, err := DomainInfo(ctx, h.svc, h.dom, c.QueryParam("name"))
		if err != nil {
			return answered(c, name, nil, err, vm)
		}
		// "The registry holds nothing" is not "the lookup failed"; only the latter gets the disclaimer.
		vm["Domain"], vm["RegAbsent"] = rep, errors.Is(rep.RegErr, errNoRDAPRecord)
		// Partial success stays 200; total failure must not.
		if err := rep.Err(); err != nil && !errors.Is(err, ErrDisabled) {
			return platform.Reply(c, http.StatusBadGateway, rep, vm, "dns/page", "dns/frag")
		}
		return answered(c, name, rep, rep.Err(), vm)
	})
}

// consistency serves the zone's own nameservers against the public resolvers.
func (h *handler) consistency(c *echo.Context) error {
	name, vm := view(c, "consistency", "DNS consistency", consistencyDesc)
	vm["QType"], vm["Types"] = walkType(c.QueryParam("type")), Types
	vm["Attribution"], vm["RDAPAttribution"] = true, true
	return serve(c, name, vm, h.lim.WalkCap, func(ctx context.Context) error {
		env, err := Consistency(ctx, h.spr, h.ecs, h.geo, h.dom, c.QueryParam("name"), c.QueryParam("type"))
		vm["Spread"] = env
		return answered(c, name, env, err, vm)
	})
}

// trace serves the delegation walk from the root, with the chain of trust validated here.
func (h *handler) trace(c *echo.Context) error {
	name, vm := view(c, "trace", "DNS trace", traceDesc)
	qtype := walkType(c.QueryParam("type"))
	vm["QType"], vm["Types"] = qtype, Types
	return serve(c, name, vm, h.lim.WalkCap, func(ctx context.Context) error {
		if h.tra == nil {
			return answered(c, name, nil, ErrDisabled, vm)
		}
		res, err := h.tra.Trace(ctx, name, qtype)
		vm["Trace"] = res
		return answered(c, name, res, err, vm)
	})
}

// index serves the lookup page, and the lookup itself when ?name= is present.
func (h *handler) index(c *echo.Context) error {
	name, vm := view(c, "lookup", "DNS Tools", lookupDesc)
	// Blank or "all" is the full fan-out; naming one type narrows to it.
	vm["QType"], vm["Resolver"] = lookupType(c.QueryParam("type")), resolverKey(c.QueryParam("resolver"))
	vm["Types"], vm["Resolvers"], vm["Attribution"] = Types, Resolvers, true
	return serve(c, name, vm, h.lim.LookupCap, func(ctx context.Context) error {
		res, err := LookupEnriched(ctx, h.svc, h.geo, c.QueryParam("name"), c.QueryParam("type"), c.QueryParam("resolver"))
		vm["Result"] = res
		return answered(c, name, res, err, vm)
	})
}

// bare pages query nothing, so they don't count.
func bare(c *echo.Context) bool { return strings.TrimSpace(c.QueryParam("name")) == "" }

// limited is the rate limiter's answer: JSON, a page offering the same request, or a notice above the result.
func limited(c *echo.Context) error {
	const msg = "Too many lookups from your IP address. One lookup asks several upstream servers, so this tool is rate limited. Try again in a second."
	_, vm := view(c, cmp.Or(strings.TrimPrefix(c.Request().URL.Path, "/"), "lookup"), "Slow down · DNS Tools", msg)
	vm["Error"], vm["Retry"] = msg, c.Request().URL.RequestURI()
	if platform.IsHTMX(c) {
		// Above the last result, not over it.
		c.Response().Header().Set("HX-Reswap", "afterbegin")
	}
	return platform.Reply(c, http.StatusTooManyRequests, map[string]string{"error": msg}, vm, "dns/page", "dns/slowdown")
}

// statusFor maps domain errors to HTTP status: the caller's mistakes are 400, upstream failures 502.
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
