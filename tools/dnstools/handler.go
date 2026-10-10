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

// Page descriptions, rendered as <meta name="description"> and og:description via the "Desc" key.
const (
	emailDesc = "Check a domain's email authentication: SPF (including the 10-lookup limit that silently breaks it), DMARC policy strength, DKIM keys at common selectors, MTA-STS policy fetched over HTTPS not just its DNS pointer, TLS-RPT and BIMI. Free, open source, JSON API included."

	domainDesc = "Who registered this domain, when it expires, what its registry lock status actually means, and every subdomain Certificate Transparency has seen under it. Registration via RDAP, subdomains via CT logs: both public, both free, and neither sends a packet at the domain itself."

	consistencyDesc = "Is your DNS change live yet? Asks every one of the zone's own authoritative nameservers directly, with recursion off, and compares them against the public resolvers. Shows which servers disagree, whether their SOA serials match, and how long the cached copies have left."

	traceDesc = "Walk the DNS delegation for any name from a root server down, one zone cut at a time, with recursion off. Every hop is shown: the server that answered, its round-trip time, the nameservers it handed back and whether the referral carried glue. The DNSSEC chain of trust is verified here against the IANA root trust anchors, not read off a resolver's AD bit. Free, open source, JSON API included."

	lookupDesc = "Look up DNS records for any domain: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR, against Cloudflare, Google or Quad9. Shows TTL as seconds and as a duration, plus rcode, header flags and query time. Free, open source, with a curl-able JSON API."
)

// Tracer is the handler's dependency for the delegation walk; *Service satisfies it.
type Tracer interface {
	Trace(ctx context.Context, name, qtype string) (*Trace, error)
}

// handler holds the routes' deps; all but svc may be nil, which leaves that card or page off.
type handler struct {
	svc  Looker
	spr  Spreader
	mail Mailer
	tra  Tracer
	ecs  ECSer
	rep  Reputer
	// The shared blocklist corpus, which dnstools never opens itself.
	block BlockChecker
	dom   *DomainClient
	// Reuses iptools' open IP2Location handles in-process: no HTTP hop.
	geo iptools.Looker
	lim *Limits
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
	// A nil svc is a wiring mistake: fail at startup, not as a recovered 500 per request.
	if svc == nil {
		panic("dnstools.Register: svc is nil")
	}
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

// reply is platform.Reply, with htmx fragments also carrying the nav, title and status line.
func reply(c *echo.Context, code int, body any, vm map[string]any, page, frag string) error {
	if platform.IsHTMX(c) {
		vm["OOB"] = true
	}
	return platform.Reply(c, code, body, vm, page, frag)
}

// readName normalises ?name= and returns what was typed when reading it took more than trimming.
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

// needName answers a bare hit (form, empty htmx slot, or JSON 400) and reports whether it did.
func needName(c *echo.Context, name string, vm map[string]any, page, example string) (bool, error) {
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

// unavailable answers 503: the request was fine, the feature is just off or busy.
func unavailable(c *echo.Context, msg string, vm map[string]any, page, frag string) error {
	vm["Error"] = msg
	return reply(c, http.StatusServiceUnavailable, map[string]string{"error": msg}, vm, page, frag)
}

const UnavailableMessage = "This check isn't available right now."

// answered renders a domain-layer result, or its error with the mapped status.
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
	const page, frag = "dns/email", "dns/emailauth"
	name, typed := readName(c)
	// Credits are page-scoped: the footer sits outside the htmx target.
	vm := withName(map[string]any{
		"Title": "Email DNS", "Desc": emailDesc, "Active": "email", "Query": name,
		"SpamhausAttribution": true,
	}, name, typed)

	if done, err := needName(c, name, vm, page, "/email?name=example.com"); done {
		return err
	}
	if h.mail == nil {
		return unavailable(c, UnavailableMessage, vm, page, frag)
	}
	if !h.lim.LookupCap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm, page, frag)
	}
	defer h.lim.LookupCap.Release(c.RealIP(), 1)

	res, err := EmailReport(c.Request().Context(), h.mail, h.rep, h.block, c.QueryParam("name"))
	if err == nil {
		vm["Email"] = res
		vm["OK"], vm["Warn"], vm["Fail"] = res.Score()
		if res.MXRep != nil {
			vm["MXRep"] = res.MXRep
		}
	}
	return answered(c, name, res, err, vm, page, frag)
}

// domain serves registration (RDAP) and CT subdomains; each half degrades on its own.
func (h *handler) domain(c *echo.Context) error {
	const page, frag = "dns/domain", "dns/domaininfo"
	name, typed := readName(c)
	vm := withName(map[string]any{
		"Title": "Domain info", "Desc": domainDesc, "Active": "domain", "Query": name,
		"CertsAttribution": true, "RDAPAttribution": true,
	}, name, typed)

	if done, err := needName(c, name, vm, page, "/domain?name=example.com"); done {
		return err
	}
	if !h.lim.DomainCap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm, page, frag)
	}
	defer h.lim.DomainCap.Release(c.RealIP(), 1)
	rep, err := DomainInfo(c.Request().Context(), h.svc, h.dom, c.QueryParam("name"))
	if err != nil {
		return answered(c, name, nil, err, vm, page, frag)
	}
	vm["RegFor"] = rep.RegistrableDomain

	// Partial success stays 200; total failure must not.
	code := http.StatusOK
	switch err := rep.Err(); {
	case errors.Is(err, ErrDisabled):
		return unavailable(c, UnavailableMessage, vm, page, frag)
	case err != nil:
		code = http.StatusBadGateway
	default:
		vm["TitleName"] = displayName(name)
	}
	if rep.RegErr == nil {
		vm["Registration"] = rep.Registration
	} else {
		vm["RegError"] = rep.RegErr.Error()
		// "The registry holds nothing" is not "the lookup failed"; only the latter gets the disclaimer.
		vm["RegAbsent"] = errors.Is(rep.RegErr, errNoRDAPRecord)
		vm["RegHasNS"] = rep.Delegated
	}
	if rep.CertErr == nil {
		vm["Certs"] = rep.CertNames
	} else {
		vm["CertError"] = rep.CertErr.Error()
	}
	return reply(c, code, rep, vm, page, frag)
}

// consistency serves the zone's own nameservers against the public resolvers.
func (h *handler) consistency(c *echo.Context) error {
	const page, frag = "dns/consistency", "dns/spread"
	name, typed := readName(c)
	qtype := walkType(c.QueryParam("type"))

	vm := withName(map[string]any{
		"Title": "DNS consistency", "Desc": consistencyDesc, "Active": "consistency",
		"Query": name, "QType": qtype, "Types": Types,
		"Attribution": true, "RDAPAttribution": true,
	}, name, typed)
	if done, err := needName(c, name, vm, page, "/consistency?name=example.com"); done {
		return err
	}
	if h.spr == nil {
		return unavailable(c, UnavailableMessage, vm, page, frag)
	}
	if !h.lim.WalkCap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm, page, frag)
	}
	defer h.lim.WalkCap.Release(c.RealIP(), 1)

	env, err := Consistency(c.Request().Context(), h.spr, h.ecs, h.geo, h.dom, c.QueryParam("name"), c.QueryParam("type"))
	if err == nil {
		// A nil ECS is falsy to {{with}}: no card when the check didn't run.
		vm["Spread"], vm["ECS"] = env.Spread, env.ECS
	}
	return answered(c, name, env, err, vm, page, frag)
}

// trace serves the delegation walk from the root, with the chain of trust validated here.
func (h *handler) trace(c *echo.Context) error {
	const page, frag = "dns/trace", "dns/tracewalk"
	name, typed := readName(c)
	qtype := walkType(c.QueryParam("type"))

	vm := withName(map[string]any{
		"Title": "DNS trace", "Desc": traceDesc, "Active": "trace",
		"Query": name, "QType": qtype, "Types": Types,
	}, name, typed)
	if done, err := needName(c, name, vm, page, "/trace?name=example.com"); done {
		return err
	}
	if h.tra == nil {
		return unavailable(c, UnavailableMessage, vm, page, frag)
	}
	if !h.lim.WalkCap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm, page, frag)
	}
	defer h.lim.WalkCap.Release(c.RealIP(), 1)

	res, err := h.tra.Trace(c.Request().Context(), name, qtype)
	if err == nil {
		vm["Trace"] = res
	}
	return answered(c, name, res, err, vm, page, frag)
}

// bare pages query nothing, so they don't count.
func bare(c *echo.Context) bool { return strings.TrimSpace(c.QueryParam("name")) == "" }

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
		c.Response().Header().Set("HX-Push-Url", "false")
		// Above the last result, not over it.
		c.Response().Header().Set("HX-Reswap", "afterbegin")
	}
	return reply(c, http.StatusTooManyRequests,
		map[string]string{"error": msg}, vm,
		"dns/ratelimited", "dns/slowdown")
}

// index serves the lookup page, and the lookup itself when ?name= is present.
func (h *handler) index(c *echo.Context) error {
	const page, frag = "dns/index", "dns/result"
	name, typed := readName(c)
	// Blank or "all" is the full fan-out; naming one type narrows to it.
	qtype := lookupType(c.QueryParam("type"))
	resolver := resolverKey(c.QueryParam("resolver"))

	vm := withName(map[string]any{
		"Title": "DNS Tools", "Desc": lookupDesc, "Active": "lookup", "Attribution": true,
		"Query": name, "QType": qtype, "AllTypes": qtype == "", "Resolver": resolver,
		"Types": Types, "Resolvers": Resolvers,
	}, name, typed)
	if done, err := needName(c, name, vm, page, "/?name=example.com&type=A"); done {
		return err
	}
	if !h.lim.LookupCap.TryAcquire(c.RealIP(), 1) {
		return unavailable(c, platform.BusyMessage, vm, page, frag)
	}
	defer h.lim.LookupCap.Release(c.RealIP(), 1)
	res, err := LookupEnriched(c.Request().Context(), h.svc, h.geo,
		c.QueryParam("name"), c.QueryParam("type"), c.QueryParam("resolver"))
	if err == nil {
		vm["Result"] = res
	}
	return answered(c, name, res, err, vm, page, frag)
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
