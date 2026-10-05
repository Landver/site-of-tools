// Package mcptools serves mcp.corpberry.com: the site's tools for AI agents
// over the Model Context Protocol, a third transport over the same domain
// calls the pages and the JSON API make (docs/README.md).
package mcptools

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/time/rate"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

// Deps is everything the tools call, built once in main.go and shared with the
// REST routes, Limits included, so a client has one budget whichever door it
// uses. A dependency that is nil at boot drops the tools that need it.
type Deps struct {
	Geo          iptools.Looker  // IP databases with Shodan, for ip_lookup and botcheck_score
	DNSGeo       iptools.Looker  // the same databases without Shodan, for DNS enrichment
	Blocklist    iptools.Checker // build with iptools.CheckerFrom
	DNSBlocklist dnstools.BlockChecker
	DNS          dnstools.Looker
	Domain       *dnstools.DomainClient
	Link         *linktools.Service
	Tracer       *linktools.Tracer
	Short        *linktools.Shortener // public resolve
	Owner        *linktools.Shortener // /mcp/owner; without a key the endpoint is a 404
	Blog         *site.Blog

	IPLimits     *iptools.Limits
	DNSLimits    *dnstools.Limits
	LinkLimits   *linktools.Limits
	CipherLimits *ciphertools.Limits
	BotLimits    *botcheck.Limits

	RequestLog *platform.RequestLog
	ToolURL    func(sub string) string // a subdomain's origin, platform.Config.URL
}

const maxBody = 1 << 20

const landingDesc = "Every corpberry.com tool for AI agents, over the Model Context Protocol: IP lookups and more, " +
	"with the same results as the web pages and the JSON API. Free, no account, no key."

// creditFlags are the footer flags (partials/footer) of each credit.
var creditFlags = map[string]string{
	platform.CreditIP2Location: "Attribution",
	platform.CreditSpamhaus:    "SpamhausAttribution",
	platform.CreditShodan:      "ShodanAttribution",
	platform.CreditCrtSh:       "CertsAttribution",
	platform.CreditRDAP:        "RDAPAttribution",
}

// trustedOrigins are the Origins hosted clients send, admitted once floor 3
// turns the foreign-Origin log below into a 403 (D15).
var trustedOrigins = map[string]bool{}

type handler struct {
	base      string
	endpoints map[string]*endpoint
	sdk       echo.HandlerFunc
	owner     *linktools.Shortener
	keys      *keyGuard
	perIP     platform.Limiter
	log       *slog.Logger
	catalog   catalog
	pages     []endpointView
	credits   []string
}

// Register wires mcp.corpberry.com onto e.
//
//	GET /               landing page, or the tool catalog as JSON
//	ANY /mcp            every public tool, for clients with tool search
//	ANY /mcp/:toolset   one toolset's tools; /mcp/owner the owner's, key required
func Register(e *echo.Echo, d Deps, base string) error {
	h, err := newHandler(d, base, e.Logger)
	if err != nil {
		return err
	}
	h.routes(e)
	return nil
}

func (h *handler) routes(e *echo.Echo) {
	e.GET("/", h.landing)
	e.Any("/mcp", h.serve)
	e.Any("/mcp/:toolset", h.serve)
}

func newHandler(d Deps, base string, log *slog.Logger) (*handler, error) {
	d = withDefaults(d)
	base = strings.TrimRight(base, "/")
	m := &calls{protocol: platform.NewLimiter(5, 20), reqlog: d.RequestLog, log: log}
	eps, err := buildEndpoints(ipSpecs(d), nil, d.Owner.HasKey(), m, base)
	if err != nil {
		return nil, err
	}
	sdk := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if ep := eps[r.PathValue("toolset")]; ep != nil {
			return ep.server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    true,
		JSONResponse:                 true,
		PropagateRequestCancellation: true,
		MaxRequestBodyBytes:          maxBody,
		// Echo's vhost map already 404s every Host it doesn't serve, which is
		// the rebinding defence; the SDK's own check would 403 dev's
		// mcp.localhost:8080.
		DisableLocalhostProtection: true,
	})
	h := &handler{
		base:      base,
		endpoints: eps,
		sdk:       echo.WrapHandler(sdk),
		owner:     d.Owner,
		keys:      &keyGuard{clients: map[string]*rate.Limiter{}},
		// Bounds only chatter that never reaches a tool: above every tool
		// class, so a call is always decided by its own budget.
		perIP: platform.NewLimiter(20, 100),
		log:   log,
	}
	h.describe(d.ToolURL)
	return h, nil
}

func withDefaults(d Deps) Deps {
	// A nil *iptools.Service is the databases failing to load: the lookups it
	// would serve can only fail, so they go.
	if s, ok := d.Geo.(*iptools.Service); ok && s == nil {
		d.Geo = nil
	}
	if d.IPLimits == nil {
		d.IPLimits = iptools.NewLimits()
	}
	if d.DNSLimits == nil {
		d.DNSLimits = dnstools.NewLimits()
	}
	if d.LinkLimits == nil {
		d.LinkLimits = linktools.NewLimits()
	}
	if d.CipherLimits == nil {
		d.CipherLimits = ciphertools.NewLimits()
	}
	if d.BotLimits == nil {
		d.BotLimits = botcheck.NewLimits()
	}
	return d
}

// serve is the gate in front of the SDK (docs/02-security-and-ops.md §2):
// requests the SDK never sees can't hurt it.
func (h *handler) serve(c *echo.Context) error {
	if resp, err := echo.UnwrapResponse(c.Response()); err == nil {
		// After the SDK's own no-cache: cipher results can be secrets.
		resp.Before(func() { resp.Header().Set("Cache-Control", "no-store") })
	}
	name := c.Param("toolset")
	ep := h.endpoints[name]
	if ep == nil {
		return refuseHTTP(c, http.StatusNotFound, "No MCP endpoint at this path. The endpoints are listed at "+h.base+"/")
	}
	req := c.Request()
	if req.Method == http.MethodGet && !platform.WantsJSON(c) {
		return h.landing(c)
	}

	ip := c.RealIP()
	key := platform.RateLimitKey(ip)
	if name == ownerEndpoint {
		if code, msg := h.checkKey(req.Header, key); code != 0 {
			return refuseHTTP(c, code, msg)
		}
		// The SDK copies every header into each handler's request; none needs this.
		req.Header.Del("X-Api-Key")
		req.Header.Del("Authorization")
	}
	if !platform.AllowKey(h.perIP, key) {
		return refuseHTTP(c, http.StatusTooManyRequests, limitedMessage)
	}

	if req.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
		switch {
		case err != nil:
			return refuseHTTP(c, http.StatusBadRequest, "Could not read the request body.")
		case len(body) > maxBody:
			return refuseHTTP(c, http.StatusRequestEntityTooLarge, "Request body over 1 MiB.")
		}
		// Without MCP-Protocol-Version the SDK assumes 2025-03-26, where a batch
		// is still legal, uncapped, and every reply in it buffered.
		if b := bytes.TrimLeft(body, " \t\r\n"); len(b) > 0 && b[0] == '[' {
			return refuseHTTP(c, http.StatusBadRequest, "JSON-RPC batching is not supported: send one message per request.")
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	switch req.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return refuseHTTP(c, http.StatusForbidden, "Cross-site browser requests are refused.")
	}
	if o := req.Header.Get("Origin"); o != "" && !strings.EqualFold(o, h.base) && !trustedOrigins[o] {
		h.log.Warn("mcp: foreign Origin", "origin", platform.Clip(o, 200),
			"user_agent", platform.Clip(req.UserAgent(), 200), "uri", ep.path)
	}

	who := &caller{ip: ip, key: key, host: req.Host, userAgent: req.UserAgent(), owner: name == ownerEndpoint, http: req.Context()}
	c.SetRequest(req.WithContext(context.WithValue(req.Context(), callerKey{}, who)))
	return h.sdk(c)
}

func refuseHTTP(c *echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
}

// checkKey admits the owner: the key arrives as X-Api-Key or Authorization:
// Bearer (how Codex sends one from an env var) and is checked by the owner
// Shortener. A client whose wrong keys used up its tries is refused before
// its key is compared, so guessing runs at one try a second.
func (h *handler) checkKey(hdr http.Header, client string) (int, string) {
	if h.keys.locked(client) {
		return http.StatusTooManyRequests, "Too many wrong keys from your address. Try again in a few seconds."
	}
	if h.owner.Authorized(ownerKey(hdr)) {
		return 0, ""
	}
	h.keys.fail(client)
	return http.StatusForbidden, "This endpoint needs the owner key, as X-Api-Key or Authorization: Bearer."
}

func ownerKey(h http.Header) string {
	if k := h.Get("X-Api-Key"); k != "" {
		return k
	}
	if scheme, token, ok := strings.Cut(h.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(token)
	}
	return ""
}

// keyGuard counts wrong owner keys per client: each spends a token of a bucket
// refilling one a second, burst five, and a client with none left is locked.
type keyGuard struct {
	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

const (
	keyTries    = 5
	keyClients  = 4096
	keyRefillHz = 1
)

func (g *keyGuard) locked(client string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.clients[client]
	return l != nil && l.Tokens() < 1
}

func (g *keyGuard) fail(client string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.clients[client]
	if l == nil {
		if len(g.clients) >= keyClients {
			g.prune()
		}
		l = rate.NewLimiter(keyRefillHz, keyTries)
		g.clients[client] = l
	}
	l.Allow()
}

// prune forgets clients whose bucket has refilled, and everyone if that frees
// nothing: a flood from that many addresses is past what per-client counts stop.
func (g *keyGuard) prune() {
	for k, l := range g.clients {
		if l.Tokens() >= keyTries {
			delete(g.clients, k)
		}
	}
	if len(g.clients) >= keyClients {
		clear(g.clients)
	}
}

type callerKey struct{}

// caller is what the gate knows of the HTTP request behind an MCP message. The
// SDK hands request context values on to handlers but not the remote address,
// and the limiter key alone won't do: for IPv6 it is a /64.
type caller struct {
	ip, key         string
	host, userAgent string
	owner           bool
	http            context.Context // ends when the client goes away
}

// callerFrom returns the gate's caller, or a zero one on a transport without
// the gate (the in-memory one tests use).
func callerFrom(ctx context.Context) *caller {
	if c, ok := ctx.Value(callerKey{}).(*caller); ok {
		return c
	}
	return &caller{}
}

// SitemapPages: this host's indexable URLs, for platform.RegisterSEO.
func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}}, nil
}

// catalog is the landing page as JSON: each public endpoint and its tools.
type catalog struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Endpoints []catalogEndpoint `json:"endpoints"`
}

type catalogEndpoint struct {
	Path  string        `json:"path"`
	URL   string        `json:"url"`
	Tools []catalogTool `json:"tools"`
}

type catalogTool struct {
	Name        string               `json:"name"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Annotations *mcp.ToolAnnotations `json:"annotations"`
}

// endpointView is one endpoint on the landing page; Site is the REST host its
// tools mirror.
type endpointView struct {
	Title, URL, Site string
	Tools            []toolView
}

type toolView struct {
	Name, Title, Description string
	ReadOnly, OpenWorld      bool
}

// describe builds the landing page and its JSON from the servers themselves,
// so neither can list a tool that isn't served. The owner's endpoint is not
// advertised.
func (h *handler) describe(toolURL func(string) string) {
	h.catalog = catalog{Name: "corpberry", Version: version()}
	add := func(ep *endpoint, title, rest string) {
		tools := make([]catalogTool, len(ep.specs))
		views := make([]toolView, len(ep.specs))
		for i, s := range ep.specs {
			t, a := s.tool, s.tool.Annotations
			tools[i] = catalogTool{Name: t.Name, Title: t.Title, Description: t.Description, Annotations: a}
			views[i] = toolView{Name: t.Name, Title: t.Title, Description: t.Description,
				ReadOnly: a.ReadOnlyHint, OpenWorld: a.OpenWorldHint == nil || *a.OpenWorldHint}
		}
		url := h.base + ep.path
		h.catalog.Endpoints = append(h.catalog.Endpoints, catalogEndpoint{Path: ep.path, URL: url, Tools: tools})
		h.pages = append(h.pages, endpointView{Title: title, URL: url, Site: rest, Tools: views})
	}
	add(h.endpoints[""], "All tools", "")
	for _, ts := range toolsets {
		ep := h.endpoints[ts.name]
		if ep == nil {
			continue
		}
		rest := ""
		if toolURL != nil {
			rest = toolURL(ts.host)
		}
		add(ep, ts.title, rest)
		h.credits = append(h.credits, ts.credits...)
	}
}

func (h *handler) landing(c *echo.Context) error {
	vm := map[string]any{
		"Title":      "MCP server — corpberry.com",
		"Desc":       landingDesc,
		"All":        h.pages[0],
		"Toolsets":   h.pages[1:],
		"ClaudeCode": "claude mcp add --scope user --transport http corpberry " + h.base + "/mcp",
	}
	for _, id := range h.credits {
		vm[creditFlags[id]] = true
	}
	return platform.Reply(c, http.StatusOK, h.catalog, vm, "mcp/index", "mcp/index")
}
