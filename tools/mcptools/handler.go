// Package mcptools serves mcp.corpberry.com: the site's tools over MCP.
package mcptools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
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

// Deps are the REST routes' own values, Limits included; a nil one drops its tools.
type Deps struct {
	Geo          iptools.Looker  // with Shodan
	DNSGeo       iptools.Looker  // the same without Shodan
	Blocklist    iptools.Checker // from iptools.CheckerFrom
	DNSBlocklist dnstools.BlockChecker
	DNS          dnstools.Looker
	Domain       *dnstools.DomainClient
	Link         *linktools.Service
	Tracer       *linktools.Tracer
	Short        *linktools.Shortener
	Owner        *linktools.Shortener // without a key /mcp/owner is a 404
	Blog         *site.Blog

	IPLimits     *iptools.Limits
	DNSLimits    *dnstools.Limits
	LinkLimits   *linktools.Limits
	CipherLimits *ciphertools.Limits
	BotLimits    *botcheck.Limits

	RequestLog *platform.RequestLog
	ToolURL    func(sub string) string
}

const maxBody = 1 << 20

const landingDesc = "An MCP server for AI agents: corpberry.com's IP, DNS, Link and Cipher Tools, Bot check and blog, " +
	"with the same results as the web pages and their JSON API. Free, no account, no key."

type handler struct {
	base      string
	endpoints map[string]*endpoint
	sdk       echo.HandlerFunc
	owner     *linktools.Shortener
	keys      *keyGuard
	protocol  platform.Limiter
	perIP     platform.Limiter
	log       *slog.Logger
	catalog   catalog
}

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
	// A nil *iptools.Service is the databases failing to load: its lookups can only fail.
	if s, ok := d.Geo.(*iptools.Service); ok && s == nil {
		d.Geo = nil
	}
	base = strings.TrimRight(base, "/")
	m := &calls{protocol: platform.NewLimiter(5, 20), reqlog: d.RequestLog, log: log}
	cipher, err := cipherSpecs(d)
	if err != nil {
		return nil, err
	}
	public := slices.Concat(ipSpecs(d), dnsSpecs(d), linkSpecs(d, log), cipher, botSpecs(d), siteSpecs(d))
	eps, err := buildEndpoints(public, ownerSpecs(d, log), d.Owner.HasKey(), m, base)
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
		// Echo's vhost map 404s foreign Hosts; the SDK's check would 403 mcp.localhost:8080.
		DisableLocalhostProtection: true,
	})
	h := &handler{
		base:      base,
		endpoints: eps,
		sdk:       echo.WrapHandler(sdk),
		owner:     d.Owner,
		keys:      &keyGuard{clients: map[string]*rate.Limiter{}},
		protocol:  m.protocol,
		// Above every tool's budget, so a call is always decided by its own.
		perIP: platform.NewLimiter(20, 100),
		log:   log,
	}
	h.describe(d.ToolURL)
	return h, nil
}

func (h *handler) serve(c *echo.Context) error {
	if resp, err := echo.UnwrapResponse(c.Response()); err == nil {
		// After the SDK's own no-cache: cipher results can be secrets.
		resp.Before(func() { resp.Header().Set("Cache-Control", "no-store") })
	}
	name := c.Param("toolset")
	ep := h.endpoints[name]
	req := c.Request()
	page := req.Method == http.MethodGet && !platform.WantsJSON(c)
	// The landing page at /mcp/owner would tell any visitor the endpoint exists.
	if ep == nil || page && name == ownerEndpoint {
		return refuseHTTP(c, http.StatusNotFound, "No MCP endpoint at this path. The endpoints are listed at "+h.base+"/")
	}
	if page {
		return h.landing(c)
	}
	// Before the owner key, so a web page can't spend its visitor's key tries.
	switch req.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return refuseHTTP(c, http.StatusForbidden, "Cross-site browser requests are refused.")
	}

	ip := c.RealIP()
	key := platform.RateLimitKey(ip)
	if name == ownerEndpoint {
		if code, msg := h.checkKey(req.Header, key); code != 0 {
			return refuseHTTP(c, code, msg)
		}
		// The SDK copies every header into each handler's request; none needs these.
		req.Header.Del("X-Api-Key")
		req.Header.Del("Authorization")
	}
	if !platform.AllowKey(h.perIP, key) {
		return refuseHTTP(c, http.StatusTooManyRequests, platform.LimitedMessage)
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

	if o := req.Header.Get("Origin"); o != "" && !strings.EqualFold(o, h.base) {
		h.log.Warn("mcp: foreign Origin", "origin", platform.Clip(o, 200),
			"user_agent", platform.Clip(req.UserAgent(), 200), "uri", ep.path)
	}

	who := &caller{ip: ip, key: key, host: req.Host, userAgent: req.UserAgent(), http: req.Context()}
	c.SetRequest(req.WithContext(context.WithValue(req.Context(), callerKey{}, who)))
	return h.sdk(c)
}

func refuseHTTP(c *echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
}

// checkKey compares a key only for a client not locked out, so guessing runs at
// one try a second; sending no key guesses nothing and costs no try.
func (h *handler) checkKey(hdr http.Header, client string) (int, string) {
	const needKey = "This endpoint needs the owner key, as X-Api-Key or Authorization: Bearer."
	k := ownerKey(hdr)
	switch {
	case k == "":
		return http.StatusForbidden, needKey
	case h.keys.locked(client):
		return http.StatusTooManyRequests, "Too many wrong keys from your address. Try again in a few seconds."
	case h.owner.Authorized(k):
		return 0, ""
	}
	h.keys.fail(client)
	return http.StatusForbidden, needKey
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

// caller is the request behind a message: the SDK passes its context, not its address.
type caller struct {
	ip, key         string
	host, userAgent string
	http            context.Context // ends when the client goes away
}

// callerFrom is the caller serve put in ctx; nothing else reaches the SDK.
func callerFrom(ctx context.Context) *caller { return ctx.Value(callerKey{}).(*caller) }

func SitemapPages() ([]platform.Page, error) {
	return []platform.Page{{Path: "/"}}, nil
}

type catalog struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Endpoints []catalogEndpoint `json:"endpoints"`
}

type catalogEndpoint struct {
	Path        string            `json:"path"`
	URL         string            `json:"url"`
	Title       string            `json:"title"`
	REST        string            `json:"rest,omitempty"`
	Attribution []platform.Credit `json:"attribution,omitempty"`
	Tools       []catalogTool     `json:"tools"`
}

type catalogTool struct {
	Name        string               `json:"name"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Annotations *mcp.ToolAnnotations `json:"annotations"`
	RateLimit   rateLimit            `json:"rate_limit"`
}

// OpenWorld is the hint as the spec reads it: unset means open.
func (t catalogTool) OpenWorld() bool {
	h := t.Annotations.OpenWorldHint
	return h == nil || *h
}

type rateLimit struct {
	PerSecond float64 `json:"per_second"`
	Burst     int     `json:"burst"`
}

func rateOf(l platform.Limiter) rateLimit {
	r, b := l.Rate()
	return rateLimit{r, b}
}

func (r rateLimit) String() string {
	if r.PerSecond > 0 && r.PerSecond < 1 {
		return fmt.Sprintf("1 per %g s, burst %d", 1/r.PerSecond, r.Burst)
	}
	return fmt.Sprintf("%g/s, burst %d", r.PerSecond, r.Burst)
}

// describe reads the catalog off the servers, so it can't list a tool they don't serve.
func (h *handler) describe(toolURL func(string) string) {
	h.catalog = catalog{Name: "corpberry", Version: version()}
	add := func(ep *endpoint, title, rest string, cr []platform.Credit) {
		tools := make([]catalogTool, len(ep.specs))
		for i, s := range ep.specs {
			tools[i] = catalogTool{Name: s.tool.Name, Title: s.tool.Title, Description: s.tool.Description,
				Annotations: s.tool.Annotations, RateLimit: rateOf(s.limiter)}
		}
		h.catalog.Endpoints = append(h.catalog.Endpoints, catalogEndpoint{Path: ep.path, URL: h.base + ep.path,
			Title: title, REST: rest, Attribution: cr, Tools: tools})
	}
	add(h.endpoints[""], "All tools", "", nil)
	for _, ts := range toolsets {
		if ep := h.endpoints[ts.name]; ep != nil {
			add(ep, ts.title, toolURL(ts.host), credits(ts.credits...))
		}
	}
}

// setup names each server after its toolset, so a second can sit beside it.
func setup(all, toolset string) map[string]string {
	name := "corpberry-" + path.Base(toolset)
	return map[string]string{
		"ClaudeCode": "claude mcp add --scope user --transport http corpberry " + all,
		"VSCode": fmt.Sprintf(`{
  "servers": {
    "%s": { "type": "http", "url": "%s" }
  }
}`, name, toolset),
		"Cursor": fmt.Sprintf(`{
  "mcpServers": {
    "%s": { "url": "%s" }
  }
}`, name, toolset),
		"Codex": "codex mcp add " + name + " --url " + toolset,
		"CodexTOML": fmt.Sprintf(`[mcp_servers.%s]
url = "%s"`, name, toolset),
		"Gemini": "gemini mcp add --transport http " + name + " " + toolset,
		"GeminiJSON": fmt.Sprintf(`{
  "mcpServers": {
    "%s": { "httpUrl": "%s" }
  }
}`, name, toolset),
		"Remote": "npx mcp-remote " + toolset,
	}
}

func (h *handler) landing(c *echo.Context) error {
	eps := h.catalog.Endpoints
	all, example := eps[0], eps[min(1, len(eps)-1)]
	vm := map[string]any{
		"Title":    "MCP server — corpberry.com",
		"Desc":     landingDesc,
		"All":      all,
		"Toolsets": eps[1:],
		"Example":  example,
		"Setup":    setup(all.URL, example.URL),
		"Protocol": rateOf(h.protocol),
		"PerIP":    rateOf(h.perIP),
	}
	for _, ep := range eps {
		for _, cr := range ep.Attribution {
			vm[cr.Flag] = true
		}
	}
	return platform.Reply(c, http.StatusOK, h.catalog, vm, "mcp/index", "mcp/index")
}
