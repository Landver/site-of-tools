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

	"github.com/labstack/echo/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

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
	Geo          iptools.Looker // with Shodan
	DNSGeo       iptools.Looker // the same without Shodan
	Blocklist    iptools.Checker
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
	m := &calls{reqlog: d.RequestLog, log: log}
	public := slices.Concat(ipSpecs(d), dnsSpecs(d), linkSpecs(d, log), cipherSpecs(d), botSpecs(d), siteSpecs(d))
	eps, err := buildEndpoints(public, ownerSpecs(d, log), m, base)
	if err != nil {
		return nil, err
	}
	sdk := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if ep := eps[r.PathValue("toolset")]; ep != nil {
			return ep.server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		JSONResponse:        true,
		MaxRequestBodyBytes: maxBody,
		// Echo's vhost map 404s foreign Hosts; the SDK's check would 403 mcp.localhost:8080.
		DisableLocalhostProtection: true,
	})
	h := &handler{
		base:      base,
		endpoints: eps,
		sdk:       echo.WrapHandler(sdk),
		owner:     d.Owner,
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
	switch req.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return refuseHTTP(c, http.StatusForbidden, "Cross-site browser requests are refused.")
	}

	ip := c.RealIP()
	if !platform.AllowKey(h.perIP, ip) {
		return refuseHTTP(c, http.StatusTooManyRequests, platform.LimitedMessage)
	}
	if name == ownerEndpoint {
		if !h.owner.Authorized(ownerKey(req.Header)) {
			return refuseHTTP(c, http.StatusForbidden, "This endpoint needs the owner key, as X-Api-Key or Authorization: Bearer.")
		}
		// The SDK copies every header into each handler's request; none needs these.
		req.Header.Del("X-Api-Key")
		req.Header.Del("Authorization")
	}

	if req.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(req.Body, maxBody+1)) // past maxBody the SDK's MaxRequestBodyBytes answers 413
		// Without MCP-Protocol-Version the SDK speaks 2025-03-26, where an uncapped batch is legal.
		if b := bytes.TrimLeft(body, " \t\r\n"); len(b) > 0 && b[0] == '[' {
			return refuseHTTP(c, http.StatusBadRequest, "JSON-RPC batching is not supported: send one message per request.")
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	if o := req.Header.Get("Origin"); o != "" && !strings.EqualFold(o, h.base) {
		h.log.Warn("mcp: foreign Origin", "origin", platform.Clip(o, 200),
			"user_agent", platform.Clip(req.UserAgent(), 200), "uri", ep.path)
	}

	who := &caller{ip: ip, host: req.Host, userAgent: req.UserAgent(), http: req.Context()}
	c.SetRequest(req.WithContext(context.WithValue(req.Context(), callerKey{}, who)))
	return h.sdk(c)
}

func refuseHTTP(c *echo.Context, code int, msg string) error {
	return c.JSON(code, map[string]string{"error": msg})
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

type callerKey struct{}

// The SDK hands a tool only the request's context, so serve puts the caller there, always.
type caller struct {
	ip              string
	host, userAgent string
	http            context.Context // ends when the client goes away
}

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
	Path  string        `json:"path"`
	URL   string        `json:"url"`
	Title string        `json:"title"`
	REST  string        `json:"rest,omitempty"`
	Tools []catalogTool `json:"tools"`
}

type catalogTool struct {
	Name        string               `json:"name"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Annotations *mcp.ToolAnnotations `json:"annotations"`
}

func (t catalogTool) OpenWorld() bool { return *t.Annotations.OpenWorldHint }

func (h *handler) describe(toolURL func(string) string) {
	h.catalog = catalog{Name: "corpberry", Version: version}
	add := func(ep *endpoint, title, rest string) {
		tools := make([]catalogTool, len(ep.specs))
		for i, s := range ep.specs {
			tools[i] = catalogTool{Name: s.tool.Name, Title: s.tool.Title, Description: s.tool.Description, Annotations: s.tool.Annotations}
		}
		h.catalog.Endpoints = append(h.catalog.Endpoints, catalogEndpoint{Path: ep.path, URL: h.base + ep.path,
			Title: title, REST: rest, Tools: tools})
	}
	add(h.endpoints[""], "All tools", "")
	for _, ts := range toolsets {
		if ep := h.endpoints[ts.name]; ep != nil {
			add(ep, ts.title, toolURL(ts.host))
		}
	}
}

// setup names each server after its toolset, so a second can sit beside it.
func setup(all, toolset string) map[string]string {
	name := "corpberry-" + path.Base(toolset)
	config := func(servers, server string) string {
		return fmt.Sprintf(`{
  "%s": {
    "%s": { %s }
  }
}`, servers, name, server)
	}
	url := `"url": "` + toolset + `"`
	return map[string]string{
		"ClaudeCode": "claude mcp add --scope user --transport http corpberry " + all,
		"VSCode":     config("servers", `"type": "http", `+url),
		"Cursor":     config("mcpServers", url),
		"Codex":      "codex mcp add " + name + " --url " + toolset,
		"Gemini":     "gemini mcp add --transport http " + name + " " + toolset,
	}
}

func (h *handler) landing(c *echo.Context) error {
	eps := h.catalog.Endpoints
	example := eps[1]
	vm := map[string]any{
		"Title":     "MCP server — corpberry.com",
		"Desc":      landingDesc,
		"Endpoints": eps,
		"Toolsets":  eps[1:],
		"Example":   example,
		"Setup":     setup(eps[0].URL, example.URL),
	}
	return platform.Reply(c, http.StatusOK, h.catalog, vm, "mcp/index", "mcp/index")
}
