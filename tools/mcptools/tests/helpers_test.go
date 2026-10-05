// Package tests drives the real stack: main.go's vhost handler, the gate, the SDK and its client.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
	"github.com/Landver/site-of-tools/tools/mcptools"
)

const (
	mcpHost     = "mcp.test"
	ipHost      = "ip.test"
	dnsHost     = "dns.test"
	linkHost    = "link.test"
	cipherHost  = "cipher.test"
	botHost     = "botcheck.test"
	apexHost    = "corpberry.test"
	base        = "http://" + mcpHost
	linkBase    = "http://" + linkHost
	apexURL     = "https://" + apexHost
	ownerKey    = "owner-test-key"
	clientIP    = "203.0.113.9"
	otherClient = "198.51.100.250"
)

type stackOpts struct {
	geo    iptools.Looker
	chk    iptools.Checker
	owner  *linktools.Shortener
	corpus *botcheck.Corpus
	log    io.Writer

	// bare leaves out every dns, link and blog dependency not set here.
	bare  bool
	dns   dnstools.Looker
	dom   *dnstools.DomainClient
	link  *linktools.Service
	short *linktools.Shortener

	ipLim     *iptools.Limits
	dnsLim    *dnstools.Limits
	linkLim   *linktools.Limits
	cipherLim *ciphertools.Limits
	botLim    *botcheck.Limits
}

// stack is the vhost handler as main.go builds it: each REST app and MCP share the Limits in stackOpts.
type stack struct {
	stackOpts
	hosts   map[string]*echo.Echo
	handler http.Handler
	srv     *httptest.Server
}

func newStack(t *testing.T, o stackOpts) *stack {
	t.Helper()
	if o.geo == nil {
		o.geo = &fakeGeo{res: richResult}
	}
	var tracer *linktools.Tracer
	var posts fs.FS
	if !o.bare {
		if o.dns == nil {
			o.dns = &fakeDNS{}
		}
		if o.dom == nil {
			o.dom = upstream{names: 3}.client(t)
		}
		if o.link == nil {
			o.link = linktools.NewService()
		}
		if o.short == nil {
			o.short = linktools.NewShortener(offlineStore(), "", linkBase)
		}
		tracer = linktools.NewTracer(platform.NewEgressGuard([]string{"80", "443"}, nil), 2*time.Second)
		posts = testPosts
	}
	// The real caps with roomy rates, so only a test passing its own Limits runs out.
	roomy := func() platform.Limiter { return platform.NewLimiter(100, 1000) }
	if o.ipLim == nil {
		o.ipLim = iptools.NewLimits()
		o.ipLim.Lookup, o.ipLim.CIDR = roomy(), roomy()
	}
	if o.dnsLim == nil {
		o.dnsLim = dnstools.NewLimits()
		o.dnsLim.Lookup, o.dnsLim.Walk = roomy(), roomy()
	}
	if o.linkLim == nil {
		o.linkLim = linktools.NewLimits()
		o.linkLim.Pure, o.linkLim.Fetch, o.linkLim.Short = roomy(), roomy(), roomy()
	}
	if o.cipherLim == nil {
		o.cipherLim = ciphertools.NewLimits()
		o.cipherLim.Pure, o.cipherLim.Heavy = roomy(), roomy()
	}
	if o.botLim == nil {
		o.botLim = botcheck.NewLimits()
		o.botLim.Check = roomy()
	}

	renderer := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
		platform.TemplateSource{Embed: mcptools.Templates, DevDir: "tools/mcptools/templates"},
	)
	app := func() *echo.Echo { return platform.NewApp(renderer, fstest.MapFS{}, false, nil) }
	hosts := map[string]*echo.Echo{ipHost: app(), cipherHost: app(), botHost: app()}
	iptools.Register(hosts[ipHost], o.geo, nil, o.chk, o.ipLim)
	ciphertools.Register(hosts[cipherHost], "http://"+cipherHost, fstest.MapFS{}, o.cipherLim)
	botcheck.Register(hosts[botHost], o.geo, o.corpus, o.chk, o.botLim)
	if o.dns != nil {
		hosts[dnsHost] = app()
		dnstools.Register(hosts[dnsHost], o.dns, o.geo, o.dom, fakeChecker{}, o.dnsLim)
	}
	if o.link != nil {
		hosts[linkHost] = app()
		linktools.Register(hosts[linkHost], o.link, tracer, o.short, linkBase, o.linkLim)
	}
	var blog *site.Blog
	if posts != nil {
		hosts[apexHost] = app()
		var err error
		if blog, err = site.Register(hosts[apexHost], platform.Config{Env: "prod", BaseDomain: apexHost}, posts); err != nil {
			t.Fatal(err)
		}
	}
	hosts[mcpHost] = app()
	if o.log != nil {
		hosts[mcpHost].Logger = slog.New(slog.NewJSONHandler(o.log, nil))
	}
	err := mcptools.Register(hosts[mcpHost], mcptools.Deps{
		Geo: o.geo, Blocklist: o.chk, IPLimits: o.ipLim,
		DNS: o.dns, DNSGeo: o.geo, DNSBlocklist: fakeChecker{}, Domain: o.dom, DNSLimits: o.dnsLim,
		Link: o.link, Tracer: tracer, Short: o.short, Owner: o.owner, LinkLimits: o.linkLim,
		CipherLimits: o.cipherLim, BotLimits: o.botLim, Blog: blog,
		ToolURL: func(sub string) string {
			if sub == "" {
				return apexURL
			}
			return "http://" + sub + ".test"
		},
	}, base)
	if err != nil {
		t.Fatal(err)
	}
	h := echo.NewVirtualHostHandler(hosts)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &stack{stackOpts: o, hosts: hosts, handler: h, srv: srv}
}

// do serves one request; hdr's Host, mcpHost if unset, picks the app.
func (s *stack) do(method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = mcpHost
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// rest asks host's JSON API: a POST when body is set, as JSON when it starts with {, else as a form.
func (s *stack) rest(host, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	h, method := map[string]string{"Host": host, "Accept": "application/json"}, http.MethodGet
	if body != "" {
		method, h["Content-Type"] = http.MethodPost, "application/x-www-form-urlencoded"
		if body[0] == '{' {
			h["Content-Type"] = "application/json"
		}
	}
	maps.Copy(h, hdr)
	return s.do(method, target, body, h)
}

func (s *stack) restOK(t *testing.T, host, target, body string) map[string]any {
	t.Helper()
	rec := s.rest(host, target, body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("REST %s%s = %d %s", host, target, rec.Code, rec.Body)
	}
	return decode(t, rec.Body.Bytes())
}

func mcpHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json, text/event-stream",
		"CF-Connecting-IP": clientIP,
	}
	maps.Copy(h, extra)
	return h
}

func rpc(id int, method string, params any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return string(b)
}

var listBody = rpc(1, "tools/list", map[string]any{})

// hostTransport sends the public Host and CF-Connecting-IP, as nginx does.
type hostTransport struct {
	host string
	hdr  map[string]string
}

func (h hostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = h.host
	for k, v := range h.hdr {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) client(t *testing.T, path string, hdr map[string]string) *mcp.ClientSession {
	t.Helper()
	if hdr == nil {
		hdr = map[string]string{"CF-Connecting-IP": clientIP}
	}
	tr := &mcp.StreamableClientTransport{
		Endpoint:   s.srv.URL + path,
		HTTPClient: &http.Client{Transport: hostTransport{host: mcpHost, hdr: hdr}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "mcptools-tests", Version: "1"}, nil).Connect(ctx, tr, nil)
	if err != nil {
		t.Fatalf("connect %s: %v", path, err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func listTools(t *testing.T, cs *mcp.ClientSession) *mcp.ListToolsResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	var names []string
	for _, tool := range listTools(t, cs).Tools {
		names = append(names, tool.Name)
	}
	return names
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("result has %d content blocks, want 1", len(res.Content))
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want text", res.Content[0])
	}
	return tc.Text
}

// object is a successful result's object, which its text block must repeat.
func object(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(t, res))
	}
	txt := text(t, res)
	if !cmp.Equal(asJSON(t, res.StructuredContent), asJSON(t, json.RawMessage(txt))) {
		t.Errorf("text block differs from structuredContent:\n%s\n%v", txt, res.StructuredContent)
	}
	return decode(t, []byte(txt))
}

func failsWith(t *testing.T, res *mcp.CallToolResult, want string) {
	t.Helper()
	if !res.IsError || res.StructuredContent != nil || !strings.Contains(text(t, res), want) {
		t.Errorf("result = isError %v %.300q, want an error saying %q", res.IsError, text(t, res), want)
	}
}

// decode keeps numbers exact, so they compare as num.
func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

// asJSON is v as encoding/json reads it back, so values of different Go types compare.
func asJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sources(obj map[string]any) []string {
	var out []string
	list, _ := obj["attribution"].([]any)
	for _, c := range list {
		out = append(out, c.(map[string]any)["source"].(string))
	}
	return out
}

// syncBuffer is a bytes.Buffer safe for the logger and the test at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
