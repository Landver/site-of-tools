// Package tests: black-box tests for mcptools, driving the real stack: the
// vhost handler main.go builds, the gate, the SDK, and the SDK's own client.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

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
	mcpHost    = "mcp.test"
	ipHost     = "ip.test"
	dnsHost    = "dns.test"
	linkHost   = "link.test"
	cipherHost = "cipher.test"
	botHost    = "botcheck.test"
	apexHost   = "corpberry.test"
	base       = "http://" + mcpHost
	linkBase   = "http://" + linkHost
	apexURL    = "https://" + apexHost
	ownerKey   = "owner-test-key"
	clientIP   = "203.0.113.9"
)

// fakeGeo answers every valid address with a copy of res, refuses the rest the
// way iptools.Service does, and remembers what it was asked.
type fakeGeo struct {
	res   iptools.Result
	err   error
	panic bool

	mu    sync.Mutex
	asked []string
}

func (f *fakeGeo) Lookup(ip string) (*iptools.Result, error) {
	f.mu.Lock()
	f.asked = append(f.asked, ip)
	f.mu.Unlock()
	if f.panic {
		panic("fake lookup exploded")
	}
	if f.err != nil {
		return nil, f.err
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", ip)
	}
	r := f.res
	r.IP = ip
	return &r, nil
}

func (f *fakeGeo) lastAsked() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.asked) == 0 {
		return ""
	}
	return f.asked[len(f.asked)-1]
}

type fakeChecker struct{ lk iptools.BlockLookup }

func (f fakeChecker) Check(context.Context, string) (iptools.BlockLookup, error) { return f.lk, nil }

var richResult = iptools.Result{
	CountryCode: "US", Country: "United States", Region: "California", City: "Mountain View",
	Zip: "94043", Timezone: "-07:00", Latitude: 37.386, Longitude: -122.0838,
	ASN: "15169", ASName: "Google LLC",
	Proxy:  &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "Acme VPN"},
	Shodan: &iptools.ShodanInfo{Found: true, Ports: []int{53, 443}, Hostnames: []string{"dns.google"}},
}

// offlineOwner is an owner Shortener with a key whose store is unreachable:
// the gate only ever asks it whether a key is right.
var offlineStore = sync.OnceValue(func() *linktools.LinkStore {
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/").
		SetServerSelectionTimeout(200 * time.Millisecond).
		SetConnectTimeout(200 * time.Millisecond))
	if err != nil {
		return nil
	}
	return linktools.NewLinkStore(context.Background(), client.Database("site-of-tools-offline"))
})

func offlineOwner(t *testing.T) *linktools.Shortener {
	t.Helper()
	s := linktools.NewShortener(offlineStore(), ownerKey, linkBase)
	if !s.HasKey() {
		t.Fatal("could not build an owner Shortener with a key")
	}
	return s
}

type stackOpts struct {
	geo   iptools.Looker
	chk   iptools.Checker
	owner *linktools.Shortener
	ipLim *iptools.Limits
	log   io.Writer

	// bare leaves out every dns, link and blog dependency not set here, as a
	// boot with them off does.
	bare      bool
	dns       dnstools.Looker
	dom       *dnstools.DomainClient
	link      *linktools.Service
	tracer    *linktools.Tracer
	short     *linktools.Shortener
	posts     fs.FS
	dnsLim    *dnstools.Limits
	linkLim   *linktools.Limits
	cipherLim *ciphertools.Limits
	botLim    *botcheck.Limits
}

// stack is the vhost handler as main.go builds it: the REST apps and the mcp
// app, each pair sharing one Limits.
type stack struct {
	handler http.Handler
	srv     *httptest.Server
}

func newStack(t *testing.T, o stackOpts) *stack {
	t.Helper()
	if o.geo == nil {
		o.geo = &fakeGeo{res: richResult}
	}
	if o.ipLim == nil {
		o.ipLim = iptools.NewLimits()
	}
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
		if o.tracer == nil {
			o.tracer = guardedTracer()
		}
		if o.short == nil {
			o.short = linktools.NewShortener(offlineStore(), "", linkBase)
		}
		if o.posts == nil {
			o.posts = testPosts
		}
	}
	if o.dnsLim == nil {
		o.dnsLim = roomyDNS()
	}
	if o.linkLim == nil {
		o.linkLim = roomyLink()
	}
	if o.cipherLim == nil {
		o.cipherLim = roomyCipher()
	}
	if o.botLim == nil {
		o.botLim = roomyBot()
	}
	renderer := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
		platform.TemplateSource{Embed: mcptools.Templates, DevDir: "tools/mcptools/templates"},
	)
	app := func() *echo.Echo { return platform.NewApp(renderer, fstest.MapFS{}, false, nil) }
	hosts := map[string]*echo.Echo{ipHost: app()}
	iptools.Register(hosts[ipHost], o.geo, nil, o.chk, o.ipLim)
	if o.dns != nil {
		hosts[dnsHost] = app()
		dnstools.Register(hosts[dnsHost], o.dns, dnsGeo, o.dom, fakeBlock{}, o.dnsLim)
	}
	if o.link != nil {
		hosts[linkHost] = app()
		linktools.Register(hosts[linkHost], o.link, o.tracer, o.short, linkBase, o.linkLim)
	}
	hosts[cipherHost] = app()
	ciphertools.Register(hosts[cipherHost], "http://"+cipherHost, fstest.MapFS{}, o.cipherLim)
	hosts[botHost] = app()
	botcheck.Register(hosts[botHost], o.geo, nil, o.chk, o.botLim)
	var blog *site.Blog
	if o.posts != nil {
		hosts[apexHost] = app()
		var err error
		if blog, err = site.Register(hosts[apexHost], platform.Config{Env: "prod", BaseDomain: apexHost}, o.posts); err != nil {
			t.Fatal(err)
		}
	}
	mcpApp := app()
	if o.log != nil {
		mcpApp.Logger = slog.New(slog.NewJSONHandler(o.log, nil))
	}
	err := mcptools.Register(mcpApp, mcptools.Deps{
		Geo: o.geo, Blocklist: o.chk, IPLimits: o.ipLim,
		DNS: o.dns, DNSGeo: dnsGeo, DNSBlocklist: fakeBlock{}, Domain: o.dom, DNSLimits: o.dnsLim,
		Link: o.link, Tracer: o.tracer, Short: o.short, Owner: o.owner, LinkLimits: o.linkLim,
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
	hosts[mcpHost] = mcpApp
	h := echo.NewVirtualHostHandler(hosts)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &stack{handler: h, srv: srv}
}

// rest is a REST route's JSON body, as a client sending Accept:
// application/json gets it; a form body is sent as one.
func (s *stack) rest(t *testing.T, host, method, target, form string) map[string]any {
	t.Helper()
	hdr := map[string]string{"Host": host, "Accept": "application/json"}
	if form != "" {
		hdr["Content-Type"] = "application/x-www-form-urlencoded"
	}
	rec := s.do(method, target, form, hdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("REST %s %s%s = %d %s", method, host, target, rec.Code, rec.Body)
	}
	return decode(t, rec.Body.Bytes())
}

// do sends one request in-process; Host defaults to the mcp host.
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

// mcpHeaders are what a 2025-era client sends with a POST.
func mcpHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json, text/event-stream",
		"CF-Connecting-IP": clientIP,
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func rpc(id int, method string, params any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return string(b)
}

// hostTransport delivers requests to the test server the way nginx does: with
// the public Host, and the client's address in CF-Connecting-IP.
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

// client connects the SDK's own client to path; opts nil is the newest
// protocol, 2026-07-28.
func (s *stack) client(t *testing.T, path string, hdr map[string]string, opts *mcp.ClientSessionOptions) *mcp.ClientSession {
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
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "mcptools-tests", Version: "1"}, nil).Connect(ctx, tr, opts)
	if err != nil {
		t.Fatalf("connect %s: %v", path, err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
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

// text is a result's only text block.
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

// object checks a successful result: structuredContent is a JSON object and
// the text block holds the same JSON. It returns that object, numbers kept
// exact.
func object(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(t, res))
	}
	if _, ok := res.StructuredContent.(map[string]any); !ok {
		t.Fatalf("structuredContent is %T, want a JSON object", res.StructuredContent)
	}
	got := decode(t, []byte(text(t, res)))
	sc, _ := json.Marshal(res.StructuredContent)
	if !jsonEqual(t, sc, []byte(text(t, res))) {
		t.Errorf("text block differs from structuredContent:\n%s\n%s", text(t, res), sc)
	}
	return got
}

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

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
