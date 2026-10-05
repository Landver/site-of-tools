package tests

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/site"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
	"github.com/Landver/site-of-tools/tools/mcptools"
)

// restRoutes is every subdomain's routes, Registered offline, minus shared infrastructure.
func restRoutes(t *testing.T) map[mcptools.Route]bool {
	t.Helper()
	cfg := platform.Config{Env: "prod", BaseDomain: "corpberry.com"}
	app := func() *echo.Echo { return platform.NewApp(nil, fstest.MapFS{}, false, nil) }
	apps := map[string]*echo.Echo{}

	apps[""] = app()
	if _, err := site.Register(apps[""], cfg, platform.SubFS(site.Posts, "posts", "site/posts", false)); err != nil {
		t.Fatal(err)
	}
	apps["ip"] = app()
	iptools.Register(apps["ip"], nil, nil, nil, nil)
	apps["botcheck"] = app()
	botcheck.Register(apps["botcheck"], nil, nil, nil, nil)
	apps["dns"] = app()
	dnstools.Register(apps["dns"], dnstools.NewService(time.Second), nil, nil, nil, nil)
	apps["link"] = app()
	linktools.Register(apps["link"], linktools.NewService(), nil, nil, cfg.URL("link"), nil)
	apps["cipher"] = app()
	ciphertools.Register(apps["cipher"], cfg.URL("cipher"), fstest.MapFS{}, nil)

	routes := map[mcptools.Route]bool{}
	for host, e := range apps {
		platform.RegisterSEO(e, cfg.URL(host), func() ([]platform.Page, error) { return nil, nil })
		for _, r := range e.Router().Routes() {
			if strings.HasPrefix(r.Path, "/static") || r.Path == "/sitemap.xml" || r.Path == "/robots.txt" {
				continue
			}
			routes[mcptools.Route{Host: host, Method: r.Method, Path: r.Path}] = true
		}
	}
	return routes
}

// TestEveryRouteHasAnMCPDecision: a REST route added without a Coverage entry,
// or an entry left behind by a removed route, fails here.
func TestEveryRouteHasAnMCPDecision(t *testing.T) {
	routes := restRoutes(t)
	coverage := mcptools.Coverage()
	for r := range routes {
		if _, ok := coverage[r]; !ok {
			t.Errorf("%q %s %s has no MCP decision in mcptools.Coverage", r.Host, r.Method, r.Path)
		}
	}

	s := newStack(t, stackOpts{owner: offlineOwner(t)})
	listed := map[string]bool{}
	for _, path := range []string{"/mcp", "/mcp/owner"} {
		hdr := map[string]string{"CF-Connecting-IP": clientIP, "X-Api-Key": ownerKey}
		for _, tool := range listTools(t, s.client(t, path, hdr, nil)).Tools {
			listed[tool.Name] = true
		}
	}
	mapped := 0
	covered := map[string]bool{}
	for r, d := range coverage {
		if !routes[r] {
			t.Errorf("Coverage has %q %s %s, which no Register serves", r.Host, r.Method, r.Path)
		}
		if (len(d.Tools) > 0) == (d.Reason != "") {
			t.Errorf("%s %s: an entry names its tools or its reason, not both", r.Method, r.Path)
		}
		if len(d.Tools) > 0 {
			mapped++
		}
		for _, name := range d.Tools {
			covered[name] = true
			if !listed[name] {
				t.Errorf("%s %s: %s is not served", r.Method, r.Path, name)
			}
		}
	}
	for name := range listed {
		if !covered[name] {
			t.Errorf("%s is served but no REST route maps to it", name)
		}
	}
	if mapped != 41 {
		t.Errorf("%d routes map to tools, want 41 (README §1 plus POST /curl)", mapped)
	}
}
