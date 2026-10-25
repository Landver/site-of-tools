package tests

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/ciphertools"
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
	"github.com/Landver/site-of-tools/tools/mailtools"
	"github.com/Landver/site-of-tools/tools/mcptools"
)

// TestEveryRouteAndTemplateInAllApps verifies that EVERY route across EVERY subdomain
// renders successfully without 500 Internal Server Error, template syntax errors, or panics.
func TestEveryRouteAndTemplateInAllApps(t *testing.T) {
	cfg := platform.Config{
		Env:        "prod",
		BaseDomain: "corpberry.com",
		ListenAddr: ":8080",
	}

	navFuncs := template.FuncMap{
		"apexURL":    func() string { return cfg.URL("") },
		"navTools":   func() []platform.Tool { return site.Tools(cfg) },
		"navCatalog": func() []platform.ToolSection { return platform.Catalog(cfg) },
		"toolURL":    cfg.URL,
		"asset":      platform.StaticURL,
	}

	renderer := platform.NewRenderer(false, navFuncs,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
		platform.TemplateSource{Embed: ciphertools.Templates, DevDir: "tools/ciphertools/templates"},
		platform.TemplateSource{Embed: mailtools.Templates, DevDir: "tools/mailtools/templates"},
		platform.TemplateSource{Embed: mcptools.Templates, DevDir: "tools/mcptools/templates"},
	)

	apps := map[string]*echo.Echo{}
	for _, sub := range []string{"", "ip", "botcheck", "dns", "link", "cipher", "mail", "mcp"} {
		apps[sub] = platform.NewApp(renderer, fstest.MapFS{}, false, nil)
	}

	// 1. Apex
	blog, err := site.Register(apps[""], cfg, testPostsFS())
	if err != nil {
		t.Fatalf("site.Register: %v", err)
	}

	// 2. IP Tools
	geo, _ := iptools.OpenService("", "", "", "", "")
	dnsGeo := geo.Offline()
	ipLim := iptools.NewLimits()
	iptools.Register(apps["ip"], geo, nil, nil, ipLim)

	// 3. Botcheck
	botLim := botcheck.NewLimits()
	botcheck.Register(apps["botcheck"], geo, nil, nil, botLim)

	// 4. DNS Tools
	dnsLim := dnstools.NewLimits()
	dnsSvc := dnstools.NewService(time.Second)
	domainClient := dnstools.NewDomainClient("", "", time.Second)
	dnstools.Register(apps["dns"], dnsSvc, dnsGeo, domainClient, nil, dnsLim)

	// 5. Link Tools
	linkLim := linktools.NewLimits()
	linkSvc := linktools.NewService()
	shortener := linktools.NewShortener(nil, "", cfg.URL("link"))
	tracer := linktools.NewTracer(nil, time.Second)
	linktools.Register(apps["link"], linkSvc, tracer, shortener, cfg.URL("link"), linkLim)

	// 6. Cipher Tools
	cipherLim := ciphertools.NewLimits()
	ciphertools.Register(apps["cipher"], cfg.URL("cipher"), fstest.MapFS{}, cipherLim)

	// 7. Mail Tools
	mailLim := mailtools.NewLimits()
	mailtools.Register(apps["mail"], cfg.URL("mail"), nil, nil, "", mailLim)

	// 8. MCP Tools
	mcptools.Register(apps["mcp"], mcptools.Deps{
		Geo: geo, DNSGeo: dnsGeo, Blog: blog,
		DNS: dnsSvc, Domain: domainClient,
		Link: linkSvc, Tracer: tracer, Short: shortener,
		IPLimits: ipLim, DNSLimits: dnsLim, LinkLimits: linkLim, CipherLimits: cipherLim, BotLimits: botLim, MailLimits: mailLim,
		ToolURL: cfg.URL,
	}, cfg.URL("mcp"))

	// SEO routes
	platform.RegisterSEO(apps["ip"], cfg.URL("ip"), iptools.SitemapPages)
	platform.RegisterSEO(apps["botcheck"], cfg.URL("botcheck"), botcheck.SitemapPages)
	platform.RegisterSEO(apps["dns"], cfg.URL("dns"), dnstools.SitemapPages)
	platform.RegisterSEO(apps["link"], cfg.URL("link"), linktools.SitemapPages)
	platform.RegisterSEO(apps["cipher"], cfg.URL("cipher"), ciphertools.SitemapPages)
	platform.RegisterSEO(apps["mail"], cfg.URL("mail"), mailtools.SitemapPages)
	platform.RegisterSEO(apps["mcp"], cfg.URL("mcp"), mcptools.SitemapPages)

	// Explicit list of all primary routes to audit
	routesToAudit := []struct {
		Subdomain string
		Path      string
	}{
		// Apex
		{"", "/"},
		{"", "/blog"},
		{"", "/sitemap.xml"},
		{"", "/robots.txt"},

		// IP
		{"ip", "/"},
		{"ip", "/blocklist"},
		{"ip", "/myip"},
		{"ip", "/asn"},
		{"ip", "/history"},
		{"ip", "/sitemap.xml"},
		{"ip", "/robots.txt"},

		// Botcheck
		{"botcheck", "/"},
		{"botcheck", "/blocklist"},
		{"botcheck", "/useragent"},
		{"botcheck", "/corpus"},
		{"botcheck", "/report"},
		{"botcheck", "/sitemap.xml"},
		{"botcheck", "/robots.txt"},

		// DNS
		{"dns", "/"},
		{"dns", "/propagation"},
		{"dns", "/trace"},
		{"dns", "/whois"},
		{"dns", "/sec"},
		{"dns", "/ecs"},
		{"dns", "/subdomains"},
		{"dns", "/reputation"},
		{"dns", "/credits"},
		{"dns", "/sitemap.xml"},
		{"dns", "/robots.txt"},

		// Link
		{"link", "/"},
		{"link", "/clean"},
		{"link", "/trace"},
		{"link", "/headers"},
		{"link", "/diff"},
		{"link", "/curl"},
		{"link", "/extract"},
		{"link", "/utm"},
		{"link", "/encode"},
		{"link", "/short"},
		{"link", "/sitemap.xml"},
		{"link", "/robots.txt"},

		// Cipher
		{"cipher", "/"},
		{"cipher", "/hash"},
		{"cipher", "/symmetric"},
		{"cipher", "/asymmetric"},
		{"cipher", "/encoding"},
		{"cipher", "/cert"},
		{"cipher", "/jwt"},
		{"cipher", "/dpop"},
		{"cipher", "/pkce"},
		{"cipher", "/sitemap.xml"},
		{"cipher", "/robots.txt"},

		// Mail
		{"mail", "/"},
		{"mail", "/health"},
		{"mail", "/disposable"},
		{"mail", "/classifier"},
		{"mail", "/blacklist"},
		{"mail", "/dmarc"},
		{"mail", "/bimi"},
		{"mail", "/arc"},
		{"mail", "/sitemap.xml"},
		{"mail", "/robots.txt"},

		// MCP
		{"mcp", "/"},
		{"mcp", "/sitemap.xml"},
		{"mcp", "/robots.txt"},
	}

	// Also audit EVERY tool path from catalog
	for _, section := range platform.Catalog(cfg) {
		for _, tool := range section.Tools {
			routesToAudit = append(routesToAudit, struct {
				Subdomain string
				Path      string
			}{
				Subdomain: tool.Subdomain,
				Path:      tool.Path,
			})
		}
	}

	for _, tc := range routesToAudit {
		app, ok := apps[tc.Subdomain]
		if !ok {
			t.Errorf("Unknown subdomain %q", tc.Subdomain)
			continue
		}

		// 1. Browser HTML request
		req := httptest.NewRequest(http.MethodGet, tc.Path, nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)

		if rec.Code == http.StatusInternalServerError {
			t.Errorf("CRITICAL 500 ERROR on [%s] %s: status=%d, body=%s", tc.Subdomain, tc.Path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "Internal Server Error") {
			t.Errorf("Internal Server Error in body on [%s] %s: body=%s", tc.Subdomain, tc.Path, rec.Body.String())
		}

		// 2. HTMX Fragment request (only for non-static/SEO)
		if !strings.HasSuffix(tc.Path, ".xml") && !strings.HasSuffix(tc.Path, ".txt") {
			reqHTMX := httptest.NewRequest(http.MethodGet, tc.Path, nil)
			reqHTMX.Header.Set("Accept", "text/html")
			reqHTMX.Header.Set("HX-Request", "true")
			recHTMX := httptest.NewRecorder()
			app.ServeHTTP(recHTMX, reqHTMX)

			if recHTMX.Code == http.StatusInternalServerError {
				t.Errorf("CRITICAL 500 ERROR on HTMX [%s] %s: status=%d, body=%s", tc.Subdomain, tc.Path, recHTMX.Code, recHTMX.Body.String())
			}
			if strings.Contains(recHTMX.Body.String(), "Internal Server Error") {
				t.Errorf("Internal Server Error in body on HTMX [%s] %s: body=%s", tc.Subdomain, tc.Path, recHTMX.Body.String())
			}
		}
	}
}
