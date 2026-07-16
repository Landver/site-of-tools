// Command site-of-tools is the single binary that powers corpberry.com and every
// simple tool. It builds one *echo.Echo per subdomain from a shared factory and
// dispatches by Host header. See docs/ARCHITECTURE.md.
package main

import (
	"context"
	"html/template"
	"log"
	"maps"
	"slices"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/botcheck"
	"github.com/Landver/site-of-tools/iptools"
	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
)

func main() {
	cfg := platform.Load()

	// Template funcs available to every template: the shared header uses these for
	// the logo link (always the apex) and the Tools dropdown. Tools come from one
	// catalog (site.Tools), so the nav and the apex index render the same list.
	staticFS := platform.SubFS(shared.Static, "static", "shared/static", cfg.IsDev())

	// In prod, version static URLs by content hash ({{asset "js/botcheck.js"}} ->
	// /static/js/botcheck.js?v=<hash>) so a deploy busts the CDN/browser cache for
	// exactly the changed files. In dev, static is served no-store, so keep URLs
	// clean — platform.StaticURL is the shared prefix logic both paths use.
	asset := platform.StaticURL
	if !cfg.IsDev() {
		asset = platform.AssetVersioner(staticFS)
	}

	navFuncs := template.FuncMap{
		"apexURL":  func() string { return cfg.URL("") },
		"navTools": func() []platform.Tool { return site.Tools(cfg) },
		"asset":    asset,
	}

	// One template set assembled from shared partials + each project's templates.
	renderer := platform.NewRenderer(cfg.IsDev(), navFuncs,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "iptools/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "botcheck/templates"},
	)

	// apex: corpberry.com
	apex := platform.NewApp(renderer, staticFS, cfg.IsDev())
	site.Register(apex, cfg)

	// ip.corpberry.com — missing databases are non-fatal; the tool reports it.
	geo, err := iptools.OpenService(cfg.DB11V4, cfg.DB11V6, cfg.ASNV4, cfg.ASNV6, cfg.PX12)
	if err != nil {
		log.Printf("ip tools: databases not loaded (%v); the tool will show a friendly message", err)
	}
	ipApp := platform.NewApp(renderer, staticFS, cfg.IsDev())
	iptools.Register(ipApp, geo)

	// botcheck.corpberry.com — reuses the same IP service for its server-side
	// reputation signals (nil geo degrades gracefully, exactly like the IP tool).
	botApp := platform.NewApp(renderer, staticFS, cfg.IsDev())
	botcheck.Register(botApp, geo)

	hosts := map[string]*echo.Echo{
		cfg.VHost(""):         apex,
		cfg.VHost("ip"):       ipApp,
		cfg.VHost("botcheck"): botApp,
	}
	log.Printf("listening on %s (env=%s); hosts: %v", cfg.ListenAddr, cfg.Env, slices.Collect(maps.Keys(hosts)))

	handler := echo.NewVirtualHostHandler(hosts)
	sc := echo.StartConfig{Address: cfg.ListenAddr}
	if err := sc.Start(context.Background(), handler); err != nil {
		log.Fatal(err)
	}
}
