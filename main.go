// Command site-of-tools is the single binary that powers corpberry.com and every
// simple tool. It builds one *echo.Echo per subdomain from a shared factory and
// dispatches by Host header. See docs/ARCHITECTURE.md.
package main

import (
	"context"
	"log"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/iptolocation"
	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
)

func main() {
	cfg := platform.Load()

	// One template set assembled from shared partials + each project's templates.
	renderer := platform.NewRenderer(cfg.IsDev(),
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
		platform.TemplateSource{Embed: iptolocation.Templates, DevDir: "iptolocation/templates"},
	)
	staticFS := platform.SubFS(shared.Static, "static", "shared/static", cfg.IsDev())

	// apex: corpberry.com
	apex := platform.NewApp(renderer, staticFS)
	site.Register(apex, cfg)

	// ip.corpberry.com — missing databases are non-fatal; the tool reports it.
	geo, err := iptolocation.OpenService(cfg.DB11V4, cfg.DB11V6, cfg.ASNV4, cfg.ASNV6)
	if err != nil {
		log.Printf("ip-to-location: databases not loaded (%v); the tool will show a friendly message", err)
	}
	ipApp := platform.NewApp(renderer, staticFS)
	iptolocation.Register(ipApp, geo)

	hosts := map[string]*echo.Echo{
		cfg.VHost(""):   apex,
		cfg.VHost("ip"): ipApp,
	}
	log.Printf("listening on %s (env=%s); hosts: %v", cfg.ListenAddr, cfg.Env, hostKeys(hosts))

	handler := echo.NewVirtualHostHandler(hosts)
	sc := echo.StartConfig{Address: cfg.ListenAddr}
	if err := sc.Start(context.Background(), handler); err != nil {
		log.Fatal(err)
	}
}

func hostKeys(m map[string]*echo.Echo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
