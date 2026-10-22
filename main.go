// Command site-of-tools serves corpberry.com and every tool subdomain, dispatching by Host header.
package main

import (
	"context"
	"errors"
	"html/template"
	"log"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
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
	"github.com/Landver/site-of-tools/tools/mcptools"
)

func main() {
	// The defers live in run so the drains fire on every exit path, and a bind failure still exits 1.
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := platform.Load()

	// Unset or unreachable Mongo is non-fatal: mdb.DB() is nil and every repo built on it no-ops.
	mongoCtx, cancelMongo := context.WithTimeout(context.Background(), 12*time.Second)
	mdb, mErr := platform.OpenMongo(mongoCtx, cfg.MongoURI, cfg.MongoDatabase)
	cancelMongo()
	if mErr != nil {
		log.Printf("mongo: disabled (%v); lookup history + request log will no-op", mErr)
	}
	// LIFO: reqlog and the hit batcher (below) drain before the client closes.
	defer mdb.Close(context.Background())

	// Index creation is bounded and best-effort; a nil db yields disabled stores.
	idxCtx, cancelIdx := context.WithTimeout(context.Background(), 10*time.Second)
	reqlog := platform.NewRequestLog(idxCtx, mdb.DB())
	lookupHistory := iptools.NewHistory(idxCtx, mdb.DB())
	corpus := botcheck.NewCorpus(mdb.DB())
	// Fed by the daily syncs below; read by botcheck's ip_blocklisted rule and the IP tool.
	blocklist := iptools.NewBlockList(mdb.DB())
	// Best-effort: failure only forfeits auto-expiry.
	_ = corpus.EnsureIndexes(idxCtx)
	_ = blocklist.EnsureIndexes(idxCtx)
	// Must be built inside the idxCtx window: a cancelled ctx silently skips its unique {code:1}
	// index, which is what makes the collision retry correct.
	linkStore := linktools.NewLinkStore(idxCtx, mdb.DB())
	// Drains pending hit counts on shutdown.
	defer linkStore.Close()
	if err := linkStore.IndexError(); err != nil {
		log.Printf("link tools: unique code index unavailable (%v); short-link creation will refuse writes", err)
	}
	cancelIdx()
	// Bounded: with Mongo unreachable each queued entry costs 5s, so a full buffer could take an hour.
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		reqlog.Close(c)
	}()

	// The syncs need this to stop before mdb.Close: freshness is max(updated_at), so a half-written
	// corpus looks fresh and the next 23 hours of boots skip the re-download.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Each skips the download if refreshed within a day, so redeploys don't re-fetch.
	// Spamhaus DROP is free for all use; it is credited in shared/templates/partials/footer.html.
	var syncs sync.WaitGroup
	syncs.Add(2)
	go func() { defer syncs.Done(); iptools.RunIPsumSync(ctx, blocklist) }()
	go func() { defer syncs.Done(); iptools.RunSpamhausDROPSync(ctx, blocklist) }()
	// Bounded: a sync that ignores its context must not hold the process open.
	defer waitBounded(&syncs, 5*time.Second)

	staticFS := platform.SubFS(shared.Static, "static", "shared/static", cfg.IsDev())

	// Prod URLs carry a content hash so a deploy busts caches; dev serves static no-store.
	asset := platform.StaticURL
	if !cfg.IsDev() {
		asset = platform.AssetVersioner(staticFS)
	}

	navFuncs := template.FuncMap{
		"apexURL":  func() string { return cfg.URL("") },
		"navTools": func() []platform.Tool { return site.Tools(cfg) },
		"toolURL":  cfg.URL,
		"asset":    asset,
	}

	renderer := platform.NewRenderer(cfg.IsDev(), navFuncs,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: site.Templates, DevDir: "site/templates"},
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
		platform.TemplateSource{Embed: ciphertools.Templates, DevDir: "tools/ciphertools/templates"},
		platform.TemplateSource{Embed: mcptools.Templates, DevDir: "tools/mcptools/templates"},
	)

	apps := map[string]*echo.Echo{}
	ownHosts := []string{cfg.MongoURI}
	for _, sub := range []string{"", "ip", "botcheck", "dns", "link", "cipher", "mcp"} {
		apps[sub] = platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
		ownHosts = append(ownHosts, cfg.VHost(sub))
	}
	ownHosts = append(ownHosts, cfg.EgressDenyAddrs...)
	// MTA-STS is HTTPS-only; RDAP hops can be plain HTTP (.kg, .mg), and so can traced links.
	httpsGuard := platform.NewEgressGuard([]string{"443"}, ownHosts)
	webGuard := platform.NewEgressGuard([]string{"80", "443"}, ownHosts)

	ipLim, dnsLim, linkLim := iptools.NewLimits(), dnstools.NewLimits(), linktools.NewLimits()
	cipherLim, botLim := ciphertools.NewLimits(), botcheck.NewLimits()
	ipCheck, dnsCheck := iptools.CheckerFrom(blocklist), dnstools.BlockCheckerFrom(blocklist)

	// A malformed blog post fails boot here rather than serving a broken page.
	blog, err := site.Register(apps[""], cfg, platform.SubFS(site.Posts, "posts", "site/posts", cfg.IsDev()))
	if err != nil {
		log.Fatalf("apex: %v", err)
	}

	// Missing databases are non-fatal; the tool reports it.
	geo, err := iptools.OpenService(cfg.DB11V4, cfg.DB11V6, cfg.ASNV4, cfg.ASNV6, cfg.PX12)
	if err != nil {
		log.Printf("ip tools: databases not loaded (%v); the tool will show a friendly message", err)
	}
	// Shodan's terms: fetched live per request, never stored. Blank SHODAN_INTERNETDB_URL disables it.
	shodan := iptools.NewShodan(cfg.ShodanURL, 4*time.Second)
	geo.WithShodan(shodan)
	// DNS shows no open ports, so it must not spend the Shodan budget per record.
	dnsGeo := geo.Offline()
	iptools.Register(apps["ip"], geo, lookupHistory, ipCheck, ipLim)

	botcheck.Register(apps["botcheck"], geo, corpus, ipCheck, botLim)

	// A blank RDAP/CT URL disables that half; the page says so rather than claim no registration.
	domainClient := dnstools.NewDomainClient(cfg.RDAPURL, cfg.CrtShURL, 20*time.Second).WithEgressGuard(webGuard)
	dnsSvc := dnstools.NewService(5 * time.Second).WithEgressGuard(httpsGuard)
	dnstools.Register(apps["dns"], dnsSvc, dnsGeo, domainClient, dnsCheck, dnsLim)

	// Only /trace dials out (via the egress gate); platform.RedactURI keeps ?u= out of the request log.
	linkSvc := linktools.NewService()
	// Keyless still resolves links but can't create, list or revoke (fail-closed).
	// Pass the bare origin: ShortURL adds "/s/" itself, so adding it here mints /s/s/ links.
	newShortener := func(key string) *linktools.Shortener {
		s := linktools.NewShortener(linkStore, key, cfg.URL("link"))
		if s != nil {
			s.CleanTarget = linktools.CleanTargetFunc(linkSvc)
		}
		return s
	}
	shortener := newShortener(cfg.LinkAPIKey)
	tracer := linktools.NewTracer(webGuard, 15*time.Second)
	linktools.Register(apps["link"], linkSvc, tracer, shortener, cfg.URL("link"), linkLim)

	// The pages compute in the browser (wasm), so pasted secrets never reach us; POSTs are the JSON API.
	ciphertools.Register(apps["cipher"], cfg.URL("cipher"), staticFS, cipherLim)

	mcptools.Register(apps["mcp"], mcptools.Deps{
		Geo: geo, DNSGeo: dnsGeo, Blocklist: ipCheck, DNSBlocklist: dnsCheck,
		DNS: dnsSvc, Domain: domainClient, Blog: blog,
		Link: linkSvc, Tracer: tracer, Short: shortener, Owner: newShortener(cfg.MCPOwnerKey),
		IPLimits: ipLim, DNSLimits: dnsLim, LinkLimits: linkLim, CipherLimits: cipherLim, BotLimits: botLim,
		RequestLog: reqlog, ToolURL: cfg.URL,
	}, cfg.URL("mcp"))

	// A sitemap covers only its own host (sitemaps.org); the apex wires its own in site.Register.
	platform.RegisterSEO(apps["ip"], cfg.URL("ip"), iptools.SitemapPages)
	platform.RegisterSEO(apps["botcheck"], cfg.URL("botcheck"), botcheck.SitemapPages)
	platform.RegisterSEO(apps["dns"], cfg.URL("dns"), dnstools.SitemapPages)
	platform.RegisterSEO(apps["link"], cfg.URL("link"), linktools.SitemapPages)
	platform.RegisterSEO(apps["cipher"], cfg.URL("cipher"), ciphertools.SitemapPages)
	platform.RegisterSEO(apps["mcp"], cfg.URL("mcp"), mcptools.SitemapPages)

	hosts := make(map[string]*echo.Echo, len(apps))
	for sub, app := range apps {
		hosts[cfg.VHost(sub)] = app
	}
	log.Printf("listening on %s (env=%s); hosts: %v", cfg.ListenAddr, cfg.Env, slices.Collect(maps.Keys(hosts)))

	handler := echo.NewVirtualHostHandler(hosts)

	// Caps the in-flight wait so the whole teardown stays inside compose's 30s stop_grace_period.
	sc := echo.StartConfig{Address: cfg.ListenAddr, GracefulTimeout: 5 * time.Second}
	err = sc.Start(ctx, handler)

	// A cancelled context is the ordinary shutdown; anything else (a bind failure) must exit non-zero.
	switch {
	case err == nil, errors.Is(err, http.ErrServerClosed), errors.Is(err, context.Canceled):
		log.Print("shutting down; draining buffered writes")
		return nil
	default:
		return err
	}
}

// waitBounded waits for wg up to d: a sync stuck in an HTTP read must not stall shutdown.
func waitBounded(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		log.Printf("blocklist syncs did not finish within %s; continuing shutdown", d)
	}
}
