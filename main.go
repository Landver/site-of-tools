// Command site-of-tools = single binary, powers corpberry.com + every simple
// tool. Builds one *echo.Echo per subdomain from shared factory -> dispatches
// by Host header. See docs/ARCHITECTURE.md.
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
	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/Landver/site-of-tools/tools/iptools"
	"github.com/Landver/site-of-tools/tools/linktools"
)

func main() {
	// run() holds everything, so its defers — the log drain, the hit batcher,
	// the Mongo disconnect — run on EVERY exit path. main only decides the
	// status code. Doing this inline meant a bind failure fell out of main and
	// exited 0, indistinguishable from a clean shutdown to a deploy script or
	// to compose's restart accounting.
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := platform.Load()

	// Open shared MongoDB client once at startup, share across features.
	// Disabled (empty MONGODB_URI) or unreachable server -> non-fatal: Mongo nil,
	// every repo built from it no-ops, app runs stateless. Same contract as IP
	// tool's missing-BIN case. Feature repos take *mongo.Database from mdb.DB()
	// (nil-safe).
	mongoCtx, cancelMongo := context.WithTimeout(context.Background(), 12*time.Second)
	mdb, mErr := platform.OpenMongo(mongoCtx, cfg.MongoURI, cfg.MongoDatabase)
	cancelMongo()
	if mErr != nil {
		log.Printf("mongo: disabled (%v); lookup history + request log will no-op", mErr)
	}
	// Close on shutdown. LIFO: reqlog drains (below) before client closes.
	defer mdb.Close(context.Background())

	// Mongo-backed features. Index creation bounded + best-effort; nil db ->
	// nil stores (disabled). Request log = engine-level, shared by every
	// subdomain; lookup history belongs to IP tool, fingerprint corpus to
	// botcheck.
	idxCtx, cancelIdx := context.WithTimeout(context.Background(), 10*time.Second)
	reqlog := platform.NewRequestLog(idxCtx, mdb.DB())
	lookupHistory := iptools.NewHistory(idxCtx, mdb.DB())
	corpus := botcheck.NewCorpus(mdb.DB())
	// Shared IP blocklist corpus (G37): ipsum + Spamhaus DROP feeds, plus any
	// other service writing flagged IPs/netblocks. Read by botcheck's
	// ip_blocklisted rule & IP tool's result card, fed by daily syncs below.
	// Nil-safe when Mongo off.
	blocklist := iptools.NewBlockList(mdb.DB())
	// Best-effort, same as history TTL index in NewHistory: failure only
	// forfeits auto-expiry -> non-fatal.
	_ = corpus.EnsureIndexes(idxCtx)
	_ = blocklist.EnsureIndexes(idxCtx)
	// Short-link store. Must be built HERE, inside the idxCtx window: building it
	// down beside the link app would hand it an already-cancelled context, and its
	// unique {code:1} index would silently never be created — which is what makes
	// the collision-retry strategy correct rather than hopeful.
	linkStore := linktools.NewLinkStore(idxCtx, mdb.DB())
	// Drains pending hit counts on shutdown, like reqlog above.
	defer linkStore.Close()
	if err := linkStore.IndexError(); err != nil {
		log.Printf("link tools: unique code index unavailable (%v); short-link creation will refuse writes", err)
	}
	cancelIdx()
	// Bounded. RequestLog.Close's own doc says it waits "bounded by ctx", and
	// context.Background() bounds nothing: with Mongo unreachable the writer
	// spends 5s per queued entry, so a full 1024-entry buffer would hold
	// shutdown open for over an hour.
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		reqlog.Close(c)
	}()

	// Shutdown signal, established HERE rather than just before Start, because
	// the background syncs below need it. Until this branch the deferred
	// mdb.Close was dead code (log.Fatal skipped it), so nothing ever pulled
	// the Mongo client out from under them. Now it does, and an interrupted
	// sync is worse than a slow one: the feeds are written as chunks of
	// upserts, and freshness is derived from max(updated_at), so a half-written
	// corpus stamps "now" on itself and the next 23 hours of boots skip the
	// re-download — leaving botcheck's ip_blocklisted rule and the IP tool's
	// reputation card reading a corpus that is half old and half new, silently.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refresh ipsum + Spamhaus DROP blocklist feeds daily in background
	// (nil-safe: no Mongo -> each returns at once). Both self-skip download if
	// corpus refreshed within last day -> redeploys don't re-fetch. DROP: free
	// for all use per Spamhaus, credited in site footer
	// (shared/templates/partials/footer.html).
	var syncs sync.WaitGroup
	syncs.Add(2)
	go func() { defer syncs.Done(); iptools.RunIPsumSync(ctx, blocklist) }()
	go func() { defer syncs.Done(); iptools.RunSpamhausDROPSync(ctx, blocklist) }()
	// Bounded: a sync that ignores its context must not hold the process open.
	defer waitBounded(&syncs, 5*time.Second)

	// Template funcs available to every template: shared header uses these for
	// logo link (always apex) + Tools dropdown. Tools come from one catalog
	// (site.Tools) -> nav + apex index render same list.
	staticFS := platform.SubFS(shared.Static, "static", "shared/static", cfg.IsDev())

	// Prod: version static URLs by content hash ({{asset "js/botcheck.js"}} ->
	// /static/js/botcheck.js?v=<hash>) -> deploy busts CDN/browser cache for
	// exactly changed files. Dev: static served no-store -> keep URLs clean.
	// platform.StaticURL = shared prefix logic both paths use.
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
		platform.TemplateSource{Embed: iptools.Templates, DevDir: "tools/iptools/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
		platform.TemplateSource{Embed: dnstools.Templates, DevDir: "tools/dnstools/templates"},
		platform.TemplateSource{Embed: linktools.Templates, DevDir: "tools/linktools/templates"},
	)

	// apex: corpberry.com — blog posts embedded (prod) / disk (dev); a
	// malformed post fails boot here rather than serving a broken page.
	apex := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	if err := site.Register(apex, cfg, platform.SubFS(site.Posts, "posts", "site/posts", cfg.IsDev())); err != nil {
		log.Fatalf("apex: %v", err)
	}

	// ip.corpberry.com — missing databases non-fatal; tool reports it.
	geo, err := iptools.OpenService(cfg.DB11V4, cfg.DB11V6, cfg.ASNV4, cfg.ASNV6, cfg.PX12)
	if err != nil {
		log.Printf("ip tools: databases not loaded (%v); the tool will show a friendly message", err)
	}
	// Shodan InternetDB enrichment (free, keyless, non-commercial): open-port
	// intel for looked-up IP, fetched live per request, never stored (Shodan's
	// terms). Blank SHODAN_INTERNETDB_URL disables it (nil -> no-op). See
	// tools/iptools/docs/reports/shodan-internetdb-feasibility.md.
	shodan := iptools.NewShodan(cfg.ShodanURL, 4*time.Second)
	geo.WithShodan(shodan)
	ipApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	iptools.Register(ipApp, geo, lookupHistory, blocklist)

	// botcheck.corpberry.com — reuses same IP service for server-side
	// reputation signals (nil geo degrades gracefully, same as IP tool) + Mongo
	// corpus for fingerprint-reuse signal.
	botApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	botcheck.Register(botApp, geo, corpus, blocklist)

	// dns.corpberry.com — DNS record lookup. Queries public resolvers directly
	// over UDP/53 (no databases to load, so nothing to degrade), and reuses the
	// SAME geo service the IP tool opened above to label resolved addresses with
	// ASN/country — in-process, no new dependency (docs/tools/dnstools/02-build-fit.md §2).
	// nil/unloaded geo just means records render without that annotation.
	dnsApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	// RDAP + Certificate Transparency: both free, keyless and public. Blank
	// URLs disable that half (nil client -> the page says the lookup is off,
	// never that the domain has no registration).
	domainClient := dnstools.NewDomainClient(cfg.RDAPURL, cfg.CrtShURL, 20*time.Second)
	dnstools.Register(dnsApp, dnstools.NewService(5*time.Second), geo, domainClient, dnstools.BlockCheckerFrom(blocklist))

	// link.corpberry.com — URL inspect / clean / short links / trace. Parsing is
	// pure and opens no connection; only /trace dials out, and only through the
	// egress gate. The URL still reaches the request log, which is why
	// platform.RedactURI strips the ?u= value before anything is written down
	// (tools/linktools/docs/06-security-and-abuse.md §5).
	linkSvc := linktools.NewService()
	// Shortener is nil unless BOTH a store and a key exist — fail-closed, so an
	// unset LINK_API_KEY means nobody can create links rather than anybody can.
	// Base origin only: Shortener.ShortURL owns the "/s/" prefix, so adding it
	// here would mint links at /s/s/.
	shortener := linktools.NewShortener(linkStore, cfg.LinkAPIKey, cfg.URL("link"))
	if shortener != nil {
		shortener.CleanTarget = linktools.CleanTargetFunc(linkSvc)
	}
	// /trace is the one place this box dials a host a stranger chose. The guard is
	// shared engine code, allows only 80/443, and refuses our own vhosts and every
	// local interface address so a trace cannot loop back into the origin behind
	// Cloudflare (tools/linktools/docs/06-security-and-abuse.md §2).
	traceGuard := platform.NewEgressGuard([]string{"80", "443"}, []string{
		cfg.VHost(""), cfg.VHost("ip"), cfg.VHost("botcheck"), cfg.VHost("dns"), cfg.VHost("link"),
		cfg.MongoURI,
	})
	tracer := linktools.NewTracer(traceGuard, 15*time.Second)
	linkApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	linktools.Register(linkApp, linkSvc, tracer, shortener, cfg.URL("link"))

	// A sitemap only covers URLs on its own host (sitemaps.org), so each
	// subdomain advertises its own /sitemap.xml + /robots.txt rather than the
	// apex trying to list them all. Apex wires its own inside site.Register,
	// where the blog's dynamic post list lives.
	platform.RegisterSEO(ipApp, cfg.URL("ip"), iptools.SitemapPages)
	platform.RegisterSEO(botApp, cfg.URL("botcheck"), botcheck.SitemapPages)
	platform.RegisterSEO(dnsApp, cfg.URL("dns"), dnstools.SitemapPages)
	platform.RegisterSEO(linkApp, cfg.URL("link"), linktools.SitemapPages)

	hosts := map[string]*echo.Echo{
		cfg.VHost(""):         apex,
		cfg.VHost("ip"):       ipApp,
		cfg.VHost("botcheck"): botApp,
		cfg.VHost("dns"):      dnsApp,
		cfg.VHost("link"):     linkApp,
	}
	log.Printf("listening on %s (env=%s); hosts: %v", cfg.ListenAddr, cfg.Env, slices.Collect(maps.Keys(hosts)))

	handler := echo.NewVirtualHostHandler(hosts)

	// GracefulTimeout caps how long Shutdown waits for in-flight requests.
	// Echo's default is 10s, and two handlers budget longer than that — the
	// RDAP/CT client at 20s and the tracer at 15s — so a slow request would run
	// the clock past compose's own stop grace and get the container SIGKILLed
	// mid-drain, which is exactly what the drains exist to prevent. Five
	// seconds: long enough for any ordinary request, short enough that total
	// teardown stays well inside the 30s stop_grace_period in
	// docker-compose.yml.
	sc := echo.StartConfig{Address: cfg.ListenAddr, GracefulTimeout: 5 * time.Second}
	err = sc.Start(ctx, handler)

	// A cancelled context is the ordinary shutdown path, not a failure. Anything
	// else is real and must reach main as an error, or the process exits 0 on a
	// bind failure.
	switch {
	case err == nil, errors.Is(err, http.ErrServerClosed), errors.Is(err, context.Canceled):
		log.Print("shutting down; draining buffered writes")
		return nil
	default:
		return err
	}
}

// waitBounded waits for wg, giving up after d. Used for the blocklist syncs:
// they take a context, but a stuck HTTP read inside one must not outrank the
// shutdown that is waiting on it.
func waitBounded(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		log.Printf("blocklist syncs did not finish within %s; continuing shutdown", d)
	}
}
