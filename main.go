// Command site-of-tools is the single binary, powers corpberry.com + every
// simple tool. Builds one *echo.Echo per subdomain from shared factory →
// dispatches by Host header. See docs/ARCHITECTURE.md.
package main

import (
	"context"
	"html/template"
	"log"
	"maps"
	"slices"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/site"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

func main() {
	cfg := platform.Load()

	// Open shared MongoDB client once at startup, share across features.
	// Disabled (empty MONGODB_URI) or unreachable server → non-fatal: Mongo nil,
	// every repo built from it no-ops, app runs stateless — same contract as IP
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

	// Mongo-backed features. Index creation bounded + best-effort; nil db →
	// nil stores (disabled). Request log = engine-level, shared by every
	// subdomain; lookup history belongs to IP tool, fingerprint corpus to
	// botcheck.
	idxCtx, cancelIdx := context.WithTimeout(context.Background(), 10*time.Second)
	reqlog := platform.NewRequestLog(idxCtx, mdb.DB())
	lookupHistory := iptools.NewHistory(idxCtx, mdb.DB())
	corpus := botcheck.NewCorpus(mdb.DB())
	// Shared IP blocklist corpus (G37): ipsum + Spamhaus DROP feeds, plus any
	// other service writing flagged IPs/netblocks. Read by botcheck's
	// ip_blocklisted rule and the IP tool's result card, fed by the daily syncs
	// below. Nil-safe when Mongo off.
	blocklist := iptools.NewBlockList(mdb.DB())
	// Best-effort, same as history TTL index in NewHistory: failure only
	// forfeits auto-expiry → non-fatal.
	_ = corpus.EnsureIndexes(idxCtx)
	_ = blocklist.EnsureIndexes(idxCtx)
	cancelIdx()
	defer reqlog.Close(context.Background())

	// Refresh the ipsum + Spamhaus DROP blocklist feeds daily in the background
	// (nil-safe: no Mongo → each returns at once). Both self-skip the download
	// if their corpus was refreshed within the last day → redeploys don't
	// re-fetch. DROP: free for all use per Spamhaus, credited in the site
	// footer (shared/templates/partials/footer.html).
	go iptools.RunIPsumSync(context.Background(), blocklist)
	go iptools.RunSpamhausDROPSync(context.Background(), blocklist)

	// Template funcs available to every template: shared header uses these for
	// logo link (always apex) + Tools dropdown. Tools come from one catalog
	// (site.Tools) → nav + apex index render same list.
	staticFS := platform.SubFS(shared.Static, "static", "shared/static", cfg.IsDev())

	// Prod: version static URLs by content hash ({{asset "js/botcheck.js"}} ->
	// /static/js/botcheck.js?v=<hash>) → deploy busts CDN/browser cache for
	// exactly the changed files. Dev: static served no-store → keep URLs clean.
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
	)

	// apex: corpberry.com
	apex := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	site.Register(apex, cfg)

	// ip.corpberry.com — missing databases non-fatal; tool reports it.
	geo, err := iptools.OpenService(cfg.DB11V4, cfg.DB11V6, cfg.ASNV4, cfg.ASNV6, cfg.PX12)
	if err != nil {
		log.Printf("ip tools: databases not loaded (%v); the tool will show a friendly message", err)
	}
	ipApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	iptools.Register(ipApp, geo, lookupHistory, blocklist)

	// botcheck.corpberry.com — reuses same IP service for server-side
	// reputation signals (nil geo degrades gracefully, same as IP tool) + Mongo
	// corpus for fingerprint-reuse signal.
	botApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
	botcheck.Register(botApp, geo, corpus, blocklist)

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
