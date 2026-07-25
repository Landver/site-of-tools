# Architecture — corpberry.com (`site-of-tools`)

`corpberry.com` = Stas's playground: portfolio landing + growing collection of
small self-built tools/experiments. Repo = **one Go server** = apex site + every
*simple* tool. Bigger projects needing real SPA get own subdomain + own stack
(Next.js etc.) later — **not** here.

> Scope: practical, not exhaustive. Lets human/AI pick up dev w/o re-deriving
> design. Change something → edit doc.

---

## 1. Stack (pinned)

No Node/npm in toolchain. Frontend JS vendored as static files; CSS built by 1
prebuilt binary.

| Layer            | Choice                                             | Version (2026-07) |
|------------------|----------------------------------------------------|-------------------|
| Language         | Go                                                 | 1.26.x (no LTS — track latest 2 series) |
| Web framework    | Echo **v5** — `github.com/labstack/echo/v5`        | v5.3.x            |
| Templating       | stdlib `html/template` (server-rendered)           | —                 |
| Interactivity    | htmx (AJAX/partials only, when plain HTML can't)   | 2.0.x (self-hosted) |
| Sprinkle-JS      | Alpine.js (small client state)                     | 3.15.x (self-hosted) |
| CSS              | Tailwind **standalone CLI** (no npm)               | v4.3.x            |
| Live reload      | air — `github.com/air-verse/air`                   | v1.65.x           |
| GeoIP            | `github.com/ip2location/ip2location-go/v9`         | v9.8.x            |
| Proxy/VPN        | `github.com/ip2location/ip2proxy-go/v4` (needs ≥v4 for PX12) | v4.2.x   |
| Database         | MongoDB — `go.mongodb.org/mongo-driver/v2` (**/v2**, not v1; request log + IP-tool lookup history + botcheck fingerprint corpus) | v2.8.x |
| Tests            | stdlib `testing` + `github.com/google/go-cmp`      | go-cmp v0.7.x     |
| Container base   | `gcr.io/distroless/static-debian12:nonroot`        | —                 |

**Why Echo v5, not v4:** v5 = current stable major; v4 loses security support
2026-12-31, v4→v5 = breaking migration. Greenfield → straight to v5. Most Echo
tutorials/blogs still show v4 — translate. Key v5 diffs:
- Handlers: `func(c *echo.Context) error` (Context = **struct pointer**, not interface).
- Renderer sig: `Render(c *echo.Context, w io.Writer, name string, data any) error`.
- No `e.Host()`. Multi-subdomain routing = `echo.NewVirtualHostHandler(map[string]*echo.Echo{...})` (§3).
- No `middleware.Logger()`. Logging = `log/slog` via `middleware.RequestLogger`.
- Start via `echo.StartConfig{Address: ...}.Start(ctx, handler)`.
- `IPExtractor` / `ExtractIPFromXFFHeader` / `TrustOption` carry over from v4.

**Why go-cmp, not testify:** stdlib runner *is* the right tool (fast, parallel,
subtests, fuzzing built in). go-cmp gives readable value-comparison diffs,
idiomatic modern choice; testify = ubiquitous-but-unremarkable default, skipped
on purpose.

---

## 2. Topology

```
        client
          │  HTTPS
          ▼
   ┌──────────────┐   Cloudflare is the ONLY thing in front.
   │  Cloudflare  │   Proxy ON. Real client IP arrives as CF-Connecting-IP.
   └──────┬───────┘
          │  HTTPS (origin cert)
          ▼
   ┌──────────────┐   nginx-reverse-proxy (separate project on this host).
   │    nginx     │   Terminates TLS. One server{} block per subdomain.
   └──────┬───────┘   Forwards Host + client-IP headers. proxy_pass → host:8080.
          │  HTTP, over the docker bridge (172.17.0.1:8080)
          ▼
   ┌──────────────┐   THIS repo. One binary, listens :8080 inside its container.
   │  Go / Echo   │   Dispatches by Host header to the right sub-app (§3).
   └──────────────┘
```

Deployment specifics (nginx blocks in `deploy/nginx/`, Docker, ports, CF trust)
in [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 3. One binary, many subdomains (host routing)

Whole site = single process. Each subdomain = own `*echo.Echo`, built by shared
factory (`platform.NewApp`) — shares middleware, renderer, IP extractor, static
serving. Virtual-host handler dispatches by `Host` header.

```go
// platform/app.go — factory: every sub-app starts identical.
func NewApp(r *Renderer, staticFS fs.FS) *echo.Echo {
    e := echo.New()
    e.Renderer = r
    e.IPExtractor = cfIPExtractor()          // CF-Connecting-IP → XFF → RemoteAddr
    e.Use(middleware.Recover(), middleware.RequestLogger(), middleware.Gzip())
    e.StaticFS("/static", staticFS)
    return e
}

// main.go — build each sub-app, then a Host→app map.
apex  := platform.NewApp(renderer, staticFS); site.Register(apex, cfg)
ipApp := platform.NewApp(renderer, staticFS); iptools.Register(ipApp, geo)

handler := echo.NewVirtualHostHandler(map[string]*echo.Echo{
    cfg.VHost(""):   apex,   // "corpberry.com"      (dev: "localhost:8080")
    cfg.VHost("ip"): ipApp,  // "ip.corpberry.com"   (dev: "ip.localhost:8080")
})
echo.StartConfig{Address: cfg.ListenAddr}.Start(context.Background(), handler)
```

- Host keys **from config** (`cfg.VHost`) — dev uses `*.localhost` (browsers
  auto-route `*.localhost` → 127.0.0.1), prod uses real domains.
- v5 matches **full Host header incl. port** — dev keys carry `:8080`
  (`ip.localhost:8080`), prod nginx forwards bare host (`ip.corpberry.com`);
  `VHost` handles diff.
- **New subdomain = 1 `*echo.Echo` + 1 map entry + 1 nginx block.** Never new service.

---

## 4. Request layering (the core pattern — read this)

Every feature serves **HTML for browsers, JSON for API/CLI** from *same* code —
via layering, not duplicated features:

```
┌─ domain layer ──────────────────────────────────────────────┐
│  e.g. Service.Lookup("8.8.8.8") → (*Result, error)            │  the real work.
│  Pure Go. Knows NOTHING about HTTP. Returns a struct.         │  Written ONCE.
└──────────────────────────┬───────────────────────────────────┘
                           │ struct
┌─ transport layer ────────▼───────────────────────────────────┐
│  handler calls domain, then Respond(c, code, data, page, frag):│  thin,
│    • CLI/API (no text/html in Accept)   → JSON                 │  written ONCE
│    • htmx (HX-Request: true)            → HTML fragment         │  in platform,
│    • browser (Accept: text/html)        → full HTML page        │  reused
└───────────────────────────────────────────────────────────────┘
```

**Rule: business logic never in handler.** Handlers parse input, call domain fn,
hand result to `Respond`. Only way 1 feature speaks 3 representations w/ zero
duplication.

```go
// platform/render.go
func WantsJSON(c *echo.Context) bool { return !prefersHTML(c) }

// prefersHTML: htmx always wants HTML; browsers send Accept: text/html.
// Everything else (curl's */*, application/json, API clients) gets JSON.
func prefersHTML(c *echo.Context) bool {
    if IsHTMX(c) { return true }
    return strings.Contains(c.Request().Header.Get("Accept"), "text/html")
}

func Respond(c *echo.Context, code int, data any, pageTmpl, fragTmpl string) error {
    switch {
    case WantsJSON(c): return c.JSON(code, data)
    case IsHTMX(c):    return c.Render(code, fragTmpl, data)
    default:           return c.Render(code, pageTmpl, data)
    }
}
```

Result: `curl 'https://ip.corpberry.com/?ip=8.8.8.8'` auto-returns JSON (curl
sends `Accept: */*`, no `text/html`); browser at same URL gets page.
See [tools/iptools/](../tools/iptools/docs/README.md).

> Real, documented, versioned **public JSON API** later → add **Huma**
> (`humaecho` adapter) on `/api/v1` of relevant sub-app. Reuses same domain fns —
> pure bolt-on, no rework. Not now.

---

## 5. Rendering & assets

**Templates** — stdlib `html/template`. Shared base partials (`head`/`header`/
`footer`) in `shared/templates/`; each project adds own. All parsed into 1 set,
addressed by unique `{{define "name"}}` names (e.g. `site/home`, `ip/index`,
`ip/result`, `partials/head`). Auto-escaped.

**`go:embed` w/ dev/prod toggle** — each package embeds *its own* `templates`
(`shared` also embeds `static`); `go:embed` can't cross directories. Prod serves
embedded copy; dev (`APP_ENV=dev`) reads same dirs from disk via `os.DirFS` **and
re-parses per request**, so edits show on refresh w/o rebuild.

```go
// shared/embed.go  (site/ and tools/<tool>/ embed their own templates likewise)
//go:embed templates
var Templates embed.FS
//go:embed all:static
var Static embed.FS
```
`platform.SubFS(embed, "templates", "shared/templates", dev)` returns disk FS in
dev, else embedded tree w/ prefix stripped. `platform.NewRenderer` takes 1
`TemplateSource` per package, parses into 1 set. Gotchas: `//go:embed` must sit
directly above `var`; patterns can't use `..` (hence 1 embed per package dir);
run binary from repo root in dev.

**CSS — Tailwind v4, CSS-first, no config file.** Source =
`shared/static/css/input.css`, `@source`-scans every project's templates:
```css
@import "tailwindcss";
@source "../../templates/**/*.html";               /* shared */
@source "../../../site/templates/**/*.html";
@source "../../../tools/iptools/templates/**/*.html";
@theme { --color-brand: #b83266; }
```
Built to `shared/static/css/styles.css` (`--minify` prod, `--watch` dev).
`styles.css` = build artifact (gitignored; built in Docker image + by `make
css`). **Tailwind sees only literal class strings** — never assemble class names
in Go; use full literals or `@source inline(...)`.

**htmx + Alpine — vendored** under `shared/static/js/` (pinned, self-hosted, no
CDN in prod). Load order in base head partial:
```html
<script src="/static/js/htmx.min.js"></script>          <!-- first, no defer -->
<script defer src="/static/js/alpine.min.js"></script>  <!-- last, MUST defer -->
```
**Critical interplay bug:** Alpine scans DOM once at boot; markup htmx *swaps in*
later w/ `x-data` etc. = dead unless re-init:
```js
document.body.addEventListener('htmx:afterSwap', e => window.Alpine.initTree(e.detail.elt));
```
Keep htmx-owned + Alpine-owned regions distinct.

---

## 6. Configuration

12-factor: all config via env vars, loaded from repo-root `.env` in dev
(gitignored), injected by `docker-compose` in prod. Config type + loader:
`platform/config.go`.

| Var | Purpose | Example |
|-----|---------|---------|
| `APP_ENV` | `dev` (disk FS + template reparse) or `prod` (embedded) | `dev` |
| `LISTEN_ADDR` | bind address inside process | `:8080` |
| `BASE_DOMAIN` | builds vhost keys; `localhost` in dev | `corpberry.com` |
| `IP2LOCATION_DB11_V4` / `_V6` | paths to DB11 BINs | `tools/iptools/assets/ipv4/...BIN` |
| `IP2LOCATION_ASN_V4` / `_V6` | paths to ASN BINs | `tools/iptools/assets/asn/...BIN` |
| `IP2PROXY_PX12` | IP2Proxy PX12 BIN — optional; enables proxy section | `tools/iptools/assets/ip2proxy/...BIN` |
| `IP2LOCATION_DOWNLOAD_TOKEN` | used by `make assets` only (not app) | — |
| `MONGODB_URI` | Mongo conn string (credentials + auth db). Optional — empty disables Mongo | `mongodb://user:pass@localhost/admin` |
| `MONGODB_DATABASE` | app database name; defaults to `site-of-tools` | `site-of-tools` |

**MongoDB** = *network* dep, not bind-mounted file like BINs — same `MONGODB_URI`
works dev + prod (add to `.env` wherever app runs; dev & prod share host but not
necessarily working copy). Config: `platform/config.go`; client:
`platform/mongo.go` (`platform.OpenMongo` → nil-safe `*Mongo` wrapper).
**Optional, degrades gracefully**: empty `MONGODB_URI` → `ErrMongoUnavailable` —
same "missing data non-fatal" contract `iptools.OpenService` uses for absent
BINs. First users: IP-tool lookup history + engine-level request log (§10).

---

## 7. Directory layout

Go rule: **1 folder = 1 package**. Two constraints shape tree — imported package
can't be `package main`; `go:embed` can't cross directories (so tool co-locating
own `templates/` must be own package).

```
site-of-tools/
├── main.go                   # package main — entrypoint: config → sub-apps → vhost → listen
├── platform/                 # shared engine (importable): config.go, app.go, render.go, conn.go, mongo.go
├── shared/                   # shared front-end ONLY: base partials + vendored htmx/alpine/css
│   ├── embed.go              #   (its own package so it can go:embed what lives here)
│   ├── templates/partials/   #   head · header · footer
│   └── static/{css,js}/      #   input.css → styles.css (built), htmx.min.js, alpine.min.js
├── site/                     # apex corpberry.com project
│   ├── site.go · embed.go
│   └── templates/home.html
├── tools/                    # self-contained tool subdomains (code + a docs/ folder each)
│   ├── iptools/              #   ip.corpberry.com — SELF-CONTAINED
│   │   ├── geoip.go          #     geo/proxy domain (pure Go, no HTTP)
│   │   ├── cidr.go           #     subnet-calculator domain
│   │   ├── handler.go        #     transport (Register + Looker interface)
│   │   ├── embed.go · tests/ #     embed + black-box tests (its own package)
│   │   ├── download-assets.sh#     fetch this tool's databases
│   │   ├── templates/        #     index · result · cidr · nav
│   │   ├── assets/           #     the .BIN databases (gitignored, bind-mounted)
│   │   └── docs/README.md    #     this tool's design + reference doc
│   └── botcheck/             #   botcheck.corpberry.com — SELF-CONTAINED
│       ├── botcheck.go · scoring.go · handler.go · goodbots.go · report.go · corpus.go · embed.go · tests/
│       ├── templates/        #     index · result
│       └── docs/             #     all of this tool's markdown, split by topic
│           ├── README.md     #       index — links to everything below
│           ├── RESEARCH.md   #       how the 12 competitor services work
│           ├── roadmap/      #       what to build next & why (per-category files)
│           ├── testing/      #       automation-detection test harness + findings
│           └── reports/      #       per-service research writeups
├── deploy/nginx/             # ready-to-install reverse-proxy server blocks
├── .githooks/pre-push        # test gate (enable: make hooks)
├── .air.toml · Dockerfile · docker-compose.yml · Makefile
├── go.mod · go.sum · mongoinit.go
├── README.md · CLAUDE.md
└── docs/{ARCHITECTURE.md, DEPLOYMENT.md}
```

Why each folder: `platform/` must be importable (can't be `main`); `shared/`,
`site/`, each `tools/<tool>/` must each be a package to embed templates beside
code. `tools/` groups tool subdomains (each own Go package, e.g. `tools/iptools`,
`tools/botcheck`); apex `site/` stays at root. `main.go` at root — composition
root = 1 thing nothing imports. No single-file folder for its own sake.

---

## 8. Adding a new tool

1. Decide: simple tool (lives here) or real SPA (own subdomain + own stack — not here).
2. `mytool/` — package w/: `geoip.go`-style domain service (pure Go, returns
   structs), `handler.go` w/ `Register(e, deps)`, `embed.go` (`//go:embed templates`),
   `templates/`, `tests/` sub-package.
3. Handlers call domain service, then `platform.Respond(...)` — free HTML+JSON+fragment.
4. Register tool's `TemplateSource` in `main.go` renderer; (new subdomain) add
   `*echo.Echo` + `cfg.VHost` map entry + `deploy/nginx/` block.
5. Tool data files? Keep in `mytool/assets/`, env-configured path, gitignored,
   bind-mounted — never baked into image.

---

## 9. Testing

- Each package's tests in own **`<pkg>/tests/`** folder (black-box — exported API
  only, no test file among code). Test genuinely needing unexported internals =
  exception, sits beside code as `foo_test.go`.
- stdlib `testing`; run `go test ./... -race` (`make test`). Domain logic
  table-driven; HTTP handlers via `net/http/httptest` + `app.ServeHTTP`; struct
  comparisons use `go-cmp`.
- Handlers depend on **small interfaces** (e.g. `iptools.Looker`) so tests inject
  fakes, never need real DBs.
- Tests that *do* need BINs = **integration tests that skip** when files absent,
  so CI & fresh clones stay green (BINs gitignored).
- Tracked **pre-push hook** (`.githooks/pre-push`, enabled by `make hooks`) runs
  `go vet ./...` + `go test ./...`, blocks push on failure.

---

## 10. Out of scope now (deliberately deferred)

- **Persistence / MongoDB** — wired, now used by 3 features: IP tool's **lookup
  history** (`tools/iptools/history.go`, repository below domain per rule #5),
  engine-level **request log** (`platform/requestlog.go`, shared async writer fed
  by request-logger middleware), botcheck's **fingerprint corpus**
  (`tools/botcheck/corpus.go`, rolling 30-day store behind `fingerprint_reuse`
  rule). All take `*mongo.Database` from shared client (`platform.OpenMongo`,
  opened once in `main.go`), self-prune via `platform.EnsureTTLIndex`; all
  degrade to no-ops when `MONGODB_URI` empty, so app still boots stateless.
  Further storage features (e.g. botcheck crowd/rarity scoring, request velocity,
  IP-tool rate limiting) follow same shape. Mongo creates collections lazily on
  first write; `make mongo-init` just materializes DB up front.
- **Huma / OpenAPI** — later, only if formal public API wanted (§4).
- **CI/CD** — now implemented (was deferred): GitHub Actions
  (`.github/workflows/ci.yml`) runs vet + build + test on every push/PR to
  `master`, auto-deploys to prod host over SSH on green `master` push. Dev & prod
  share this host. See DEPLOYMENT.md §8.
