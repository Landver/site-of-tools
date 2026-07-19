# Architecture — corpberry.com (`site-of-tools`)

`corpberry.com` is Stas's personal playground: a portfolio landing page plus a
growing collection of small self-built tools and experiments. This repo is the
**one Go server** that powers the apex site and every *simple* tool. Bigger
projects that need a real SPA get their own subdomain and their own stack
(Next.js etc.) later — they do **not** live here.

> Scope note: keep this doc practical, not exhaustive. It exists so a human or
> an AI can pick up development without re-deriving the design. When something
> changes, edit the doc.

---

## 1. Stack (pinned)

No Node/npm anywhere in the toolchain. Frontend JS is vendored as static files;
CSS is built by a single prebuilt binary.

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

**Why Echo v5, not v4:** v5 is the current stable major; v4 loses security
support 2026-12-31 and v4→v5 is a breaking migration. Starting greenfield we go
straight to v5. Practical consequence: most Echo tutorials/blogs online still
show v4 — translate them. Key v5 differences:
- Handlers are `func(c *echo.Context) error` (Context is a **struct pointer**, not an interface).
- Renderer signature is `Render(c *echo.Context, w io.Writer, name string, data any) error`.
- No `e.Host()`. Multi-subdomain routing uses `echo.NewVirtualHostHandler(map[string]*echo.Echo{...})` (§3).
- No `middleware.Logger()`. Logging is `log/slog` via `middleware.RequestLogger`.
- Start via `echo.StartConfig{Address: ...}.Start(ctx, handler)`.
- `IPExtractor` / `ExtractIPFromXFFHeader` / `TrustOption` carry over from v4.

**Why go-cmp, not testify:** the Go stdlib test runner *is* the good tool here
(fast, parallel, subtests, fuzzing built in). For value comparison, go-cmp gives
readable diffs and is the idiomatic modern choice; testify is the ubiquitous-
but-unremarkable default we skip on purpose.

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

Deployment specifics (nginx blocks in `deploy/nginx/`, Docker, ports, Cloudflare
trust) live in [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 3. One binary, many subdomains (host routing)

The whole site is a single process. Each subdomain is its own `*echo.Echo`
instance, all built by a shared factory (`platform.NewApp`) so they share
middleware, the renderer, the IP extractor, and static-file serving. A
virtual-host handler dispatches by `Host` header.

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

- Host keys are **derived from config** (`cfg.VHost`) so dev uses `*.localhost`
  (browsers auto-route `*.localhost` → 127.0.0.1) and prod uses the real domains.
- v5 matches the **full Host header including the port**, so dev keys carry
  `:8080` (`ip.localhost:8080`) while prod nginx forwards a bare host
  (`ip.corpberry.com`). `VHost` handles that difference.
- **Adding a subdomain = one `*echo.Echo` + one map entry + one nginx block.** Never a new service.

---

## 4. Request layering (the core pattern — read this)

Every feature serves **HTML for browsers and JSON for API/CLI clients** from the
*same* code. This is achieved by layering, not by duplicating features:

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

**Rule: business logic never lives in a handler.** Handlers parse input, call a
domain function, and hand the result to `Respond`. That is the only reason one
feature can speak three representations with zero duplication.

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

Result: `curl 'https://ip.corpberry.com/?ip=8.8.8.8'` returns JSON automatically
(curl sends `Accept: */*`, no `text/html`); a browser at the same URL gets the page.
See [tools/iptools/](../tools/iptools/docs/README.md).

> When a real, documented, versioned **public JSON API** is wanted later, add
> **Huma** (`humaecho` adapter) on `/api/v1` of the relevant sub-app. It reuses
> the same domain functions — pure bolt-on, no rework. Not needed now.

---

## 5. Rendering & assets

**Templates** — stdlib `html/template`. Shared base partials (`head`/`header`/
`footer`) live in `shared/templates/`; each project adds its own templates. All
are parsed into one set, addressed by unique `{{define "name"}}` names (e.g.
`site/home`, `ip/index`, `ip/result`, `partials/head`). Auto-escaped.

**`go:embed` with a dev/prod toggle** — each package embeds *its own* `templates`
(and `shared` also embeds `static`), because `go:embed` cannot reach across
directories. Prod serves the embedded copy; dev (`APP_ENV=dev`) reads the same
dirs from disk via `os.DirFS` **and re-parses per request**, so edits show on
refresh with no rebuild.

```go
// shared/embed.go  (site/ and tools/<tool>/ embed their own templates likewise)
//go:embed templates
var Templates embed.FS
//go:embed all:static
var Static embed.FS
```
`platform.SubFS(embed, "templates", "shared/templates", dev)` returns the disk FS
in dev, else the embedded tree with the prefix stripped. `platform.NewRenderer`
takes one `TemplateSource` per package and parses them into a single set.
Gotchas: `//go:embed` must sit directly above the `var`; patterns can't use `..`
(hence one embed per package dir); run the binary from repo root in dev.

**CSS — Tailwind v4, CSS-first, no config file.** Source is
`shared/static/css/input.css`, which `@source`-scans every project's templates:
```css
@import "tailwindcss";
@source "../../templates/**/*.html";               /* shared */
@source "../../../site/templates/**/*.html";
@source "../../../tools/iptools/templates/**/*.html";
@theme { --color-brand: #b83266; }
```
Built to `shared/static/css/styles.css` (`--minify` prod, `--watch` dev).
`styles.css` is a build artifact (gitignored; built in the Docker image and by
`make css`). **Tailwind only sees literal class strings** — never assemble class
names in Go; use full literals or `@source inline(...)`.

**htmx + Alpine — vendored** under `shared/static/js/` (pinned, self-hosted, no
CDN in prod). Load order in the base head partial:
```html
<script src="/static/js/htmx.min.js"></script>          <!-- first, no defer -->
<script defer src="/static/js/alpine.min.js"></script>  <!-- last, MUST defer -->
```
**Critical interplay bug:** Alpine scans the DOM once at boot; markup htmx *swaps
in* later with `x-data` etc. is dead unless re-initialized:
```js
document.body.addEventListener('htmx:afterSwap', e => window.Alpine.initTree(e.detail.elt));
```
Keep htmx-owned and Alpine-owned regions distinct.

---

## 6. Configuration

12-factor: all config via env vars, loaded from a repo-root `.env` in dev
(gitignored), injected by `docker-compose` in prod. Config type + loader live in
`platform/config.go`.

| Var | Purpose | Example |
|-----|---------|---------|
| `APP_ENV` | `dev` (disk FS + template reparse) or `prod` (embedded) | `dev` |
| `LISTEN_ADDR` | bind address inside the process | `:8080` |
| `BASE_DOMAIN` | builds vhost keys; `localhost` in dev | `corpberry.com` |
| `IP2LOCATION_DB11_V4` / `_V6` | paths to DB11 BINs | `tools/iptools/assets/ipv4/...BIN` |
| `IP2LOCATION_ASN_V4` / `_V6` | paths to ASN BINs | `tools/iptools/assets/asn/...BIN` |
| `IP2PROXY_PX12` | IP2Proxy PX12 BIN — optional; enables the proxy section | `tools/iptools/assets/ip2proxy/...BIN` |
| `IP2LOCATION_DOWNLOAD_TOKEN` | used by `make assets` only (not the app) | — |
| `MONGODB_URI` | MongoDB connection string (credentials + auth db). Optional — empty disables Mongo | `mongodb://user:pass@localhost/admin` |
| `MONGODB_DATABASE` | app database name; defaults to `site-of-tools` | `site-of-tools` |

**MongoDB** is a *network* dependency, not a bind-mounted file like the BINs, so
the same `MONGODB_URI` works from dev and prod (add it to `.env` wherever you run
the app; dev and prod share the host but not necessarily the working copy). The
config lives in `platform/config.go` and the client in `platform/mongo.go`
(`platform.OpenMongo` → a nil-safe `*Mongo` wrapper). It is **optional and
degrades gracefully**: an empty `MONGODB_URI` yields `ErrMongoUnavailable`, exactly
the "missing data is non-fatal" contract `iptools.OpenService` uses for absent
BINs. Its first users are the IP-tool lookup history and the engine-level request
log (§10).

---

## 7. Directory layout

Go rule: **one folder = one package**. Two constraints shape the tree — a package
others import can't be `package main`, and `go:embed` can't cross directories
(so a tool that co-locates its own `templates/` must be its own package).

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
│       ├── botcheck.go · scoring.go · handler.go · embed.go · tests/
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

Why each folder exists: `platform/` must be importable (can't be `main`);
`shared/`, `site/`, and each `tools/<tool>/` must each be a package to embed the
templates that sit beside their code. `tools/` groups the tool subdomains (each
its own Go package, e.g. `tools/iptools`, `tools/botcheck`); the apex `site/`
stays at the root. `main.go` is at the root because the composition root is the
one thing nothing imports. Nothing is a single-file folder for its own sake.

---

## 8. Adding a new tool

1. Decide: simple tool (lives here) or real SPA (own subdomain + own stack — not here).
2. `mytool/` — a package with: `geoip.go`-style domain service (pure Go, returns
   structs), `handler.go` with `Register(e, deps)`, `embed.go` (`//go:embed templates`),
   `templates/`, and a `tests/` sub-package.
3. Handlers call the domain service, then `platform.Respond(...)` — free HTML+JSON+fragment.
4. Register the tool's `TemplateSource` in `main.go`'s renderer, and (new subdomain)
   add a `*echo.Echo` + a `cfg.VHost` map entry + an `deploy/nginx/` block.
5. Tool data files? Keep them in `mytool/assets/`, env-configured path, gitignored,
   bind-mounted — never baked into the image.

---

## 9. Testing

- Each package's tests live in its own **`<pkg>/tests/`** folder (black-box —
  they use only the package's exported API, so no test file sits among the code).
  A test that genuinely needs unexported internals is the exception and sits
  beside the code as `foo_test.go`.
- stdlib `testing`; run `go test ./... -race` (`make test`). Domain logic is
  table-driven; HTTP handlers are driven through `net/http/httptest` +
  `app.ServeHTTP`; struct comparisons use `go-cmp`.
- Handlers depend on **small interfaces** (e.g. `iptools.Looker`) so tests
  inject fakes and never need the real databases.
- Tests that *do* need the BINs are **integration tests that skip** when the files
  aren't present, so CI and fresh clones stay green (the BINs are gitignored).
- A tracked **pre-push hook** (`.githooks/pre-push`, enabled by `make hooks`) runs
  `go vet ./...` + `go test ./...` and blocks the push on failure.

---

## 10. Out of scope now (deliberately deferred)

- **Persistence / MongoDB** — wired and now in use by three features: the
  IP tool's **lookup history** (`tools/iptools/history.go`, a repository below the
  domain per rule #5), the engine-level **request log** (`platform/requestlog.go`,
  a shared async writer fed by the request-logger middleware), and botcheck's
  **fingerprint corpus** (`tools/botcheck/corpus.go`, the rolling 30-day store
  behind the `fingerprint_reuse` rule). All take the
  `*mongo.Database` from the shared client (`platform.OpenMongo`, opened once in
  `main.go`) and self-prune via `platform.EnsureTTLIndex`; all degrade to no-ops
  when `MONGODB_URI` is empty, so the app still boots stateless. Further storage
  features (e.g. botcheck crowd/rarity scoring, request velocity, IP-tool rate
  limiting) follow the same shape. Mongo creates collections lazily on first write;
  `make mongo-init` just materializes the database up front.
- **Huma / OpenAPI** — later, only if a formal public API is wanted (§4).
- **CI/CD** — now implemented (was deferred): GitHub Actions (`.github/workflows/ci.yml`)
  runs vet + build + test on every push/PR to `master` and auto-deploys to the prod
  host over SSH on a green `master` push. Dev and prod share this host. See DEPLOYMENT.md §8.
