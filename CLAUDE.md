# CLAUDE.md — working agreement for `site-of-tools`

`corpberry.com` — Stas's personal portfolio + a collection of small self-built
tools. **One Go binary** serves the apex site and every simple tool, dispatching
by subdomain. Full design in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md);
edge/container plumbing in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Context: the owner is a Python backend dev (FastAPI fan), new to Go and to this
frontend stack. Favor the simple, idiomatic path and explain Go-specific choices.

## Golden rules

1. **Layer everything.** Business logic lives in a domain package (pure Go,
   returns structs), never in a handler. Handlers parse input → call domain →
   `platform.Respond(...)`. This is what lets one feature serve HTML + JSON + htmx
   fragment with zero duplication. See ARCHITECTURE §4.
2. **Every feature speaks HTML and JSON** via content negotiation (browser/htmx →
   HTML, everyone else → JSON). Don't build separate API and web features.
3. **No Node/npm. Ever.** Frontend JS (htmx, Alpine) is vendored under
   `shared/static/js/`. CSS is built by the Tailwind **standalone binary**. If a
   task tempts you toward `npm`/`node_modules`, stop.
4. **htmx only when plain HTML can't do it** (AJAX, partial swaps, WS).
5. **Persistence lives below the domain.** MongoDB is now available — a shared
   server (`localhost`), a dedicated `site-of-tools` database, and a
   client in `platform/mongo.go` (`platform.OpenMongo`, `MONGODB_URI` config).
   **No feature uses it yet**, and the app stays stateless until one does. When a
   feature needs storage, put it *below* the domain service (a repository the
   service calls), never in a handler. See ARCHITECTURE §10.
6. **Tests are required and enforced.** Each package's tests live in a
   `<pkg>/tests/` folder (black-box, exported API); run
   `go test ./... -race` (`make test`). The tracked `.githooks/pre-push` hook runs
   `go vet` + `go test` and blocks a failing push (enable once with `make hooks`).
   stdlib `testing` + `go-cmp`; handlers via `httptest`; DB-dependent tests skip
   when the BINs are absent. Don't disable the hook to push red.
7. **Never commit** the `.BIN` databases, `.env`, built `styles.css`, the
   Tailwind/air/Go binaries, or the Go tarball. DB assets are bind-mounted.

## Pinned versions (don't drift; re-verify before bumping)

Go 1.26.x · Echo **v5** (`github.com/labstack/echo/v5`) · htmx 2.0.x · Alpine
3.15.x · Tailwind standalone v4.3.x · air `github.com/air-verse/air` v1.65.x ·
`github.com/ip2location/ip2location-go/v9` v9.8.x · `github.com/ip2location/ip2proxy-go/v4`
v4.2.x · `go.mongodb.org/mongo-driver/v2` v2.8.x (use **/v2**, not v1) ·
`github.com/google/go-cmp`
v0.7.x · base `gcr.io/distroless/static-debian12:nonroot`.

## Echo v5, not v4 (important)

Most Echo material online is v4. This project is **v5**. Differences that bite:
- Handlers: `func(c *echo.Context) error` (Context is a struct pointer).
- Renderer: `Render(c *echo.Context, w io.Writer, name string, data any) error`.
- Multi-subdomain routing: `echo.NewVirtualHostHandler(map[string]*echo.Echo{...})` (no `e.Host()`).
- Start: `echo.StartConfig{Address: ...}.Start(ctx, handler)`.
- Logging: `log/slog` via `middleware.RequestLogger` (no `middleware.Logger()`).
- Host matching includes the **port** — dev keys carry `:8080`, prod is bare.

When unsure of an exact v5 signature, check the pinned v5 docs (context7:
`/labstack/echox` is the v5 docs source) — don't copy a v4 snippet verbatim.

## Layout (Go: one folder = one package)

- `main.go` at repo **root** — the single binary's entrypoint.
- `platform/` — shared importable engine: `config.go`, `app.go`, `render.go`,
  `conn.go`, `mongo.go` (shared Mongo client — plumbing only, no feature uses it yet).
- `shared/` — shared front-end only (base partials + vendored htmx/alpine/css); its
  own package so it can `go:embed` those files.
- `site/` — the apex corpberry.com project (its own package, same embed reason).
- `tools/<tool>/` — each tool subdomain, self-contained (e.g. `tools/iptools/`,
  `tools/botcheck/`): domain code + `handler.go` + `templates/` (+ tool `assets/`)
  + a `tests/` sub-package + a `docs/` folder holding the tool's markdown
  (`docs/README.md`, and for botcheck `docs/RESEARCH.md`/`ROADMAP.md`/`reports/`).
  Each is its own Go package (embed reason); keep `.md` in `docs/`, not the code root.
- Tests go in `<pkg>/tests/` (black-box). A white-box test that needs unexported
  symbols is the exception and sits beside the code as `*_test.go`.
- Don't reintroduce `internal/` or `cmd/`, and don't split a tool's code from its
  templates/assets/docs — co-location is deliberate. New tools go under `tools/`.

## Common commands (Makefile)

- `make deps` — `go mod tidy` (populate go.mod + go.sum)
- `make tools` — Tailwind binary + air + enable git hooks
- `make hooks` — enable the pre-push test gate
- `make assets` — download IP2Location LITE BINs (uses `.env` token)
- `make mongo-init` — create the `site-of-tools` Mongo database (needs `MONGODB_URI`; run from a host that can reach the server)
- `make css` / `make css-watch` — build / watch `styles.css`
- `make dev` — live reload (`APP_ENV=dev`, disk FS + template reparse)
- `make test` — `go test ./... -race`
- `make build` / `make docker` — prod

## Gotchas worth remembering

- `go:embed` line must sit directly above the `var`; run the binary from repo
  root in dev (`os.DirFS` is cwd-relative).
- Tailwind sees only **literal** class strings — never build class names in Go.
- Alpine needs `defer`; re-init Alpine on `htmx:afterSwap` for swapped-in markup.
- In containers bind `0.0.0.0:8080` (not container-loopback); publish to host loopback.
- nginx must `proxy_set_header Host $host;` or host routing collapses.

## Don't do

- Don't reach for a JS SPA framework here — that's for separate subdomain projects.
- Don't add Huma/OpenAPI unless a formal public API is explicitly wanted (later bolt-on).
- Don't downgrade `ip2proxy-go` below `/v4` — v3 panics opening the PX12 database.
