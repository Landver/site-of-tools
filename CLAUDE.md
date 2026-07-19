# CLAUDE.md — working agreement for `site-of-tools`

`corpberry.com` — Stas's personal portfolio + collection small self-built
tools. **One Go binary** serves apex site + every simple tool, dispatching
by subdomain. Full design in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md);
edge/container plumbing in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

Context: owner = Python backend dev (FastAPI fan), new to Go + this frontend
stack. Favor simple, idiomatic path, explain Go-specific choices.

## Golden rules

1. **Layer everything.** Business logic lives in domain package (pure Go,
   returns structs), never handler. Handlers parse input → call domain →
   `platform.Respond(...)`. Lets one feature serve HTML + JSON + htmx
   fragment w/ zero duplication. See ARCHITECTURE §4.
2. **Every feature speaks HTML + JSON** via content negotiation (browser/htmx →
   HTML, everyone else → JSON). Don't build separate API + web features.
3. **No Node/npm. Ever.** Frontend JS (htmx, Alpine) vendored under
   `shared/static/js/`. CSS built by Tailwind **standalone binary**. Task
   tempts toward `npm`/`node_modules` → stop.
4. **htmx only when plain HTML can't do it** (AJAX, partial swaps, WS).
5. **Persistence lives below domain.** MongoDB wired — shared server
   (`localhost`), `site-of-tools` database, client in
   `platform/mongo.go` (`platform.OpenMongo`, opened once in `main.go`,
   `MONGODB_URI` config). Three features use it: IP tool's **lookup history**
   (`tools/iptools/history.go`), engine-level **request log**
   (`platform/requestlog.go`), botcheck's **fingerprint corpus**
   (`tools/botcheck/corpus.go`). All nil-safe — empty `MONGODB_URI` disables
   Mongo, they no-op, app still boots stateless. New storage sits *below* the
   domain service (repository the service/handler calls), never driver in
   handler; take `*mongo.Database` from shared client, ensure self-pruning
   index w/ `platform.EnsureTTLIndex`. See ARCHITECTURE §10.
6. **Tests required + enforced.** Each package's tests live in a
   `<pkg>/tests/` folder (black-box, exported API); run
   `go test ./... -race` (`make test`). Tracked `.githooks/pre-push` hook runs
   `go vet` + `go test`, blocks failing push (enable once w/ `make hooks`).
   stdlib `testing` + `go-cmp`; handlers via `httptest`; DB-dependent tests
   skip when BINs absent. Don't disable hook to push red.
7. **Never commit** `.BIN` databases, `.env`, built `styles.css`, Tailwind/air/
   Go binaries, Go tarball. DB assets bind-mounted.

## Pinned versions (don't drift; re-verify before bumping)

Go 1.26.x · Echo **v5** (`github.com/labstack/echo/v5`) · htmx 2.0.x · Alpine
3.15.x · Tailwind standalone v4.3.x · air `github.com/air-verse/air` v1.65.x ·
`github.com/ip2location/ip2location-go/v9` v9.8.x · `github.com/ip2location/ip2proxy-go/v4`
v4.2.x · `go.mongodb.org/mongo-driver/v2` v2.8.x (use **/v2**, not v1) ·
`github.com/google/go-cmp`
v0.7.x · base `gcr.io/distroless/static-debian12:nonroot`.

## Echo v5, not v4 (important)

Most Echo material online is v4. This project = **v5**. Differences that bite:
- Handlers: `func(c *echo.Context) error` (Context = struct pointer).
- Renderer: `Render(c *echo.Context, w io.Writer, name string, data any) error`.
- Multi-subdomain routing: `echo.NewVirtualHostHandler(map[string]*echo.Echo{...})` (no `e.Host()`).
- Start: `echo.StartConfig{Address: ...}.Start(ctx, handler)`.
- Logging: `log/slog` via `middleware.RequestLogger` (no `middleware.Logger()`).
- Host matching includes **port** — dev keys carry `:8080`, prod bare.

Unsure of exact v5 signature → check pinned v5 docs (context7:
`/labstack/echox` = v5 docs source) — don't copy a v4 snippet verbatim.

## Layout (Go: one folder = one package)

- `main.go` at repo **root** — single binary's entrypoint.
- `platform/` — shared importable engine: `config.go`, `app.go`, `render.go`,
  `conn.go`, `mongo.go` (shared Mongo client; used by request log, IP-tool lookup history, botcheck fingerprint corpus — see rule #5).
- `shared/` — shared front-end only (base partials + vendored htmx/alpine/css); own
  package so it can `go:embed` those files.
- `site/` — apex corpberry.com project (own package, same embed reason).
- `tools/<tool>/` — each tool subdomain, self-contained (e.g. `tools/iptools/`,
  `tools/botcheck/`): domain code + `handler.go` + `templates/` (+ tool `assets/`)
  + `tests/` sub-package + `docs/` folder holding tool's markdown
  (`docs/README.md`, botcheck's index at `docs/README.md` linking out
  to `docs/RESEARCH.md`/`reports/`, `docs/roadmap/`, `docs/testing/`, and
  per-topic reference files — split by topic, keep any single doc read
  small).
  Each own Go package (embed reason); keep `.md` in `docs/`, not code root.
- Tests go in `<pkg>/tests/` (black-box). White-box test needing unexported
  symbols = exception, sits beside code as `*_test.go`.
- Don't reintroduce `internal/` or `cmd/`, don't split tool's code from its
  templates/assets/docs — co-location deliberate. New tools go under `tools/`.

## Common commands (Makefile)

- `make deps` — `go mod tidy` (populate go.mod + go.sum)
- `make tools` — Tailwind binary + air + enable git hooks
- `make hooks` — enable pre-push test gate
- `make assets` — download IP2Location LITE BINs (uses `.env` token)
- `make mongo-init` — create `site-of-tools` Mongo database (needs `MONGODB_URI`; run from a host that can reach server)
- `make css` / `make css-watch` — build / watch `styles.css`
- `make dev` — live reload (`APP_ENV=dev`, disk FS + template reparse)
- `make test` — `go test ./... -race`
- `make build` / `make docker` — prod

## Gotchas worth remembering

- `go:embed` line must sit directly above `var`; run binary from repo
  root in dev (`os.DirFS` is cwd-relative).
- Tailwind sees only **literal** class strings — never build class names in Go.
- Alpine needs `defer`; re-init Alpine on `htmx:afterSwap` for swapped-in markup.
- Containers bind `0.0.0.0:8080` (not container-loopback); publish to host loopback.
- nginx must `proxy_set_header Host $host;` or host routing collapses.

## Don't do

- Don't reach for JS SPA framework here — that's for separate subdomain projects.
- Don't add Huma/OpenAPI unless formal public API explicitly wanted (later bolt-on).
- Don't downgrade `ip2proxy-go` below `/v4` — v3 panics opening the PX12 database.
