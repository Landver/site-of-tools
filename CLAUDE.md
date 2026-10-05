# CLAUDE.md — working agreement for `site-of-tools`

`corpberry.com`: Stas's portfolio + small self-built tools. **One Go binary**
serves the apex site and every tool, dispatching by subdomain. Design:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); edge/container:
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Owner = Python/FastAPI dev, new to
Go + this frontend stack: prefer the simple idiomatic path, explain Go choices.

## Golden rules

1. **Layer everything.** Logic in a pure-Go domain package returning structs,
   never in a handler. Handler: parse input → call domain → `platform.Respond`.
2. **Every feature speaks HTML + JSON + MCP** from one domain call: browser/htmx
   → HTML, others → JSON, agents → a tool in `tools/mcptools`. A new API
   endpoint ships w/ its MCP tool or a `mcptools.Coverage` exclusion (test-enforced).
3. **No Node/npm. Ever.** htmx/Alpine vendored in `shared/static/js/`; CSS via
   the Tailwind **standalone binary**.
4. **htmx only when plain HTML can't** (AJAX, partial swaps, WS).
5. **Persistence below the domain.** One Mongo client (`platform.OpenMongo` in
   `main.go`, `MONGODB_URI`); repositories take `*mongo.Database`, self-prune
   via `platform.EnsureTTLIndex`, are nil-safe (no URI → app boots stateless).
6. **Tests required.** Black-box in `<pkg>/tests/` (white-box `*_test.go` only
   for unexported needs); `testing` + `go-cmp`; handlers via `httptest`; DB/BIN
   tests skip when absent. `make test` = `go test ./... -race`; pre-push hook
   (`make hooks`) blocks red pushes — never disable it.
7. **Never commit** `.BIN` databases, `.env`/`.env.prod`, built `styles.css`,
   `shared/static/wasm/`, tool binaries, Go tarballs.

## Pinned versions (don't drift; re-verify before bumping)

Go 1.26.x · `github.com/labstack/echo/v5` · htmx 2.0.x · Alpine 3.15.x ·
Tailwind v4.3.x · air v1.65.x · `ip2location-go/v9` v9.8.x ·
`ip2proxy-go/v4` v4.2.x (v3 panics on PX12) · `miekg/dns` v1.1.73 ·
`go.mongodb.org/mongo-driver/v2` v2.8.x · `x/net` v0.57.x · `x/crypto` v0.54.x
(ciphertools only) · `go-cmp` v0.7.x · `goldmark` v1.8.4 · `goldmark-meta`
v1.1.0 · `modelcontextprotocol/go-sdk` v1.8.x + `google/jsonschema-go` v0.4.x
(mcptools only) · `gcr.io/distroless/static-debian12:nonroot`.

## Echo v5, not v4

Most Echo material online is v4. v5: handlers `func(c *echo.Context) error`;
`Render(c *echo.Context, w io.Writer, name string, data any) error`; subdomains
via `echo.NewVirtualHostHandler(map[string]*echo.Echo{...})`; start via
`echo.StartConfig{...}.Start(ctx, h)`; logging = `log/slog` +
`middleware.RequestLogger`; host matching includes the port (dev keys carry
`:8080`). Unsure → context7 `/labstack/echox`; never paste a v4 snippet.

## Layout (one folder = one package)

- `main.go` (root): config → sub-apps → vhost map → listen.
- `platform/`: shared engine — config, app factory, `Respond`/`Reply`, Mongo,
  `netgate.go` (**outbound SSRF gate**: anything dialling a caller-chosen host
  uses `EgressGuard`, never its own copy), `ratelimit.go` (each package's
  `Limits`, built once in `main.go`, shared by REST and MCP), redact, credits.
- `shared/`: base partials + vendored JS/CSS (own package for `go:embed`).
- `site/`: apex landing, tools index, blog (`site/posts/*.md`, frontmatter
  `title`, `description`, quoted `date: "YYYY-MM-DD"`, optional `draft: true`).
- `tools/<tool>/`: one subdomain each — domain code, `handler.go`,
  `templates/`, `tests/`, `docs/` (markdown lives only there).
- `tools/ciphertools/` builds **twice** (native + wasm in the browser): only
  `handler.go` (`//go:build !js`) may import Echo/`platform`; the rest is pure
  Go, no I/O. No silent server fallback when the engine fails.
- `tools/mcptools/` (mcp.corpberry.com): adapters only, args → the same domain
  call → result; tool packages never import the SDK. Docs in its `docs/`.
- No `internal/` or `cmd/`; keep a tool's code, templates and docs together.

## Commands (Makefile)

`deps` (go mod tidy) · `tools` (Tailwind + air + hooks) · `hooks` · `assets`
(IP2Location BINs) · `mongo-init` · `css` / `css-watch` · `wasm` (cipher
engine) · `dev` (live reload) · `test` · `build` / `docker`.

## Gotchas

- `//go:embed` sits right above its `var`; run from repo root in dev.
- Tailwind sees only **literal** class strings: never build class names in Go.
- Alpine needs `defer`; re-init it on `htmx:afterSwap`.
- Containers bind `0.0.0.0:8080`; nginx must `proxy_set_header Host $host;`.
- `wasm_exec.js` must match the Go that built `cipher.wasm`; wasm vet only
  `./tools/ciphertools ./tools/ciphertools/wasm`.
- `{{else with}}` doesn't parse here: nest `if`/`with`.
- New template func → `navBaseFuncs` + `main.go` navFuncs (+ a
  `ciphertools.FragmentTemplates` stub if a cipher template calls it).
- Goldens: `UPDATE_GOLDEN=1` rewrites them; review the diff.

## Don't

- No JS SPA framework here (separate subdomain projects).
- No Huma/OpenAPI unless a formal public API is wanted.
