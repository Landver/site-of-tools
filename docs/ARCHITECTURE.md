# Architecture — corpberry.com (`site-of-tools`)

`corpberry.com` = Stas's playground: a portfolio landing plus small self-built
tools. **One Go server** serves the apex site and every *simple* tool; projects
that need a real SPA get their own subdomain and stack elsewhere. Practical, not
exhaustive: change something → edit this doc.

## 1. Stack (pinned)

No Node/npm in the toolchain: frontend JS is vendored, CSS comes from one
prebuilt binary.

| Layer | Choice | Version |
|---|---|---|
| Language | Go (no LTS: track the latest 2 series) | 1.26.x |
| Web | Echo **v5** `github.com/labstack/echo/v5` | v5.3.x |
| Templates | stdlib `html/template`, server-rendered | — |
| Interactivity | htmx (only when plain HTML can't) + Alpine.js, self-hosted | 2.0.x / 3.15.x |
| CSS | Tailwind **standalone CLI** | v4.3.x |
| Live reload | air | v1.65.x |
| GeoIP / proxy | `ip2location-go/v9`, `ip2proxy-go/v4` (v4 needed for PX12) | v9.8.x / v4.2.x |
| Database | MongoDB `go.mongodb.org/mongo-driver/v2` (**/v2**) | v2.8.x |
| MCP | `modelcontextprotocol/go-sdk` + `google/jsonschema-go` | v1.8.x / v0.4.x |
| Tests | stdlib `testing` + `go-cmp` | v0.7.x |
| Container | `gcr.io/distroless/static-debian12:nonroot` | — |

**Echo v5, not v4:** v4 loses security support 2026-12-31 and most tutorials
still show v4. v5: `func(c *echo.Context) error`; `Render(c, w, name, data)`;
subdomains via `echo.NewVirtualHostHandler`; logging via `log/slog` +
`middleware.RequestLogger`; start via `echo.StartConfig{...}.Start`.
**go-cmp, not testify:** the stdlib runner is the right tool; go-cmp adds
readable diffs.

## 2. Topology

```
client → Cloudflare (proxy ON, the only thing in front) → nginx (TLS, one server{} per subdomain)
       → Go binary in a container, :8080, dispatching by Host (§3)
```

Ports, nginx, Docker and the client-IP trust model: [DEPLOYMENT.md](DEPLOYMENT.md).

## 3. One binary, many subdomains (host routing)

One process; each subdomain is its own `*echo.Echo` from the shared factory
`platform.NewApp` (renderer, Cloudflare-aware IP extractor, recover, request
log, security headers, gzip, static files). `main.go` builds one app per entry
of its `subdomains` list and hands the Host → app map to
`echo.NewVirtualHostHandler`.

- Host keys come from config (`cfg.VHost`): `*.localhost:8080` in dev (v5 matches
  the port too), bare domains in prod.
- Hosts: apex (`site`), `ip.`, `botcheck.`, `dns.`, `link.`, `cipher.`, `mcp.`.
  The same list feeds the outbound guards' deny list.
- New subdomain = one list entry + its `Register` + an nginx block. Never a new
  service.

## 4. Request layering (the core pattern — read this)

```
domain layer      Service.Lookup("8.8.8.8") → (*Result, error)    pure Go, no HTTP, written once
transport layer   handler: parse input → domain call → Respond(c, code, data, page, frag)
                    • API/CLI (no text/html in Accept) → JSON
                    • htmx (HX-Request)                → HTML fragment
                    • browser (Accept: text/html)      → full page
```

**Business logic never lives in a handler.** That is how one feature speaks
three representations with no duplication: `curl 'https://ip.corpberry.com/?ip=8.8.8.8'`
gets JSON, a browser gets the page. `platform.Respond` serves a domain struct
directly; `platform.Reply` covers routes whose page view model differs from
the JSON body. Responses vary on `Accept`, `HX-Request` and
`HX-History-Restore-Request`, fragments are `no-store`, and a history restore
gets the full page.

**Third transport: MCP.** `tools/mcptools` serves the same domain calls to AI
agents at `mcp.corpberry.com` (stateless Streamable HTTP, JSON responses):
`/mcp` = every public tool, `/mcp/<toolset>` = one toolset, `/mcp/owner` = the
owner's short-link writes behind `MCP_OWNER_KEY`. An adapter only maps typed
arguments → the handler's domain call → result. Each tool spends its REST
twin's `Limits`, so a client has one budget whichever door it uses.
`mcptools.Coverage` maps every REST route to a tool or a reasoned exclusion,
and a test fails on a route without one. Details:
[tools/mcptools/docs/](../tools/mcptools/docs/README.md).

```
GET  dns.corpberry.com/?name=x → handler → dnstools.LookupEnriched → Respond
POST mcp.corpberry.com/mcp/dns → gate → SDK → middleware → adapter → dnstools.LookupEnriched
```

A formal, versioned public JSON API would be **Huma** on `/api/v1` over the same
domain functions — a bolt-on, not now.

## 5. Rendering & assets

- **Templates:** each package embeds its own `templates/` (`go:embed` can't
  cross directories); all parse into one set addressed by unique
  `{{define}}` names (`ip/index`, `partials/head`). Prod serves the embedded copy;
  dev (`APP_ENV=dev`) reads disk via `os.DirFS` and re-parses per request
  (`platform.SubFS`, `platform.NewRenderer`).
- **CSS:** Tailwind v4, CSS-first: `shared/static/css/input.css` `@source`-scans
  every package's templates and builds `styles.css` (gitignored). Tailwind sees
  only literal class names: never assemble them in Go.
- **htmx + Alpine:** vendored in `shared/static/js/`; htmx first, Alpine last
  with `defer`; re-init Alpine on `htmx:afterSwap`.
- **Security headers** (`platform/app.go`, every sub-app): CSP, `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`. `worker-src` allows `blob:`
  (botcheck's Worker); `connect-src` allows only `api6.ipify.org` off-origin.
  `script-src` keeps `'unsafe-inline'`/`'unsafe-eval'` for Alpine — tightening
  it needs Alpine's CSP build plus per-request nonces.

## 6. Configuration

Env vars only: repo-root `.env` in dev, `.env` + `.env.prod` via compose in prod
(`platform/config.go`).

| Var | Purpose |
|---|---|
| `APP_ENV` | `dev` (disk FS, template reparse) or `prod` |
| `LISTEN_ADDR` / `BASE_DOMAIN` | bind address; vhost keys (`localhost` in dev) |
| `IP2LOCATION_DB11_V4`/`_V6`, `IP2LOCATION_ASN_V4`/`_V6`, `IP2PROXY_PX12` | BIN paths (PX12 optional) |
| `IP2LOCATION_DOWNLOAD_TOKEN` | `make assets` only |
| `MONGODB_URI` / `MONGODB_DATABASE` | optional; empty → stateless (§10) |
| `LINK_API_KEY` | short-link writes on link.corpberry.com |
| `MCP_OWNER_KEY` | `/mcp/owner`; empty → 404 |
| `EGRESS_DENY_ADDRS` | host's public IPs/CIDRs every outbound guard refuses |

Missing data is never fatal: absent BINs, Mongo or keys switch the feature off.

## 7. Directory layout

One folder = one package; `platform/` must be importable and every package that
embeds templates must own them.

```
main.go            entrypoint: config → apps → vhost map → listen
platform/          engine: config, app, render, mongo, conn, netgate, redact, ratelimit, credits, text
shared/            base partials + vendored htmx/alpine/css (embedded)
site/              apex: landing, tools index, blog (site/posts/*.md)
tools/<tool>/      one subdomain each: domain code · handler.go · embed.go · templates/ · tests/ · docs/
  iptools · botcheck · dnstools · linktools (+ extension/) · ciphertools (+ wasm/) · mcptools
docs/              ARCHITECTURE.md, DEPLOYMENT.md
```

Cross-cutting engine files:
- `platform/netgate.go` — the **outbound gate**. `PubliclyRoutable` is the
  deny-by-default address check (unmapping first). `EgressGuard` applies it as a
  `net.Dialer.Control` hook, after resolution, on the address actually dialled
  (no DNS-rebinding window), plus a port allowlist and a host/IP deny list;
  `Transport` builds the guarded HTTP client (no proxy, no keep-alive).
  `RateLimitKey` keys clients by IP, IPv6 by its /64. Anything dialling a
  caller-chosen host uses it.
- `platform/redact.go` — strips pasted-URL query values (`u`, `a`, `b`, `curl`,
  `text`, `v`) before **both** log sinks, splitting by hand so a malformed escape
  can't leak.
- `platform/ratelimit.go` — `Limiter` and the non-queueing `Cap` with per-client
  shares; each package's `Limits` is built once and shared by REST and MCP.
- `platform/credits.go` — data-source credits for the footer and MCP results.

## 8. Adding a new tool

1. Simple tool → here; real SPA → its own subdomain and stack elsewhere.
2. `tools/mytool/`: a pure-Go domain service returning structs, `handler.go`
   with `Register(e, deps, lim)`, `embed.go`, `templates/`, `tests/`.
3. Handlers call the domain, then `platform.Respond`.
4. Add its `TemplateSource` and `subdomains` entry in `main.go`, and an nginx
   block (DEPLOYMENT §3).
5. Data files go in `mytool/assets/`, gitignored and bind-mounted.
6. Every route gets an MCP decision — a tool in `tools/mcptools` or a
   `Coverage` exclusion — and its page's terminal block ends with
   `{{template "partials/mcp-hint" "<toolset>"}}`.

## 9. Testing

- Black-box tests in `<pkg>/tests/`; a test that needs unexported internals sits
  beside the code as `foo_test.go`.
- `go test ./... -race` (`make test`); table-driven domain tests; handlers via
  `httptest`; `go-cmp` for structs; small interfaces so tests inject fakes.
- BIN- or Mongo-dependent tests skip when absent; goldens rewrite with
  `UPDATE_GOLDEN=1`.
- The tracked pre-push hook (`make hooks`) runs vet + tests and blocks red pushes.

## 10. Out of scope now (deliberately deferred)

- **MongoDB** is wired (one client from `platform.OpenMongo`, repositories below
  the domain, self-pruning via `platform.EnsureTTLIndex`, all no-ops without
  `MONGODB_URI`) and used by: IP lookup history, the request log (one record per
  request, and per MCP message: tool, outcome, latency, IP — never arguments or
  results), botcheck's fingerprint corpus, and link short links (the only one
  that *is* the feature: unique index, long TTL so a slug is never reissued).
  Further storage follows the same shape.
- **Huma / OpenAPI** — only if a formal public API is wanted (§4).
