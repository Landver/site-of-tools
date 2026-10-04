# Security, abuse and operations

Part of the [MCP plan](README.md). Rewritten after review round 1
([log](03-review-log.md)): two blockers and several majors there were real,
and some of them are weaknesses REST already has that MCP would make cheaper
to exploit.

## 1. Threat model

**Who:** anonymous agents and scripts calling `/mcp` directly; other people's
browsers driven by a hostile page; an honest agent that read attacker-chosen
text (a TXT record, a redirect target) and was steered by it; whoever obtains
the owner key.

**What they can hurt:**

- **The box.** One binary serves every subdomain, so one panic, one memory
  blow-up or one pegged CPU takes the whole site down, not just MCP.
- **Upstreams we are a guest of**: public resolvers, zones' own nameservers,
  Shodan InternetDB (community reports, recorded in the iptools feasibility
  report, put a one-hour IP ban at ~600 fast requests; it recommends ~1 req/s),
  rdap.org, crt.sh, and whatever host `link_redirect_chain` is pointed at.
- **The domain's reputation**: short links on corpberry.com pointing at
  phishing get the whole domain blocklisted (`linktools/short.go`).
- **Secrets passing through cipher tools**, and the logs that could keep them.

## 2. The `/mcp` gate: Echo, before the SDK

Requests the SDK never sees can't hurt it. In order:

| Step | Rule | Why |
|---|---|---|
| 1 | `/mcp/<toolset>` with an unknown toolset → 404 | `getServer` runs twice per request and a nil server is a 400; routing is decided here, and `getServer` stays a pure lookup |
| 2 | Browser `GET` (`Accept: text/html`) → the landing page; any other GET/DELETE/OPTIONS → passed on (the SDK answers 405, `Allow: POST`) | a pasted URL shows something useful; a CORS preflight fails because we send no CORS headers |
| 3 | `/mcp/owner`: the key, from `X-Api-Key` or `Authorization: Bearer` (Codex keeps it in an env var that way), must pass the owner `Shortener`'s own `Authorized` (SHA-256 + constant-time) → else 403, behind a failed-key limiter (1/s, burst 5, then 429). On success both headers are **deleted** and an owner flag goes into the request context. Public endpoints ignore `Authorization` entirely | the SDK copies every request header into each handler's `RequestExtra`; nothing downstream needs the key. A gateway's own bearer token can't trip a 403 on public use |
| 4 | Per-IP HTTP limiter on all of `/mcp` → 429 | protocol chatter |
| 5 | POST body read into memory, at most 1 MiB → 413; a body whose first non-space byte is `[` → **400** | **blocker** (round 1): without `MCP-Protocol-Version` the SDK assumes 2025-03-26, where JSON-RPC batches are still legal, uncapped, and every reply is buffered. Batching left the spec in 2025-06-18. (Nesting depth is already capped at 1000 by the SDK's own JSON reader.) |
| 6 | `Sec-Fetch-Site: cross-site` or `same-site` → 403. Any other `Origin` that isn't ours: **logged** in floor 2b; from floor 3 (D15) an allowlist built from those logs, and 403 for the rest | see §3 |
| 7 | Into the request context: the **raw** client IP (`c.RealIP()`) *and* its limiter key (`platform.RateLimitKey`), plus the request's own context for cancellation | the SDK gives handlers headers but no remote address; the key alone won't do, because for IPv6 it is a `/64` prefix, which `ip_lookup "self"` and `CreatedIP` can't use |
| 8 | `Cache-Control: no-store`, set in a `Before` hook on Echo's response (`echo.UnwrapResponse(c.Response())`), so it lands after the SDK's own header and `echo.WrapHandler` stays as is | the SDK sets `no-cache, no-transform` itself; cipher results can be secrets |

Then the SDK handler: `Stateless`, `JSONResponse`,
`PropagateRequestCancellation`, `MaxRequestBodyBytes: 1 MiB` (a second guard),
`DisableLocalhostProtection` (§3), `Logger: nil` (at Info it writes three lines
per stateless request). nginx's block also sets `client_max_body_size 1m`
rather than copying cipher's 8 MiB.

## 3. Browsers and DNS rebinding (D15)

What actually keeps a hostile page from driving our tools through its visitors'
browsers is already layered, and verified in review: the SDK answers 415 to
anything but `Content-Type: application/json` (so `text/plain`, form posts and
`sendBeacon` fail); a cross-origin JSON POST needs a CORS preflight; we send
no CORS headers, so the preflight fails and the POST is never sent. Scripts
cannot set `Sec-Fetch-*`.

The Origin check sits on top, and it is the one place the plan **knowingly
departs from the spec**, for one floor: the transport section says a present,
invalid `Origin` MUST get 403, while Anthropic's connector docs say strict
Origin checks reject its connectors and don't say what Origin it sends. So:

1. **Floor 2b:** reject browser cross-site requests by `Sec-Fetch-Site` (a header
   only browsers send); log every other foreign `Origin` with its user agent;
   connect a real claude.ai connector, plus ChatGPT if available.
2. **Floor 3:** an allowlist of the `Origin` values hosted clients
   actually sent, and 403 for every other foreign `Origin`. That is compliant.

DNS rebinding: Echo's vhost map matches `Host` exactly and serves an empty app
(404) for anything else (`echo/v5 vhost.go`), so a rebound name never reaches
`/mcp`. The SDK's own localhost check would 403 dev's `mcp.localhost:8080`
(it accepts only the literal `localhost` or a loopback IP), hence
`DisableLocalhostProtection: true`. Tested both ways.

## 4. Inside the SDK: the receiving middleware

Runs once per JSON-RPC message, in the goroutine that runs the handler. In
order:

| Step | Rule | Why |
|---|---|---|
| 1 | `defer recover()` → for `tools/call` an `isError` "internal error" result, otherwise a JSON-RPC internal error; stack logged, arguments not | **blocker** (round 1): the SDK runs handlers in their own goroutines with no `recover` anywhere in v1.8.0, and Echo's `Recover` only guards the HTTP goroutine. A panic that REST turns into a 500 would kill every subdomain. Only `ciphertools.Run` and one dnstools path recover today |
| 2 | Deadline per class (pure 5 s, upstream 25 s, fetch 20 s, heavy 15 s) and `context.AfterFunc` on the HTTP request context | `PropagateRequestCancellation` only cancels 2026-07-28 requests; older clients' work would run to completion |
| 3 | Rate limit: `tools/call` → the tool's class; **every other method** (`server/discover`, `initialize`, `tools/list`, …) → a `protocol` class | list floods; and anything a future SDK lets through |
| 4 | Concurrency caps from the tool package's `Limits`, **the same ones its REST routes use** (floor 1c): `x/sync/semaphore.Weighted` with `TryAcquire`, so a full cap answers "busy, retry in a few seconds" instead of queueing. `upstream` 8, `fetch` 4, `heavy` by memory (≈256 MiB budget; `ciphertools.MemoryCost(op, in)` charges Argon2 and scrypt their own parameters, everything else a flat 16 MiB) | per-IP limits don't bound the box: ten IPs × burst 5 of Argon2 at 64 MiB × 4 threads would, and caps on MCP alone would leave `POST /password/hash` open |
| 5 | Call the tool | |
| 6 | Output post-processing (§7) | |
| 7 | Per-call record (§8), through the existing `RequestLog` repository and slog | rule #5: storage stays below, in the repository that already exists |

## 5. Outbound reach

MCP adds no new place that dials out. But "the same guards" was not true:
only the link tracer (`link_redirect_chain`, REST `/trace`) goes through `platform.EgressGuard`. MCP makes every one of
these paths scriptable at agent speed, so **floor 1b hardens them for REST and
MCP alike** before the `dns` and `link` toolsets ship:

| Path | Dials | Guard today | Floor 1b |
|---|---|---|---|
| `link_redirect_chain` (REST `/trace`) | any URL | `EgressGuard`: 80/443, own vhosts + Mongo + interface addresses denied, no proxy, no keep-alive | one subdomain list feeds both the vhost map and the deny list (the tracer is built before the map today, so "derive it from the map" isn't literally possible); the guard learns to take **literal addresses** into its address deny set (today they only reach its hostname map), fed with the host's public IPs from config, which `net.InterfaceAddrs()` never sees inside the container |
| `dns_email_auth` (MTA-STS) | `https://mta-sts.<domain>/…` | own `dialPublicOnly`, `Proxy: ProxyFromEnvironment`, keep-alives on | `EgressGuard`, port 443 only, `Proxy: nil`, `DisableKeepAlives` (the tracer's own comment explains how the proxy setting bypasses the gate) |
| `dns_consistency`, `dns_trace` | the zone's own nameservers | `routable()` in `spread.go:438` misses CGNAT, multicast, reserved, NAT64; `trace.go`'s `traceRoutable` is already stricter | `platform.PubliclyRoutable` at those two call sites, the promotion `trace.go`'s own comment asks for; its tests already expect the stricter set |
| MX reputation (in `dns_email_auth`) | nothing: it filters addresses before a corpus read and asks the pinned resolver | `routable()` | **no change**: it never dials, and ~20 fixtures sit in TEST-NET ranges that `PubliclyRoutable` would reject |
| `dns_domain_info` | rdap.org, crt.sh, and wherever they redirect | `http.Client` default: follows any redirect | a `CheckRedirect` that requires HTTPS, and every dial to a host other than the configured base goes through the guard. The base itself stays dialable, which keeps the tests' loopback `httptest` servers working |
| `ip_lookup`, `botcheck_score` (with `ip`), DNS enrichment | Shodan InternetDB | `Service.Lookup` calls Shodan **inside every lookup**, with `context.Background()`, so DNS enrichment calls it once per A/AAAA record and once per nameserver | dnstools gets `geo.Offline()`, a copy of the service without Shodan (DNS keeps only ASN/country, so REST output is unchanged); the one `*Shodan` gets a **process-wide** ~1/s limiter; when spent, the open-ports card is skipped and the result says so |

Leaking the origin IP is inherent: any outbound fetch to an attacker's server
shows it. That is why the next section's ingress check is a gate, not a nicety.

## 6. Rate limits and capacity (D12)

- **One budget per client per tool package, whichever door it uses.** Each
  package builds its `Limits` once (floor 1c): rate stores plus concurrency
  caps, handed to its REST `Register` and to `mcptools.Deps`. Otherwise MCP
  doubles every budget, including the `/s/:code` global breaker. Shape:
  `platform/ratelimit.go` holds a `Limiter` alias for Echo's store,
  `NewLimiter(rate, burst)` and a `RateLimit` middleware **always keyed by
  `RateLimitKey`** (dnstools keys on the raw IP today, which would give an IPv6
  client two buckets in a "shared" store); each package has `type Limits
  struct{…}` + `NewLimits()` (dnstools `{Lookup, Walk}`, linktools `{Pure,
  Fetch, Resolve, ResolveGlobal}`, …; ciphertools' lives in `handler.go`, its
  only `!js` file); `Register(…, lim *Limits)` treats nil as fresh limits, so
  existing tests pass nil. Classes are names in this plan, not shared stores:
  "pure" is four stores in four packages.
- **Classes priced by cost, not calls.** `dns_consistency` is a zone walk, up
  to 8 nameservers × ~6 probes, 3 resolvers, 6 ECS queries and RDAP: 50–100
  upstream operations at the same 2/s REST allows a lookup (9 fan-out types
  plus retries and a few dangling-CNAME probes). Starting numbers (REST adopts
  them too; tune on logs):

  | Class | Rate | Burst | Tools |
  |---|---|---|---|
  | `pure` | 10/s | 50 | cidr, link parsing, light cipher ops, site |
  | `dns` | 2/s | 10 | `dns_lookup`, `dns_email_auth`, `dns_domain_info` |
  | `dns-walk` | 1 per 2 s | 3 | `dns_consistency`, `dns_trace` |
  | `upstream` | 2/s | 10 | `ip_lookup`, `botcheck_score` |
  | `fetch` | 1/s | 5 | `link_redirect_chain`, owner tools |
  | `heavy` | 1/s | 5 | `cipher_password_hash`, `cipher_password_verify`, `cipher_keys_generate`, `cipher_jwt_sign` (signing accepts RSA-8192 keys) |
  | `resolve` | 20/s + global 200/s | 60 / 400 | `link_short_resolve` (the `/s/:code` stores) |
  | `protocol` | 5/s | 20 | every non-`tools/call` method |

- **The client IP must be real.** `cfIPExtractor` trusts `CF-Connecting-IP`
  unconditionally, and the link-tools security doc already lists "nginx only
  accepts Cloudflare" as unverifiable from the repo. If it doesn't, a forged
  header buys unlimited buckets on every subdomain. **Floor-2b gate:** confirm
  on the proxy host that only Cloudflare's ranges (or Authenticated Origin
  Pulls) can connect. And `RateLimitKey` returns unparseable input unchanged as
  a key today; it should fold it into one shared bucket (fail closed).
- **Hosted connectors share IPs.** claude.ai calls from Anthropic's published
  range (IPv4 only), so its users share buckets. Accepted for a personal site;
  the per-call log shows when it bites.

## 7. Untrusted output

The spec says servers MUST "sanitize tool outputs". Third-party strings reach
results through several paths, and some are spliced into prose today:
MTA-STS errors embed the attacker's `Content-Type` header (up to Go's 10 MB
header limit) into an error *and* a note; the tracer stores `Location` before
its 2048-byte check, keeps `Server`/`Content-Type` up to the 64 KB header cap,
and copies TLS error text (attacker-chosen certificate names) into notes;
`link_extract` can return 2,000 anchors of 200 bytes from a hostile email.
JSON escaping covers C0 controls only, so bidi overrides, zero-width and Unicode
Tag characters pass straight through.

- **One post-processor on every MCP result:** each string capped at 2 KB with a
  visible `…[truncated N bytes]` marker (2 KB keeps a 4096-bit DKIM key whole);
  bidi, format and Tag characters rewritten as visible `\u{…}` text. It **never
  cuts a list**: dropping one nameserver can drop the one that disagrees. Size
  is handled by each tool's declared concise projection, and a result still
  over the hard cap is a tool error saying how to narrow the call. Parity tests
  compare against the post-processed projection of the REST body.
- **At the source (floor 1b, REST benefits):** bound the header values above
  before storing them; notes name the field instead of quoting it.
- **Labelling:** every tool returning third-party strings says so in its
  description, since clients needn't fetch the server `instructions`.
- Measured by review: `dns_lookup ALL` up to 15–25 KB on TXT-heavy zones,
  `dns_consistency type=TXT` 25–60 KB, `dns_domain_info` ~22 KB with 200 CT
  names, `link_extract` 30–60 KB on a click-tracked newsletter. Each has a
  concise default in the [catalog](01-tool-catalog.md).

## 8. Owner tools, secrets and logs

- **Owner tools (D4)** live only at `/mcp/owner`, which serves just the three
  short-link tools: not next to tools that return attacker text in the same
  server. Their own key, `MCP_OWNER_KEY`, rotatable without touching the REST
  `LINK_API_KEY`: `main.go` builds a second `Shortener` over the same
  `LinkStore` with it (the REST one is nil whenever `LINK_API_KEY` is unset,
  so reusing it would tie the two together). Unset → `/mcp/owner` is 404
  (fail-closed, like the REST shortener). `link_short_create` is marked **destructive**: it publishes a
  redirect on our domain, and a steered agent minting one to a phishing page is
  the threat, so clients must ask first. Setup snippets use user-scope client
  config (`claude mcp add --scope user … --header "X-Api-Key: …"`), never a
  committed `.mcp.json`.
- **Per-call record**, written through the existing `RequestLog` repository
  (rule #5: no new collection, no driver in `mcptools`) and to slog: method
  `MCP`, URI `/mcp/<endpoint>#<tool>`, outcome class (`ok`, `tool_error`,
  `limited`, `busy`, `timeout`, `panic`), latency, rate-limit key, client name
  if sent (else the user agent). `ShouldRecord` skips the HTTP-level `/mcp`
  line so nothing is counted twice. **Never arguments, never results, never error
  text**: cipher errors quote their input (`%s=%q` in `password.go`), so an
  error message is as sensitive as the argument it came from.
- The HTTP request log keeps logging `POST /mcp/…` without bodies or headers,
  as it does for every route.

## 9. Licensed data (D17)

Through a web page the footer credits IP2Location LITE, Spamhaus and Shodan;
an MCP result has no footer. IP2Location LITE's licence asks for credit in
"all sites… and documentation", Spamhaus for credit plus its copyright notice,
and Shodan InternetDB allows non-commercial use with attribution (the repo's own
report calls re-display a grey area). So:

- Results built on licensed data carry an `attribution` list (source, notice,
  link), from one place in Go that the footer partial renders too.
- The landing page carries the full credits.
- Shodan stays in `ip_lookup` behind the process-wide limiter (D17's lean); the
  alternative is to drop open ports from MCP results entirely.

## 10. Outside the repo

1. **Cloudflare DNS:** proxied record `mcp`. Proxied records publish `A`
   records, which claude.ai needs (its connectors are IPv4-only).
2. **nginx:** a `server{}` block for `mcp.corpberry.com` forwarding `Host` and
   the client-IP headers, `client_max_body_size 1m`. **Gate:** the proxy accepts
   only Cloudflare's ranges, or uses Authenticated Origin Pulls (§6).
   Recommended for the shared proxy: `default_server` returns 444, so a trace
   to the bare origin IP reaches nothing.
3. **Cloudflare bot protection:** Bot Fight Mode is zone-wide on the Free plan
   and can't be skipped per hostname; it blocks Anthropic and Smithery. The
   site's `curl` users suggest it is off today: confirm. Optional backstop: one
   generous Cloudflare rate-limit rule on `mcp.*`, sized for shared connector
   IPs.
4. **`.env`:** `MCP_OWNER_KEY` (new; unset disables `/mcp/owner`).
5. **Floor 8:** a TXT record on `corpberry.com` for the MCP Registry's domain
   proof.
