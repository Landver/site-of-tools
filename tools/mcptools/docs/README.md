# MCP server (`mcp.corpberry.com`): build plan

**Status: planned, not built (2026-10-04).** Decisions marked *lean* are waiting
for the owner. Reviewed before handover; see the [review log](02-review-log.md).

| Doc | What's in it |
|---|---|
| this file | the plan: decisions, architecture, security, tests, floors |
| [00-research.md](00-research.md) | MCP spec + Go SDK facts, and how comparable public servers did it, with sources |
| [01-tool-catalog.md](01-tool-catalog.md) | every REST endpoint → its MCP tool (or why it isn't one) |
| [02-review-log.md](02-review-log.md) | what the reviewers found and what changed because of it |

## 1. What this is

Every tool on the site already speaks two representations from one domain call:
HTML for browsers and JSON for `curl` (ARCHITECTURE §4). MCP is a **third
transport over the same domain code**, so an AI agent (Claude Code, Claude
Desktop and claude.ai, Cursor, VS Code, ChatGPT and so on) can call the tools
as tools instead of being told how to `curl` them.

- **One new subdomain**, `mcp.corpberry.com`, served by the same binary like
  every other host: one `*echo.Echo`, one vhost entry, one nginx block.
- **Every REST endpoint covered, by 29 tools** (+3 key-gated owner tools), not
  one tool per route: the research is unambiguous that agents choose worse
  among many overlapping tools ([catalog](01-tool-catalog.md#how-rest-maps-to-tools)).
- **One endpoint per toolset.** `https://mcp.corpberry.com/mcp` serves all of
  them; `/mcp/ip`, `/mcp/dns`, `/mcp/link`, `/mcp/cipher`, `/mcp/botcheck` and
  `/mcp/site` serve one toolset each (2–10 tools), for clients that load every
  tool definition into context.
- **Same results as the REST API.** Each tool's structured result is the JSON
  `curl` gets for the same input. Where it isn't, the catalog names the
  deviation and why (always a token budget).
- **Nothing new reaches the network.** No tool dials anything a REST route
  doesn't already dial, through the same guards. MCP adds a door, not a
  capability.

**Not in scope:** user accounts or OAuth, a stdio/npm package, MCP Apps (UI in
the chat), tasks, elicitation, sampling, Server Cards (not merged), resources
and prompts (floor 9, optional), and an MCP endpoint on each tool's own
subdomain.

## 2. Decisions

Each row: the choice, the lean, and what the alternative costs. Confidence is
how sure the lean is right, not how sure it works.

| # | Decision | Lean | Conf. | Alternative and its cost |
|---|---|---|---|---|
| D1 | SDK | Official `github.com/modelcontextprotocol/go-sdk` **v1.8.0** | 90% | `mark3labs/mcp-go` v1.1.1: active and popular, but it took ~5 weeks to support the current spec, and the official SDK is the one GitHub's own Go server pins ([research §3](00-research.md#3-official-sdk-vs-mark3labsmcp-go)). |
| D2 | Where the code lives | One package, `tools/mcptools/`: transport + one adapter file per toolset; tool packages stay SDK-free | 75% | Each tool exports its own `mcp.go`: better co-location, but the SDK leaks into five packages and `ciphertools` would need a second `!js` file, breaking the "only handler.go is `!js`" rule. |
| D3 | Transport | Streamable HTTP, **stateless**, **plain JSON responses**, no legacy SSE endpoint | 90% | Spec 2026-07-28 removed sessions and the SDK serves those clients only in stateless mode, so this is barely a choice. SSE responses would add Cloudflare/nginx buffering trouble; no tool here streams. |
| D4 | Owner tools (short-link create/list/revoke) | In MCP, listed only on requests carrying `LINK_API_KEY` in a header; that list is `cacheScope: "private"`; a wrong key is `403` | 70% | Leave them out: simplest, but "every endpoint" stops being true. A separate `/mcp/owner` path: also fine, one more URL. Key as a tool argument: never; it would sit in the model's context and the provider's logs. The spec allows a list that varies by credential ([research §1](00-research.md#1-the-spec-2026-07-28-is-stateless)). |
| D5 | Toolsets | Path-selected: `/mcp` (all) and `/mcp/<toolset>` | 80% | One endpoint only: 29 tools in every client's context. Header-selected toolsets (GitHub also offers them): harder to paste into a config. |
| D6 | Where adapter logic lives | **Push handler orchestration down first** (floor 1). Adapters only map arguments → domain call → result | 90% | Copy the orchestration into adapters: fast, but two copies of `/domain`'s concurrency, `/consistency`'s ECS card, IP enrichment and so on, which will drift. Golden rule #1 says no. |
| D7 | `outputSchema` | **None in v1**: `structuredContent` + JSON text, no declared schema | 75% | Declare one per tool: the SDK turns a result that fails its own schema into a protocol error, and REST structs serialise nil slices as `null` against an inferred `type: array`. Add per tool later, behind a conformance test. |
| D8 | Auth for public tools | None, same as REST | 90% | OAuth: no accounts to protect, and it locks out every client without an OAuth flow. |
| D9 | `GET /history` (recent lookups by web visitors) | **Not a tool** | 60% | One small tool for strict parity. Costs a slot in every context for data no agent task needs: addresses *other* people looked up. |
| D10 | `link_short_resolve` counts a hit? | No | 75% | Yes: hit counts then include agents that only asked where a link goes. |
| D11 | `botcheck_score` semantics | Scores the fingerprint/headers/IP the agent supplies; never the MCP request itself; no corpus reads or writes | 75% | Score the MCP request (REST `GET /` parity): that describes Anthropic's or OpenAI's HTTP client, not the user. Write to the corpus: synthetic payloads poison `fingerprint_reuse`. |
| D12 | Rate limits | Per tool call, per client IP (`/64` for v6), same numbers as REST, in one SDK middleware; plus a coarse limit on `/mcp` itself | 70% | Per-session or per-user: impossible without accounts, and sessions no longer exist. Known cost: hosted connectors share a few egress IPs, so their users share buckets (§5). |
| D13 | Discovery | Landing page at `/` (HTML + JSON, also on a browser `GET /mcp`), an MCP line in every page's "Using this from the terminal" block, an apex catalog entry, then the official MCP Registry (`com.corpberry/tools`, DNS-verified) | 80% | Registry first: it is still preview, and names should be stable before they're announced. |
| D14 | Tool granularity | **29 tools**: network calls one tool each; pure transforms of one thing share a tool with an `operation`; reads and writes never share one ([catalog rules](01-tool-catalog.md#how-rest-maps-to-tools)) | 65% | 1:1 with REST routes: 36 tools, simplest adapter, measurably worse tool choice. Harder consolidation (~20): `link_diff` into `link_inspect`, `link_utm` into `link_clean`, blog as a resource; fewer tools, each harder to describe. |
| D15 | Origin check (a spec MUST) | Reject a POST whose `Sec-Fetch-Site` says cross-site; log every rejection with its `Origin` | 65% | `http.NewCrossOriginProtection()`: stdlib, but it also 403s any server-side client that sends an `Origin` unlike our Host, and Anthropic warns strict Origin checks break its connectors; we'd maintain an allowlist of hosted clients. See §5 for why this is enough. |

## 3. Architecture

```
client (Claude Code, claude.ai connector, Cursor, …)
  │  POST https://mcp.corpberry.com/mcp/dns    tools/call dns_lookup {...}
  ▼
Cloudflare → nginx → Echo vhost "mcp.corpberry.com"     (same path as every host;
  │                                                       unknown Hosts already 404)
  │  NewApp middleware: recover · request log · security headers (gzip skipped on /mcp)
  │  /mcp, /mcp/:toolset: browser GET → landing page · /mcp limiter · client IP → context
  │                       · browser cross-site POST → 403 (D15)
  ▼
go-sdk StreamableHTTPHandler        Stateless · JSONResponse · PropagateRequestCancellation
  │                                 MaxRequestBodyBytes 1 MiB · DisableLocalhostProtection
  │  getServer(req): the *mcp.Server for this toolset; owner variant if the key header is valid
  ▼
receiving middleware                tool name → rate class → limiter; per-call log record
  ▼
adapter (tools/mcptools/dns.go)     typed args → domain call → result
  ▼
dnstools.LookupEnriched             ← the SAME code GET dns.corpberry.com/ runs
```

### 3.1 Package layout

```
tools/mcptools/                  # mcp.corpberry.com, self-contained like every tool
├── handler.go     # Register(e, Deps): landing (HTML + JSON), /mcp routes, origin check, key check
├── server.go      # one *mcp.Server per toolset, built at boot (+ owner variants for all/link)
├── middleware.go  # receiving middleware: rate class check, per-call log record
├── registry.go    # tool spec (name, toolset, class, hints) + the coverage table
├── limits.go      # rate classes (pure/upstream/fetch/heavy/resolve) on Echo's memory store
├── schema.go      # inferred input schema + enums/bounds from domain lists (jsonschema.For, then edit)
├── ip.go dns.go link.go cipher.go botcheck.go site.go   # one adapter per toolset
├── embed.go · templates/index.html                      # landing page
├── tests/         # black-box: in-memory client, HTTP, parity, golden tools/list, coverage
└── docs/
```

`mcptools` imports the tool packages; nothing imports `mcptools` except
`main.go`. Tool packages never import the SDK. `ciphertools` is called through
`ciphertools.Run`, so its wasm build is untouched.

### 3.2 Wiring (`main.go`)

```go
mcpApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
mcptools.Register(mcpApp, mcptools.Deps{
    Geo: geo, History: lookupHistory, Blocklist: blocklist,
    DNS: dnsSvc, Domain: domainClient,
    Link: linkSvc, Tracer: tracer, Shortener: shortener,
    Blog: blog,
}, cfg.URL("mcp"))
platform.RegisterSEO(mcpApp, cfg.URL("mcp"), mcptools.SitemapPages)
hosts[cfg.VHost("mcp")] = mcpApp
```

Plus `cfg.VHost("mcp")` in the trace guard's deny list, and `dnsSvc`/`blog`
hoisted into variables (both are built inline today). A dependency that is off
at boot (nil tracer, nil shortener, Mongo down) **removes its tools** from
`tools/list` rather than leaving tools that can only fail; a dependency that
fails at call time is a tool error, the same split the handlers make between
503 and 502. The list is therefore fixed per process, which is what the spec's
"MUST NOT vary per-connection" asks.

### 3.3 One tool, end to end

```go
// dns.go: transport only. Arguments in, domain call, struct out.
type dnsLookupArgs struct {
    Name     string `json:"name" jsonschema:"domain name, or an IP address for a reverse (PTR) lookup"`
    Type     string `json:"type,omitempty" jsonschema:"record type, or ALL (default) for every common type at once"`
    Resolver string `json:"resolver,omitempty" jsonschema:"public resolver to ask (default cloudflare)"`
}

func (t *toolset) dnsLookup(ctx context.Context, _ *mcp.CallToolRequest, a dnsLookupArgs) (*mcp.CallToolResult, any, error) {
    set, err := dnstools.LookupEnriched(ctx, t.deps.DNS, t.deps.Geo, a.Name, a.Resolver, typesFor(a.Type))
    if err != nil {
        return nil, nil, err // SDK → isError result carrying the REST API's own message
    }
    return nil, set, nil // SDK → structuredContent + the same JSON as text
}
```

The rate check and the log record are not in the handler: the receiving
middleware does both for every tool, keyed on the tool's registered class. The
`type` and `resolver` enums are added to the inferred schema in `schema.go`
from `dnstools.Types` and `dnstools.Resolvers` (the SDK's `jsonschema` tag
carries descriptions only). Errors pass through as returned, **except** storage
and driver errors in the short-link tools, which map to the same fixed sentence
the REST handler uses (they can carry connection strings).

`LookupEnriched` is the floor-1 extraction of what `dnstools/handler.go`'s
`show` + `enrich` do today. The handler then calls it too, so the two
transports cannot drift.

### 3.4 Floor 1: what moves out of handlers

Behaviour-preserving moves, each pinned first by a golden test of the current
REST JSON:

| From (handler) | To (domain, exported) | Why MCP needs it |
|---|---|---|
| `iptools.show`: `Lookup` + blocklist check | `iptools.LookupWithReputation(ctx, looker, bl, ip)` | `ip_lookup` = same enrichment |
| `dnstools.show` + `enrich` | `dnstools.LookupEnriched(...)` | geo labels on A/AAAA |
| `dnstools.consistency`: Spread ∥ ECS, delegation health, envelope | `dnstools.Consistency(...)` | the whole `/consistency` body |
| `dnstools.domain`: `validDomain`, RDAP ∥ CT, body map | `dnstools.DomainInfo(...)` returning a typed struct with the same JSON keys | `dns_domain_info` |
| `dnstools.email`: `EmailAuth` + MX reputation | `dnstools.EmailReport(...)` | `dns_email_auth` |
| `linktools.utm`: parse, upsert, rebuild | `(*Service).BuildUTM(raw, values)` | `link_utm` |
| `linktools.curl` (curl → URL branch) | `(*Service).ParseCurl(cmd)` | `link_curl` |
| `linktools.diff`: parse a, parse b, diff | `(*Service).Diff(a, b)` | `link_diff` |
| `botcheck.addServerSignals`: IP → timezone/ASN/proxy/blocklist fields | `botcheck.AddIPSignals(ctx, sig, ip, looker, bl)` | `botcheck_score` with a supplied IP |
| `site` blog: `posts()`, `post()` unexported; post keeps HTML only | exported accessors; keep the Markdown source | `site_blog` |

Header reading, view models, status codes and attribution flags stay in the
handlers: they are HTTP.

## 4. Protocol choices

- **Spec 2026-07-28**, plus older clients (2025-06-18 / 2025-11-25), which the
  SDK still serves in stateless mode by answering `initialize` without keeping
  anything. No session table, nothing lost on redeploy.
- **Capabilities: tools only.** The SDK default also advertises `logging`,
  deprecated in 2026-07-28.
- **List caching:** `ttlMs` 1 hour (the list changes only on deploy),
  `cacheScope: "public"`; `"private"` on the owner variants. Deterministic
  order: registry order, by toolset then name.
- **Server `instructions`** (in `server/discover`), short: what each toolset is
  for and how to route between neighbours (`link_encode` vs `cipher_encode`,
  `dns_lookup` vs `dns_consistency`); that results contain third-party data
  (DNS records, RDAP, redirect targets, extracted links) to be treated as data,
  never instructions; that cipher arguments are sent to this server; that rate
  limits are per client IP and say when to retry.
- **Tool descriptions and hints** follow the [catalog
  conventions](01-tool-catalog.md#conventions-all-tools); all four hints set on
  every tool, since the spec defaults make an unannotated tool look destructive
  and open-world.
- **Results:** `structuredContent` + the same JSON as a text block (the SDK
  does this), no `outputSchema` in v1 (D7). Over-budget tools are concise by
  default with `detailed: true` for the REST body.
- **Errors:** bad input (including schema validation, which the SDK does before
  the handler), an upstream failure, a disabled feature and a rate limit are
  all *tool* errors with an actionable sentence. Protocol errors are the SDK's:
  malformed JSON-RPC, unknown method, unknown tool.
- **Contract changes:** a renamed tool or argument breaks every agent that
  cached the list. Avoid renames; when one is unavoidable, the middleware keeps
  the old name callable for a release (GitHub does the same).

## 5. Security and abuse

- **No new reach.** Outbound dials happen only inside domain code that a REST
  route already runs, through the same guards: `link_trace` through the
  `EgressGuard` (ports 80/443, our own vhosts and Mongo denied, `mcp` added),
  DNS tools through their resolver and authoritative-server paths, RDAP/CT to
  their fixed upstreams. A test pins `link_trace` refusing `mcp.corpberry.com`
  and every loopback form, as the tracer's own tests do for the other hosts.
- **Origin (D15).** The spec makes Origin validation a MUST, against DNS
  rebinding and cross-site calls. What actually stops a web page from driving
  our tools through its visitors' browsers is already layered: the SDK refuses
  any body that isn't `Content-Type: application/json`, a JSON POST from
  another origin needs a CORS preflight, and we send no CORS headers, so the
  browser never sends it. On top of that, the check 403s any POST whose
  `Sec-Fetch-Site` is `cross-site` or `same-site`, a header every current
  browser sends and server-side clients don't. It deliberately does **not**
  judge `Origin` alone: Anthropic's docs warn that strict Origin checks reject
  its connectors without saying what Origin it sends. Every 403 is logged with
  its `Origin` and user agent, and floor 2 connects a real claude.ai connector
  before anything else ships. DNS rebinding is covered by the Host check (next
  point).
- **DNS rebinding.** `DisableLocalhostProtection: true`, because the SDK's
  check 403s dev's `mcp.localhost:8080`; Echo's vhost map already 404s every
  unknown Host, which is the defence rebinding needs. Tested.
- **Rate limits per tool call** (D12), in the receiving middleware, keyed on
  `platform.RateLimitKey(c.RealIP())` carried in the request context. Over
  limit is a tool error with a retry hint. A coarse limiter on `/mcp` itself
  (discover/list floods) answers HTTP 429. A small global concurrency cap on
  `upstream` + `fetch` calls stops one burst of agents tying up the box.
  **Known cost:** hosted connectors call from a few shared egress IPs (claude.ai
  is IPv4-only, from Anthropic's published range), so their users share one
  bucket per IP. Accept it for a personal site, watch the limited-call rate in
  the per-call log, revisit with data.
- **Body limit 1 MiB** via the SDK's `MaxRequestBodyBytes` (413), against the
  cipher REST API's 8 MiB: arguments arrive through a model's context, and
  nobody pastes 8 MB into one.
- **Owner key** (D4): read from `Authorization: Bearer …` or `X-Api-Key`,
  checked with the existing constant-time `Shortener.Authorized`, never a tool
  argument, never logged. Absent → public tool set. Present and wrong → 403
  (not 401: a 401 makes spec-following clients start OAuth discovery against a
  server that has none). Keyed lists are `cacheScope: "private"` so no shared
  cache hands them on.
- **Untrusted output ("sanitize tool outputs", a spec MUST).** DNS TXT records,
  RDAP remarks, redirect targets and extracted link text are attacker-chosen
  strings that end up in a model's context. They stay inside JSON string fields
  (escaped by the encoder, never spliced into prose, descriptions or the
  instructions), every list is bounded by the domain (CT 200 names, trace 10
  hops, upstream bodies 8 MB) and every result by the token budget, and the
  instructions say to treat them as data. That is the defence available to a
  server; the client owns the rest.
- **Secrets in cipher calls** (keys, tokens, passwords): never logged,
  `Cache-Control: no-store`, descriptions say "test material only".
- **Cancellation and timeouts:** `PropagateRequestCancellation` stops the work
  when the client hangs up; the slowest tools are bounded by the domain's own
  budgets (RDAP/CT 20 s, trace 15 s), inside nginx's 60 s read timeout and
  Cloudflare's origin timeout.
- **No redirects** anywhere under `/mcp` (no trailing-slash or canonicalising
  redirect): Claude drops `Authorization` on a cross-host redirect, and the
  owner key would vanish with it. Tested.

## 6. Logging and privacy

- The HTTP request log sees `POST /mcp/dns` and nothing else (bodies are never
  logged, as for every route). `ShouldRecord` skips `/mcp` so it is not
  counted twice.
- **One record per tool call** instead, from the receiving middleware: slog
  line + `RequestLog.Record` with method `MCP`, URI `/mcp/<toolset>#<tool>`,
  outcome (ok / error / limited), latency, client IP, user agent, and the
  client's self-reported name (`claude-code`, `claude-ai`, … unauthenticated,
  telemetry only). **Never arguments, never results**: a DNS name is harmless,
  a JWT key is not, and the logger can't tell them apart. Same reasoning as
  `platform.RedactURI`.
- `server/discover`, `initialize` and `tools/list` get the same record with the
  method in place of the tool. That is where adoption shows: which clients,
  which toolsets.

## 7. Landing page and discovery

`GET mcp.corpberry.com/` (and a browser's `GET /mcp`, which every server
surveyed answers with a raw JSON-RPC error) follows golden rule #2: a page for
browsers, JSON for `curl`, both rendered from the live registry, so the page
can't list a tool that doesn't exist.

- Page: the endpoint with a copy button; per-client setup snippets ([research
  §5](00-research.md#5-clients-and-install-snippets)); a table per toolset with
  each tool's title, description and read-only/open-world badges; a "what is
  sent where" note; **the rate limits, published** (no surveyed server does).
  No raw JSON-RPC `curl` example: a 2026-07-28 call needs `_meta` plus three
  headers, and `curl` users already have the REST API, which the page links.
- JSON: `{name, version, endpoint, toolsets: [{name, endpoint, tools: [{name,
  title, description, annotations}]}]}`.
- Every tool page's "Using this from the terminal" block gains one line, from
  a shared partial: "Use it from an AI agent: `https://mcp.corpberry.com/mcp/<toolset>`".
- Apex catalog (`site.Tools`) gains an "MCP server" entry; header nav picks it
  up.
- Official MCP Registry in the last floor: `server.json` in the repo, name
  `com.corpberry/tools`, one `streamable-http` remote, domain proved by a
  Cloudflare TXT record (no code). Re-published whenever the endpoint changes,
  so the entry never goes stale the way Cloudflare's and Globalping's have.

## 8. Testing

All in `tools/mcptools/tests/` (black-box), plus golden tests in each tool's
`tests/` for floor 1. `go test ./... -race`, no network, no BINs.

| Test | Catches |
|---|---|
| **Golden REST JSON** (floor 1, before any move) | the refactor changing a REST response by one byte |
| **Coverage**: every route registered by every `Register` (with fakes) maps to a (tool, operation) or an exclusion in the coverage table | a REST endpoint added without an MCP decision |
| **Golden `tools/list`** per toolset (names, descriptions, schemas, hints) | an accidental change to the agent-facing contract; changes become a reviewed diff |
| **Size budgets**: `tools/list` per toolset; each tool's result on a realistic fixture | descriptions and results creeping into every client's context |
| **Parity**: same fake deps, REST JSON body == MCP `structuredContent` (`detailed: true` where concise is the default) | MCP and REST drifting apart |
| **In-memory client** (`mcp.NewInMemoryTransports`): every tool and operation, happy path + one bad input | broken argument mapping, error text, hints |
| **HTTP** (`httptest` + `StreamableClientTransport`): vhost routing, each toolset path, browser GET → page, other GET → 405, body limit → 413, owner key absent/wrong/right, `cacheScope` public vs private, no 3xx anywhere | wiring, gating |
| **Origin/Host**: `Sec-Fetch-Site: cross-site` POST → 403; POST with a foreign `Origin` but no `Sec-Fetch-Site` → served; unknown Host → 404 | D15 and the rebinding defence |
| **Client IP reaches the handler** through the request context | the SDK behaviour that is true but undocumented |
| **Protocol versions**: a 2026-07-28 client and a 2025-11-25 client both list and call | the stateless-mode promise |
| **Rate limits**: burst + 1 calls → tool error with retry hint; `/mcp` flood → 429 | limiter wiring |
| **Egress**: `link_trace` to `mcp.localhost:8080`, `127.0.0.1`, `[::1]` refused | the deny-list addition |
| **Cipher bounds drift**: schema min/max vs the op's error at bound + 1 | schemas lying about limits |
| **Live smoke** (skips unless `MCP_LIVE_URL` is set): discover, list, one call per toolset against prod | deploy plumbing (DNS, nginx, Cloudflare) |

MCP Inspector is the usual manual check, but it runs on `npx`; the SDK's own
client in the live smoke test covers the same ground without breaking the
no-Node rule.

## 9. Delivery floors

One PR per floor, from a fresh branch off `master`, deployed and smoke-tested
before the next starts.

| Floor | Ships | Done when |
|---|---|---|
| 0 | Owner answers D1–D15 | this table has no *lean* left |
| 1 | Golden REST tests, then the domain push-down (§3.4). No MCP code yet | every golden test green before and after; REST byte-identical |
| 2 | `tools/mcptools` skeleton: SDK pinned, vhost, `/mcp` + toolset routing, origin/key checks, landing page, limits, logging, **`ip` toolset**; docs (ARCHITECTURE, CLAUDE, DEPLOYMENT); DNS + nginx + Cloudflare | `claude mcp add` against prod lists and calls the `ip` tools, **and a claude.ai custom connector does too**; the per-call log shows what `Origin` it sent |
| 3 | `dns` toolset; budgets measured, concise defaults where needed | parity + golden list green; live smoke |
| 4 | `link` toolset, public tools | same; `link_trace` egress test |
| 5 | Owner tools + key gating | public list unchanged; keyed list has +3 and is `private`; 403 on a wrong key |
| 6 | `cipher` toolset (10 tools over 15 ops) | every op called through MCP with its existing test vectors |
| 7 | `botcheck` + `site` toolsets | no corpus writes from MCP (test) |
| 8 | Discovery: page partial, apex entry, README, MCP Registry | listing live; domain verified |
| 9 | *Optional*: resources (tracking rules, encoding reference, blog posts) and prompts (`audit_domain`, `inspect_link`) | only if call logs show agents need them |

## 10. Outside the repo

Same manual steps cipher.corpberry.com needed (`deploy/nginx/` is referenced
in DEPLOYMENT.md but not in git; blocks live on the proxy host):

1. Cloudflare: proxied DNS record `mcp` (it must publish an `A` record:
   claude.ai connectors are IPv4-only; proxied records do).
2. nginx: a `server{}` block for `mcp.corpberry.com`, copied from `cipher`'s,
   forwarding `Host` and the client-IP headers. No SSE settings needed (D3).
3. Cloudflare security: exempt `mcp.corpberry.com` from Bot Fight Mode and any
   WAF challenge, or allowlist Anthropic's published egress range. MCP clients
   are automated by definition; a challenge breaks every one of them, silently,
   before the app logs anything.
4. Floor 8: a TXT record on `corpberry.com` for the registry's domain proof.
5. Nothing new in `.env`: the owner tools reuse `LINK_API_KEY`.

## 11. Docs to update (in the floors that change them)

- `CLAUDE.md`: layout gains `tools/mcptools`; pinned `go-sdk` version; golden
  rule #2 becomes "HTML + JSON + MCP": a new API endpoint ships with its tool
  (or operation) or a coverage-table exclusion.
- `docs/ARCHITECTURE.md`: §1 stack table, §3 host map, §4 MCP as the third
  transport, §7 layout, §10 the request log's MCP records.
- `docs/DEPLOYMENT.md`: §3 the new block; the Cloudflare exemption.
- `README.md` (repo): one paragraph + the endpoint.

## 12. Risks

| Risk | Mitigation |
|---|---|
| A hosted client sends an `Origin` or trips a WAF rule and can't connect | D15 judges `Sec-Fetch-Site`, not `Origin`; Cloudflare exemption; claude.ai connector tested in floor 2 before anything else ships |
| Shared egress IPs of hosted connectors exhaust per-IP buckets | watch limited calls in the per-call log; raise MCP's `upstream` class if real users hit it |
| 29 tools still too many for clients without tool search | toolset endpoints (2–10 tools each); descriptions route between neighbours |
| A third-party string steers the model (prompt injection) | data stays in JSON fields; instructions say so; the only destructive tool is the key-gated revoke |
| Spec churn (three versions in 13 months) | stateless + no optional features = little surface; an SDK bump is one PR |
| The SDK's ctx-value propagation (undocumented) changes | pinned by a test; fallback is `req.Extra.Header` + the CF header |
| The agent-facing contract changes by accident | golden `tools/list` test turns every change into a reviewed diff |
