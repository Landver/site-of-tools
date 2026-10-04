# MCP server (`mcp.corpberry.com`): build plan

**Status: planned, not built (2026-10-04).** Decisions marked *lean* are waiting
for the owner. Reviewed before handover; see the [review log](03-review-log.md).

| Doc | What's in it |
|---|---|
| this file | the plan: decisions, architecture, protocol, tests, floors |
| [00-research.md](00-research.md) | MCP spec + Go SDK facts, and how comparable public servers did it, with sources |
| [01-tool-catalog.md](01-tool-catalog.md) | every REST endpoint → its MCP tool (or why it isn't one) |
| [02-security-and-ops.md](02-security-and-ops.md) | threat model, the request gate, limits, outbound reach, untrusted output, deploy steps |
| [03-review-log.md](03-review-log.md) | what the reviewers found and what changed because of it |

## 1. What this is

Every tool on the site already speaks two representations from one domain call:
HTML for browsers and JSON for `curl` (ARCHITECTURE §4). MCP is a **third
transport over the same domain code**, so an AI agent (Claude Code, Claude
Desktop and claude.ai, Cursor, VS Code, ChatGPT and so on) can call the tools
as tools instead of being told how to `curl` them.

- **One new subdomain**, `mcp.corpberry.com`, served by the same binary like
  every other host: one `*echo.Echo`, one vhost entry, one nginx block.
- **Every REST endpoint covered, by 29 public tools**, not one tool per route:
  the research is unambiguous that agents choose worse among many overlapping
  tools ([catalog](01-tool-catalog.md#how-rest-maps-to-tools)). The three
  key-gated short-link writes live on their own endpoint.
- **Endpoints:** `https://mcp.corpberry.com/mcp` serves all 29;
  `/mcp/ip`, `/mcp/dns`, `/mcp/link`, `/mcp/cipher`, `/mcp/botcheck` and
  `/mcp/site` one toolset each (1–10 tools); `/mcp/owner` the owner's three
  short-link tools, behind a key.
- **Same results as the REST API.** Each tool's structured result is the JSON
  `curl` gets for the same input, sanitized. Where it isn't, the catalog names
  the deviation and why (almost always a token budget).
- **Nothing new reaches the network.** No tool dials anything a REST route
  doesn't already dial. Review found those REST paths guarded unevenly, so
  they are hardened first, for both transports (floor 1b).

**Not in scope:** user accounts or OAuth, a stdio/npm package, MCP Apps (UI in
the chat), tasks, elicitation, sampling, Server Cards (not merged), resources
and prompts (floor 9, optional), and an MCP endpoint on each tool's own
subdomain.

## 2. Decisions

Each row: the choice, the lean, and what the alternative costs. Confidence is
how sure the lean is right, not how sure it works. The ones that genuinely
need the owner are **bold**; the rest can be accepted as leaned.

| # | Decision | Lean | Conf. | Alternative and its cost |
|---|---|---|---|---|
| D1 | SDK | Official `github.com/modelcontextprotocol/go-sdk` **v1.8.0** | 90% | `mark3labs/mcp-go` v1.1.1: active and popular, but ~5 weeks late to the current spec; the official SDK is the one GitHub's own Go server pins ([research §3](00-research.md#3-official-sdk-vs-mark3labsmcp-go)). |
| D2 | Where the code lives | One package, `tools/mcptools/`: transport + one adapter file per toolset; tool packages stay SDK-free | 75% | Each tool exports its own `mcp.go`: better co-location, but the SDK leaks into five packages and `ciphertools` would need a second `!js` file. |
| D3 | Transport | Streamable HTTP, **stateless**, **plain JSON responses**, no legacy SSE, no JSON-RPC batches | 90% | Spec 2026-07-28 removed sessions and the SDK serves it only stateless, so this is barely a choice. SSE adds proxy-buffering trouble; no tool streams. |
| **D4** | Owner tools (short-link create/list/revoke) | Only at `/mcp/owner`, which serves just those three, behind a new `MCP_OWNER_KEY` in `X-Api-Key`; create marked destructive ([security §8](02-security-and-ops.md#8-owner-tools-secrets-and-logs)) | 70% | Leave them out of MCP: simplest, safest, but "every endpoint" stops being true. Mix them into `/mcp` behind a header: a shared cache can serve the anonymous list to the owner, and they'd sit beside tools returning attacker text. |
| D5 | Toolsets | Path-selected: `/mcp` (all) and `/mcp/<toolset>` | 80% | One endpoint only: 29 tools in every client's context. Header-selected toolsets: harder to paste into a config. |
| D6 | Where adapter logic lives | **Push handler orchestration down first** (floor 1a). Adapters only map arguments → domain call → result | 90% | Copy the orchestration into adapters: fast, but two copies of `/domain`'s concurrency, `/consistency`'s ECS card, IP enrichment, which will drift. Golden rule #1 says no. |
| D7 | `outputSchema` | **None in v1**: `structuredContent` + JSON text, no declared schema | 75% | Declare one per tool: the SDK turns a result that fails its own schema into a protocol error, and the inferred schemas are wrong for `[]byte`/`json.RawMessage` (`ciphertools/jwt.go` has two), `net.IP`, custom marshalers and nil maps. Add per tool later, behind a conformance test. |
| D8 | Auth for public tools | None, same as REST | 90% | OAuth: no accounts to protect, and it locks out every client without an OAuth flow. |
| **D9** | `GET /history` (recent lookups by web visitors) | **Not a tool** | 60% | One small tool for strict parity; it costs a slot in every context for data no agent task needs: addresses *other* people looked up. |
| D10 | `link_short_resolve` counts a hit? | No | 75% | Yes: hit counts then include agents that only asked where a link goes. |
| D11 | `botcheck_score` semantics | Scores the fingerprint/headers/IP the agent supplies; never the MCP request itself; no corpus reads or writes | 75% | Score the MCP request (REST `GET /` parity): that describes Anthropic's or OpenAI's HTTP client, not the user. Write to the corpus: synthetic payloads poison `fingerprint_reuse`. |
| **D12** | Rate limits | Per JSON-RPC message; **limiter stores shared with each tool's REST twin**; classes priced by upstream cost, REST adopting the same numbers; global concurrency caps incl. memory-weighted `heavy` ([security §6](02-security-and-ops.md#6-rate-limits-and-capacity-d12)) | 70% | MCP-only limiters at REST's current numbers: simpler, but doubles every client's budget and prices a 100-query DNS walk like an 8-query lookup. |
| D13 | Discovery | Landing page at `/` (HTML + JSON, also on a browser `GET /mcp`), an MCP line in every page's "Using this from the terminal" block, an apex catalog entry, then the official MCP Registry (`com.corpberry/tools`, DNS-verified) | 80% | Registry first: it is still preview, and names should be stable before they're announced. |
| D14 | Tool granularity | **29 tools**: network calls one tool each; pure transforms of one thing share a tool with an `operation`; reads and writes never share one ([catalog rules](01-tool-catalog.md#how-rest-maps-to-tools)) | 65% | 1:1 with REST routes: 36 tools, simplest adapter, measurably worse tool choice. Harder consolidation (~20): fewer tools, each harder to describe. |
| D15 | Origin check (a spec MUST) | Two steps: floor 2 rejects browser cross-site requests by `Sec-Fetch-Site` and **logs** foreign `Origin`s; before floor 3, an allowlist from those logs and 403 for the rest ([security §3](02-security-and-ops.md#3-browsers-and-dns-rebinding-d15)) | 70% | Strict from day one (`http.NewCrossOriginProtection`): compliant at once, but Anthropic warns strict Origin checks break its connectors, and we don't know what Origin they send. |
| **D16** | Harden REST's outbound paths before MCP exposes them | Yes, floor 1b: MTA-STS, nameserver probes and RDAP/CT through the one egress guard; Shodan only where its data is shown, under a process-wide limiter; third-party strings bounded at the source ([security §5](02-security-and-ops.md#5-outbound-reach)) | 80% | Ship MCP first, harden later: faster, but it automates access to paths review found weak, and one of them can get the site's IP banned by Shodan. |
| **D17** | Licensed data in MCP results (IP2Location LITE, Spamhaus DROP, Shodan InternetDB) | Keep, with an `attribution` list in each result built from the same credits the footer shows ([security §9](02-security-and-ops.md#9-licensed-data-d17)) | 60% | Drop Shodan's open ports from MCP: cleanest under its non-commercial terms, loses the one live-scan signal `ip_lookup` has. |

## 3. Architecture

```
client (Claude Code, claude.ai connector, Cursor, …)
  │  POST https://mcp.corpberry.com/mcp/dns    tools/call dns_lookup {...}
  ▼
Cloudflare → nginx → Echo vhost "mcp.corpberry.com"     (unknown Hosts already 404)
  │  NewApp middleware: recover · request log · security headers (gzip skipped on /mcp)
  ▼
the /mcp gate (Echo)    toolset 404 · browser GET → landing page · owner key → 403 / strip
                        /mcp limiter · body ≤ 1 MiB, no batches · Sec-Fetch-Site / Origin
                        client IP → context · Cache-Control: no-store
  ▼
go-sdk StreamableHTTPHandler        Stateless · JSONResponse · MaxRequestBodyBytes 1 MiB
  │  getServer(req): pure lookup by toolset (owner → the owner server)
  ▼
receiving middleware (per message)  recover · deadline · rate class · concurrency cap
                                    → tool → sanitize output · per-call log record
  ▼
adapter (tools/mcptools/dns.go)     typed args → domain call → result
  ▼
dnstools.LookupEnriched             ← the SAME code GET dns.corpberry.com/ runs
```

Each step's reason is in [security §2 and §4](02-security-and-ops.md#2-the-mcp-gate-echo-before-the-sdk).

### 3.1 Package layout

```
tools/mcptools/                  # mcp.corpberry.com, self-contained like every tool
├── handler.go     # Register(e, Deps): landing (HTML + JSON) + the /mcp gate
├── server.go      # one *mcp.Server per toolset + the owner server, built at boot
├── middleware.go  # receiving middleware: recover, deadline, limits, caps, log
├── sanitize.go    # output post-processor: string caps, bidi/format escaping, budget
├── registry.go    # tool spec (name, toolset, class, hints) + the coverage table
├── schema.go      # inferred input schema + enums/bounds from domain lists
├── ip.go dns.go link.go cipher.go botcheck.go site.go owner.go   # adapters
├── embed.go · templates/index.html                               # landing page
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
    Geo: geo, Blocklist: blocklist,
    DNS: dnsSvc, Domain: domainClient,
    Link: linkSvc, Tracer: tracer, Shortener: shortener,
    Blog: blog,
    Limits: limits, // the stores each REST Register also gets (floor 1c)
}, cfg.URL("mcp"), cfg.MCPOwnerKey)
platform.RegisterSEO(mcpApp, cfg.URL("mcp"), mcptools.SitemapPages)
hosts[cfg.VHost("mcp")] = mcpApp
```

Plus the trace guard's deny list built from the `hosts` map, and `dnsSvc` /
`blog` / `limits` hoisted into variables. A dependency that is off at boot (nil
tracer, nil shortener, Mongo down, no owner key) **removes its tools** from the
list rather than leaving tools that can only fail; a dependency that fails at
call time is a tool error, the same split the handlers make between 503 and
502. Each list is therefore fixed per process, which is what the spec's "MUST
NOT vary per-connection" asks.

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

Recovery, the deadline, the rate check, the concurrency cap, sanitizing and
the log record are not in the handler: the receiving middleware does them for
every tool, keyed on the tool's registered class. The `type` and `resolver`
enums are added to the inferred schema in `schema.go` from `dnstools.Types` and
`dnstools.Resolvers` (the SDK's `jsonschema` tag carries descriptions only).
Errors pass through as returned, **except** storage and driver errors in the
owner tools, which map to the fixed sentence the REST handler uses (they can
carry connection strings).

### 3.4 Floor 1: what changes before any MCP code

**1a: push-down** (behaviour-preserving; each move pinned first by a golden
test of the current REST JSON):

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

**1b: outbound hardening** (D16, REST benefits): MTA-STS, nameserver probes and
RDAP/CT through the one guard; a DB-only lookup for DNS enrichment and a
process-wide Shodan limiter; third-party header values bounded where they
enter; credits moved into Go so the footer and MCP share them (D17). Detail in
[security §5](02-security-and-ops.md#5-outbound-reach).

**1c: shared, cost-priced limits** (D12): each tool package builds its limiter
stores once and both transports use them; the new classes apply to REST too;
`RateLimitKey` folds unparseable input into one bucket.

Header reading, view models, status codes and attribution flags stay in the
handlers: they are HTTP.

## 4. Protocol choices

- **Spec 2026-07-28**, plus older clients (2025-06-18 / 2025-11-25), which the
  SDK serves in stateless mode by answering `initialize` without keeping
  anything. Legacy JSON-RPC **batches are refused** before the SDK (they
  bypass every per-call limit).
- **Capabilities set explicitly: tools, `listChanged: false`.** Left nil, the
  SDK advertises deprecated `logging` and infers `listChanged: true`, after
  which `subscriptions/listen` holds an SSE stream open even in JSON mode.
- **List caching:** `ttlMs` 1 hour (lists change only on deploy).
  `cacheScope: "public"` everywhere except `/mcp/owner` (`"private"`). The SDK
  orders tools by name, so the prefixes group them by toolset.
- **Server `instructions`** per toolset server, naming only that server's own
  tools: what each is for and how to choose between neighbours, that results
  hold third-party data, that cipher arguments are sent to this server, how
  rate limits answer. Clients needn't fetch them (`server/discover` is
  optional), so the third-party-data line is also in each affected tool's
  description.
- **Results:** `structuredContent` (always a JSON object, never `null`) + the
  same JSON as a text block, no `outputSchema` (D7). Over-budget tools are
  concise by default with `detailed: true` for the REST body.
- **Errors:** bad input (schema validation runs first, in the SDK), an upstream
  failure, a disabled feature, a rate limit or a full concurrency cap are all
  *tool* errors with an actionable sentence. Protocol errors are the SDK's:
  malformed JSON-RPC, unknown method, unknown tool.
- **Contract changes:** a renamed tool or argument breaks every agent that
  cached the list. Avoid renames; when one is unavoidable, the middleware keeps
  the old name callable for a release (GitHub does the same).

## 5. Security in one screen

Full detail in [02-security-and-ops.md](02-security-and-ops.md).

- **The box:** panics recovered per message (the SDK doesn't); batches refused;
  1 MiB bodies; per-message rate classes; global concurrency caps including
  memory-weighted password hashing and key generation.
- **Browsers:** JSON-only bodies + no CORS headers already stop cross-site
  calls; `Sec-Fetch-Site` check on top; Origin allowlist after floor 2 (D15).
  DNS rebinding stops at Echo's exact-Host vhost map.
- **Outbound:** every path through the one egress guard before the `dns` and
  `link` toolsets ship (D16); Shodan under a process-wide limiter.
- **Rate limits:** shared with REST, priced by cost; the client IP is trusted
  only once nginx is confirmed to accept Cloudflare alone (floor-2 gate).
- **Untrusted output:** strings capped and bidi/format characters made visible;
  third-party data labelled in descriptions.
- **Owner tools:** own endpoint, own rotatable key, stripped before the SDK,
  failed-key limiter, create marked destructive.
- **Logs:** outcome class only; never arguments, results or error text.
- **Licences:** `attribution` in results that use licensed data (D17).

## 6. Landing page and discovery

`GET mcp.corpberry.com/` (and a browser's `GET /mcp`, which every server
surveyed answers with a raw JSON-RPC error) follows golden rule #2: a page for
browsers, JSON for `curl`, both rendered from the live registry, so the page
can't list a tool that doesn't exist.

- Page: the endpoint with a copy button; per-client setup snippets ([research
  §5](00-research.md#5-clients-and-install-snippets)); a table per toolset with
  each tool's title, description and read-only/open-world badges; a "what is
  sent where" note; **the rate limits, published** (no surveyed server does);
  the data credits. No raw JSON-RPC `curl` example: a 2026-07-28 call needs
  `_meta` plus three headers, and `curl` users have the REST API, which the
  page links. The owner endpoint is not advertised.
- JSON: `{name, version, endpoint, toolsets: [{name, endpoint, tools: [{name,
  title, description, annotations}]}]}`.
- Every tool page's "Using this from the terminal" block gains one line, from
  a shared partial: "Use it from an AI agent: `https://mcp.corpberry.com/mcp/<toolset>`".
- Apex catalog (`site.Tools`) gains an "MCP server" entry; header nav picks it
  up.
- Official MCP Registry in floor 8: `server.json` in the repo, name
  `com.corpberry/tools`, one `streamable-http` remote, domain proved by a
  Cloudflare TXT record (no code). Re-published whenever the endpoint changes,
  so the entry never goes stale the way Cloudflare's and Globalping's have.

## 7. Testing

All in `tools/mcptools/tests/` (black-box), plus golden and hardening tests in
each tool's `tests/` for floor 1. `go test ./... -race`, no network, no BINs.

| Test | Catches |
|---|---|
| **Golden REST JSON** (floor 1a, before any move) | the refactor changing a REST response by one byte |
| **Coverage**: every route registered by every `Register` (with fakes) maps to a (tool, operation) or an exclusion | a REST endpoint added without an MCP decision |
| **Golden `tools/list`** per endpoint (names in order, descriptions, schemas, hints); names match `^[a-z0-9_]{1,64}$` | an accidental change to the agent-facing contract |
| **Size budgets**: `tools/list` per endpoint; each tool's result on a realistic fixture | descriptions and results creeping into context |
| **Parity**: REST JSON body, sanitized == MCP `structuredContent` (`detailed: true` where concise is default) | MCP and REST drifting apart |
| **Result shape**: every tool and operation returns an object `structuredContent`, never `null` | legacy TS/Python clients rejecting the whole result |
| **In-memory client** (`mcp.NewInMemoryTransports`): every tool and operation, happy path + one bad input | argument mapping, error text, hints |
| **HTTP** (`httptest` + `StreamableClientTransport`): vhost routing, each endpoint, browser GET → page, other GET → 405, body > 1 MiB → 413, **2-element batch → 400**, `Cache-Control: no-store`, no 3xx anywhere | the gate |
| **Owner endpoint**: no key / wrong key → 403 then 429; right key → 3 tools, `private`; the key header never reaches a handler | D4 |
| **Origin/Host**: `Sec-Fetch-Site: cross-site` → 403; foreign `Origin` → logged (floor 2) / allowlisted (after); unknown Host → 404 | D15, rebinding |
| **Panic**: a tool that panics → `isError`, process alive; fuzz each adapter's arguments | the SDK's missing `recover` |
| **Limits**: burst + 1 → tool error with retry hint, shared with the REST twin (spend on REST, refused on MCP); full concurrency cap → "busy"; list flood → limited | D12 |
| **Cancellation**: a 2025-11-25 client hanging up stops the handler | the `AfterFunc` bridge |
| **Sanitizer**: 10 KB string → capped with marker; U+202E and Tag characters → visible escapes | untrusted output |
| **Egress (floor 1b)**: MTA-STS, nameserver probes, RDAP redirects and `link_trace` all refuse loopback, private, CGNAT, our own hosts; DNS enrichment makes no Shodan call | D16 |
| **Client IP reaches the handler** through the request context; unparseable IP → shared bucket | undocumented SDK behaviour; fail-closed keys |
| **Protocol eras**: a 2026-07-28 and a 2025-11-25 client both list and call; `subscriptions/listen` returns at once | the stateless promise; `listChanged: false` |
| **Cipher bounds drift**: schema min/max vs the op's error at bound + 1 | schemas lying about limits |
| **Live smoke** (skips unless `MCP_LIVE_URL` is set): discover, list, one call per toolset against prod | DNS, nginx, Cloudflare |

MCP Inspector is the usual manual check, but it runs on `npx`; the SDK's own
client in the live smoke test covers the same ground without breaking the
no-Node rule.

## 8. Delivery floors

One PR per floor, from a fresh branch off `master`, deployed and smoke-tested
before the next starts.

| Floor | Ships | Done when |
|---|---|---|
| 0 | Owner answers the **bold** decisions (D4, D9, D12, D16, D17); the rest stand as leaned unless the owner objects | no *lean* left in §2 |
| 1a | Golden REST tests, then the domain push-down (§3.4). No MCP code | REST byte-identical before and after |
| 1b | Outbound hardening, Shodan split + limiter, source-side string bounds, credits in Go | egress tests green; DNS lookups make no Shodan calls |
| 1c | Limiter stores shared and cost-priced; `RateLimitKey` fail-closed | REST limits tests updated; one store per family |
| 2 | `tools/mcptools` skeleton: SDK pinned, vhost, gate, middleware, sanitizer, landing page, logging, **`ip` toolset**; docs (ARCHITECTURE, CLAUDE, DEPLOYMENT); DNS + nginx + Cloudflare. **Gates:** nginx accepts only Cloudflare; Bot Fight Mode off | `claude mcp add` against prod lists and calls the `ip` tools, **and a claude.ai custom connector does too**; its `Origin` is in the log |
| 3 | Origin allowlist (D15 step 2); `dns` toolset; budgets measured, concise defaults where needed | parity + golden list green; live smoke |
| 4 | `link` toolset, public tools | same; egress tests |
| 5 | `/mcp/owner` + `MCP_OWNER_KEY` | public lists unchanged; owner tests green |
| 6 | `cipher` toolset (10 tools over 15 ops) | every op called through MCP with its existing test vectors |
| 7 | `botcheck` + `site` toolsets | no corpus writes from MCP (test) |
| 8 | Discovery: page partial, apex entry, README, MCP Registry | listing live; domain verified |
| 9 | *Optional*: resources (tracking rules, encoding reference, blog posts) and prompts (`audit_domain`, `inspect_link`) | only if call logs show agents need them |

## 9. Docs to update (in the floors that change them)

- `CLAUDE.md`: layout gains `tools/mcptools`; pinned `go-sdk` version; golden
  rule #2 becomes "HTML + JSON + MCP": a new API endpoint ships with its tool
  (or operation) or a coverage-table exclusion.
- `docs/ARCHITECTURE.md`: §1 stack table, §3 host map, §4 MCP as the third
  transport, §7 layout, §10 the request log's MCP records.
- `docs/DEPLOYMENT.md`: §3 the new block and its body limit; the Cloudflare
  ingress gate; `MCP_OWNER_KEY`.
- `README.md` (repo): one paragraph + the endpoint.

## 10. Risks

| Risk | Mitigation |
|---|---|
| A hosted client sends an `Origin` or trips a WAF rule and can't connect | D15 observes before it enforces; Bot Fight Mode off; claude.ai connector tested in floor 2 before anything else ships |
| One hostile request takes down every subdomain (panic, memory, CPU) | recover per message; batches refused; body and depth caps; global and memory-weighted caps |
| Shared egress IPs of hosted connectors exhaust per-IP buckets | per-call log shows `limited`; raise MCP's classes if real users hit them |
| Shodan bans the site's IP | DB-only enrichment; process-wide ~1/s limiter; open ports skipped when spent |
| 29 tools still too many for clients without tool search | toolset endpoints (1–10 tools); descriptions route between neighbours |
| A third-party string steers the model (prompt injection) | sanitized, capped, labelled; the owner tools live on their own endpoint and create asks first |
| Spec churn (three versions in 13 months) | stateless + no optional features = little surface; an SDK bump is one PR |
| The SDK's ctx-value propagation (undocumented) changes | pinned by a test; fallback is `req.Extra.Header` + the CF header |
| The agent-facing contract changes by accident | golden `tools/list` test turns every change into a reviewed diff |
