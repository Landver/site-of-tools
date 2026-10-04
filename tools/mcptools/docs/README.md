# MCP server (`mcp.corpberry.com`): build plan

**Status: planned, not built (2026-10-04).** The six **bold** decisions in §2
wait for the owner; the rest stand unless the owner objects. Reviewed by five
independent agents in three rounds before handover; every finding and what it
changed is in the [review log](03-review-log.md).

| Doc | What's in it |
|---|---|
| this file | the plan: decisions, architecture, the refactors first, tests, floors |
| [00-research.md](00-research.md) | MCP spec + Go SDK facts, and how comparable public servers did it, with sources |
| [01-tool-catalog.md](01-tool-catalog.md) | every REST endpoint → its MCP tool (or why it isn't one) |
| [02-security-and-ops.md](02-security-and-ops.md) | threat model, the request gate, limits, outbound reach, untrusted output, deploy steps |
| [03-review-log.md](03-review-log.md) | what the reviewers found and what changed because of it |

## 1. What this is

Every tool on the site already speaks two representations from one domain call:
HTML for browsers and JSON for `curl` ([ARCHITECTURE §4](../../../docs/ARCHITECTURE.md)). MCP is a **third
transport over the same domain code**, so an AI agent (Claude Code, Claude
Desktop and claude.ai, Cursor, VS Code, ChatGPT, Codex, Gemini CLI) can call the
tools as tools instead of being told how to `curl` them.

- **One new subdomain**, `mcp.corpberry.com`, served by the same binary like
  every other host: one `*echo.Echo`, one vhost entry, one nginx block.
- **Every JSON endpoint has a decision**: 40 routes become 35 public tools +
  3 owner tools, one per distinct task, generated where the domain already
  holds the contract ([catalog](01-tool-catalog.md#how-rest-maps-to-tools)).
  Two JSON routes are deliberately not tools: `ip.corpberry.com/history` (D9,
  the owner's call) and the apex JSON catalog (replaced by `tools/list`). A
  coverage test fails CI on any route without an entry. The owner's three
  short-link tools (create, list, revoke) live on their own key-gated
  endpoint.
- **Endpoints:** `https://mcp.corpberry.com/mcp` (all 35, for clients with tool
  search such as Claude Code); `/mcp/ip`, `/mcp/dns`, `/mcp/link`,
  `/mcp/cipher`, `/mcp/botcheck`, `/mcp/site` (1–15 tools each, for every other
  client); `/mcp/owner` (3 tools, key required).
- **The pages that prompted this point to it as soon as it works**: each tool
  page's "Using this from the terminal" block gains an MCP line in the same
  floor as its toolset, starting with IP Tools in floor 2a.
- **Same results as the REST API**, projected where a token budget demands it;
  each projection is declared per tool and checked by a parity test.
- **Nothing new reaches the network.** No tool dials anything a REST route
  doesn't already dial. Review found those REST paths guarded unevenly and
  capped loosely, so they are fixed first, for both transports (floors 1a–1c).
  **Those floors are worth doing even if MCP were dropped.**

**Not in scope:** user accounts or OAuth, a stdio/npm package, MCP Apps (UI in
the chat), tasks, elicitation, sampling, Server Cards (not merged), resources
and prompts (floor 9, optional), and an MCP endpoint on each tool's own
subdomain.

## 2. Decisions

Each row: the choice, the lean, and what the alternative costs. Confidence is
how sure the lean is right, not how sure it works. The ones that genuinely need
the owner are **bold**; the rest stand as leaned unless the owner objects.

| # | Decision | Lean | Conf. | Alternative and its cost |
|---|---|---|---|---|
| D1 | SDK | Official `github.com/modelcontextprotocol/go-sdk` **v1.8.0** | 90% | `mark3labs/mcp-go` v1.1.1: active and popular, but ~5 weeks late to the current spec; the official SDK is the one GitHub's own Go server pins ([research §3](00-research.md#3-official-sdk-vs-mark3labsmcp-go)). |
| D2 | Where the code lives | One package, `tools/mcptools/`: transport + one adapter file per toolset; tool packages stay SDK-free | 75% | Each tool exports its own `mcp.go`: better co-location, but the SDK leaks into five packages and `ciphertools` would need a second `!js` file. |
| D3 | Transport | Streamable HTTP, **stateless**, **plain JSON responses**, no legacy SSE, no JSON-RPC batches | 90% | Spec 2026-07-28 removed sessions and the SDK serves it only stateless, so this is barely a choice. SSE adds proxy-buffering trouble; no tool streams. |
| **D4** | Owner tools (short-link create/list/revoke) | Only at `/mcp/owner`, which serves just those three, behind a new `MCP_OWNER_KEY` (`X-Api-Key` or `Authorization: Bearer`); create marked destructive ([security §8](02-security-and-ops.md#8-owner-tools-secrets-and-logs)) | 70% | Leave them out of MCP: simplest and safest, but "every endpoint" stops being true. Mix them into `/mcp` behind a header: a shared cache can serve the anonymous list to the owner, and they'd sit beside tools returning attacker text. |
| D5 | Toolsets | Path-selected: `/mcp` (all) and `/mcp/<toolset>` | 80% | One endpoint only: 35 tools in every client's context; Cursor's soft cap is ~40 across *all* servers. Header-selected toolsets: harder to paste into a config. |
| D6 | Where adapter logic lives | **Push handler logic down first** (floor 1a). Adapters only map arguments → domain call → result | 90% | Copy it into adapters: fast, but two copies of `/domain`'s concurrency, `/consistency`'s ECS card, IP enrichment, the owner create path, which will drift. Golden rule #1 says no. |
| D7 | `outputSchema` | **None in v1**: `structuredContent` + JSON text, no declared schema | 75% | Declare one per tool: the SDK turns a result that fails its own schema into a protocol error, and inferred schemas are wrong for `[]byte`/`json.RawMessage`, `net.IP`, custom marshalers and nil maps. Later, per tool, behind a conformance test. |
| D8 | Auth for public tools | None, same as REST | 90% | OAuth: no accounts to protect, and it locks out every client without an OAuth flow. |
| **D9** | `GET /history` (recent lookups by web visitors) | **Not a tool** | 60% | One small tool for strict parity; it costs a slot in every context for data no agent task needs: addresses *other* people looked up. |
| D10 | `link_short_resolve` counts a hit? | No | 75% | Yes: hit counts then include agents that only asked where a link goes. |
| D11 | `botcheck_score` semantics | Scores the fingerprint/headers/IP the agent supplies; what wasn't supplied is **skipped, not failed**, and the result says how much was evaluated; no corpus reads or writes | 75% | Score the MCP request itself (REST `GET /` parity): that describes Anthropic's or OpenAI's HTTP client. Score as-is: absent headers fire rules, and a headers-only call can read "human" with 59 of 68 rules skipped. |
| **D12** | Rate limits and capacity | Limiter stores **and concurrency caps** built once per tool package and shared by REST and MCP, keyed the same way; classes priced by upstream cost, which REST adopts too; every JSON-RPC message counted ([security §6](02-security-and-ops.md#6-rate-limits-and-capacity-d12)). **REST changes too:** `/consistency` and `/trace` go from 2/s (burst 10) to 1 per 2 s (burst 3); IP lookups and botcheck get limits for the first time (2/s); `POST /jwt/sign` drops from 10/s to 1/s | 70% | MCP-only limiters and caps: simpler, but each transport gets its own budget, and someone could still exhaust the box's memory through REST's `POST /password/hash`, which MCP-only caps don't cover. |
| D13 | Discovery | Landing page at `/` (HTML + JSON, also on a browser `GET /mcp`), an MCP line on every page's "Using this from the terminal" block, an apex catalog entry, then the official MCP Registry (`com.corpberry/tools`, DNS-verified) | 80% | Registry first: it is still preview, and names should be stable before they're announced. |
| **D14** | Tool granularity | **One tool per distinct task, 35 tools**; no operation switches; cipher tools generated from field specs the ops export ([catalog rules](01-tool-catalog.md#how-rest-maps-to-tools)) | 70% | Merged tools with an `operation` argument (29, the first draft): reviewers found the merged contracts couldn't be stated honestly (defaults, enums and bounds differ per op) and hid a mode switch. Harder merging (~20): fewer tools, each harder to use correctly. |
| D15 | Origin check (a spec MUST) | Two steps: floor 2b rejects browser cross-site requests by `Sec-Fetch-Site` and **logs** foreign `Origin`s; floor 3 adds an allowlist from those logs and 403 for the rest ([security §3](02-security-and-ops.md#3-browsers-and-dns-rebinding-d15)) | 70% | Strict from day one (`http.NewCrossOriginProtection`): compliant at once, but Anthropic warns strict Origin checks break its connectors, and we don't know what Origin they send. |
| **D16** | Harden REST's outbound paths before MCP exposes them | Today several REST features can be steered into connecting to private networks or to this server; fix them before agents can call them at machine speed. Yes (floor 1b): nameserver probes and RDAP/CT redirects through the one guard, MTA-STS through it on 443 with no proxy; Shodan only where its data is shown, under a process-wide limiter; third-party strings bounded at the source ([security §5](02-security-and-ops.md#5-outbound-reach)) | 80% | Ship MCP first, harden later: faster, but it automates access to paths review found weak, and one can get the site's IP banned by Shodan. |
| **D17** | Licensed data in MCP results (IP2Location LITE, Spamhaus DROP, Shodan InternetDB) | Keep, with an `attribution` list in each result built from the same credits the footer shows ([security §9](02-security-and-ops.md#9-licensed-data-d17)) | 60% | Drop Shodan's open ports from MCP: cleanest under its non-commercial terms, loses the one live-scan signal `ip_lookup` has. |

### Terms used below

- **Golden test**: saves today's output to a file and fails when a change
  alters it; the diff is then reviewed like code.
- **AST test**: a test that reads the Go source itself (its syntax tree) to
  check something, here that every field an op reads is declared.
- **Pointer-typed argument**: `*bool` instead of `bool`, so "not sent" (`nil`)
  differs from `false`.
- **Semaphore + `TryAcquire`**: a counter of jobs in flight; when it is full,
  the call answers "busy" at once instead of queueing.
- **Receiving middleware**: code the SDK runs around every MCP message, like
  FastAPI middleware around every request.
- **Projection**: the REST JSON with declared fields dropped or reshaped for
  MCP (a concise default, a wrapper, an added `attribution`).

## 3. Architecture

```
client (Claude Code, claude.ai connector, Cursor, …)
  │  POST https://mcp.corpberry.com/mcp/dns    tools/call dns_lookup {...}
  ▼
Cloudflare → nginx → Echo vhost "mcp.corpberry.com"     (unknown Hosts already 404)
  │  NewApp middleware: recover · request log · security headers · gzip
  ▼
the /mcp gate (Echo)    toolset 404 · browser GET → landing page · owner key → 403 / strip
                        /mcp limiter · body ≤ 1 MiB, no batches · Sec-Fetch-Site / Origin
                        raw IP + limiter key → context · Cache-Control: no-store
  ▼
go-sdk StreamableHTTPHandler        Stateless · JSONResponse · MaxRequestBodyBytes 1 MiB
  │  getServer(req): pure lookup by toolset (owner → the owner server)
  ▼
receiving middleware (per message)  recover · deadline · the tool's Limits (rate + cap)
                                    → tool → sanitize · per-call record
  ▼
adapter (tools/mcptools/dns.go)     typed args → domain call → result
  ▼
dnstools.LookupEnriched             ← the SAME code GET dns.corpberry.com/ runs,
                                      behind the SAME dnstools.Limits
```

Each step's reason is in [security §2 and §4](02-security-and-ops.md#2-the-mcp-gate-echo-before-the-sdk).

### 3.1 Package layout

```
tools/mcptools/                  # mcp.corpberry.com, self-contained like every tool
├── handler.go     # Register(e, Deps, base) error: landing (HTML + JSON) + the /mcp gate
├── server.go      # one *mcp.Server per toolset + the owner server, built at boot
├── middleware.go  # receiving middleware: recover, deadline, Limits, sanitize, record
├── sanitize.go    # output post-processor: string caps, bidi/format escaping, hard cap
├── registry.go    # tool spec (name, toolset, limits, hints, projection) + Coverage table
├── schema.go      # inferred input schemas + enums/bounds from domain lists and cipher specs
├── ip.go dns.go link.go cipher.go botcheck.go site.go owner.go   # adapters
├── embed.go · templates/index.html                               # landing page
├── tests/         # black-box: in-memory client, HTTP, parity, golden tools/list, coverage
└── docs/
```

`mcptools` imports the tool packages; nothing imports `mcptools` except
`main.go` (platform ← iptools ← dnstools/botcheck ← mcptools ← main; no
cycles). Tool packages never import the SDK. `ciphertools` is reached through
`ciphertools.Run` and its exported field specs, all in files without a build
tag, so its wasm build is untouched.

### 3.2 Wiring (`main.go`)

```go
// One subdomain list feeds both the vhost map and the trace guard's deny list,
// so a new subdomain can't be left out of either (floor 1b).
ipLim, dnsLim, linkLim := iptools.NewLimits(), dnstools.NewLimits(), linktools.NewLimits()
cipherLim, botLim := ciphertools.NewLimits(), botcheck.NewLimits()
// … each REST Register(…, xxxLim) as today, then MCP gets the same values.

// The owner's Shortener: same store, its own key, and the same cleaner the
// REST one gets (without it, create with clean: true fails).
owner := linktools.NewShortener(linkStore, cfg.MCPOwnerKey, cfg.URL("link"))
if owner != nil {
    owner.CleanTarget = linktools.CleanTargetFunc(linkSvc)
}

mcpApp := platform.NewApp(renderer, staticFS, cfg.IsDev(), reqlog)
if err := mcptools.Register(mcpApp, mcptools.Deps{
    Geo: geo, Blocklist: iptools.CheckerFrom(blocklist), // never a nil *BlockList in an interface
    DNS: dnsSvc, Domain: domainClient,
    Link: linkSvc, Tracer: tracer,
    Short: shortener, // public resolve; nil without LINK_API_KEY, like /s/:code's 503
    Owner: owner,     // nil without MCP_OWNER_KEY → /mcp/owner is 404
    Blog:  blog,
    IPLimits: ipLim, DNSLimits: dnsLim, LinkLimits: linkLim, CipherLimits: cipherLim, BotLimits: botLim,
    RequestLog: reqlog,
}, cfg.URL("mcp")); err != nil {
    return err
}
platform.RegisterSEO(mcpApp, cfg.URL("mcp"), mcptools.SitemapPages)
hosts[cfg.VHost("mcp")] = mcpApp
```

`site_blog` is the one tool with an MCP-only limiter: the REST blog has none
and is static. A dependency that is off at boot (nil tracer, nil shortener, nil
owner shortener, Mongo down) **removes its tools** from the list rather than
leaving tools that can only fail; a dependency that fails at call time is a tool error, the same split the
handlers make between 503 and 502. Each list is fixed per process, which is
what the spec's "MUST NOT vary per-connection" asks.

### 3.3 One tool, end to end

```go
// dns.go: transport only. Arguments in, domain call, struct out.
type dnsLookupArgs struct {
    Name     string `json:"name" jsonschema:"domain name, or an IP address for a reverse (PTR) lookup"`
    Type     string `json:"type,omitempty" jsonschema:"record type, or ALL (default) for every common type at once"`
    Resolver string `json:"resolver,omitempty" jsonschema:"public resolver to ask (default cloudflare)"`
    Detailed bool   `json:"detailed,omitempty" jsonschema:"return the full REST body, including zone-file renderings"`
}

func (t *toolset) dnsLookup(ctx context.Context, _ *mcp.CallToolRequest, a dnsLookupArgs) (*mcp.CallToolResult, any, error) {
    set, err := dnstools.LookupEnriched(ctx, t.deps.DNS, t.deps.Geo, a.Name, a.Type, a.Resolver)
    if err != nil {
        return nil, nil, err // SDK → isError result carrying the REST API's own message
    }
    return nil, t.project("dns_lookup", set, a.Detailed), nil // SDK → structuredContent + JSON text
}
```

Recovery, the deadline, the rate check, the concurrency cap, sanitizing and
the per-call record are not in the handler: the receiving middleware does them
for every tool, from the tool's registered `Limits`. Enums come into the
inferred schema in `schema.go` from `dnstools.Types` / `dnstools.Resolvers`
(the SDK's `jsonschema` tag carries descriptions only). Defaults ("" → the
default resolver, `ALL` → the fan-out, lower-casing) live inside
`LookupEnriched`, so REST and MCP can't normalise differently.

### 3.4 Floor 1: what changes before any MCP code

**1a: push-down, one PR per package** (behaviour-preserving; each move pinned
first by a golden test of the current REST JSON, compared semantically):

| Package | From the handler | To the domain (exported) |
|---|---|---|
| iptools | `show`: lookup + blocklist; the self-IP rule | `LookupWithReputation(ctx, looker, checker, ip)` over a small `Checker` interface (`*BlockList` can't be faked) converted from nil like `dnstools.BlockCheckerFrom`; `Routable(ip)`; `(*Service).Offline()` (a copy without Shodan, for 1b) |
| dnstools | `show` + `enrich`; `consistency` (Spread ∥ ECS, delegation health, envelope); `domain` (validation, RDAP ∥ CT); `email` + MX reputation; resolver/type defaults and lower-casing | `LookupEnriched`, `Consistency`, `DomainInfo` (a struct whose fields are declared in the map's alphabetical key order so the JSON stays identical, each half's error kept as `json:"-"` for the handler's 503/502/`RegAbsent`), `EmailReport` |
| linktools | `utm` (with **absent = keep** support); the curl → URL branch; `diff`; the owner create path (body, TTL parsing, sentinel → fixed sentence) | `BuildUTM(raw, changes)`, `ParseCurl(cmd)` (alphabetical fields), `Diff(a, b)`, `Shortener.CreateFrom(req, ip)`, `PublicError(err)`, `CodeFromShortURL`; `RuleCatalog` lookups for a `param` and for a URL's verdict |
| ciphertools | the JSON → `Input` conversion (with its `FormatFloat 'f'` trap); field names, defaults and bounds scattered as literals | `InputFromJSON`; **per-op field specs** (name, type, enum, default, min, max, description) that the ops' parsers and MCP's `schema.go` both read, guarded by an AST test; `MemoryCost(op, in)` for 1c. All pure, wasm-safe |
| botcheck | header → `Signals` mapping, `Now`, `EgressIP` (a zero `Now` silently skips the timezone checks); IP → timezone/ASN/proxy/blocklist | a constructor in a new file (the scorer's file imports only stdlib) and `AddIPSignals`; header and IP rules **skip** when not supplied, and `Report` counts evaluated / skipped / fired per tier (D11). Over HTTP the request's own headers always count as supplied (a missing header stays evidence), so REST verdicts don't change; REST JSON gains the counts, as one reviewed golden diff |

**1b: outbound hardening, three PRs** (D16; REST benefits): (1) egress:
nameserver probes and trace through `PubliclyRoutable`, RDAP/CT redirect hops
through the guard (the configured base stays dialable, which keeps the
loopback test servers working), MTA-STS through the guard on 443 with no proxy
and no keep-alive, the guard taking literal addresses (the host's public IPs,
from config) into its address deny set, one subdomain list for vhosts and deny
list; (2) Shodan: DNS gets `geo.Offline()`, Shodan gets one process-wide
limiter; (3) third-party header values bounded where they enter, and the
licence credits moved into Go so the footer partial and MCP render the same
text (D17). Detail in [security §5](02-security-and-ops.md#5-outbound-reach).

**1c: shared limits and caps** (D12): `platform/ratelimit.go` (a `Limiter`
alias for Echo's store, `NewLimiter`, a `RateLimit` middleware always keyed by
`RateLimitKey`, so dnstools stops keying on the raw IP); per package `Limits`
+ `NewLimits()` with its rate stores and `x/sync/semaphore.Weighted` caps
(`TryAcquire`, so a full cap answers "busy" instead of queueing);
`Register(…, lim *Limits)` with nil meaning fresh limits, so existing tests
pass nil; the new cost classes for REST too; `RateLimitKey` folds unparseable
input into one bucket.

Header reading, view models, status codes and attribution flags stay in the
handlers: they are HTTP.

## 4. Protocol choices

- **Spec 2026-07-28**, plus older clients (2025-06-18 / 2025-11-25), which the
  SDK serves in stateless mode by answering `initialize` without keeping
  anything. Legacy JSON-RPC **batches are refused** before the SDK.
- **Capabilities set explicitly: tools, `listChanged: false`.** Left nil, the
  SDK advertises deprecated `logging` and infers `listChanged: true`, after
  which `subscriptions/listen` holds an SSE stream open even in JSON mode.
- **List caching:** `ttlMs` 1 hour; `cacheScope: "public"` everywhere except
  `/mcp/owner` (`"private"`). Tools come back in name order (the SDK sorts), so
  the prefixes group them.
- **Server `instructions`** per endpoint, naming only that endpoint's tools;
  the `/mcp` one also routes across toolsets (`dns_trace` vs
  `link_redirect_chain`, `link_percent_encode` vs `cipher_encode`). Clients
  needn't fetch instructions, so the third-party-data line is also in each
  affected tool's description.
- **Results:** `structuredContent` (always a JSON object) + the same JSON as
  text, no `outputSchema` (D7), concise by default where over budget,
  `detailed: true` for the full body.
- **Errors:** bad input (schema validation runs first, in the SDK), an
  upstream failure, a disabled feature, a rate limit or a full cap are *tool*
  errors with an actionable sentence; protocol errors are the SDK's.
- **Contract changes:** a renamed tool or argument breaks every agent that
  cached the list. Avoid renames; when one is unavoidable, the middleware keeps
  the old name callable for a release (GitHub does the same).

## 5. Security in one screen

Full detail in [02-security-and-ops.md](02-security-and-ops.md).

- **The box:** panics recovered per message (the SDK doesn't); batches refused;
  1 MiB bodies; every JSON-RPC message rate-limited; concurrency caps shared
  with REST, memory-weighted for password hashing and key generation.
- **Browsers:** JSON-only bodies + no CORS headers already stop cross-site
  calls; `Sec-Fetch-Site` check on top; Origin allowlist from floor 3 (D15).
  DNS rebinding stops at Echo's exact-Host vhost map.
- **Outbound:** every dialling path through the one egress guard before the
  `dns` and `link` toolsets ship (D16); Shodan under a process-wide limiter.
- **Rate limits:** one budget per client per tool package, whichever door;
  priced by cost; the client IP trusted only once nginx is confirmed to accept
  Cloudflare alone (floor-2b gate).
- **Untrusted output:** strings capped and bidi/format characters made visible;
  lists never cut; third-party data labelled.
- **Owner tools:** own endpoint, own `Shortener` over the same store with its
  own key, key stripped before the SDK, failed-key limiter, create marked
  destructive.
- **Logs:** per-call records through the existing request log (rule #5) and
  slog: outcome class only; never arguments, results or error text.
- **Licences:** `attribution` in results that use licensed data (D17).

## 6. Landing page and discovery

`GET mcp.corpberry.com/` (and a browser's `GET /mcp`, which every server
surveyed answers with a raw JSON-RPC error) follows golden rule #2: a page for
browsers, JSON for `curl`, both rendered from the live registry, so the page
can't list a tool that doesn't exist. The page's view model and JSON body
differ, so floor 2a moves the `reply` helper (copied today in dnstools and
linktools) into `platform` and uses it here.

- **Page:** the endpoints with copy buttons; per-client setup ([research
  §5](00-research.md#5-clients-and-install-snippets)): `/mcp` only for Claude
  Code, toolset URLs for everyone else, Gemini CLI's `httpUrl` (its `url` means
  SSE), ChatGPT's developer mode, claude.ai's per-plan limits; a table per
  toolset (title, description, read-only / open-world badges); "what is sent
  where"; **the rate limits, published** (no surveyed server does); the data
  credits; a link to each tool's REST API for `curl` users (a raw 2026-07-28
  JSON-RPC call needs `_meta` plus three headers). The owner endpoint isn't
  advertised; its setup note says it needs a client that can send headers
  (Claude Code with `--scope user`, Codex's `bearer_token_env_var`, VS Code,
  Cursor, Gemini CLI), which rules out claude.ai and ChatGPT.
- **JSON:** `{name, version, endpoints: [{path, tools: [{name, title,
  description, annotations}]}]}`.
- **Plumbing:** `templates/` registered as a `TemplateSource` in `main.go` and as
  an `@source` line in `input.css` (Tailwind sees only literal class names).
- **Per-page MCP line:** today each tool page carries its own "Using this from
  the terminal" block inline (26 templates, hard-coded URLs), not a shared
  partial. Floor 2a adds one partial and the IP pages' line; each toolset's
  floor then adds the line to its own pages. Any template function the partial
  needs goes into `navBaseFuncs` and the cipher `FragmentTemplates` stubs too,
  or the wasm engine fails to parse its templates.
- **Apex catalog:** `site.Tools` gains "MCP server" (last, keeping A→Z).
- **Official MCP Registry** in floor 8: `server.json` in the repo, name
  `com.corpberry/tools`, one `streamable-http` remote per public endpoint,
  domain proved by a Cloudflare TXT record (no code). Re-published whenever an
  endpoint changes, so it never goes stale the way Cloudflare's and
  Globalping's entries have.

## 7. Testing

All in `tools/mcptools/tests/` (black-box), plus golden, hardening and limits
tests in each tool's `tests/` for floor 1. `go test ./... -race`, no network,
no BINs.

| Test | Catches |
|---|---|
| **Golden REST JSON** (each 1a PR, before its move; semantic compare, since struct fields replace sorted map keys) | a refactor changing a REST response |
| **Coverage**: each `Register` built offline with fakes; every route from `e.Router().Routes()` (minus `/static*`, sitemap, robots) must have a `Coverage` entry: a tool, an exclusion, or **planned** (so floor 2a passes before floors 3–7 land); no stale entries; each landed tool appears in `tools/list` | a REST endpoint added without an MCP decision |
| **Golden `tools/list`** per endpoint (names in order, descriptions, schemas, hints); names match `^[a-z0-9_]{1,64}$` | an accidental change to the agent-facing contract |
| **Cipher field specs**: AST scan finds every `in.Get` / `intField` / `in.Fields` / `in.Files` key declared; schema bound vs the op's error at bound + 1 | contracts drifting from the code |
| **Size budgets**: `tools/list` per endpoint; each tool's result on a realistic fixture (TXT-heavy zone, 200 CT names, click-tracked newsletter) | context bloat |
| **Parity**: MCP `structuredContent` == the tool's declared projection of the REST body, semantic compare (`UseNumber`); exempt tools listed with the reason | MCP and REST drifting apart |
| **Result shape**: every tool returns an object, never `null`, with each optional argument omitted in turn (absent ≠ empty ≠ false) | legacy-client failures; `unwrap`/`utm` defaults |
| **In-memory client** (`mcp.NewInMemoryTransports`): every tool, happy path + one bad input | argument mapping, error text, hints |
| **HTTP** (`httptest` + `StreamableClientTransport`): vhost routing, each endpoint, browser GET → page, other GET → 405, body > 1 MiB → 413, **2-element batch → 400**, `Cache-Control: no-store`, no 3xx anywhere | the gate |
| **Owner endpoint**: no key / wrong key → 403 then 429; `X-Api-Key` and Bearer both work; 3 tools, `private`; the key header never reaches a handler; works with `LINK_API_KEY` unset | D4 |
| **Origin/Host**: `Sec-Fetch-Site: cross-site` → 403; a foreign `Origin` → logged (2b) / allowlisted (3); unknown Host → 404 | D15, rebinding |
| **Panic**: a tool that panics → `isError`, process alive; fuzz each adapter's arguments | the SDK's missing `recover` |
| **Limits** (1c + MCP): spend a budget over REST, get refused over MCP; IPv6 client = one bucket on both doors; full cap → "busy"; list flood → limited; unparseable IP → shared bucket | D12 |
| **Cancellation**: a 2025-11-25 client hanging up stops the handler | the `AfterFunc` bridge |
| **Sanitizer**: 10 KB string → capped with marker; U+202E and Tag characters → visible escapes; a 9-nameserver result keeps all 9 | untrusted output; no silent list cuts |
| **Egress** (1b): nameserver probes, trace, RDAP redirect hops, MTA-STS and `link_redirect_chain` refuse loopback, private, CGNAT and our hosts; DNS lookups make no Shodan call | D16 |
| **Client IP**: the raw IP and the limiter key both reach the handler through the request context | undocumented SDK behaviour; `"self"` and `CreatedIP` need the raw IP |
| **Protocol eras**: a 2026-07-28 and a 2025-11-25 client both list and call; `subscriptions/listen` returns at once | the stateless promise; `listChanged: false` |
| **Botcheck coverage**: headers-only call → client rules counted as skipped, verdict not "human" by default | D11 |
| **Live smoke** (skips unless `MCP_LIVE_URL` is set): discover, list, one call per toolset against prod | DNS, nginx, Cloudflare |

MCP Inspector is the usual manual check, but it runs on `npx`; the SDK's own
client in the live smoke test covers the same ground without breaking the
no-Node rule.

## 8. Delivery floors

One PR per row, each from a fresh branch off `master`, deployed and checked
before the next. Floors 1a–1c change REST only and are worth shipping on their
own.

| Floor | Ships | Done when |
|---|---|---|
| 0 | Owner answers the six **bold** decisions (D4, D9, D12, D14, D16, D17) | each bold row answered |
| 1a ×5 | Push-down, one PR each: iptools, dnstools, linktools, ciphertools (field specs + AST test), botcheck (skip-not-fail + coverage counts) | golden REST tests green before and after; botcheck's JSON gains its coverage counts as one reviewed golden diff |
| 1b ×3 | Egress (incl. `EgressGuard` literal addresses + config, one subdomain list); Shodan (`Offline()` + process-wide limiter); string bounds at the source + credits in Go | egress tests green; DNS makes no Shodan calls |
| 1c | `platform/ratelimit.go`, per-package `Limits` with caps, REST on the new classes, `RateLimitKey` fail-closed | limits tests green, incl. updated `netgate_test` |
| 2a | `tools/mcptools`: SDK pinned, vhost, gate, middleware, sanitizer, landing page, per-call records, coverage test with *planned* entries, **`ip` toolset**; `reply` moved into `platform`; the shared terminal-block partial + the IP pages' MCP line; config (`MCP_OWNER_KEY`) + `.env.example` + `config_test`; docs | all tests green locally |
| 2b | Launch: Cloudflare DNS, nginx block, deploy. **Gates:** nginx accepts only Cloudflare; Bot Fight Mode off | `claude mcp add` lists and calls the `ip` tools against prod, **and a claude.ai custom connector does too**; its `Origin` is in the log |
| 3 | Origin allowlist (D15 step 2); `dns` toolset with its concise defaults; the DNS pages' MCP line | parity + golden list green; live smoke |
| 4 | `link` toolset, public tools; the link pages' MCP line | same; egress tests |
| 5 | `/mcp/owner` with its own `Shortener` | owner tests green; public lists unchanged |
| 6 | `cipher` toolset, generated from the field specs (15 tools); the cipher pages' MCP line | every op called through MCP with its existing test vectors |
| 7 | `botcheck` + `site` toolsets (blog keeps Markdown as `json:"-"`; `site.Register` returns the blog); the botcheck page's MCP line | no corpus writes from MCP (test) |
| 8 | Discovery: apex catalog entry, repo README, MCP Registry | listing live; domain verified |
| 9 | *Optional*: resources (tracking rules, encoding reference, blog posts) and prompts (`audit_domain`, `inspect_link`) | only if call logs show agents need them |

## 9. Docs and config to update (in the floors that change them)

- `CLAUDE.md`: layout gains `tools/mcptools`; pins `go-sdk` v1.8.x **and**
  `google/jsonschema-go` v0.4.x (`schema.go` imports it directly); golden rule
  #2 becomes "HTML + JSON + MCP": a new API endpoint ships with its tool or a
  `Coverage` entry.
- `docs/ARCHITECTURE.md`: §1 stack table, §3 host map, §4 MCP as the third
  transport, §7 layout, §10 the request log's MCP records.
- `docs/DEPLOYMENT.md`: §3 the new block and its body limit; the Cloudflare
  ingress gate; `MCP_OWNER_KEY`; and drop the stale `deploy/nginx/` reference
  (the folder left git in an earlier commit).
- `platform/config.go` + `config_test.go` + `.env.example`: `MCP_OWNER_KEY`, the
  host's public addresses for the egress deny set.
- Repo `README.md`: one paragraph + the endpoints.
- CI, Dockerfile, air and the Makefile need no change.

## 10. Risks

| Risk | Mitigation |
|---|---|
| A hosted client sends an `Origin` or trips a WAF rule and can't connect | D15 observes before it enforces; Bot Fight Mode off; claude.ai tested in floor 2b before anything else ships |
| One hostile request takes down every subdomain (panic, memory, CPU) | recover per message; batches refused; body and depth caps; caps shared with REST, memory-weighted |
| Shared egress IPs of hosted connectors exhaust per-IP buckets | per-call records show `limited`; raise the MCP-facing classes if real users hit them |
| Shodan bans the site's IP | DB-only enrichment; process-wide ~1/s limiter; open ports skipped when spent |
| 35 tools on `/mcp` too many for some clients | `/mcp` recommended only with tool search; toolset URLs (1–15 tools) for the rest |
| A third-party string steers the model (prompt injection) | sanitized, capped, labelled; the owner tools live on their own endpoint and create asks first |
| Cipher contracts drift from the ops | generated from the ops' own field specs; AST test |
| Spec churn (three versions in 13 months) | stateless + no optional features = little surface; an SDK bump is one PR |
| The SDK's ctx-value propagation (undocumented) changes | pinned by a test; fallback is `req.Extra.Header` + the CF header |
| The agent-facing contract changes by accident | golden `tools/list` turns every change into a reviewed diff |
