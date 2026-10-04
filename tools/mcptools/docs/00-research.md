# Research: MCP in October 2026, and how others built theirs

Part of the [MCP plan](README.md). Gathered 2026-10-04 from primary sources
(spec pages, SDK source and releases, vendors' own docs). Items marked
**unverified** were not confirmed against a primary source. Two spec points
that decide the design (tool lists varying by credential; `cacheScope`) were
re-read from the spec pages directly, not from a summary.

## 1. The spec: 2026-07-28 is stateless

Current version **2026-07-28**; the two before it are 2025-11-25 and 2025-06-18
[S1][S3]. What changed that matters here [S2][S4]:

- **No sessions, no handshake.** `Mcp-Session-Id` (SEP-2567), the `initialize`
  round trip, the GET stream, `Last-Event-ID` resumability, `ping` and
  `logging/setLevel` are gone. Every request carries `_meta` with the protocol
  version, client info and client capabilities (SEP-2575); servers implement
  `server/discover`, which also carries the optional `instructions` [S8].
- **Headers.** Every POST carries `MCP-Protocol-Version`, and now `Mcp-Method`
  and `Mcp-Name` too (SEP-2243). A header that disagrees with the body is a 400
  (`-32020 HeaderMismatch`). Older clients still `initialize`; a server answers
  GET/DELETE with 405 and ignores a session id.
- **Legacy HTTP+SSE** is formally deprecated (SEP-2596).
- **`tools/list`** "MUST NOT vary per-connection", "MAY vary by the
  authorization presented on the request", and SHOULD be in a deterministic
  order [S5]. Every complete list result MUST carry `ttlMs` and `cacheScope`
  [S9b]: `"public"` = identical for all callers, cacheable by shared gateways;
  `"private"` = varies per authorization context, never shared across tokens.
  **So a key-gated tool list is allowed, as long as it is marked `private`.**
- **Tool names** SHOULD be 1–128 chars of `[A-Za-z0-9_.-]`, case-sensitive,
  unique per server (SEP-986) [S5].
- **Schemas.** `inputSchema` must be a JSON Schema object with `type: object`;
  a tool with no arguments uses `{"type":"object","additionalProperties":false}`.
  Default dialect 2020-12. `outputSchema` is optional; if given, results MUST
  conform to it. `structuredContent` may be any JSON value, and a tool that
  returns it SHOULD also return the same JSON as a text block [S5][S6].
- **Errors.** Unknown tool or malformed request → JSON-RPC protocol error.
  Upstream failures, business errors **and input validation errors** →
  `isError: true` results, which clients SHOULD show the model so it can
  correct itself [S5].
- **Annotations are hints, untrusted by clients**, with defaults that bite:
  `readOnlyHint` false, **`destructiveHint` true**, `idempotentHint` false,
  **`openWorldHint` true** [S6]. A tool that leaves them unset advertises itself
  as destructive and open-world.
- **Security (tools page):** servers MUST validate all inputs, implement access
  controls, **rate limit tool invocations**, and **sanitize tool outputs** [S5].
  Transport: servers MUST validate `Origin` and answer a present-but-invalid one
  with 403 [S4]. Authorization is OPTIONAL [S30].
- **Safe to ignore for a stateless read-mostly server:** tasks (now an
  extension, SEP-2663), multi-round-trip requests/elicitation (SEP-2322),
  sampling, roots, logging (deprecated, SEP-2577), `x-mcp-header`,
  `subscriptions/listen`, OAuth.

## 2. The official Go SDK, v1.8.0

`github.com/modelcontextprotocol/go-sdk` **v1.8.0**, released 2026-09-14 (v1.7.0,
2026-07-28, added the 2026-07-28 spec). Needs Go ≥ 1.25; we build with 1.26
[S12][S13].

**New modules** it brings into `go.mod` (from its v1.8.0 `go.mod`):
`google/jsonschema-go` v0.4.3, `segmentio/encoding`, `yosida95/uritemplate/v3`,
`golang-jwt/jwt/v5`, `golang.org/x/oauth2`, `golang.org/x/tools`. `go-cmp` and
`x/time` are already ours, and none of the pinned modules gets bumped (review
round 2 checked the requirement graph). The `mcp` package imports
`x/oauth2` directly, so that one is linked; the footprint is still modest.

**Server and typed tools** [S14][S15][S17]:

```go
srv := mcp.NewServer(&mcp.Implementation{Name: "corpberry", Title: "Corpberry Tools", Version: rev},
    &mcp.ServerOptions{
        Instructions: "…",
        Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}, // default adds deprecated logging
        SetCacheable: func(_ context.Context, _ mcp.Request, c *mcp.Cacheable) { /* ttlMs, cacheScope */ },
    })
mcp.AddTool(srv, &mcp.Tool{Name: "dns_lookup", Title: "DNS lookup", Description: "…",
    Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true,
        DestructiveHint: jsonschema.Ptr(false), OpenWorldHint: jsonschema.Ptr(true)}},
    func(ctx context.Context, req *mcp.CallToolRequest, in Args) (*mcp.CallToolResult, Out, error) { … })
```

- **Schema inference** (jsonschema-go) [S16][S19]: the `json` tag names the
  property; a field without `omitempty`/`omitzero` is **required**; structs get
  `additionalProperties: false`. The `jsonschema:"…"` tag is **a description
  only**; values like `enum=…` are rejected. Enums, min/max and defaults are set
  by building the schema with `jsonschema.For[T]`, editing it, and passing it
  as `Tool.InputSchema`. Arguments are validated against the schema before the
  handler runs.
- **Results:** a non-`any` `Out` gets an inferred `outputSchema` and is
  returned as `structuredContent`; when `Content` is nil the SDK adds a text
  block with the same JSON. `Out = any` means no output schema.
- **Errors:** a plain Go `error` becomes an `isError: true` result carrying its
  text; a `*jsonrpc.Error` becomes a protocol error; **output that fails its own
  `outputSchema` becomes a protocol error** [S15][S16]. That last one matters
  for D7: a REST struct with a nil slice (JSON `null`) against an inferred
  `type: array` fails at runtime.

**HTTP** — `mcp.NewStreamableHTTPHandler(getServer func(*http.Request) *mcp.Server,
opts)`. All of `StreamableHTTPOptions` in v1.8.0 [S14]: `Stateless`,
`JSONResponse`, `Logger`, `EventStore`, `SessionTimeout` (stateful only),
`DisableLocalhostProtection`, `CrossOriginProtection` (**deprecated**: wrap the
handler instead), `MaxRequestBodyBytes` (default 4 MiB → 413),
`PropagateRequestCancellation` (cancel the handler when the client goes away).

- 2026-07-28 requests are accepted only with `Stateless: true` [S18].
- Stateless mode: POST only, GET/DELETE → 405, `Content-Type: application/json`
  enforced (415), `Accept` must list both JSON and event-stream.
- No built-in rate limiting, concurrency cap or per-call timeout: ours to add.
- The SDK doesn't send `X-Accel-Buffering: no` for SSE; `JSONResponse` avoids
  the question.

**Middleware** [S22][S23]: `srv.AddReceivingMiddleware(m…)` with
`Middleware func(MethodHandler) MethodHandler`; a `tools/call` arrives as
`*mcp.CallToolRequest`, so one middleware can name the tool, check its rate
class, log the outcome, and short-circuit with an `isError` result.

**Request context** [S22][S24]: `req.Extra.Header` exposes HTTP headers (nil on
in-memory transports); there is no remote address. The handler's `ctx` carries
the HTTP request context's values, so an IP set by Echo middleware is visible
in tool handlers. This is **true in the v1.8.0 source but undocumented**, so
the plan pins it with a test.

**Advisories** [S20][S21][S12]:

| ID | What | Fixed in |
|---|---|---|
| GHSA-xw59-hvm2-8pj6 / CVE-2026-34742 (High) | DNS-rebinding protection off by default | v1.4.0 |
| GHSA-89xv-2j6f-qhc8 / CVE-2026-33252 (High) | cross-site tool execution on HTTP servers without auth, "especially stateless" | v1.4.1 (Content-Type check + `CrossOriginProtection`) |
| CVE-2026-27896, GHSA-q382-vc8q-7jhj | — | v1.3.1, v1.4.1 |

**v1.6.0 turned the Origin check back off by default** (the Content-Type check
stays); the SDK's advice is to wrap the handler, e.g. in Go 1.25's
`http.NewCrossOriginProtection()`. That one passes requests with no `Origin` /
`Sec-Fetch-Site`, but **403s any `Origin` that differs from the Host** even
without `Sec-Fetch-Site`, i.e. a server-side client that sets `Origin` [S41].
Anthropic warns that over-strict Origin checks break its connectors (§5), so
the plan's check keys on `Sec-Fetch-Site`, the header only browsers send
(README D15).

**Gotcha for this repo:** in dev, requests reach the binary on 127.0.0.1 with
`Host: mcp.localhost:8080`. The SDK's localhost protection accepts only the
literal `localhost` or a loopback IP as Host on a loopback connection, so dev
gets 403s. `DisableLocalhostProtection: true` is safe here because Echo's
virtual-host map already 404s every Host it doesn't know, which is exactly the
DNS-rebinding defence.

**Testing** [S25]: `mcp.NewInMemoryTransports()` + `srv.Connect` (server first)
+ `mcp.NewClient(…).Connect` + `CallTool`; over HTTP, `httptest.NewServer` +
`&mcp.StreamableClientTransport{Endpoint: url}`.

## 3. Official SDK vs `mark3labs/mcp-go`

`mark3labs/mcp-go` v1.1.1 (2026-09-23) is active and more starred (9.2k vs
5.2k; 1,880 vs 1,443 importers on pkg.go.dev, 2026-10-04) [S26][S44]. The
official SDK still wins for us: it is a Tier 1 SDK maintained with the spec
[S27], it supported 2026-07-28 on publication day (mcp-go took ~5 weeks), it
publishes security advisories, and GitHub's own `github-mcp-server` (Go)
v1.14.0 pins `go-sdk v1.8.0` [S28].

## 4. Security guidance worth copying

- **Origin + auth:** above. Auth is optional; we have no accounts.
- **Rate limits, timeouts, cancellation:** servers rate limit; senders set
  timeouts; closing the stream is cancellation and the server SHOULD stop work
  (`PropagateRequestCancellation`) [S5][S31].
- **SSRF** (the spec's section is about OAuth URL fetching, but it is the right
  list): HTTPS-only where possible, block private/link-local/metadata ranges,
  re-check every redirect hop, no TOCTOU between resolve and dial, no
  hand-rolled IP parsing [S29]. `platform/netgate.go` already does all of this at
  dial time.
- **Prompt injection:** the spec only says clients must treat descriptions,
  annotations and results as untrusted [S32][S5]. Server-side, the useful moves
  are: third-party strings stay data fields, are size-bounded, and never land in
  a description or the instructions.
- **Handles on unauthenticated servers are bearer tokens:** high entropy,
  bounded lifetime [S5]. Our only handles are short-link codes, created only with
  the owner key.

## 5. Clients and install snippets

What the public servers below all document, and what the landing page will
show [P3][P13][P9][P22][P39]:

| Client | How | Endpoint to give it |
|---|---|---|
| Claude Code | `claude mcp add --scope user --transport http corpberry https://mcp.corpberry.com/mcp` | `/mcp` (it loads MCP tools through tool search) |
| claude.ai / Claude Desktop | Customize → Connectors → add a custom connector by URL. Free plans allow one custom connector; on Team/Enterprise only owners add them [P42] | a toolset URL |
| ChatGPT | Settings → Apps → Advanced → Developer mode → create an app, no auth; beta, paid plans [P43] | a toolset URL (OpenAI's guidance is under 20 tools per turn) |
| VS Code | `.vscode/mcp.json`: `{"servers": {"corpberry": {"type": "http", "url": "…"}}}` [P44] | a toolset URL |
| Cursor | `~/.cursor/mcp.json`: `{"mcpServers": {"corpberry": {"url": "…"}}}`, or a one-click deeplink; ~40-tool soft cap across all servers [P45] | a toolset URL |
| Codex CLI | `codex mcp add corpberry --url …`, or `[mcp_servers.corpberry] url = "…"` in `config.toml`; `bearer_token_env_var` for keys [P46] | a toolset URL |
| Gemini CLI | `gemini mcp add --transport http corpberry …`, or `httpUrl` in settings: **its `url` key means SSE**, which this server doesn't speak [P47] | a toolset URL |
| stdio-only clients | `npx mcp-remote <url>` (their toolchain, not ours) | a toolset URL |

Owner tools need a client that can send a header (Claude Code, Codex, VS Code,
Cursor, Gemini CLI); claude.ai and ChatGPT connectors can't.

What Anthropic's connector docs say a server must survive [P38][P39]:

- **claude.ai calls from Anthropic's infrastructure**, not the user's machine,
  IPv4 only, and refuses hostnames that resolve to any non-public address. The
  user's own IP is never what a hosted connector shows us.
- **A CDN/WAF 403 or 429 breaks the connection** before the app sees it; the
  fix is to exempt the MCP host or allowlist Anthropic's published egress range.
- **No cross-host redirects**: Claude drops `Authorization` on them.
- **"An overly strict `Origin` check rejects Anthropic's requests."** The docs
  do not say what `Origin`, if any, Claude sends. Unverified either way, so the
  Origin policy (D15) is built not to depend on it and is live-tested.
- `clientInfo.name` varies (`claude-ai`, `Anthropic`, `claude-code`, …) and is
  unauthenticated: telemetry only.
- Tool results: Claude Code warns above 10K tokens and spills above 25K to a
  file; claude.ai allows ~150K characters and 240 s per call [P22][P23].

## 6. How comparable public servers did it

Probed live on 2026-10-04 (`initialize`/`tools/list`/`server/discover` plus
sample calls) where marked **(P)**.

| Server | Endpoint, auth | Tools | Output |
|---|---|---|---|
| nslookup.io | `mcp.nslookup.io/mcp`; anonymous except 6 OAuth `my_*` tools (401 + `WWW-Authenticate`) [P2] | 23, snake_case, no prefix, no annotations; descriptions point at siblings ("use uptime_check_multi instead") (P) | pretty-printed JSON as text, verbose (P) |
| Globalping | `mcp.globalping.dev/mcp` + `/sse`; now 401 without OAuth/token (P) [P3] | 11: `ping`, `traceroute`, `dns`, `mtr`, `http`, … | — |
| Cloudflare | `*.mcp.cloudflare.com/mcp`, stateless; `/sse` answers 410 with migration hints (P) [P5] | docs server: 2 annotated tools (P). Radar had one `get_*` tool per endpoint and was **deprecated** for "Code Mode" (3 tools); Cloudflare measured 2,594 tools ≈ 1.17M tokens vs ~1.1K [P6][P7] | Code Mode caps results ~6K tokens, truncation marked [P7] |
| GitHub (Go, official SDK) | `api.githubcopilot.com/mcp/`, OAuth/PAT; subsets by URL `/x/{toolset}`, `/readonly`, or `X-MCP-Toolsets` headers [P9] | ~97 tools in ~24 toolsets, 5 on by default; `issue_read(method)` merged four tools; reads and writes separate [P8][P10] | JSON, optional CSV, field-selection enums [P11] |
| IPinfo | POST at `mcp.ipinfo.io/`; old + new protocol; `X-Accel-Buffering: no` (P) | 6, `ipinfo_` prefix; batch `ips[]`, `detailed` flag, `page`/`page_size`; annotations, output schema, `instructions` (P) | `structuredContent` (P) |
| Context7 | `mcp.context7.com/mcp`, anonymous, old + new protocol (P) [P13] | 2 kebab-case tools, very prescriptive descriptions ("at most 3 calls per question"), full annotations (P) | Markdown-ish text (P) |
| DeepWiki | `mcp.deepwiki.com/mcp`, anonymous; `/sse` deprecated [P14] | 3 (P) | Markdown, mirrored into `structuredContent.result` (P) |

- **GET / on the MCP host:** DeepWiki and IPinfo serve a human page with
  per-client config; Globalping redirects to GitHub; the rest 404. A browser on
  `/mcp` gets a raw JSON-RPC 405/406 everywhere (P). Easy to do better.
- **Elsewhere:** Censys (hosted, PAT + org header, 12+ workflow tools) [P12];
  DNS Spy (50+ tools, Enterprise only; **unverified**, site behind a
  challenge) [P15]; VirusTotal and IP2Location ship *local* servers only
  [P17][P18]; Shodan, urlscan.io and Robtex have only community servers
  (**unverified** negative). No widely used *remote* dev-utilities server
  exists: `it-tools-mcp` (121 local tools) is archived, CyberChef wrappers
  expose one `bake_recipe` tool [P19][P20]. A public server doing what
  cipher.corpberry.com does would be close to unique.
- **Registry entries** exist for nslookup.io, Context7, IPinfo and GitHub;
  Cloudflare's still lists `/sse` URLs that answer 410, Globalping's points at a
  host that doesn't resolve (P) [P21]. Keep the entry in step with the server.
- **No anonymous server publishes numeric rate limits** or sends RateLimit
  headers (P). Publishing ours on the landing page is cheap differentiation.
- **Protocol eras coexist:** Context7, IPinfo and Cloudflare accept 2026-07-28
  and older clients; nslookup.io and DeepWiki still reject 2026-07-28 (P).

**Tool-design guidance** that the plan follows:

- **Fewer, consolidated tools.** OpenAI's soft target is under 20 functions per
  turn [P24]; Anthropic: overlapping tools distract agents, consolidate related
  operations, and 58 tools cost ~55K tokens before tool search kicks in
  [P1][P25][P26]. Claude Code loads MCP tools through tool search by default on
  recent models; other clients load every definition [P22].
- **Names:** snake_case with a service prefix; the Claude API disallows dots;
  the connector directory caps names at 64 chars [P26][P27].
- **Descriptions:** like onboarding a new teammate, 3–4+ sentences including
  when *not* to use the tool, unambiguous parameter names, enums for fixed sets;
  no hidden or behavioural instructions [P1][P24][P26][P27].
- **Responses:** high-signal fields, concise by default with a detailed switch
  (Anthropic's example: 206 → 72 tokens), paginate/filter/truncate [P1].
- **Errors:** fixable problems as `isError: true` saying how to fix; generic
  500-style messages fail directory review [P27][S5].
- **Annotations:** `title` and `readOnlyHint`/`destructiveHint` drive Claude's
  automatic permissions and are required for the directory [P27].
- **Tests:** GitHub snapshots every tool schema and keeps old names callable
  when renaming [P8][P30].

**Operational traps** [P31][P35][P36][P38][P40][P41]: nginx buffers responses
and closes idle reads at 60 s; Cloudflare 524s after its origin timeout
(documented as 125 s, Enterprise-adjustable); Bot Fight Mode blocks
Smithery's scanner and, as above, can block Anthropic; a 403 where a 401 is
expected confuses OAuth-capable scanners; `Access-Control-Allow-Origin: *`
with credentials is invalid (nslookup.io sends it). With stateless JSON
responses, none of the buffering or session-affinity traps apply to us.

## 7. Registry and discovery

- **Official MCP Registry** is still **preview** ("breaking changes or data
  resets may occur"); API v0.1 frozen since 2025-10-24; `server.json` schema
  `2025-12-11` [S33][S37][S43]. A remote server is
  `{"name": "com.corpberry/tools", "version": "…", "remotes": [{"type":
  "streamable-http", "url": "https://mcp.corpberry.com/mcp"}]}` [S34].
- **Domain proof** for a `com.corpberry/*` name: DNS TXT on corpberry.com
  (`v=MCPv1; k=ed25519; p=<pubkey>`, then `mcp-publisher login dns`), or the
  same string at `https://corpberry.com/.well-known/mcp-registry-auth`
  (`mcp-publisher login http`). DNS covers subdomain namespaces, HTTP only the
  exact domain [S35][S36][S42]. DNS is one Cloudflare record and no code.
- **Server Cards** (SEP-2127, card at `<mcp-url>/server-card`, domain index at
  `/.well-known/ai-catalog.json`) are still an open PR (updated 2026-09-30); the
  older `.well-known/mcp` proposals (SEP-1649, SEP-1960) are closed [S38][S39].
  Not worth building yet.

## 8. Echo v5 integration

`echo.WrapHandler(h http.Handler) echo.HandlerFunc` exists in v5 (checked in our
pinned v5.3.0 source and on pkg.go.dev for v5.4.0) [S40]. Mount with
`e.Any("/mcp", …)` so the SDK, not Echo's router, answers GET/DELETE with 405.
`*echo.Response` implements `Flush`/`Unwrap`, so even SSE would pass through.

## Sources

- [S1] https://modelcontextprotocol.io/specification/versioning
- [S2] https://modelcontextprotocol.io/specification/2026-07-28/changelog
- [S3] https://blog.modelcontextprotocol.io/posts/2026-07-28/
- [S4] https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- [S5] https://modelcontextprotocol.io/specification/2026-07-28/server/tools (re-read directly)
- [S6] https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts
- [S8] https://modelcontextprotocol.io/specification/2026-07-28/server/discover
- [S9b] https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching (re-read directly)
- [S12] https://github.com/modelcontextprotocol/go-sdk/releases
- [S13] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/go.mod (re-read directly)
- [S14] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/streamable.go
- [S15] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/server.go
- [S16] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/tool.go
- [S17] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/server.md
- [S18] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/docs/protocol.md
- [S19] https://github.com/google/jsonschema-go/blob/v0.4.3/jsonschema/infer.go
- [S20] https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-xw59-hvm2-8pj6
- [S21] https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-89xv-2j6f-qhc8
- [S22] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/shared.go
- [S23] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/examples/server/middleware/main.go
- [S24] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/internal/jsonrpc2/conn.go
- [S25] https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/tool_example_test.go
- [S26] https://github.com/mark3labs/mcp-go/releases
- [S27] https://modelcontextprotocol.io/docs/2026-07-28/sdk
- [S28] https://github.com/github/github-mcp-server/blob/v1.14.0/go.mod
- [S29] https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices
- [S30] https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- [S31] https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation
- [S32] https://modelcontextprotocol.io/specification/2026-07-28
- [S33] https://modelcontextprotocol.io/registry/about
- [S34] https://modelcontextprotocol.io/registry/remote-servers
- [S35] https://modelcontextprotocol.io/registry/authentication
- [S36] https://github.com/modelcontextprotocol/registry/tree/main/internal/api/handlers/v0/auth
- [S37] https://github.com/modelcontextprotocol/registry
- [S38] https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2127
- [S39] https://github.com/modelcontextprotocol/experimental-ext-server-card/blob/main/docs/discovery.md
- [S40] https://pkg.go.dev/github.com/labstack/echo/v5#WrapHandler
- [S41] https://pkg.go.dev/net/http#CrossOriginProtection
- [S42] https://modelcontextprotocol.io/registry/quickstart
- [S43] https://github.com/modelcontextprotocol/registry/blob/main/pkg/model/constants.go
- [S44] https://pkg.go.dev/github.com/modelcontextprotocol/go-sdk/mcp?tab=importedby

Comparable servers and client docs:

- [P1] https://www.anthropic.com/engineering/writing-tools-for-agents
- [P2] https://www.npmjs.com/package/@nslookup-io/mcp-server
- [P3] https://github.com/jsdelivr/globalping-mcp-server
- [P5] https://github.com/cloudflare/mcp-server-cloudflare
- [P6] https://github.com/cloudflare/mcp-server-cloudflare/tree/main/apps/radar
- [P7] https://blog.cloudflare.com/code-mode-mcp/ · https://github.com/cloudflare/mcp
- [P8] https://github.com/github/github-mcp-server
- [P9] https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md
- [P10] https://github.blog/changelog/2025-10-29-github-mcp-server-now-comes-with-server-instructions-better-tools-and-more
- [P11] https://github.com/github/github-mcp-server/tree/main/pkg/github
- [P12] https://docs.censys.com/docs/platform-mcp-server
- [P13] https://github.com/upstash/context7
- [P14] https://docs.devin.ai/work-with-devin/deepwiki-mcp
- [P15] https://dnsspy.io/blog/dns-spy-mcp-server
- [P17] https://pypi.org/project/gti-mcp/
- [P18] https://github.com/ip2location/mcp-ip2location-io
- [P19] https://github.com/wrenchpilot/it-tools-mcp
- [P20] https://github.com/slouchd/cyberchef-api-mcp-server
- [P21] https://registry.modelcontextprotocol.io/v0.1/servers
- [P22] https://code.claude.com/docs/en/mcp
- [P23] https://claude.com/docs/connectors/building
- [P24] https://developers.openai.com/api/docs/guides/function-calling
- [P25] https://www.anthropic.com/engineering/advanced-tool-use
- [P26] https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools
- [P27] https://claude.com/docs/connectors/building/review-criteria
- [P30] https://github.com/github/github-mcp-server/blob/main/docs/testing.md
- [P31] https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- [P35] https://nginx.org/en/docs/http/ngx_http_proxy_module.html
- [P36] https://developers.cloudflare.com/fundamentals/reference/connection-limits/
- [P38] https://claude.com/docs/connectors/building/troubleshooting (re-read directly)
- [P39] https://claude.com/docs/connectors/building/testing (re-read directly)
- [P40] https://smithery.ai/docs/build/publish
- [P41] https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials
- [P42] https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp
- [P43] https://www.speakeasy.com/docs/mcp/build/integrate/clients/using-chatgpt-developer-mode-with-gram (secondary)
- [P44] https://code.visualstudio.com/docs/copilot/customization/mcp-servers
- [P45] https://forum.cursor.com/t/tools-limited-to-40-total/67976 (forum report)
- [P46] https://learn.chatgpt.com/docs/extend/mcp?surface=cli
- [P47] https://geminicli.com/docs/tools/mcp-server/
