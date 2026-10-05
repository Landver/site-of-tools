# MCP server: mcp.corpberry.com

`tools/mcptools` serves the site's tools to AI agents over the Model Context
Protocol: a third transport over the same domain calls as the pages and the
JSON API ([ARCHITECTURE §4](../../../docs/ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)).
Stateless Streamable HTTP with JSON responses, spec 2026-07-28 plus older
clients, official `go-sdk` v1.8.0. Public tools need no account or key.

| Doc | Holds |
|---|---|
| this file | endpoints, request flow, decisions, what is left, adding a tool, tests |
| [01-tool-catalog.md](01-tool-catalog.md) | each tool's REST twin and how it differs; what isn't a tool |
| [02-security-and-ops.md](02-security-and-ops.md) | threats, gate, middleware, egress, limits, sanitizer, owner key, logs, licences |
| [00-research.md](00-research.md) | the spec, SDK and client facts the code relies on, with sources |

## Endpoints

| Path on `https://mcp.corpberry.com` | Serves |
|---|---|
| `/` | landing page: endpoints, per-client setup, every tool with the rate its limiter reports; the same catalog as JSON for non-browsers |
| `/mcp` | all 35 public tools, for clients with tool search (Claude Code) |
| `/mcp/ip` · `/mcp/dns` · `/mcp/link` · `/mcp/cipher` · `/mcp/botcheck` · `/mcp/site` | one toolset each (2, 5, 11, 15, 1, 1 tools), for every other client |
| `/mcp/owner` | the owner's 3 short-link tools, behind `MCP_OWNER_KEY`; never advertised |

A browser `GET` on a public endpoint gets the landing page. Tool lists are
fixed per process: a dependency off at boot (IP databases, Mongo, the RDAP and
CT URLs, the owner key) removes its tools, and a toolset left with none is a 404.

## Request flow

```
POST /mcp/dns   tools/call dns_lookup {"name": "example.com"}
  │  Cloudflare → nginx → Echo vhost (platform.NewApp: recover, request log, headers, gzip)
  ▼
gate        handler.go serve: endpoint · browser page · Sec-Fetch-Site · owner key ·
            per-IP limit · 1 MiB body, no batches · Origin log · caller into ctx
  ▼
SDK         StreamableHTTPHandler, stateless + JSON: validates arguments, fills defaults
  ▼
middleware  middleware.go, per message: recover · deadline · rate · cap · tool ·
            sanitize · record
  ▼
adapter     dns.go: typed args → dnstools.LookupEnriched → concise projection + attribution
  ▼
domain      the call GET dns.corpberry.com/ makes, on the same dnstools.Limits
```

Each step's rules are in [02-security-and-ops.md](02-security-and-ops.md).
Files: `handler.go` (`Register`, `Deps`, gate, owner-key guard, landing page),
`server.go` (one `*mcp.Server` per endpoint, boot checks), `middleware.go`,
`registry.go` (`toolSpec`, deadlines, `toolsets`, `Coverage`), `schema.go`
(input schemas), `sanitize.go`, and one adapter per toolset (`ip.go` … `owner.go`).

## Decisions

- **Official SDK, one package.** Only `mcptools` imports `go-sdk` and
  `jsonschema-go`; tool packages, ciphertools' wasm build included, never do.
- **Stateless, JSON responses only**: no sessions, no SSE.
- **Toolsets by path.** Clients without tool search load every tool into the
  model's context ([limits](00-research.md#clients)), so each toolset has a URL.
- **One tool per task.** No operation switches; reads and writes never share
  a tool; same-task routes share one (`GET`/`POST /extract`), a two-task route
  splits (`/curl` → parse, build).
- **Adapters only map** arguments → the handler's domain call → result. Logic
  both doors need lives in the domain (`LookupEnriched`, `InputFromJSON`,
  `Shortener.CreateFrom`).
- **Contracts come from the domain**: enums, defaults and bounds are read at
  boot (`dnstools.Types`, `linktools.Personas`, ciphertools' field specs).
- **Results** are the REST body as `structuredContent` (always an object) plus
  the same JSON as text; concise by default where the REST body passes ~20 KB,
  `detailed: true` for all of it.
- **No `outputSchema`**, so a schema slip can't turn a good result into a
  protocol error ([SDK](00-research.md#go-sdk-v180)).
- **Errors are tool errors** (`isError`) with the REST message, so the model
  can fix its call.
- **One budget per client per tool package**, whichever door
  ([limits](02-security-and-ops.md#rate-limits-and-caps)).
- **No auth on public tools**, as on REST. The owner's short-link tools live
  on their own endpoint with their own key, never beside tools that return
  third-party text.
- **Server metadata**: capabilities are tools only (`listChanged: false`);
  lists are cached an hour (`public`, `private` on `/mcp/owner`); each
  endpoint's `instructions` name only its own tools.
- **Licensed data stays**, credited in each result ([licences](02-security-and-ops.md#logs-and-licences)).
- **Discovery**: the landing page, an MCP line closing every tool page's
  terminal block, the apex tools index, then the MCP Registry.
- **Out of scope**: OAuth or accounts, a stdio package, MCP Apps, tasks,
  elicitation, sampling, resources, prompts, an endpoint per tool subdomain.

## Left outside the repo

1. **Launch** ([DEPLOYMENT §3–5](../../../docs/DEPLOYMENT.md#3-nginx-per-subdomain)):
   the proxied Cloudflare `mcp` record, the nginx block, a check that the proxy
   accepts only Cloudflare, Bot Fight Mode off, `EGRESS_DENY_ADDRS` and
   `MCP_OWNER_KEY` in `.env.prod`; then `claude mcp add` and a claude.ai custom
   connector against prod.
2. **Origin allowlist**: once the `mcp: foreign Origin` log lines show what
   hosted clients send, allow those and answer 403 to every other foreign
   `Origin`, as the spec requires ([why it waits](02-security-and-ops.md#gate)).
3. **MCP Registry listing** (still preview): a `server.json` named
   `com.corpberry/tools` with one `streamable-http` remote per public
   endpoint, the name proved by a TXT record on corpberry.com
   (`v=MCPv1; k=ed25519; p=<pubkey>`, then `mcp-publisher login dns`)
   ([docs](https://modelcontextprotocol.io/registry/remote-servers),
   [auth](https://modelcontextprotocol.io/registry/authentication)).
   Re-publish whenever an endpoint changes.

## Adding a tool

1. Move whatever its REST handler does beyond HTTP into the tool package, so
   both doors call one exported function.
2. In `<toolset>.go`, an args struct (`json` tag = argument name, `jsonschema`
   tag = description only, a pointer where absent ≠ empty) and a `toolSpec`:
   name `<toolset>_<task>`; title; a 3–5 sentence description (what, when a
   sibling fits better, an example; ending in `thirdParty` when the result
   carries someone else's strings); `inputSchema[T](…)` with the domain's
   enums, defaults and bounds; hints via `readOnly`/`acts`; a deadline; the
   REST twin's limiter and cap; `narrow` (how to ask for less); `whole` when
   the result holds no third-party text.
3. Map its route in `Coverage`, or give the route an exclusion with a reason.
4. A new toolset also needs a `toolsets` entry (title, REST host, credits) and
   the MCP line on its pages ([ARCHITECTURE §8](../../../docs/ARCHITECTURE.md#8-adding-a-new-tool)).
5. Add a parity test against the REST twin; `UPDATE_GOLDEN=1` rewrites the
   `tools/list` goldens, then review the diff.

Don't rename a published tool or argument: clients cache lists for an hour
and agents remember names.

## Tests

`tests/` runs offline (fakes, in-memory and `httptest` clients):

- **coverage**: every REST route has a `Coverage` entry, 41 map to tools, and
  every served tool has a route;
- **`tools/list` goldens** per endpoint, `/mcp` = their union, size budgets
  (3 KB a tool, 32 KB a toolset, 64 KB for `/mcp`), cache scope and TTL,
  instructions naming only served tools;
- **results**: parity with each REST twin's body as projected; every tool
  answers an object given only its required arguments; concise results stay
  under 20 KB where REST is over;
- **the rest**: gate, owner key, shared limits and caps, hang-up
  cancellation, panics, `null` arguments, records without arguments, the
  sanitizer, the landing page (setup snippets, published rates, credits, the
  MCP line in every terminal block).
