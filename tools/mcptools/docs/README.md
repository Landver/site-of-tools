# MCP server: mcp.corpberry.com

`tools/mcptools` serves the site's tools to AI agents over the Model Context
Protocol: a third transport over the same domain calls as the pages and the
JSON API ([ARCHITECTURE §4](../../../docs/ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)).
Stateless Streamable HTTP with JSON responses, spec 2026-07-28 plus older
clients, official `go-sdk` v1.8.0. Public tools need no account or key.

| Doc | Holds |
|---|---|
| this file | endpoints, request flow, decisions, what is left, adding a tool, tests |
| [01-tool-catalog.md](01-tool-catalog.md) | where each tool differs from its REST twin |
| [02-security-and-ops.md](02-security-and-ops.md) | threats, gate, middleware, egress, limits, sanitizer, owner key, logs, licences |

## Endpoints

| Path on `https://mcp.corpberry.com` | Serves |
|---|---|
| `/` | landing page: endpoints, per-client setup, every tool; the same catalog as JSON for non-browsers |
| `/mcp` | all 35 public tools, for clients with tool search (Claude Code) |
| `/mcp/ip` · `/mcp/dns` · `/mcp/link` · `/mcp/cipher` · `/mcp/botcheck` · `/mcp/site` | one toolset each, for every other client |
| `/mcp/owner` | the owner's 3 short-link tools, behind `MCP_OWNER_KEY`; never advertised |

A browser `GET` on a public endpoint gets the landing page. Tool lists are
fixed per process: a dependency off at boot (IP databases, Mongo, the RDAP and
CT URLs, the owner key) removes its tools, and a toolset left with none is a 404.

## Request flow

`POST /mcp/dns` → gate (`handler.go` `serve`) → SDK (stateless, JSON;
validates arguments, fills defaults) → `middleware.go`, per message → adapter
(`dns.go`) → the call and `dnstools.Limits` `GET dns.corpberry.com/` uses.
Each step's rules are in [02](02-security-and-ops.md).

Files: `handler.go` (`Register`, `Deps`, gate, owner-key guard, landing page),
`server.go` (one `*mcp.Server` per endpoint, boot checks), `middleware.go`,
`registry.go` (`toolSpec`, deadlines, `toolsets`, `Coverage`), `schema.go`
(input schemas), `sanitize.go`, and one adapter per toolset (`ip.go` … `owner.go`).

## Decisions

- **Official SDK, one package.** Only `mcptools` imports `go-sdk` and
  `jsonschema-go`; tool packages, ciphertools' wasm build included, never do.
- **Stateless, JSON responses only**: no sessions, no SSE.
- **Toolsets by path.** Clients without tool search load every tool into the
  model's context, so each toolset has a URL.
- **One tool per task.** No operation switches; reads and writes never share
  a tool; same-task routes share one (`GET`/`POST /extract`), a two-task route
  splits (`/curl` → parse, build).
- **Adapters only map** arguments → the handler's domain call → result. Logic
  both doors need lives in the domain (`LookupEnriched`, `InputFromJSON`,
  `Shortener.CreateFrom`).
- **Contracts come from the domain**: enums, defaults and bounds are read at
  boot (`dnstools.Types`, `linktools.Personas`, ciphertools' field specs).
- **Results** are the REST body as `structuredContent` (always an object) plus
  the same JSON as text; concise by default where the REST body passes ~20 KB
  (Claude Code warns past 10K tokens), `detailed: true` for all of it.
- **No `outputSchema`**, so a schema slip can't turn a good result into a
  protocol error.
- **Errors are tool errors** (`isError`) with the REST message, so the model
  can fix its call.
- **One budget per client per tool package**, whichever door
  ([limits](02-security-and-ops.md#rate-limits-and-caps)).
- **No auth on public tools**, as on REST. The owner's short-link tools live
  on their own endpoint with their own key, never beside tools that return
  third-party text.
- **Licensed data stays**, credited in each result ([licences](02-security-and-ops.md#logs-and-licences)).
- **Discovery**: the landing page, an MCP line closing every tool page's
  terminal block, the apex tools index, then the MCP Registry.
- **Out of scope**: OAuth or accounts, a stdio package, MCP Apps, tasks,
  elicitation, sampling, resources, prompts, an endpoint per tool subdomain.

## Left outside the repo

1. **Launch**: [DEPLOYMENT §3–5](../../../docs/DEPLOYMENT.md#3-nginx-per-subdomain).
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
   REST twin's limiter and cap.
3. Map its route in `Coverage`, or give the route an exclusion with a reason.
4. A new toolset also needs a `toolsets` entry (title, REST host) and
   the MCP line on its pages ([ARCHITECTURE §8](../../../docs/ARCHITECTURE.md#8-adding-a-new-tool)).
5. Add a parity test against the REST twin; `UPDATE_GOLDEN=1` rewrites the
   `tools/list` goldens, then review the diff.

Don't rename a published tool or argument: clients cache lists for an hour
and agents remember names.

## Tests

`tests/` runs offline (fakes, in-memory and `httptest` clients); each file is
named for what it pins.
