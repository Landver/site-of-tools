# Research: the outside facts the code relies on

Checked 2026-10-04 against the spec, go-sdk v1.8.0's source and vendors' docs.

## Spec 2026-07-28

- Stateless: no sessions, no `initialize`. Each request carries `_meta`
  (version, client info, capabilities), `server/discover` serves
  `instructions`, and the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`
  headers must match the body (else 400). 2025-11-25 and 2025-06-18 clients
  still `initialize`; batches left the spec in 2025-06-18. [S1][S2]
- `tools/list` MUST NOT vary per connection, MAY vary by authorization, and
  carries `ttlMs` and `cacheScope` (`public` shareable by gateways, `private`
  never across credentials). Names SHOULD be 1–128 chars of `[A-Za-z0-9_.-]`. [S3][S4]
- A declared `outputSchema` binds every result; `structuredContent` SHOULD
  repeat as text (2025-11-25 typed it as an object; the TS and Python SDKs
  reject anything else). Failures and bad input are `isError` results; unset
  hints read as destructive and open-world. [S3][S5]
- Servers MUST validate inputs, rate-limit calls, sanitize outputs, and 403 a
  present, invalid `Origin`; auth is optional. A closed stream cancels. [S2][S3][S6]

## go-sdk v1.8.0

- Official and Tier 1, it supported 2026-07-28 on release day; v1.4.1 fixed DNS
  rebinding and cross-site calls on servers without auth. [S7][S8][S9]
- 2026-07-28 needs `Stateless: true`: POST only (405), `application/json`
  (415), `Accept` listing JSON and event stream, 413 past 4 MiB. `getServer`
  runs twice a request; nil → 400. [S10]
- Worked around: a POST without `MCP-Protocol-Version` is read as 2025-03-26,
  where batches are legal, uncapped and buffered; it never calls `recover`;
  `"arguments": null` panics; nil `Capabilities` advertises `logging` and
  `listChanged`, so `subscriptions/listen` holds a stream open;
  `PropagateRequestCancellation` covers 2026-07-28 only. [S10][S12]
- Localhost protection 403s a non-loopback `Host` on a loopback connection.
  Go's `http.NewCrossOriginProtection`, which the SDK recommends, 403s any
  `Origin` that differs from the `Host`, as a server-side client's may. [S10][S14]
- Schemas (jsonschema-go v0.4.3): no `omitempty` means required, pointers are
  nullable, and the `jsonschema` tag is a description only (enums, bounds and
  defaults are edits). Arguments are validated and defaults filled in before
  the handler. [S11][S13]
- `Out = any`: no `outputSchema`, `structuredContent` plus the same JSON as
  text. A Go `error` → `isError`; output failing a declared schema → protocol
  error, and inferred ones mistype `[]byte`, `net.IP`, custom marshalers. [S11][S13]
- A handler's `ctx` carries the HTTP request context's values (undocumented;
  a test pins it); no remote address is passed. JSON depth is capped at 1000.
  Echo mounts the handler via `echo.WrapHandler`, path values intact. [S12][S15]

## Clients

| Client | Setup | Quirks |
|---|---|---|
| Claude Code | `claude mcp add --scope user --transport http` | tool search; warns over 10K-token results, spills over 25K to a file [C1] |
| claude.ai, Claude Desktop | Customize → Connectors | from Anthropic's cloud, IPv4 only; refuses non-public hosts; a CDN or WAF 403/429 breaks it; no cross-host redirects; strict `Origin` checks fail and its `Origin` is undocumented; one connector on free plans [C2][C3][C4] |
| ChatGPT | Settings → Apps → Developer mode | beta, paid plans; OpenAI advises under 20 tools [C5][C6] |
| VS Code | `.vscode/mcp.json`, `"type": "http"` | [C7] |
| Cursor | `~/.cursor/mcp.json` | ~40 tools across all servers [C8] |
| Codex CLI | `codex mcp add --url`, or `config.toml` | a key via `bearer_token_env_var` [C9] |
| Gemini CLI | `gemini mcp add --transport http`, or `httpUrl` | its `url` key means SSE [C10] |
| stdio-only | `npx mcp-remote <url>` | — |

claude.ai and ChatGPT connectors can't send a header (the owner key).
`clientInfo.name` is unauthenticated: telemetry only. The Claude API rejects
dots in tool names; Anthropic's directory caps names at 64 chars [C11][C12].
Cloudflare's Bot Fight Mode blocks Anthropic's and Smithery's clients [C2][C13].

## Sources

- Spec 2026-07-28: [S1](https://modelcontextprotocol.io/specification/2026-07-28/changelog) changelog · [S2](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) transport · [S3](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) tools · [S4](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching) caching · [S5](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts) schema · [S6](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation) cancellation
- SDK: [S7](https://modelcontextprotocol.io/docs/2026-07-28/sdk) tiers · [S8](https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-xw59-hvm2-8pj6), [S9](https://github.com/modelcontextprotocol/go-sdk/security/advisories/GHSA-89xv-2j6f-qhc8) advisories · go-sdk v1.8.0 [S10](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/streamable.go) `streamable.go`, [S11](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/tool.go) `tool.go`, [S12](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/server.go) `server.go` · [S13](https://github.com/google/jsonschema-go/blob/v0.4.3/jsonschema/infer.go) `infer.go` · [S14](https://pkg.go.dev/net/http#CrossOriginProtection) `CrossOriginProtection` · [S15](https://pkg.go.dev/github.com/labstack/echo/v5#WrapHandler) `WrapHandler`
- Clients: [C1](https://code.claude.com/docs/en/mcp) Claude Code · [C2](https://claude.com/docs/connectors/building/troubleshooting), [C3](https://claude.com/docs/connectors/building/testing) connectors · [C4](https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp) plans · [C5](https://www.speakeasy.com/docs/mcp/build/integrate/clients/using-chatgpt-developer-mode-with-gram) ChatGPT · [C6](https://developers.openai.com/api/docs/guides/function-calling) OpenAI · [C7](https://code.visualstudio.com/docs/copilot/customization/mcp-servers) VS Code · [C8](https://forum.cursor.com/t/tools-limited-to-40-total/67976) Cursor · [C9](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) Codex · [C10](https://geminicli.com/docs/tools/mcp-server/) Gemini · [C11](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools) names · [C12](https://claude.com/docs/connectors/building/review-criteria) directory · [C13](https://smithery.ai/docs/build/publish) Smithery
