# Security and operations

## Threat model

Anonymous scripts, hostile pages driving visitors' browsers, agents steered by
attacker text in a result, a leaked owner key. At stake: the box (one binary
serves every subdomain), upstreams we are a guest of, the domain's reputation
(phishing short links), secrets in cipher calls.

## Gate

`handler.go` `serve`, before the SDK, in order:

1. `Cache-Control: no-store` on every response: cipher results can be secrets.
2. Unknown toolset or one with no tools, `/mcp/owner` unconfigured or browsed → 404.
3. Browser `GET` → the landing page; other `GET`/`DELETE` → the SDK's 405.
4. `Sec-Fetch-Site: cross-site` or `same-site` → 403, ahead of the owner key
   so a page can't spend its visitors' key tries.
5. `/mcp/owner`: the [owner key](#owner-key).
6. All of `/mcp`, per address: 20/s, burst 100 → 429.
7. Body over 1 MiB → 413; a JSON-RPC batch → 400 ([why](00-research.md#go-sdk-v180)).
8. A foreign `Origin` is served and logged (`mcp: foreign Origin`).
9. Raw IP, rate-limit key, host, user agent and HTTP context into the context.

Echo's exact-Host vhost map stops DNS rebinding, so the SDK's localhost check
(it would 403 dev's `mcp.localhost:8080`) is off. A page can't make a browser
post here (anything but JSON gets 415; cross-origin JSON fails its preflight),
so the spec's 403 for a foreign `Origin` waits for an allowlist ([why](00-research.md#clients)).

## Middleware

`middleware.go`, per JSON-RPC message:

1. `"arguments": null` is read as none ([SDK quirks](00-research.md#go-sdk-v180)).
2. `recover` → an "Internal error" result, stack logged without arguments.
3. Deadline: 25 s IP, DNS and botcheck tools, 20 s `link_redirect_chain` and
   owner tools, 15 s heavy cipher, 5 s the rest and other methods; a hang-up
   cancels the call on any protocol version (`context.AfterFunc`).
4. Rate: the tool's limiter; any other method, the protocol one (5/s, burst 20).
5. Capacity: a budget all clients share, if any, then the cap; full → "Busy".
6. The tool, then [sanitize](#untrusted-output) and [record](#logs-and-licences).

## Outbound reach

MCP dials nothing REST doesn't. Each dial a caller can aim passes a
`platform.EgressGuard` on the address dialled, denying our vhosts, Mongo, local
interfaces and `EGRESS_DENY_ADDRS`. A traced host learns the origin IP, hence
the [Cloudflare-only proxy](../../../docs/DEPLOYMENT.md#4-client-ip-trust-model).

| Path | Guard |
|---|---|
| `link_redirect_chain` | ports 80/443 on every hop; no proxy, no keep-alive |
| MTA-STS in `dns_email_auth` | port 443; no proxy, no keep-alive, no redirects |
| nameserver probes in `dns_consistency`, `dns_trace` | the guard's address check (`nsRoutable`) |
| RDAP (`dns_domain_info`, `dns_consistency`), crt.sh | own host direct, other hops guarded; each 1/s (burst 5) process-wide |
| Shodan in `ip_lookup`, `botcheck_score` | fixed host, 1/s (burst 5) process-wide; DNS never calls it (`geo.Offline()`) |

## Rate limits and caps

Keyed by `platform.RateLimitKey` (IPv4 address, IPv6 /64, one bucket for junk).
Each package's `Limits`, built once in `main.go`, serves its REST routes and tools.

| Tools | Rate (burst) | Cap in flight |
|---|---|---|
| `ip_lookup`; `botcheck_score` | 2/s (10) each | 8 each |
| `dns_lookup`, `dns_email_auth`; `dns_domain_info` | 2/s (10), one store | 8; 4 of its own |
| `dns_consistency`, `dns_trace` | 1 per 2 s (3) | 4 |
| `link_redirect_chain`; owner tools (REST `/short`'s store) | 1/s (5) each | 4; — |
| `link_short_resolve` | 20/s (60), plus 200/s (400) for everyone | — |
| cipher `jwt_sign`, `password_hash`, `password_verify`, `keys_generate` | 1/s (5) | 256 MiB of memory |
| other cipher and link tools, `ip_cidr`, `site_blog` (MCP-only) | 10/s (50) per package | — |

A client holds at most a quarter of a cap unless it holds nothing. A heavy op
weighs Argon2's or scrypt's memory parameter, else 16 MiB. Hosted connectors
share their provider's addresses, so their users share budgets.

## Untrusted output

`sanitize.go`, on every result: strings and keys cut at 2 KB with a
`…[truncated N bytes]` marker, invisible characters (format, Tag block,
variation selectors, DEL, C1, U+2028/9, Hangul fillers) shown as `\u{XXXX}`.
Lists are never cut: a dropped nameserver can be the one that disagrees. Over
80 KB → a tool error with the tool's hint for asking less. `whole` tools
(cipher, `site_blog`, link tools reworking the caller's input) skip the 2 KB
cut. The tracer and MTA-STS check clip third-party header values at the source.

## Owner key

`/mcp/owner` needs short-link storage and `MCP_OWNER_KEY`: a second `Shortener`
on the same store, rotated apart from `LINK_API_KEY`, serving only the three
short-link tools. The key, as `X-Api-Key` or `Authorization: Bearer`, is
compared as SHA-256 in constant time. No key → 403, costing no try; a wrong one
spends one of the client's 5 tries (one back a second), then 429 before any
compare. Both headers are deleted before the SDK, which copies headers into
every handler. Configure it per user (`claude mcp add --scope user … --header
"X-Api-Key: …"`), never in a committed `.mcp.json`.

## Logs and licences

- Per message, a slog `MCP` line and a request-log record: host, URI
  `/mcp/<endpoint>#<tool or method>`, outcome as status (`ok` 200,
  `tool_error` 422, `error` 400, `limited` 429, `busy` 503, `timeout` 504,
  `cancelled` 499, `internal`/`panic` 500), latency, bytes out, raw IP, client
  name and version (else user agent). Never arguments, results or error text:
  cipher errors quote their input. The HTTP-level Mongo log skips `/mcp`.
- Credits live once, in `platform/credits.go`, for the footer and for MCP
  results' `attribution` ([which tools](01-tool-catalog.md)): IP2Location
  LITE's notice word for word, Spamhaus's copyright line, Shodan's visible
  credit (non-commercial use), crt.sh, rdap.org. The landing page names each
  toolset's sources; its footer prints them in full.
