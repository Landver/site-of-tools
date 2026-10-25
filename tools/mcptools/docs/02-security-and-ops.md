# Security and operations

## Threat model

Anonymous scripts, hostile pages driving visitors' browsers, agents steered by
attacker text in a result, a leaked owner key. At stake: the box (one binary
serves every subdomain), upstreams we are a guest of, the domain's reputation
(phishing short links), secrets in cipher calls.

## Gate

`handler.go` `serve`, before the SDK, in order:

1. `Cache-Control: no-store` on every response: cipher results can be secrets.
2. Unknown toolset or one with no tools, `/mcp/owner` unconfigured or without
   the [owner key](#owner-key) → 404.
3. A browser `GET`, `/mcp/owner` aside → the landing page; other `GET`/`DELETE` → the SDK's 405.
4. `Sec-Fetch-Site: cross-site` or `same-site` → 403.
5. All of `/mcp`, per address: 20/s, burst 100 → 429.
6. Body over 1 MiB → 413; a JSON-RPC batch → 400.
7. A foreign `Origin` is served and logged (`mcp: foreign Origin`).
8. Raw IP, host, user agent and HTTP context into the context.

Echo's exact-Host vhost map stops DNS rebinding, so the SDK's localhost check
(it would 403 dev's `mcp.localhost:8080`) is off. A page can't make a browser
post here (anything but JSON gets 415; cross-origin JSON fails its preflight),
so the spec's 403 for a foreign `Origin` waits for an allowlist: claude.ai's
connectors call from Anthropic's cloud with an undocumented `Origin`, and Go's
`CrossOriginProtection` would 403 any `Origin` that isn't the `Host`.

## Middleware

`middleware.go`, per JSON-RPC message:

1. `"arguments": null` is read as none.
2. `recover` → an "Internal error" result, stack logged without arguments.
3. Deadline: 25 s `ip_lookup`, DNS and botcheck tools, 20 s
   `link_redirect_chain`, `link_headers_inspect` and owner tools, 15 s heavy
   cipher and mail, 5 s the rest and other methods; a hang-up cancels the call
   (`context.AfterFunc`).
4. Rate: the tool's limiter; any other method only the gate's per-address limit.
5. Capacity: the tool's cap; full → "Busy". Heavy cipher ops hold their memory
   budget in `ciphertools.Limits.Run`, and `link_short_resolve` checks the
   short-link breaker itself; both use REST's own instances.
6. The tool, then [sanitize](#untrusted-output) and [record](#logs-and-licences).

## Outbound reach

MCP dials nothing REST doesn't. Each dial a caller can aim passes a
`platform.EgressGuard` on the address dialled, denying our vhosts, Mongo, local
interfaces and `EGRESS_DENY_ADDRS`. A traced host learns the origin IP, hence
the [Cloudflare-only proxy](../../../docs/DEPLOYMENT.md#4-client-ip-trust-model).

| Path | Guard |
|---|---|
| `link_redirect_chain`, `link_headers_inspect` | the name deny list, then ports 80/443 on every dial; no proxy, no keep-alive |
| MTA-STS and VMC in `mail_domain_health` | `mailtools.Service`'s one client: port 443, the name deny list first, no proxy, no keep-alive, no redirects |
| nameserver probes in `dns_consistency`, `dns_trace` | the guard's address check (`nsRoutable`) |
| RDAP (`dns_domain_info`, `dns_consistency`), crt.sh | own host direct, other hops guarded; each 1/s (burst 5) process-wide |
| Shodan in `ip_lookup`, `botcheck_score` | fixed host, 1/s (burst 5) process-wide; DNS is given the service without it |

## Rate limits and caps

Keyed by `platform.RateLimitKey` (IPv4 address, IPv6 /64, one bucket for junk).
Each package's `Limits`, built once in `main.go`, serves its REST routes and tools.

| Tools | Rate (burst) | Cap in flight |
|---|---|---|
| `ip_lookup`; `botcheck_score` | 2/s (10) each | 8 each |
| `dns_lookup`; `dns_domain_info` | 2/s (10), one store | 8; 4 of its own |
| `dns_consistency`, `dns_trace` | 1 per 2 s (3) | 4 |
| `link_redirect_chain`, `link_headers_inspect`; owner tools (REST `/short`'s store) | 1/s (5) each | 4; — |
| `mail_domain_health`, `mail_check_dnsbl`, `mail_dmarc_parse` | 2/s (10) | 8 |
| `link_short_resolve` | 20/s (60), plus 200/s (400) for everyone | — |
| cipher `jwt_sign`, `password_hash`, `password_verify`, `keys_generate` | 1/s (5) | 256 MiB of memory |
| other cipher, link and mail tools, `ip_cidr`, `site_blog` (MCP-only) | 10/s (50) per package | — |

A client holds at most a quarter of a cap unless it holds nothing. A heavy op
weighs Argon2's or scrypt's memory parameter, else 16 MiB. Hosted connectors
share their provider's addresses, so their users share budgets.

## Untrusted output

`sanitize.go`, on every result: invisible characters (format, Tag block,
variation selectors, DEL, C1, U+2028/9, Hangul fillers) in strings and keys
shown as `\u{XXXX}`. Neither lists nor strings are cut. A result over 80 KB
becomes a tool error saying to ask for less, and error text is clipped at
80 KB. The tracer and the header probe clip third-party header values at the
source.

## Owner key

`/mcp/owner` needs short-link storage and `MCP_OWNER_KEY`: a second `Shortener`
on the same store, rotated apart from `LINK_API_KEY`, serving only the three
short-link tools. The key, as `X-Api-Key` or `Authorization: Bearer`, is
compared as SHA-256 in constant time before any other check; no key or a wrong
one gets an unknown path's 404, so only the key's holder learns the endpoint
exists. Both headers are deleted before the SDK, which copies headers into
every handler. Configure it per user (`claude mcp add --scope user … --header
"X-Api-Key: …"`), never in a committed `.mcp.json`.

## Logs and licences

- Per message, a slog `MCP` line and a request-log record: host, URI
  `/mcp/<endpoint>#<tool or method>`, status (200 ok, 422 tool error, 400
  protocol error, 429 limited, 503 busy, 504 timeout, 499 hung up, 500
  internal), latency, bytes out, raw IP, client name and version (else user
  agent). Never arguments, results or error text: cipher errors quote their
  input. The HTTP-level Mongo log skips the `/mcp` POSTs the SDK answered;
  refusals before it and the landing page are logged there.
- Credits live once, in `platform/credits.go`, for the footer and for MCP
  results' `attribution` ([which tools](01-tool-catalog.md)): IP2Location
  LITE's notice word for word, Spamhaus's copyright line, Shodan's visible
  credit (non-commercial use), crt.sh, rdap.org; the mail blocklist tools carry
  Spamhaus's.
