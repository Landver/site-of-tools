# Tool catalog — every REST endpoint, mapped

Part of the [MCP plan](README.md). This is the contract: every JSON endpoint
on every subdomain maps to exactly one MCP tool (and operation), or is listed
under [Not tools](#not-tools) with the reason. The coverage test (README §8)
enforces it, so a new REST route without an entry here fails CI.

## How REST maps to tools

One tool per REST route is the pattern the research says not to copy
([research §6](00-research.md#6-how-comparable-public-servers-did-it)):
Cloudflare retired its one-tool-per-endpoint Radar server, the 121-tool IT-Tools
server is archived, and the public servers agents use well expose 2–23 tools.
So coverage is total but tools are consolidated, by four rules:

1. **Anything that touches the network is its own tool.** Its latency, rate
   class and side effects differ, and the model should choose it on purpose.
2. **Pure transforms of the same thing share a tool**, with an `operation`
   argument, when their arguments mostly overlap (JWT decode/sign, password
   hash/verify, key generate/inspect).
3. **Reads and writes never share a tool.** Clients decide permissions per
   tool from its hints, and Claude's connector directory rejects mixed tools.
4. **Every REST route lands on exactly one (tool, operation)** or an exclusion.

Result: **29 public tools + 3 owner tools** covering 40 REST routes; the two
remaining JSON routes are deliberate exclusions (below). The 1:1 alternative is
36 + 3 (decision D14).

## Conventions (all tools)

- **Name** `<toolset>_<thing>`, snake_case, `[a-z0-9_]`, ≤ 64 chars, no dots
  (the Claude API rejects dots in tool names). The prefix is the toolset, which
  is also the subdomain.
- **Description**, written for a model meeting the tool for the first time:
  what it does, when to use it and when to use a neighbour instead, what the
  result means, one example input. 3–5 sentences. No instructions about how the
  model should behave in general; routing across toolsets lives in the server
  `instructions`.
- **Arguments use full words**, not the REST query keys: `url` not `u`,
  `value` not `v`, `url_a`/`url_b` not `a`/`b`. Cipher keeps its POST field
  names; they are already words.
- **Enums and bounds come from the domain at boot**, never retyped: DNS types
  from `dnstools.Types`, resolvers from `dnstools.Resolvers`, trace personas
  from `linktools.Personas()`, cipher bounds from the ops' `intField` limits.
- **Result = the REST JSON body**, as `structuredContent` plus the same JSON
  compact as text. No `outputSchema` in v1 (D7).
- **Budget:** a typical result stays under ~5K tokens (~20 KB of JSON) and none
  passes ~20K tokens (Claude Code warns at 10K and spills to a file at 25K). A
  tool whose realistic result is over budget gets a concise default and
  `detailed: true` returns the REST body unchanged; the parity test then
  compares `detailed: true`. Lists that can grow are already capped in the
  domain (CT names 200, trace hops 10).
- **Errors are tool errors** (`isError: true`) with the REST API's own message,
  which already says what to fix. Schema violations come back the same way (the
  SDK validates first).
- **Rate class** per tool (the strictest of its operations), REST numbers,
  keyed on `platform.RateLimitKey(client IP)`:

  | Class | Rate | Burst | Used by |
  |---|---|---|---|
  | `pure` | 10/s | 50 | CPU only: cidr, link parsing, light cipher ops, site |
  | `upstream` | 2/s | 10 | asks third parties: all `dns_*`, `ip_lookup` (Shodan) |
  | `fetch` | 1/s | 5 | dials a stranger's host or writes Mongo: `link_trace`, owner tools |
  | `heavy` | 1/s | 5 | burns CPU on purpose: `cipher_password`, `cipher_keys` |
  | `resolve` | 20/s + global 200/s | 60 / 400 | `link_short_resolve`, the `/s/:code` pair |

- **Hints**: all four set explicitly on every tool, because the spec defaults
  (`destructiveHint` and `openWorldHint` true) make an unannotated tool look
  dangerous. Columns below: **R** read-only, **I** idempotent, **O** open
  world, **D** destructive; a missing letter means `false`.

## Toolsets at a glance

| Toolset | Endpoint | Tools | Owner tools |
|---|---|---|---|
| (all) | `https://mcp.corpberry.com/mcp` | 29 | +3 |
| `ip` | `…/mcp/ip` | 2 | — |
| `dns` | `…/mcp/dns` | 5 | — |
| `link` | `…/mcp/link` | 10 | +3 (short-link writes) |
| `cipher` | `…/mcp/cipher` | 10 | — |
| `botcheck` | `…/mcp/botcheck` | 1 | — |
| `site` | `…/mcp/site` | 1 | — |

## `ip` — ip.corpberry.com

| Tool | REST twin | Arguments (← REST key) | Result | Class | Hints |
|---|---|---|---|---|---|
| `ip_lookup` | `GET /?ip=` | `ip`? | `iptools.Result` incl. `proxy`, `blocklist`, `shodan` | upstream | R I O |
| `ip_cidr` | `GET /cidr` | `cidr` | `iptools.Subnet` | pure | R I |

- **`ip_lookup` without `ip`** looks up the address the MCP request came from,
  as the REST route does. Over MCP that is the *client's host*: the user's
  machine for Claude Code, Anthropic's or OpenAI's cloud for hosted connectors.
  The description says so, and the result adds `"self": true` plus a one-line
  note naming whose address it is.
- MCP calls never write lookup history (JSON calls don't either today).
- The REST route has no rate limiter; the MCP tool gets `upstream` because each
  lookup can call Shodan InternetDB. (Worth adding to REST too; out of scope.)
- `GET /history` is not a tool (D9, see [Not tools](#not-tools)).

## `dns` — dns.corpberry.com

| Tool | REST twin | Arguments | Result | Class | Hints |
|---|---|---|---|---|---|
| `dns_lookup` | `GET /` | `name`; `type`? enum `dnstools.Types` + `ALL` (default); `resolver`? cloudflare (default) / google / quad9 | `ResultSet`, A/AAAA enriched with ASN/country | upstream | R I O |
| `dns_consistency` | `GET /consistency` | `name`; `type`? default `A` | `ECSEnvelope` (spread + delegation health + ECS card) | upstream | R I O |
| `dns_trace` | `GET /trace` | `name`; `type`? default `A` | `Trace` (root-down walk, DNSSEC chain) | upstream | R I O |
| `dns_domain_info` | `GET /domain` | `name` | `{name, registration \| registration_error, certificate_names \| certificate_names_error}` | upstream | R I O |
| `dns_email_auth` | `GET /email` | `name` | `EmailAuth` incl. `mx_rep` | upstream | R I O |

- An IP literal in `dns_lookup.name` means PTR, as on the page.
- `dns_domain_info`: one upstream answering is a success; both failing is a
  tool error, matching the REST 502.
- Budget suspects, measured in floor 3: `dns_consistency` (every nameserver ×
  every resolver) and `dns_lookup` with `ALL`. Over budget → concise default +
  `detailed`.

## `link` — link.corpberry.com

| Tool | REST twin | Arguments | Result | Class | Hints |
|---|---|---|---|---|---|
| `link_inspect` | `GET /?u=` | `url` (← `u`) | `Inspection` (each param names its tracking rule, if any) | pure | R I |
| `link_clean` | `GET /clean` | `url`; `unwrap`? default true; `strip_affiliate`? (← `affiliate`); `sort`? | `CleanResult` | pure | R I |
| `link_tracking_rules` | `GET /clean/rules` | `param`?; `full`? | see below | pure | R I |
| `link_diff` | `GET /diff` | `url_a` (← `a`), `url_b` (← `b`) | `Diff` | pure | R I |
| `link_trace` | `GET /trace` | `url`; `persona`? enum `linktools.Personas()` | `Chain` | fetch | O |
| `link_curl` | `GET /curl` (both directions) | `command` (← `curl`) **or** `url` + `persona`?, `follow_redirects`?, `show_headers`? | `{url, headers, inspection}` or `{curl}` | pure | R I |
| `link_extract` | `GET/POST /extract` | `text` | `Extraction` | pure | R I |
| `link_utm` | `GET /utm` | `url`; `utm_source`?, `utm_medium`?, `utm_campaign`?, `utm_term`?, `utm_content`? | `{url}` | pure | R I |
| `link_encode` | `GET /encode` | `value` (← `v`) | `EncodeResult` | pure | R I |
| `link_short_resolve` | `GET /s/:code` | `code` (a code or the full short URL) | `{code, short, target}` | resolve | R I |

Owner tools, listed only when the request carries a valid key (D4):

| Tool | REST twin | Arguments | Result | Class | Hints |
|---|---|---|---|---|---|
| `link_short_create` | `POST /short` | `url`; `slug`?; `ttl`? Go duration, e.g. `720h`; `note`?; `clean`? | `{code, short, target, created_at, expires_at, hits, original?, cleaned?}` | fetch | O (it publishes a redirect) |
| `link_short_list` | `GET /short` (keyed) | `limit`? 1–50 | `{links: [...]}` (`CreatedIP` stays `json:"-"`) | fetch | R |
| `link_short_revoke` | `DELETE /short/:code` | `code` | `{status: "revoked", code}` | fetch | D I |

Deviations and traps:

- **`link_trace` is not read-only.** Tracing *visits* the URL: a one-time login
  link, an unsubscribe link or an email-verification link acts on the first
  GET. `readOnlyHint: false`, so clients that ask before side effects do ask,
  and the description names the links not to trace.
- **`link_tracking_rules`**: the REST body is the whole catalog (161 tracking
  rules plus the never-strip and wrapper tables), several thousand tokens and
  the browser extension's data feed. MCP answers `param` ("what is `gclid`?")
  with the matching entries; without it, version, scope, counts and the list of
  parameter names; `full: true` is the REST body. `link_inspect` and
  `link_clean` already name the rule for each parameter they meet.
- **`link_curl`** keeps the REST route's two directions in one tool, because
  the route does: give `command` to take a curl line apart, or `url` to build
  one. Both together is a tool error naming the conflict.
- **`link_encode` vs `cipher_encode`**: both decode base64. Descriptions route
  between them: `link_encode` for URL percent-encoding (and the decode ladder),
  `cipher_encode` for bytes as hex/base32/base64.
- **`link_short_resolve`** answers "no such link" for expired, revoked and
  never-existed alike, exactly like `/s/:code` (anything else is an existence
  oracle). It records **no hit**: reading where a link points is not following
  it (D10).
- `/trace` refuses our own hosts; floor 2 adds `cfg.VHost("mcp")` to the deny
  list.

## `cipher` — cipher.corpberry.com

The 15 ops in `ciphertools.Ops()` become 10 tools. One generic adapter maps
`(tool, operation)` → op name, builds a `ciphertools.Input` from the typed
arguments, and calls `ciphertools.Run`; the wasm build is untouched because
nothing in `ciphertools` imports the SDK.

| Tool | Ops (REST twins) | Arguments | Class | Hints |
|---|---|---|---|---|
| `cipher_jwt` | `operation: decode` → `jwt-decode` (`POST /jwt/decode`); `sign` → `jwt-sign` (`POST /jwt/sign`) | decode: `token`; `key`?, `key_enc`?, `leeway`?, `now`? · sign: `alg`, `key`, `payload` (JSON text); `key_enc`?, `header`?, `kid`?, `exp`?, `iat`? | pure | R |
| `cipher_hash` | `hash` (`POST /hash`); with `key` → `hmac` (`POST /hmac`) | `text` or `base64` (binary → file field); `key`? (→ HMAC), `key_enc`?; `enc`?, `expected`?, `trim_newline`? | pure | R I |
| `cipher_password` | `operation: hash` → `password-hash`; `verify` → `password-verify` | `password`; hash: `algo`, `bcrypt_cost`?, `argon2_m`?, `argon2_t`?, `argon2_p`?, `scrypt_n`?, `scrypt_r`?, `scrypt_p`?, `pbkdf2_iterations`? · verify: `hash`; `password_enc`? | heavy | R |
| `cipher_encrypt` | `encrypt` (`POST /encrypt`), `operation` = its `mode` (encrypt / decrypt) | `algo`, `key`; `key_enc`?, `nonce`?, `aad`?, `aad_enc`?, `text`?, `data`?, `data_enc`?, `enc`? | pure | R |
| `cipher_keys` | `operation: generate` → `keys-generate`; `inspect` → `keys-inspect` | generate: `type` (rsa-2048/3072/4096, ec-p256/p384/p521, ed25519), `comment`? · inspect: `key` · both: `passphrase`? | heavy | R |
| `cipher_cert` | `cert` (`POST /cert`) | `cert` (PEM) or `cert_base64` (DER → file field); `key`? (does it match?) | pure | R I |
| `cipher_totp` | `totp` (`POST /totp`) | `secret` or otpauth URI; `mode`? totp/hotp; `algo`?, `digits`?, `period`?, `counter`?, `code`? (check it), `issuer`?, `label`? (build a URI) | pure | R |
| `cipher_random` | `random` (`POST /random`) | `kind` token/password/uuid; `format`? hex/base64url/base64/alnum; `bytes`?, `length`?, `count`?, `version`? 4/7, `exclude_ambiguous`? | pure | R |
| `cipher_encode` | `encode` (`POST /encode`); `operation: basic_auth` → `basic` (`POST /encode/basic`) | convert: `text`, `from`; basic_auth: `user` + `password`, or `header` to decode | pure | R I |
| `cipher_identify` | `identify` (`POST /identify`) | `text` | pure | R I |

- **The page's promise does not cover MCP.** cipher.corpberry.com runs in the
  browser so nothing leaves the tab. An MCP call sends its arguments to this
  server *and* through the user's AI provider, exactly like the `curl` path the
  page already describes ("From a terminal your input goes to this server").
  Every cipher description carries one line saying so and "use test material,
  not production secrets". Arguments are never logged (README §6).
- Bounds (`bcrypt_cost`, `count`, …) appear in the schema as
  `minimum`/`maximum`, taken from the ops; a drift test checks each against the
  op's own error at bound + 1.
- Not idempotent where an operation draws randomness (salts, nonces, keys,
  tokens, `iat`). The hint is honest rather than uniform.
- `operation` that doesn't match the supplied arguments (e.g. `sign` without
  `payload`) is a tool error naming the missing field, before any work.

## `botcheck` — botcheck.corpberry.com

| Tool | REST twin | Arguments | Result | Class | Hints |
|---|---|---|---|---|---|
| `botcheck_score` | `GET /` (server signals) and `POST /check` (fingerprint) | `fingerprint`? object (the collector's `/check` payload); `http`? `{user_agent, accept, accept_language, accept_encoding, sec_ch_ua, sec_ch_ua_platform, sec_fetch_mode}`; `ip`?; `detailed`? | `Report` | pure | R I |

- **Scores what it is given** (D11). Over HTTP, `/` and `/check` read the
  *caller's* own headers and IP. Over MCP the caller is an MCP client or a cloud
  broker, so scoring it describes Anthropic or OpenAI, not the user. The tool
  scores the fingerprint, headers and IP the agent supplies (e.g. a dump from a
  headless-browser test run). IP signals (timezone, ASN, proxy/VPN/Tor,
  blocklist) come from the supplied `ip` through the code the handler uses
  (moved down in floor 1). Nothing supplied → tool error saying what to send.
- **No corpus reads or writes.** `/check` records every fingerprint for the
  `fingerprint_reuse` and `ip_fingerprint_churn` rules. Agent-supplied, possibly
  synthetic payloads must not train that corpus, so both rules stay silent and
  the result says they were not evaluated.
- `fingerprint` is typed `object`, not the 91-field `Signals` struct: inferring
  that struct would add several thousand tokens to every `tools/list`. The
  server decodes it into `Signals` and names any field it rejects.
- **Concise by default:** fired checks in full, the rest as counts per tier;
  `detailed: true` returns every check. The `clientPayload` echo (G54) is
  dropped; the caller already has it.

## `site` — corpberry.com

| Tool | REST twin | Arguments | Result | Class | Hints |
|---|---|---|---|---|---|
| `site_blog` | `GET /blog`, `GET /blog/:slug` | `slug`? | no slug: `[{slug, title, date, description, url}]`; slug: the post | pure | R I |

- **Deviation:** the REST post body is rendered HTML. MCP returns the post's
  Markdown source: it is what the post is, at a fraction of the tokens. Needs
  the blog loader to keep the source beside the HTML (floor 7).

## Not tools

| Route(s) | Why not a tool |
|---|---|
| `GET ip.corpberry.com/history` | D9: lists addresses *other* visitors looked up from the web page; no agent task needs it, and it would be one more tool in every context. One small tool if the owner disagrees. |
| apex `GET /` (JSON tool catalog) | The MCP server *is* the catalog: `tools/list`, the `instructions`, and the landing page's JSON at `mcp.corpberry.com/`. |
| `GET /blog/feed.xml` | RSS for feed readers; `site_blog` covers the content. |
| cipher page shells (`GET /`, `/hash`, …) and `GET /static/wasm/cipher.wasm` | The in-browser engine. MCP calls the same ops natively. |
| `GET botcheck.corpberry.com/botcheck-sw.js` | The Service Worker the browser collector registers; not an API. |
| `GET link.corpberry.com/encoding` | Static reference page with no JSON form. Candidate MCP *resource* (floor 9). |
| `GET link.corpberry.com/extension/privacy` | The extension's privacy policy. |
| `GET /sitemap.xml`, `/robots.txt`, `/static/*` on every host | SEO and assets. |
