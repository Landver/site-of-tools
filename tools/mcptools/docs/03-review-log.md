# Review log

Part of the [MCP plan](README.md). Before handover, the plan was reviewed by
independent agents, two at a time, each with one lens and the instruction to
verify claims against the code, the spec and the SDK source rather than trust
the plan's wording. Each finding is listed with what changed because of it.

## Round 1A — protocol and Go SDK correctness

Checked against go-sdk v1.8.0 source, jsonschema-go v0.4.3 and the 2026-07-28
spec sources. The blocker was re-verified independently
(`mcp/streamable.go:1445-1452`, `mcp/transport.go:739-758` at v1.8.0).

| # | Sev. | Finding | Change |
|---|---|---|---|
| 1 | **blocker** | A POST without `MCP-Protocol-Version` is treated as 2025-03-26, where JSON-RPC **batches are still accepted**, uncapped; in JSON-response mode every reply is buffered. One 1 MiB body ≈ 20k `tools/list` calls, counted once by the `/mcp` limiter. | Echo pre-handler reads the body (≤ 1 MiB, else 413) and answers **400 to any JSON array** before the SDK sees it (batching left the spec in 2025-06-18). Every JSON-RPC message, not only `tools/call`, now passes a `protocol` rate class in the middleware. Test: a 2-element batch → 400. |
| 2 | major | `site_blog`'s list was a top-level array. Spec 2025-11-25 types `structuredContent` as an object; the TS and Python SDKs reject anything else, so legacy clients fail the whole result. A typed-nil `Out` is sent as `null`, same failure. | Rule added to the catalog: `structuredContent` is always a JSON object, never `null`. `site_blog` lists as `{posts: [...]}` (REST `/blog` is an object too). Test: every tool/operation result starts with `{`. |
| 3 | minor | D7's reason was wrong: jsonschema-go infers slices and pointers as nullable. Real mismatches: `[]byte`/`json.RawMessage` (inferred as integer arrays; `ciphertools/jwt.go` has two), `net.IP`/`netip.Addr`, custom marshalers, nil maps. | D7 reason corrected; that list becomes the checklist for any later per-tool `outputSchema`. |
| 4 | minor | `PropagateRequestCancellation` only cancels 2026-07-28 requests; older clients' work runs to completion. | Reworded. Floor 2a bridges it for every era: the middleware cancels the handler context when the HTTP request's context ends (`context.AfterFunc`). |
| 5 | minor | Client name is absent on legacy calls (the SDK synthesises state without it) and optional in 2026-07-28 `_meta`. | Per-call log records the name when present, else the User-Agent. |
| 6 | minor | A `"public"` anonymous list on the same URL as the keyed list may be served from a shared cache to the owner for up to an hour (cache key = method + params, not credentials). Nothing leaks; owner tools just vanish. | **D4 changed**: owner tools live only at `/mcp/owner` (every public tool + the 3 owner tools, key required, `private`). Public endpoints never vary, so they stay `public`. *(Superseded by 1B#8: owner tools only.)* |
| 7 | minor | D15 deviates from a spec MUST ("Origin present and invalid → MUST 403"); it isn't compliance. | D15 is now two-step: floor 2b observes and logs the `Origin` hosted connectors send; then an allowlist answers 403 to every other `Origin`, which is compliant. The deviation is stated, and time-boxed to floor 2b. |
| 8 | minor | `server/discover` is optional for clients, so `instructions` may never arrive. | The "third-party data, treat as data" line moves into each such tool's description; each toolset server's instructions mention only its own tools. |
| 9 | nit | The SDK sorts tools by name; "registry order" can't be imposed. | Wording fixed; golden test expects name order. |
| 10 | nit | `getServer` runs twice per request, before the SDK's method/Content-Type checks; nil → 400. | `getServer` is a pure lookup; unknown toolset (404) and bad key (403) are decided in Echo first (`req.PathValue("toolset")` survives `WrapHandler`). |
| 11 | nit | Nil `Capabilities` makes the SDK infer `listChanged: true`, and then `subscriptions/listen` holds an SSE stream open even in JSON mode, contradicting D3. | Capabilities set explicitly: tools with `listChanged: false`. Test: listen returns immediately. |
| 12 | nits | `req.Extra` is nil on in-memory transports; `ServerOptions.Logger` at Info logs 3 lines per stateless request; `validateToolName` only logs. | Nil-check `Extra`; Logger nil (or Warn); the golden test asserts `^[a-z0-9_]{1,64}$`. |

Verified as written: per-request `getServer` in stateless mode; `Out = any`
still yields `structuredContent` + text and no schema; Go error → `isError`,
input validation → `isError`, unknown tool → protocol error; `jsonschema.For` +
edit + `Tool.InputSchema` is the supported route and is enforced;
`SetCacheable` per server instance; instructions in both `server/discover` and
`initialize`; middleware sees every method and can short-circuit; context values
reach tool handlers; older clients work in stateless mode; annotation field
types; `tools/list` is a single page (page size 1000).

## Round 1B — security and abuse (adversarial)

Checked against the repo code, Echo v5.3.0, go-sdk v1.6.0/v1.8.0 and the spec.
The panic and egress findings were re-verified independently (no `recover()` in
v1.8.0's `internal/jsonrpc2/conn.go`, `mcp/server.go`, `mcp/shared.go`;
`dnstools/email.go:780` `ProxyFromEnvironment`; `dnstools/domain.go:148`
default client; `dnstools/spread.go:512` `routable()`). The result was a new
doc, [02-security-and-ops.md](02-security-and-ops.md).

| # | Sev. | Finding | Change |
|---|---|---|---|
| 1 | **blocker** | Same batch hole as 1A#1, plus the per-call log would write 20k records for it. | As 1A#1. The header is not made mandatory: legacy clients send `initialize` without it, and with batches refused a header-less single message is harmless. |
| 2 | **blocker** | A panic in any tool kills the process: the SDK runs handlers in goroutines with no `recover`, and Echo's `Recover` guards only the HTTP goroutine. One bad input would take down every subdomain. | Outermost receiving middleware recovers per message (`isError` / internal error, stack logged without arguments); per-adapter fuzz test that the process survives. |
| 3 | major | **Hidden Shodan fan-out**, already in REST: `iptools.Service.Lookup` calls Shodan inside every lookup with `context.Background()`, so DNS enrichment calls it per A/AAAA record and per nameserver; the repo's own report puts a one-hour ban at ~600 fast calls. | Floor 1b: DB-only lookup for enrichment (DNS keeps only ASN/country, so REST output is unchanged); Shodan only from `ip_lookup` and botcheck under a process-wide ~1/s limiter; `botcheck_score` moved to `upstream`. |
| 4 | major | "Through the same guards" was false: only `link_trace` *(now `link_redirect_chain`)* uses `EgressGuard`. MTA-STS has its own dialer with `ProxyFromEnvironment` and keep-alives; nameserver probes use a `routable()` that admits CGNAT/multicast/reserved; RDAP/CT follow any redirect; the deny list misses the host's public IP inside the container. | New decision **D16**, floor 1b: every path through the one guard (443-only + no proxy for MTA-STS, `PubliclyRoutable` for probes, HTTPS-only redirects for RDAP/CT), deny list built from the `hosts` map plus configured public addresses *(revised, 2A#2)*. nginx `default_server` 444 recommended. |
| 5 | major | Per-IP limits trust `CF-Connecting-IP` unconditionally; whether nginx only accepts Cloudflare is unverified (the link-tools security doc already says so). `RateLimitKey` returns unparseable input as its own key. | Floor-2b **gate**: confirm the proxy accepts only Cloudflare ranges or Authenticated Origin Pulls. Floor 1c: unparseable keys fold into one bucket. |
| 6 | major | Classes count calls, not cost (`dns_consistency` ≈ 50–100 upstream queries at the same 2/s as an 8-query lookup); separate MCP limiters double every budget; no box-wide cap on heavy ops (Argon2 64 MiB × 4 threads, scrypt 128 MiB, RSA-4096 keygen); JWT signing accepts RSA-8192 but was `pure`. | **D12 rewritten**: stores shared with REST twins (floor 1c), cost-priced classes incl. `dns-walk`, a `protocol` class for every non-call method, non-blocking concurrency caps with a memory-weighted `heavy` budget, `cipher_jwt` *(now `cipher_jwt_sign`)* → `heavy`. |
| 7 | major | Third-party strings were neither bounded nor kept out of prose: MTA-STS splices the attacker's `Content-Type` (up to 10 MB) into errors and notes; the tracer stores `Location` before its length check and copies TLS error text into notes; `link_extract` can return 2,000 anchors; JSON leaves bidi, zero-width and Tag characters intact. | Output post-processor on every result (2 KB string cap with marker, bidi/format/Tag made visible, result budget); source-side bounds in floor 1b; more budget suspects listed. |
| 8 | major | Owner tools in the same server as tools returning attacker text; `link_short_create` hinted non-destructive (auto-approvable); the key header is copied into every handler's `RequestExtra`; key guessing only behind the coarse limiter; a gateway's unrelated `Authorization` header would 403 public use. | `/mcp/owner` serves **only** the three owner tools; own rotatable `MCP_OWNER_KEY`, `X-Api-Key` only *(Bearer added, 2B M6)*, header deleted before the SDK; failed-key limiter; create marked destructive; user-scope setup snippet. |
| 9 | minor | JSON nesting depth unbounded in segmentio/encoding. | **Partly refuted:** v1.8.0 checks depth ≤ 1000 before decoding (`internal/json/json.go:17-41`). Kept: 1 MiB body and nginx `client_max_body_size 1m`. |
| 10 | minor | Cancellation reaches only 2026-07-28 clients; cipher errors echo input, so logging `err.Error()` leaks; the SDK sets `Cache-Control: no-cache, no-transform`, not `no-store`. | Per-class deadlines + `AfterFunc` bridge; the log records an outcome class only; a response wrapper sets `no-store` *(replaced by a `Before` hook, 2A#12)*. |
| 11 | minor | Licence credits (IP2Location LITE, Spamhaus, Shodan) live in page footers; MCP results have none, and Shodan is non-commercial with attribution. | New decision **D17**: `attribution` list in results from the same credits the footer renders; credits on the landing page; dropping Shodan from MCP is the alternative. |
| 12 | nits | Bot Fight Mode is zone-wide on the Free plan, not per host; D15 departs from a MUST and should say so. | §10 rewritten (confirm it is off; optional edge rate-limit rule); D15 now states the deviation and ends it before floor 3. |

Verified as written: Echo's vhost map matches `Host` exactly and 404s the
rest; cross-site browser calls are already blocked (JSON-only bodies, failed
preflight, unforgeable `Sec-Fetch-*`); the owner-key compare has no timing or
length leak, and 403 rather than 401 is right; the request log stores no
headers or bodies; `link_short_resolve` is oracle-safe; the tracer sends no
cookies, Referer or Authorization and re-gates every hop; the botcheck corpus
is written only by `POST /check`; cipher bounds are checked before work; no
request decompression; drafts are filtered at load; miekg/dns escapes control
characters in DNS text.

## Round 2A — architecture fit and implementability

Checked against the repo, Echo v5.3.0 and go-sdk v1.8.0. No blockers; it also
supplied the concrete Go shapes now in README §3.4.

| # | Sev. | Finding | Change |
|---|---|---|---|
| 1 | major | Concurrency caps lived only in the MCP middleware, so the plan's own Argon2 attack still worked through `POST /password/hash`. | Caps move into each package's `Limits` (floor 1c), shared by REST and MCP: `x/sync/semaphore.Weighted` + `TryAcquire`; memory weight from a pure, wasm-safe `ciphertools.MemoryCost`. |
| 2 | major | Floor 1b as written would break tests and target a path that never dials: a guarded RDAP/CT transport refuses the tests' loopback `httptest` servers; MX reputation only filters addresses before a corpus read, and `PubliclyRoutable` there breaks ~20 TEST-NET fixtures; "host IPs via config" needs an `EgressGuard` API change; "deny list from the hosts map" is impossible as ordered in `main.go`. | Guard RDAP/CT redirect hops only (HTTPS-only `CheckRedirect`, base host dialable); `PubliclyRoutable` only at `spread.go:438` and `traceRoutable`; MX row says "no change"; the guard takes literal addresses into its address set; one subdomain list feeds both vhosts and deny list. |
| 3 | major | "Shared stores" don't give one budget unless both doors key alike: dnstools keys on the raw IP, linktools/ciphertools on `RateLimitKey`, so an IPv6 client gets two buckets; "pure" is four stores, not one. | `platform/ratelimit.go` (`Limiter` alias, `NewLimiter`, a `RateLimit` middleware always keyed by `RateLimitKey`); per-package `Limits` + `NewLimits()`; `Register(…, lim)` with nil = fresh (tests unchanged); `netgate_test` updated for fail-closed keys. |
| 4 | major | The push-down table missed logic adapters would duplicate: cipher JSON → `Input` (with its float-format trap) and field bounds held as literals; the owner create path; the self-IP rule; DNS defaults; botcheck header mapping and `Now` (zero `Now` skips timezone checks); tracking-rule lookups; a fakeable blocklist interface. | README §3.4 is now a per-package table: `InputFromJSON` + field specs, `Shortener.CreateFrom`/`PublicError`, `Routable`, defaults inside `LookupEnriched`, a botcheck constructor in a new file, `RuleCatalog` lookups, `LookupWithReputation` over a `Checker` converted from nil (the nil-interface trap `reputation.go` warns about). |
| 5 | minor | Structs replacing maps serialise in field order, maps in sorted key order. | Fields declared in the maps' alphabetical order; golden tests compare semantically; `DomainInfo` keeps each half's error as `json:"-"`. |
| 6 | minor | The context carried only the limiter key, which for IPv6 is a `/64`. | Raw IP and key both go into the context. |
| 7 | minor | A new exported `Markdown` field on `Post` would leak into REST JSON (no tags); the blog is built inside `site.Register`; floors disagreed (1a vs 7). | `json:"-"`; `site.Register` returns the blog; done in floor 7; `site_blog` parity is a declared projection. |
| 8 | minor | `NewShortener` returns nil without `LINK_API_KEY`, so the owner endpoint wasn't independent of it. | A second `Shortener` over the same store with `MCP_OWNER_KEY`; the gate reuses its `Authorized`. |
| 9 | minor | Missing plumbing: `@source` in `input.css`, a `TemplateSource`, new template funcs in `navBaseFuncs` and the cipher `FragmentTemplates` stubs (or the wasm engine fails to parse); the terminal block is inline in ~25 templates, not a partial; `platform.Respond` can't serve a page whose view model and JSON differ. | All in README §6; the landing page uses the `reply` pattern, promoted to `platform` on this third copy. |
| 10 | minor | Floors 1a, 1b and 2 were several PRs each; the coverage test couldn't pass before floors 3–7; missing `.env.example`/config tests, a `jsonschema-go` pin, the stale `deploy/nginx/` reference, the per-call log's destination, `Register` returning an error. | Floors split (1a ×5, 1b ×3, 2a code / 2b launch); `Coverage` gains *planned*; README §9 lists the config/docs; records go through `RequestLog`; `mcptools.Register` returns an error. |
| 11 | nit | Skipping gzip on `/mcp` is unnecessary and would put an MCP path into `platform/app.go`. | Dropped. |
| 12 | nit | No custom writer needed for `no-store`. | Echo's `UnwrapResponse` + `Before` hook. |
| 13 | nit | `x/oauth2` *is* linked (`mcp` imports it). | Research §2 corrected. |

Verified as implementable: `WrapHandler` keeps path values; `e.Any`; header
deletion and body swap persist; request-context values reach handlers; results
reach the middleware as raw JSON + text (so the sanitizer can rewrite both);
`e.Router().Routes()` lists routes; every `Register` builds offline with fakes;
`geo.Offline()` needs no interface change; no import cycles; the wasm build is
untouched; the SDK bumps no pinned module; layout and template names fit.

## Round 2B — coverage completeness and agent usability

Route coverage was **complete**: 40 mapped routes, the two exclusions, 15 ops,
no route unmapped or mapped twice. The problems were in the contracts.

| # | Sev. | Finding | Change |
|---|---|---|---|
| M1 | major | `botcheck_score` treated missing data as evidence: absent headers fire soft rules (a Chrome UA alone → "suspicious"), a hand-built fingerprint → "bot", and a call without one skips 59 of 68 rules yet can read "human". | D11 revised: the domain's existing "skipped" mechanism extends to headers and IP (floor 1a); `Report` counts evaluated/skipped/fired per tier; `fingerprint` must be a collector payload with its `v` stamp. |
| M2 | major | The cipher contract was hand-copied and wrong in ~10 places (password `sets`, `now` on sign/cert/TOTP, `password_enc` on hashing, encrypt's optional key and algo, sign's defaults and `exp` presets, `passphrase` on generate only, invented `base64`/`cert_base64` args); per-op defaults and enums can't share one schema. | Cipher tools are **generated** from per-op field specs that the ops themselves read (floor 1a), with an AST test; the catalog's cipher table is now illustrative and corrected. |
| M3 | major | Absent ≠ empty/false: `link_utm` deletes every utm field not supplied; `link_clean.unwrap` defaults to true but a plain `bool` defaults false. | Pointer-typed optional args; `link_utm` absent = keep, `""` = remove (declared deviation); a test omits each optional argument in turn. |
| M4 | major | Hidden mode switches contradicted rule 2 (HMAC when `key` present; `link_curl` by which argument is set); hash and HMAC differ in algorithms, result shape and key handling. | **D14 reversed**: one tool per distinct task, no operation switches: `cipher_hmac` and the two `link_curl_*` tools split out; all cipher ops 1:1 (35 tools). |
| M5 | major | Concise shapes were unspecified and several results blow the budget (`dns_consistency type=TXT` 25–60 KB, `link_extract` 30–60 KB, `dns_domain_info` ~22 KB, TXT-heavy `dns_lookup` 15–25 KB); a list-cutting sanitizer can drop the one disagreeing nameserver. | Concise defaults defined per tool in the catalog; one `detailed` flag; the sanitizer never cuts lists, over-cap results become a tool error. |
| M6 | major | Snippets missing for ChatGPT, Codex and Gemini CLI (whose `url` means SSE); claude.ai plan limits; 35/29 tools exceed OpenAI's guidance and crowd Cursor's ~40 cap. | Research §5 now covers eight clients; `/mcp` recommended only for Claude Code, toolset URLs for the rest; owner tools need header-capable clients; Bearer accepted on `/mcp/owner`. |
| m7 | minor | Parity can't hold literally for several tools (blog view model, a 302, `limit`, `self`, supplied headers). | Parity compares a declared projection per tool; exemptions listed with reasons. |
| m8 | minor | `ip_lookup` without `ip` silently changes subject. | `ip` required; the literal `"self"` asks for the caller's address. |
| m9 | minor | `link_tracking_rules(param)` underspecified (prefix, host-scoped, affiliate-gated, never-strip wins); the counts were wrong. | Returns exact, prefix and never-strip matches with hosts; optional `url` gives the verdict via `lookupTracking`; counts corrected (95 / 64 / 21). |
| m10 | minor | Name collisions on `/mcp`: `dns_trace`/`link_trace`, `link_encode`/`cipher_encode`; descriptions naming tools absent from a toolset endpoint. | Renamed `link_redirect_chain`, `link_percent_encode`; descriptions name only same-toolset tools; cross-toolset routing in the `/mcp` instructions. |
| m11 | minor | Agents will try `link_short_resolve` on bit.ly and use the tracer as a page fetcher. | Foreign hosts → error naming `link_redirect_chain`; its description says status and headers per hop, no body, fetched from our IP. |
| m12 | minor | "Strictest operation" priced cheap ops as heavy. | Moot after M4: each op is its own tool with its own class. |
| m13 | minor | Generated values (random, keys, encrypt's key) also pass through us and the provider. | "Test material only, in and out" on every cipher description. |
| m14 | minor | Blog Markdown has frontmatter and relative image paths. | Stripped / made absolute. |
| nits | | `botcheck_score` lacked the open-world hint; the key is `mx_reputation`; "≤ 8 queries" was wrong; Bearer for Codex; `--scope user`. | All fixed. |

Also from this round's reading of the spec: `idempotentHint` and
`destructiveHint` only mean something on tools that aren't read-only, so the
first draft's "not idempotent where randomness is drawn" note was a misreading
and is gone.

## Round 3 — cold read: consistency and clarity

A fresh reader checked the five docs against each other and against the code.
**Consistent:** all 38 tool names, toolset sizes, the 15 ops, 13 cross-doc
anchors, rate classes, decision numbers, and a dozen code citations
(`spread.go:438`, `email.go:780`, `domain.go:148`, `geoip.go:178`, the limiter
numbers, `mx_reputation`, the 26 inline terminal blocks, …). No blockers.

| # | Sev. | Finding | Change |
|---|---|---|---|
| 1 | major | "Every REST endpoint covered by 35 tools" overstated the owner's literal ask: two JSON routes are excluded, and only one was surfaced as a decision. | README §1 now says every JSON endpoint has a *decision*: 40 routes → 35 + 3 tools, two named exclusions, a CI coverage test. |
| 2 | major | The catalog put the blog's Markdown in floor 1a; README and 2A#7 say floor 7. | Catalog says floor 7. |
| 3 | major | The wiring sketch would fail a copy-paste implementer: the owner `Shortener` lacked `CleanTarget` (`clean: true` errors); `Deps` had no public `Shortener` for `link_short_resolve`; no `Limits` for botcheck or the blog. | Sketch fixed (owner built with the cleaner, `Short` added and listed only with `LINK_API_KEY`, `botcheck.NewLimits()`); `site_blog`'s limiter declared MCP-only. |
| 4 | major | Floor 1a was "behaviour-preserving" yet the botcheck row changes REST JSON. | Over HTTP the request's own headers always count as supplied, so verdicts don't change; the new counts are one reviewed golden diff, stated in the row and the floor's done-when. |
| 5 | major | D12 (a bold decision) hid that saying yes changes REST limits. | The cell lists the REST changes (`/consistency` and `/trace` to 1 per 2 s, burst 3; IP and botcheck limited for the first time; `POST /jwt/sign` 10/s → 1/s) and states the alternative's cost plainly. |
| 6–15 | minor/nit | "*lean* waits for the owner" made all 17 rows owner decisions; "three short-link writes" (list is a read); host-IP config in two floors; deadlines and caps missing for some classes; superseded review-log rows without pointers; `reply` promotion worded two ways; Go jargon unexplained for a newcomer; the per-page MCP line, the thing that prompted the request, came last (floor 8); an empty advisories row; an unlinked ARCHITECTURE reference. | Status line and floor 0 name the six bold decisions; wording fixed; config in floor 1b only; every class has a deadline and `dns-walk` a cap; pointers added; `reply` moves in floor 2a; a "Terms" list after §2; each toolset's floor adds its own pages' MCP line, starting in 2a; advisories as a sentence; link added. |

Verdict, in the reviewer's words: with these edits "a cold reader can answer
floor 0 from the plan alone, and the plan meets the owner's request."
