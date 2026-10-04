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
| 4 | minor | `PropagateRequestCancellation` only cancels 2026-07-28 requests; older clients' work runs to completion. | Reworded. Floor 2 bridges it for every era: the middleware cancels the handler context when the HTTP request's context ends (`context.AfterFunc`). |
| 5 | minor | Client name is absent on legacy calls (the SDK synthesises state without it) and optional in 2026-07-28 `_meta`. | Per-call log records the name when present, else the User-Agent. |
| 6 | minor | A `"public"` anonymous list on the same URL as the keyed list may be served from a shared cache to the owner for up to an hour (cache key = method + params, not credentials). Nothing leaks; owner tools just vanish. | **D4 changed**: owner tools live only at `/mcp/owner` (every public tool + the 3 owner tools, key required, `private`). Public endpoints never vary, so they stay `public`. |
| 7 | minor | D15 deviates from a spec MUST ("Origin present and invalid → MUST 403"); it isn't compliance. | D15 is now two-step: floor 2 observes and logs the `Origin` hosted connectors send; then an allowlist answers 403 to every other `Origin`, which is compliant. The deviation is stated, and time-boxed to floor 2. |
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
| 4 | major | "Through the same guards" was false: only `link_trace` uses `EgressGuard`. MTA-STS has its own dialer with `ProxyFromEnvironment` and keep-alives; nameserver probes use a `routable()` that admits CGNAT/multicast/reserved; RDAP/CT follow any redirect; the deny list misses the host's public IP inside the container. | New decision **D16**, floor 1b: every path through the one guard (443-only + no proxy for MTA-STS, `PubliclyRoutable` for probes, HTTPS-only redirects for RDAP/CT), deny list built from the `hosts` map plus configured public addresses. nginx `default_server` 444 recommended. |
| 5 | major | Per-IP limits trust `CF-Connecting-IP` unconditionally; whether nginx only accepts Cloudflare is unverified (the link-tools security doc already says so). `RateLimitKey` returns unparseable input as its own key. | Floor-2 **gate**: confirm the proxy accepts only Cloudflare ranges or Authenticated Origin Pulls. Floor 1c: unparseable keys fold into one bucket. |
| 6 | major | Classes count calls, not cost (`dns_consistency` ≈ 50–100 upstream queries at the same 2/s as an 8-query lookup); separate MCP limiters double every budget; no box-wide cap on heavy ops (Argon2 64 MiB × 4 threads, scrypt 128 MiB, RSA-4096 keygen); JWT signing accepts RSA-8192 but was `pure`. | **D12 rewritten**: stores shared with REST twins (floor 1c), cost-priced classes incl. `dns-walk`, a `protocol` class for every non-call method, non-blocking concurrency caps with a memory-weighted `heavy` budget, `cipher_jwt` → `heavy`. |
| 7 | major | Third-party strings were neither bounded nor kept out of prose: MTA-STS splices the attacker's `Content-Type` (up to 10 MB) into errors and notes; the tracer stores `Location` before its length check and copies TLS error text into notes; `link_extract` can return 2,000 anchors; JSON leaves bidi, zero-width and Tag characters intact. | Output post-processor on every result (2 KB string cap with marker, bidi/format/Tag made visible, result budget); source-side bounds in floor 1b; more budget suspects listed. |
| 8 | major | Owner tools in the same server as tools returning attacker text; `link_short_create` hinted non-destructive (auto-approvable); the key header is copied into every handler's `RequestExtra`; key guessing only behind the coarse limiter; a gateway's unrelated `Authorization` header would 403 public use. | `/mcp/owner` serves **only** the three owner tools; own rotatable `MCP_OWNER_KEY`, `X-Api-Key` only, header deleted before the SDK; failed-key limiter; create marked destructive; user-scope setup snippet. |
| 9 | minor | JSON nesting depth unbounded in segmentio/encoding. | **Partly refuted:** v1.8.0 checks depth ≤ 1000 before decoding (`internal/json/json.go:17-41`). Kept: 1 MiB body and nginx `client_max_body_size 1m`. |
| 10 | minor | Cancellation reaches only 2026-07-28 clients; cipher errors echo input, so logging `err.Error()` leaks; the SDK sets `Cache-Control: no-cache, no-transform`, not `no-store`. | Per-class deadlines + `AfterFunc` bridge; the log records an outcome class only; a response wrapper sets `no-store`. |
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
