# DNS lookup tool — build-fit / feasibility filter

Not a design doc. This filters the 36-report research corpus down to *what this
specific stack can actually ship*, w/ evidence, then hands the owner a tiered
proposal & the decisions only they can make. No Go written here, no feature
picked. Corpus: `tools/dnstools/docs/reports/` (36 files). Read in full for
this doc: `CLAUDE.md`, `docs/ARCHITECTURE.md`,
`tools/iptools/docs/README.md`, `reports/go-dns-implementation.md`,
`reports/browser-constraints-dns-2026.md`, `reports/abuse-ratelimits-and-ethics.md`.

---

## 1. What this stack can actually do

Constraints in scope for every bucket below: one Go binary (`CGO_ENABLED=0`,
distroless base, currently **15.99 MB**), Echo v5 + htmx + Tailwind standalone,
**no Node ever**, Mongo optional/nil-safe, one Hetzner box behind Cloudflare
(proxy on) + nginx, no budget for paid data (CLAUDE.md rule #3, ARCHITECTURE §1/§2).

**The one open blocker before any server-side bucket ships:** whether outbound
UDP/53 (and TCP/53, for truncated answers) is permitted off the Hetzner box.
Nobody in the corpus could test it — `go-dns-implementation.md`: *"Neither pass
could reach the box… Test on the box before writing code."* If it's blocked,
DoH-over-443 is a proven fallback (`POST application/dns-message` → HTTP 200,
61 B from Cloudflare, Google **and** Quad9, verified 2026-09-16) and most of
Tier 0 below still ships; `+trace` and querying an arbitrary authoritative NS
do **not** survive that fallback (DoH endpoints are themselves stub resolvers,
they can't be pointed at a specific NS).

### Ship-today-pure-Go
(`github.com/miekg/dns` v1.1.73, in-process, no third party — or DoH-443 fallback where noted)

| Feature | Notes |
|---|---|
| A/AAAA/CNAME/MX/NS/TXT/SOA/PTR/SRV, TTL, rcode/flags, query timing | table stakes, `net.Resolver` structurally can't do this (no TTL anywhere in its API) — must be miekg |
| Arbitrary + modern RR types: CAA, DS, DNSKEY, CDS/CDNSKEY, TLSA, SSHFP, SVCB/HTTPS, NAPTR, LOC, URI, DNAME, ZONEMD, raw `TYPE<n>` | 88 types in miekg's `TypeToString`, 80 constructors, all verified firsthand |
| NXDOMAIN/NODATA/denial-of-existence detail via NSEC/NSEC3 in the authority section | consumer tools skip this; miekg types both |
| `+trace` delegation walk (root → TLD → authoritative), parent-vs-child NS/glue diff, SOA-serial agreement across a zone's own NS | **needs raw UDP/TCP egress**, dies on the DoH fallback |
| DNSSEC surface: DO bit, AD flag, inline RRSIG, KSK/ZSK split, `KSK.ToDS()` vs parent DS | chain-walk math is caller code either way; library gives primitives only |
| Extended DNS Errors (RFC 8914) decode | best "why did this fail" feature in the whole corpus, almost nobody ships it |
| NSID (which anycast node answered) | cheap EDNS option, free PoP identification |
| Multi-resolver comparison / fan-out, server picks the resolvers over plain UDP/53 | our own queries to e.g. 1.1.1.1/8.8.8.8/9.9.9.9, not their DoH JSON |
| Reverse/PTR incl. auto `in-addr.arpa`/`ip6.arpa` construction, zone-file-format output | `dns.ReverseAddr` |
| In-process TTL-respecting cache + `singleflight` | measured: 12 RR types serial 3.06s vs `errgroup` 477ms; 10 concurrent identical lookups → 1 upstream query |
| Query budget / resolver allowlist / no free-form `@server` | abuse controls, not features, but zero-dependency Go |
| ASN/geo/proxy enrichment of resolved IPs & nameservers | **already in-process** — `tools/iptools/geoip.go`'s `Service` can be called directly, same binary, no new dep |
| DNSBL/RBL reputation card on resolved MX/A IPs, curated ~10-15 zones | DNS-as-a-database queries (`127.0.0.x` encoding), same shape as existing blocklist code in `tools/iptools/blocklist.go` |
| Mongo lookup history | reuse `tools/iptools/history.go` pattern verbatim, nil-safe |

**One caveat inside this bucket:** EDNS Client Subnet (ECS) is only
corpus-verified over Google's **DoH JSON** param (`browser-constraints-dns-2026.md`).
ECS is an EDNS0 OPT-code (RFC 7871) so it *should* work identically over plain
UDP/53 to `8.8.8.8`, since DoH JSON is a translation layer over the same
backend — but nobody in the corpus queried it that way. Verify before counting
on it.

### Needs-a-free-public-API
(third party, keyless, but a network dependency outside our control — mirrors `tools/iptools/shodan.go`'s pattern)

| Feature | Source | Caveat |
|---|---|---|
| CT-log subdomain enumeration | `crt.sh/?q=%25.<domain>&output=json`, CORS `*`, no key | "best-effort, never load-bearing" — observed one 502 in two probes minutes apart |
| RDAP registration lookup | `rdap.org` bootstrap → registry (e.g. `rdap.verisign.com`), CORS `*` both hops, no key | cross-host redirect: **both** hops must send ACAO or a browser-side call dies on hop 2 |
| Real multi-vantage-point propagation grid | Globalping (`globalping.io`), free, keyless, 5,000+ real probes, 150 credits/probe/day | the *only* credible free source of real geographic DNS answers — see "structurally impossible" below for why we can't fake this ourselves |
| DNS cache purge on a public resolver | Cloudflare `/api/v1/purge` (unauthenticated POST), Google (reCAPTCHA-gated), OpenDNS `api.php` | Cloudflare's is fire-and-forget async, no verification built in — we'd add the poll-and-confirm loop ourselves |
| Deep-link to a DNSSEC debugger on failure | dnsviz.net, Verisign DNSSEC Debugger | zero infra, one URL template |

### Needs-paid-data (skip)
| Feature | Why skip |
|---|---|
| Historical/passive DNS archive from a vendor (SecurityTrails, Farsight DNSDB, Validin, Silent Push) | quotas either paid outright or unverifiable/contradictory across sources per `securitytrails-passive-dns.md` |
| DNSlytics reverse-NS/MX/PTR/SPF, hosting history, subdomain lookup beyond the one free keyless `ip2asn` endpoint | credit-metered, 5-20 credits per call |
| WhoisXMLAPI, ViewDNS paid bulk WHOIS/reverse products, DomainTools suite | all commercial, no usable free tier for this shape of query volume |
| MXToolbox's blacklist check specifically | their own docs classify it a paid "Network request" even against a free API key |
| Continuous monitoring w/ SMS/PagerDuty/webhook alert channels at real scale | real per-message cost + infra to run reliably; email-only via existing SMTP-less repo is already a stretch |

### Client-side-JS-only
(genuinely needs the *visitor's* browser, not ours — see `browser-constraints-dns-2026.md`)

| Feature | Why client-only |
|---|---|
| ECS geo-steering explorer via Google's DoH JSON `edns_client_subnet` param | framing is "what does *your* network see" — doing it server-side just relabels our IP's view; Cloudflare doesn't support the param at all, so it's Google-only either way |
| "Check from your browser" resolver-disagreement view (CF+Google+Quad9+DNS4EU wireformat GET) | spends the *visitor's* quota instead of ours — the one real cost-transfer mechanism in the whole feature set |
| Honest "your resolver took Nms" timing | needs `PerformanceResourceTiming` against **our own** `Timing-Allow-Origin`-headered hostname; only the browser sees its own DNS phase |

### Structurally-impossible
(with this stack, today, no amount of Go code fixes it)

| Feature | Why |
|---|---|
| "Which resolver does *this visitor's OS* use" — w/o a delegated beacon subzone | DoH only reveals which resolver the **DoH provider** used, never the visitor's stub. Verified: Cloudflare-DoH and Google-DoH returned *different* `ns` values for the identical query from the identical host. Needs Tier 2's beacon infra (§4); without it, flatly impossible. |
| Timing a third-party resolver's real latency from the browser | no DoH endpoint tested sends `Timing-Allow-Origin`; cross-origin Resource Timing reads `0` unconditionally |
| DNS over QUIC (DoQ) anywhere in this stack | miekg/dns has zero QUIC code (re-grepped, false positives only); the one Go lib that has it (`AdguardTeam/dnsproxy`) drags in quic-go/gonum/opentelemetry/protobuf — disqualified by CLAUDE.md's few-deps ethos on its own |
| Real geographic propagation testing from *our own* infra | one Hetzner box = one vantage point behind one anycast PoP per operator; "22 resolvers in 17 countries" is a many-probe-network product we don't have and can't simulate — must borrow Globalping's real probes or don't claim geographic coverage |
| AXFR against a third party's zone, shipped as a recon feature | not a Go-library limit — RFC 5936 makes refusal the default posture, a successful transfer against a stranger means you found *their* misconfiguration, and it's a "won't build" (legal/abuse), not a "can't build" |

---

## 2. What the repo already gives us for free

Specific files, not a general "we have good patterns" hand-wave:

- **Content negotiation, done once.** `platform/render.go`'s `Respond(c, code, data, pageTmpl, fragTmpl)` + `WantsJSON`/`IsHTMX` already implement CLAUDE.md rule #2. A `dns` domain package returning a plain struct gets HTML + JSON + htmx fragment for zero new code — same mechanism `iptools` and `botcheck` already use.
- **The exact domain-service shape to copy.** `tools/iptools/geoip.go`: `Service` struct, `OpenService`, `Lookup`, and a small `Looker` interface the handler depends on so tests inject a fake. `go-dns-implementation.md` recommends mirroring this verbatim: `dns.Service`, `dns.Result`, a `Resolver` interface. `tools/iptools/handler.go` is the transport-layer template (`Register` + query-param parsing + `platform.Respond`).
- **Mongo lookup history, ready to clone.** `tools/iptools/history.go`: one doc per lookup, TTL index via `platform.EnsureTTLIndex` (90-day self-prune, doubles as newest-first sort, no second index), write happens in a background goroutine off the request path, nil-safe repository when `MONGODB_URI` is empty. `platform/mongo.go`'s `OpenMongo` is already opened once in `main.go` and shared — a DNS history collection is a new repository below the domain layer, not new infrastructure.
- **The third-party-API client pattern.** `tools/iptools/shodan.go`: dedicated `*http.Client` w/ explicit timeout (never `http.DefaultClient`), self-identifying User-Agent so an upstream can contact us instead of silently blocking, nil-receiver = disabled (blank config → no-op, never a broken page), three distinguishable result states (not-checked / checked-and-empty / checked-and-found) so the UI never implies a negative it didn't verify, payload never persisted. This is the template for calling crt.sh, rdap.org, or Globalping — copy it wholesale rather than reinventing, per `abuse-ratelimits-and-ethics.md`'s explicit recommendation.
- **The blocklist + rate-limiter seam, already reserved.** `tools/iptools/blocklist.go` names `Source: "rate-limiter"` as an expected value in the shared `ip_blocklist` Mongo corpus, and `botcheck`'s `ip_blocklisted` rule already reads that corpus. A DNS-tool ban write lands in the same place and every other tool benefits instantly — this is an existing cross-tool contract, not a new concept.
- **In-process cross-tool reuse, already precedented.** `tools/iptools/docs/README.md` states outright that `botcheck` "borrows its server-side IP layer from" `iptools`. Same binary, same process — a `dnstools` tool can call `iptools.Service.Lookup` directly for ASN/geo/proxy labels on every resolved IP and every nameserver host, no new dependency, no HTTP hop.
- **`IPExtractor` is already trustworthy.** `platform/app.go`'s `cfIPExtractor()` (CF-Connecting-IP → XFF → RemoteAddr) is safe to key a rate limiter on *because* DEPLOYMENT §4 establishes Cloudflare as the sole front door — an invariant this doc's §5 asks the owner to reconfirm before any new subdomain or beacon zone touches that assumption.
- **What is *not* already here, confirmed by grep:** no rate limiter, throttle, or semaphore exists anywhere in the repo today (`abuse-ratelimits-and-ethics.md`, re-verified). `platform/app.go` wires only `Recover`, `RequestLogger`, `Gzip`. Any DNS tool that goes public needs this added — it is not a gap specific to DNS, but this would be the first feature to actually need it in anger (iptools' own docs list rate limiting under "Later," unshipped).
- **`botcheck.Evaluate(Signals) Report`** is a pure function already in-repo; usable as a cheap, spoofable-but-free soft gate on expensive DNS features (propagation fan-out, trace) exactly as `abuse-ratelimits-and-ethics.md` suggests.

---

## 3. Placement: page inside `ip.corpberry.com` vs its own subdomain

### Option A — page/tab inside `ip.corpberry.com`

| | |
|---|---|
| **What it looks like** | Fourth sub-nav tab alongside IP lookup / CIDR calc / History (`tools/iptools/templates/nav.html`), same `*echo.Echo`, same template set |
| **Consequences** | Reuses the sub-nav pattern & the existing `Result`/`Looker` shape directly, zero new nginx block, zero new vhost entry. But: IP2Location attribution footer (`.Attribution` flag) is gated per-page already, so no bleed there — however the *mental model* is wrong: iptools answers "what is this IP", DNS lookup answers "what does this name resolve to" — adjacent, not the same tool. Bloats one already-large subdomain's nav & docs (`tools/iptools/docs/README.md` would need a DNS section bolted on, or a second doc under the same package). Binary size is a wash either way — one binary regardless of vhost count. |

### Option B — own subdomain (`dns.corpberry.com`)

| | |
|---|---|
| **What it looks like** | New `tools/dnstools/` package (own `Register`, `templates/`, `docs/`), one map entry in `main.go`'s vhost handler, one `deploy/nginx/` block — exactly ARCHITECTURE §8's "new subdomain = 1 `*echo.Echo` + 1 map entry + 1 nginx block, never new service" |
| **Consequences** | Own identity, own SEO surface, own docs/README the way `botcheck` has its own despite borrowing iptools' IP layer in-process (§2) — proven precedent that shared code ≠ shared subdomain. Cleaner attribution boundary (no IP2Location credit reason to appear on a DNS-only page). Sets up cleanly for Tier 2's beacon zone (§4), which needs its *own* delegated subzone regardless of where the main tool lives — a subdomain project is the natural home for that, a tab inside iptools is not. Cost: one more nginx block, one more Cloudflare DNS record, one more `cfg.VHost` entry — all boilerplate ARCHITECTURE §8 already describes as routine. |

**Lean: Option B, own subdomain — confidence ~65%.**
Rationale: the botcheck precedent (own subdomain, shared server-side IP layer)
is the closest analog in this exact repo and it chose separation; DNS lookup
is a distinct enough mental model to deserve its own landing/docs/SEO surface;
and Tier 2's beacon zone all but requires subdomain-shaped infra anyway, so
starting there avoids a later move. Confidence isn't higher because the
binary-size and engineering-cost arguments are genuinely a wash (one binary,
either way), so this is mostly a taste/positioning call the owner may weigh
differently.

---

## 4. Tiered build proposal

Every tier lists only what's in §1's inventory — nothing hand-waved, nothing
requiring infra not already confirmed to exist or explicitly flagged as new.

### Tier 0 — a weekend, still genuinely useful

**Ship-today-pure-Go only, DoH-443 fallback if UDP/53 egress is blocked.**

- A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + a handful of the modern types (DS/DNSKEY/TLSA/SVCB-HTTPS), TTL, rcode/flags, query timing
- Reverse/PTR w/ auto `in-addr.arpa`/`ip6.arpa`
- NXDOMAIN vs NODATA distinguished via the authority-section SOA
- Single resolver, chosen from a short allowlist (no free-form `@server` — closes the SSRF hole day one)
- Content negotiation for free (`platform.Respond`)
- ASN/geo enrichment of the resolved IPs by calling `iptools.Service.Lookup` in-process
- **Required, not optional, before this goes public:** Echo v5 `middleware.RateLimiterWithConfig` keyed on `c.RealIP()` (~20 lines, `abuse-ratelimits-and-ethics.md`'s own estimate) + a per-request query budget. Nothing in this repo rate-limits anything today (§2); shipping a public DNS-query endpoint without this is the one item the abuse report treats as non-negotiable.

**Costs:** a weekend, one new Go package, zero new infra, zero new
dependencies beyond `miekg/dns` itself (needs adding to CLAUDE.md's pinned
list — see §5). **Buys:** a working, safe, useful single-lookup tool with a
feature set already ahead of `net.Resolver`-based competitors on TTL/flags/RR
coverage alone. **Blocked by:** nothing, except confirming UDP/53 egress
before assuming `+trace` is available even here in embryonic form (it isn't
in Tier 0 regardless — that's Tier 1).

### Tier 1 — the version worth telling people about

**Adds: needs-a-free-public-API items, the rest of ship-today-pure-Go, real abuse controls.**

- `+trace` delegation walk from root (**requires confirmed raw UDP/TCP egress** — the one feature in this tier that dies on the DoH fallback; if egress is blocked, this line moves to "later, revisit if egress changes")
- Multi-resolver comparison / fan-out (our own queries to a small curated resolver set, not their DoH)
- DNSSEC panel: DO bit, AD, inline RRSIG, EDE decode, NSID
- Parent-vs-child NS/glue diff, SOA-serial agreement across a zone's own NS
- CT-log subdomain enumeration (crt.sh) & RDAP registration lookup (rdap.org) — both via the `shodan.go` client pattern, best-effort, never load-bearing
- DNSBL/RBL reputation card on resolved MX/A records, curated list, reusing `tools/iptools/blocklist.go`'s shape
- Mongo-backed lookup history, `tools/iptools/history.go` pattern verbatim — **with the TTL question resolved first, see §5**
- In-process TTL-respecting answer cache + `singleflight` (the single highest-leverage abuse control, per the abuse report)
- Cloudflare free-plan rate-limiting rule (dashboard, zero code) layered on top of Tier 0's in-process limiter
- ECS geo-steering explorer as a client-side-JS-only add-on (Google DoH JSON only) — cheap, zero server cost, genuinely novel per the corpus

**Costs:** the bulk of the DNS domain package (trace walk, DNSSEC primitives,
fan-out concurrency via `errgroup`), 2-3 new best-effort third-party clients
copying an existing pattern, the abuse-control layer. Realistically multiple
weeks, not a weekend. **Buys:** feature parity with or ahead of most of the
free competitor set surveyed (MXToolbox, NsLookup.io, dnschecker.org) on the
differentiators — EDE, NSID, parent/child diff — that almost nothing else in
the category ships. **Blocked by:** the UDP/53 egress test (for `+trace`
specifically), and the abuse-control build-out landing *before* this ships
publicly, not after.

### Tier 2 — only if it earns it

Each line here needs something we don't have today. Said plainly, not implied.

- **Resolver-identity / DNS-leak beacon.** The single most distinctive feature
  in the whole corpus, and the only one requiring genuinely new infrastructure:
  a **delegated DNS subzone** (e.g. `p.corpberry.com. NS ns1.p.corpberry.com.`
  + glue A record) with a small authoritative responder running **outside the
  Cloudflare proxy**, answering inbound UDP/53 directly on the Hetzner box.
  That is a real exception to ARCHITECTURE §2's "Cloudflare is the ONLY thing
  in front" invariant — not a config tweak, an architecture decision (§5).
  Without it, "which resolver does the visitor use" is flatly
  structurally-impossible per §1, no amount of Go fixes that.
- **Full DNSSEC chain-of-trust validation to the root anchor.** Primitives
  exist in miekg (`RRSIG.Verify`, `KSK.ToDS`); the chain walk is unowned
  caller code either way. The one existing library that does this,
  `peterzen/goresolver`, is 11-25 stars, pins an old miekg version, and was
  confirmed firsthand to **panic** (not error) when its configured resolver
  is unreachable — a real robustness bug in a security-relevant path. Hand-roll
  it (more code, more control, more testing burden) or accept that bus factor.
  Either way it's meaningfully more work than Tier 1's DO-bit/AD/EDE surface.
- **Real geographic propagation grid.** Needs Globalping (§1's
  needs-a-free-public-API bucket) — not built from our own infra, because one
  Hetzner box structurally cannot fake multi-vantage-point coverage (§1).
  Doable, but it's an integration with someone else's free service's credit
  economy (150 credits/probe/day), not a Go feature.
- **Zone health audit / letter-grade score** (SOA/glue/NS/DNSSEC/MX/CAA
  checks, à la Zonemaster/MXToolbox/DNS Spy). Technically all ship-today-pure-Go
  primitives, but it's ~30-70 named checks worth of surface, a scoring model,
  and a whole audit UI — a project on its own, not an add-on to Tier 1.
- **Email-auth suite** (SPF/DKIM/DMARC/BIMI/MTA-STS parse + policy-fetch +
  RFC-lint). Same story: doable in pure Go + one HTTPS fetch for MTA-STS
  policy files, but it's a second product's worth of checks bolted onto this one.
- **Continuous monitoring with change diffs.** The Mongo pattern makes
  passive change-detection genuinely cheap (`tools/iptools/history.go`'s shape
  extends almost directly), but *scheduled* re-checks + real alert delivery is
  new operational surface (a scheduler, retry logic, a notification channel
  that isn't email-only) this repo doesn't have today.

---

## 5. Open questions for the owner

Each stated so a cold reader can answer it without more context.

1. ~~**Outbound UDP/53 (and TCP/53) from the Hetzner box — has anyone actually
   tested it?**~~ **ANSWERED 2026-09-16:** tested on the host directly. UDP/53
   to Cloudflare/Google/Quad9, TCP/53, and direct-to-authoritative with RD=0
   all work. No DoH fallback needed; `+trace` is viable. Original question: Every research pass in this corpus tried and failed to reach
   the box. If it's blocked, Tier 1's `+trace` and any query-a-specific-NS
   feature are off the table until that changes; Tier 0 still ships via
   DoH-over-443. Test: `dig @1.1.1.1 example.com`, `dig +tcp @1.1.1.1
   example.com`, `dig @198.41.0.4 . NS` (a root server, RD=0) — run from the
   box itself, before any of Tier 1 is scoped in detail.

2. **Own subdomain (`dns.corpberry.com`) or a tab inside `ip.corpberry.com`?**
   §3 lays out both with a soft lean toward a new subdomain (~65% confidence).
   This also determines whether Tier 2's beacon zone gets a natural home or
   needs its own separate carve-out later.

3. **Is the owner willing to open a beacon subzone outside the Cloudflare
   proxy for Tier 2's resolver-identity feature?** This is the one item in
   the whole proposal that changes the deployment topology described in
   ARCHITECTURE §2 ("Cloudflare is the ONLY thing in front"). It's also a
   (small) new attack surface — an authoritative nameserver answering the
   open internet, even scoped to one zone with no recursion. Worth doing only
   if resolver-identity is a feature the owner actually wants; otherwise skip
   Tier 2's headline item entirely and the rest of Tier 2 stands on its own.

4. **What's the minimum abuse-control bar for a public v1?** Verified: this
   repo has zero rate-limiting code anywhere today. The corpus's stated
   minimum is Cloudflare's free-plan rule (1 rule, 10s window, IP-only) +
   Echo's in-process limiter + a query budget — all in Tier 0 above. Is that
   sufficient for launch, or does the owner want challenge-gating (Turnstile,
   `botcheck.Evaluate` as a soft gate) from day one? The former is ~20 lines;
   the latter adds a third-party JS dependency and UX friction to every visit.

5. **Which resolver(s) does the tool query server-side by default?** Google
   publishes a number (1500 QPS/IP); Cloudflare and Quad9 don't. This also
   changes ANY-button behavior (Cloudflare `NOTIMP`/42B vs Quad9's real
   510B answer) and ECS availability (Google-only). A resolver dropdown that
   silently changes answer *shape* is explicitly flagged as a trap in the
   corpus — pick per-feature, not one global default, or decide it's fine to
   simplify to one.

6. **How sensitive is DNS lookup history, and what's the retention?** A DNS
   history row is domain + requester IP — more sensitive than iptools'
   IP-lookup history (just an IP), because it's closer to a "who looked up
   what domain" registry. `tools/iptools/history.go` uses a 90-day TTL.
   Match it, shorten it, or drop the requester IP from the stored record
   entirely and keep only the queried name? This is a liability question, not
   a technical one.

7. **Ship AXFR / free-form `@server` / subdomain brute-force, or omit them on
   purpose?** DigWebInterface ships all three behind a lookup counter.
   MXToolbox and Zonemaster instead frame zone-transfer exposure as a health
   finding on the user's *own* domain, and CT-log enumeration (already in
   Tier 1) covers the "what subdomains exist" use case with zero packets sent
   to any target. The corpus's explicit recommendation is to omit all three.
   Does the owner want parity with DigWebInterface's power-user feature set
   anyway, accepting the legal-grey AXFR exposure that comes with it?

8. **Add `github.com/miekg/dns` v1.1.73 to CLAUDE.md's pinned-versions list
   now?** It's the only viable library for ~90% of this feature set (§1), but
   upstream is maintenance-only (README states the repo "will at some point
   be archived") and its v2 successor needs Go ≥1.27 (we pin 1.26.x) with its
   own README giving a ~2028 target for a stable v1.0. Pin v1 now and
   revisit at the next dependency review, or wait until the tool is actually
   being built to add the pin?
