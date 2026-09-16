# Abuse, rate limits & legal footing for a public DNS tool

What breaks, who complains, and who we answer to if `dns.corpberry.com` lets strangers fire DNS queries from one Hetzner box. Headline: **classic amplification is the wrong threat model** (we can't spoof, we aren't an open resolver), but three real risks replace it: **request fan-out** (one HTTP GET -> N outbound queries), **attribution laundering** (the target's logs show our IP, the abuse report reaches Hetzner), and **upstream ToS** (Cloudflare names "security scanning use-cases or proxied traffic" as the exact shape it rate-limits). Informs two decisions: which features ship at all (AXFR, arbitrary `@server`, propagation fan-out, subdomain enum), & what abuse machinery has to exist on day one.

- **Scope:** amplification/reflection · request fan-out · resolver ToS & QPS (Google/Cloudflare/Quad9) · AXFR legal footing · scraping vs APIs · caching & per-IP limiting as controls · what shipped tools actually enforce · what we already have in-repo · **Date of every quoted limit:** 2026-09-15.
- **Firsthand check:** ~30 probes from a macOS host w/ working `dig` & open UDP/53. Measured response-vs-query sizes on 1.1.1.1; compared `ANY` handling across 1.1.1.1 / 8.8.8.8 / 9.9.9.9; called Google & Cloudflare DoH JSON w/ an `Origin` header; probed Quad9 :5053 & :443; pulled `robots.txt` from 5 tool sites; read `x-api-quota` off HackerTarget; parsed DigWebInterface's live form & fair-use text; hit Turnstile `siteverify` w/ no creds; `dig`'d our own zone. **Deliberately not run:** any AXFR against a third party (house rule) & any quota exhaustion test. AXFR claims below are RFC + docs, never observed. **Fact-check pass (2026-09-16):** re-pulled `robots.txt` for mxtoolbox.com & dnsdumpster.com and re-checked HackerTarget/DNSChecker/DNSDumpster headers, all matched; re-fetched Google/Cloudflare DoH JSON CORS headers (still `access-control-allow-origin: *`); fetched RFC 5358/5936 text directly to check the two AXFR quotes word-for-word (accurate); fetched Cloudflare's rate-limiting-rules, Turnstile plans, and 1.1.1.1 network-operators pages directly (corrected the Turnstile solve-volume figure, confirmed the plan table); fetched Echo's rate-limiter docs directly (the >16k-identifier line is documented prose, not inference); fetched Hetzner's own Terms & Conditions (found, but it doesn't cover scanning specifically).

## The mechanics

**A lookup tool is a stub client, not a resolver.** Amplification/reflection needs two things we won't have: a **UDP listener answering strangers** & a **spoofed source address**. [RFC 5358 / BCP 140](https://www.rfc-editor.org/rfc/rfc5358.txt) is aimed at open recursors ("nameservers SHOULD NOT offer recursive service to external networks"); a Go process making outbound queries isn't one. The amplification numbers are still worth knowing because they bound **our own inbound bandwidth** & they become live the moment anyone proposes the beacon/authoritative-zone feature (see `browser-constraints-dns-2026.md` option D).

Response sizes **observed** on `@1.1.1.1`; query sizes **computed** from the wire format (12B header + QNAME + 4 + 11B OPT RR):

| Query (`+dnssec +bufsize=4096`) | query B (computed) | response B (observed) | ratio |
|---|---|---|---|
| `google.com TXT` | 39 | **1187** | ~30x |
| `org DNSKEY` | 32 | **895** | ~28x |
| `. NS` | 28 | **525** | ~19x |
| `cloudflare.com DNSKEY` | 43 | **313** | ~7x |
| `example.com A` | 40 | **179** | ~4.5x |

**`ANY` is resolver-dependent, & that decides whether an "ANY" button is a liability.** Observed, same query `isc.org ANY`, no EDNS tuning: **1.1.1.1 -> `NOTIMP`, 42 B** (Cloudflare simply refuses the qtype); **8.8.8.8 -> `NOERROR`, SOA + RRSIG only** ([RFC 8482](https://www.rfc-editor.org/rfc/rfc8482.html)-style minimal answer); **9.9.9.9 -> `NOERROR`, 510 B** of real records. So an ANY feature pointed at Quad9 is ~14x; pointed at Cloudflare it is ~1x & useless. Pick the upstream per feature, don't offer a resolver dropdown that silently changes the answer's *shape*.

**The real multiplier is request count, not bytes.** Every attractive feature turns one cheap HTTP GET into many outbound queries:

| Feature | Queries per click | Aimed at |
|---|---|---|
| Single `name`/`type` | 1 | one resolver |
| "All common types" (A/AAAA/MX/NS/TXT/SOA/CAA/DMARC/DKIM…) | ~10-15 | one resolver |
| Propagation grid (whatsmydns ships 22 resolvers, per `whatsmydns.md`) | ~22 per type | 22 networks |
| Delegation trace (`+trace`) | ~5-10 | root -> TLD -> **the target's own NS** |
| Per-NS diff / SOA-serial compare | 1 per NS, 2-13 typical | **the target's own NS** |
| Subdomain brute force (if ever) | hundreds+, all NXDOMAIN | **the target's own NS** |

The bottom three rows are the dangerous ones: they bypass caching by design & land on the victim's authoritative servers. A subdomain brute force is indistinguishable on the wire from a **pseudo-random subdomain / DNS water-torture attack**, whose whole trick is generating names that can't be cached so every query reaches the origin ([Akamai glossary](https://www.akamai.com/glossary/what-are-pseudo-random-subdomain-attacks)). Cloudflare says this out loud on its own operator page: *"High rates of failed responses (like `SERVFAIL`) against the same domain may trigger rate limiting to protect upstream nameservers."*

**Attribution laundering is the practical abuse.** A recon-minded visitor gets our IP in the target's query logs & our AS in their SIEM. The abuse report goes to **Hetzner**, not to us. This is the identical failure mode that shelved the live port scanner (see `iptools-port-scanner-shodan` memory); DNS is far milder (no TCP connects to arbitrary ports, tiny packets), but the reporting path is the same. Hetzner's [Terms & Conditions](https://www.hetzner.com/legal/terms-and-conditions/) (retrieved) prohibit "(d)DOS attacks" & "compromis[ing] the integrity and availability of the networks, servers and data of third parties," but say nothing explicit about outbound scanning or nullroute speed; the "Hetzner nullroutes fast on outbound-scan reports" characterisation itself is still community/secondhand & is flagged as such below.

**A resolver field is an SSRF hole.** `@server` accepting a free-form IP means a visitor can aim our box at `127.0.0.1:53`, `10.0.0.0/8`, `169.254.0.0/16` or the Mongo host's network & read the response. Any resolver input needs a **deny-list of RFC1918 / loopback / link-local / CGNAT / IPv6 ULA**, or better, an **allowlist** of named public resolvers.

**ECS leaks the visitor sideways.** Server-side proxying is privacy-positive by default: the authoritative sees *our* Hetzner IP, not the visitor's. That flips if we forward EDNS Client Subnet. Observed on `dns.google/resolve`: `edns_client_subnet=0.0.0.0/0` = explicit opt-out & works; `edns_client_subnet=203.0.113.0/24` (TEST-NET-3) came back **`Status: 5` REFUSED** w/ the echo mangled to `203.0.113.0/0`, i.e. Google validates the prefix. Do not plumb the visitor's real prefix into ECS.

**Upstream terms & limits (all checked 2026-09-15):**

| Upstream | Published limit | Governing terms | Teeth |
|---|---|---|---|
| **Google Public DNS** | *"Your per-IP address QPS rate is less than 1500 QPS"* = no request needed; above that, file a rate-limit-increase request. Throttling keyed to IPv4 addr or **IPv6 /64** | Google's general terms; *"free service with no SLA"* | throttling |
| **Cloudflare 1.1.1.1** | No public QPS number. Operator page: typical apps *"should not encounter any rate limiting"*; rare limiting for **"security scanning use-cases or proxied traffic"**; advice is to **spread queries across multiple source IPs** | [Cloudflare Website & Online Services ToU](https://www.cloudflare.com/website-terms/) §7: *"You may not use the Websites or Online Services in any manner that could damage, disable, overburden, disrupt or impair any Cloudflare servers or APIs"* | throttling |
| **Quad9** | Nothing published. Privacy policy is silent on volume, frequency & programmatic access | separate **anomalous-conditions** policy: on a suspected event they collect *"query labels, source addresses, arrival times, responses"* & archive it permanently once root-caused | logging, unspecified |
| **HackerTarget** | `x-api-quota: 50` / `x-api-count: 3` / `x-api-boost: 0` observed live; 2 req/s; per-**endpoint** quotas | free tier ToS | 429 |

Two asymmetries matter. (1) Google is the only one w/ a **number** you can design against; Cloudflare & Quad9 give you a vibe. (2) Cloudflare's "proxied traffic" phrasing describes precisely what a public lookup tool is, so *our* per-IP hygiene is the thing standing between us & their limiter. Quad9 :5053 JSON timed out from this host, matching `dns-apis-and-pricing.md`; that's network-local, not a verdict on the service.

**AXFR: legal-grey, technically dead, still shipped.** [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936.txt) makes refusal the default posture: *"A general-purpose implementation SHOULD NOT have a default policy for AXFR requests to be 'open to all'"* & *"A DNS implementation SHOULD provide means to restrict AXFR sessions to specific clients."* So a successful AXFR against a stranger means you found a **misconfiguration**, which is exactly why unsolicited transfers read as unauthorized access under computer-misuse statutes in some jurisdictions, & why every pentest write-up on it assumes an engagement letter. Practically it also doesn't work: `subdomain-enumeration-and-ct.md` treats AXFR as refused-in-practice & Certificate Transparency as the replacement that sends **zero packets to the target**. Yet the type is still in the UI everywhere: DigWebInterface ships `AXFR` in both its short & full type selectors (**observed** in its live `<select>`), NsLookup.io lists AXFR/IXFR in its 52-type API enum, & HackerTarget runs a dedicated `/zonetransfer/?q=` endpoint that attempts AXFR against **every** NS. MXToolbox & Zonemaster take the defensible framing: they test *your own* zone for "Open Zone Transfer" as a **health finding**, not as a recon tool.

**Scraping other tools vs using their APIs.** MXToolbox's `robots.txt` (observed) explicitly `Disallow: /api/v*`, `/pro/`, `/public/checkout/` & blocks AI-training bots by name. DNSDumpster disallows `/quick/`, `/htmld/`, `/dl/`. Neither is a licence question so much as a stated intent. The harder constraint is structural: HackerTarget's quota is keyed to **source IP**, so proxying every visitor's lookup through one Hetzner box burns a single shared 20-50/day allowance & 429s almost immediately (`dnsdumpster-hackertarget.md`). Scraping HTML is worse than the API in every dimension: `whatsmydns.net/robots.txt` & `viewdns.info/robots.txt` both returned **HTTP 403 w/ a Cloudflare JS challenge** to plain curl (observed; `cType: 'managed'` & `'interactive'` respectively), so scraping them means solving challenges, which is the line between "unusual client" and "deliberate evasion".

## What the popular tools actually do about it

| Tool | Control | Source |
|---|---|---|
| **DigWebInterface** | reCAPTCHA after **100 lookups / 24h / client**, temp ban on failure | firsthand page text |
| **DNSChecker** | Cloudflare **managed challenge** on everything but `robots.txt`; CSRF token + session binding on the AJAX API; a captcha wired but dormant (`CaptchaEnable = !!0`) | `dnschecker-org.md` |
| **NsLookup.io** | documented per-IP buckets: **30 req/min** lookup/propagation/health, 100/min SSL, **5/min & 20/hour** security scan; `x-ratelimit-limit/remaining/reset` headers; reCAPTCHA v3 on the browser path only; **no CORS** on `/api/v1/*` | `nslookup-io.md` |
| **HackerTarget** | per-IP **per-endpoint** daily quotas + 2 req/s + 429, quota state in response headers | firsthand headers |
| **DNSDumpster** | Turnstile in the CSP, `frame-ancestors 'none'`, `cache-control: private, no-store` on result fragments | `dnsdumpster-hackertarget.md` |
| **Google Admin Toolbox** | reCAPTCHA on cache-flush; **hard-coded domain refusal** (`?domain=google.com` -> *"This domain is not allowed"*) | `google-admin-toolbox-dig.md` |
| **whatsmydns / ViewDNS** | whole site behind a Cloudflare challenge | firsthand 403 |

Two are worth more than a line.

**DigWebInterface's quota is the honest model for a hobby tool.** Verbatim from the page: *"This tool is not intended for automated lookups. Any other usage is in general welcome and free. To prevent abuse a CAPTCHA needs to be solved for every 100 lookups in a 24 hour period. Failing to solve it may result in a temporary ban."* Note the shape: generous free ceiling, **no account**, no API, no key, a challenge only at the boundary, & the policy stated in one sentence on the page rather than buried in a ToS. It's also the only tool in the set that ships `AXFR` + arbitrary `@server` + `+trace` behind nothing but that counter.

**NsLookup.io splits the browser path from the API path, & that's the design insight.** reCAPTCHA v3 mints a token per browser lookup, but their public API accepted a plain curl w/ no token & no key, rate-limited purely by IP w/ `x-ratelimit-*` headers, & sends **no CORS headers**, so nobody can build a browser-only frontend on it. The captcha protects the *human* surface (where a challenge is free to show); the *machine* surface is protected by numbers & by withholding CORS. A tool that speaks HTML + JSON off one handler, like ours must per CLAUDE.md rule #2, needs exactly this split: challenge the HTML path, meter the JSON path.

**Disclaimers barely exist.** Nobody in this set shows an "only query domains you are authorized to" notice. The closest thing to an ethics statement in the whole category is DigWebInterface's one-liner & MXToolbox/Zonemaster framing zone-transfer exposure as *your* misconfiguration rather than *their* recon feature.

## Options for us, w/ trade-offs

Stack context: single Go binary, Echo v5, htmx, no Node, optional Mongo, Hetzner box behind Cloudflare + nginx. Verified in-repo today: **no rate limiter of any kind exists** (`grep` for rate-limit/throttle/semaphore across `*.go` returns nothing); `platform/app.go` wires only `Recover`, `Gzip` & `RequestLogger`. `dig` confirms `corpberry.com` is on `dion/lisa.ns.cloudflare.com` & `ip.corpberry.com` resolves to Cloudflare proxy IPs, so the edge controls below are already available, just unconfigured.

| Option | What it buys | Cost / complexity | Risk |
|---|---|---|---|
| **Cloudflare rate-limiting rule** (free plan) | edge-side throttle before traffic reaches Hetzner | dashboard only, zero code | Free plan = **1 rule**, period fixed at **10 s**, counting characteristic **IP only**. Burns the single rule; CGNAT visitors share a bucket |
| **Echo v5 `middleware.RateLimiterWithConfig`** | per-IP token bucket in-process; `IdentifierExtractor` -> `c.RealIP()` (already resolves `CF-Connecting-IP` per DEPLOYMENT §4), custom `DenyHandler` | ~20 lines in `platform/app.go` | memory store is documented as unsuited above **~16k distinct identifiers**; per-process, resets on deploy |
| **Query budget per HTTP request** | caps fan-out at the source: N outbound queries per page render, hard stop | a counter in the domain service | pure win; needs a UX for "truncated" |
| **Resolver allowlist** (named presets, no free-form IP) | kills the SSRF hole & keeps us off unknown networks | a map + validation | loses "query my own NS", the feature power users want |
| **Answer cache honoring RRset TTL** (in-proc map, or Mongo + `platform.EnsureTTLIndex`) | the single highest-leverage control: repeat lookups cost zero outbound packets | small; TTL floor/ceiling (e.g. 30 s / 1 h) | stale answers on a propagation tool are a *correctness* bug, so exempt propagation & trace from cache |
| **Edge `Cache-Control` on GET results** | Cloudflare absorbs repeats before nginx | one header | same staleness trap |
| **Mongo-backed ban list** writing to the shared `ip_blocklist` corpus w/ `Source: "rate-limiter"` | persistent bans across restarts; botcheck already reads this corpus (`ip_blocklisted` rule) | repository below domain, per rule #5 | `blocklist.go` **already names `"rate-limiter"`** as an expected source, so this is the intended seam, not a new concept |
| **Turnstile on expensive features only** | DigWebInterface's model w/ modern plumbing; `<script>` tag + `POST challenges.cloudflare.com/turnstile/v0/siteverify` (probed: returns `{"error-codes":["missing-input-secret"],"success":false}`) | no Node needed; token single-use, 300 s TTL, ≤2048 chars; server-side verify **mandatory**; free plan is **unlimited solves/verification requests**, capped at 20 widgets & **10 hostnames/widget** ([Cloudflare Turnstile plans](https://developers.cloudflare.com/turnstile/plans/), confirmed — corrects an earlier "~1M solves/mo" secondhand figure that doesn't appear in current Cloudflare docs) | a third-party JS dep on an otherwise dependency-light page; the real free-tier ceiling is **hostnames/widget** (10), not solve volume |
| **`botcheck.Evaluate(Signals) Report`** as a soft gate | reuse our own tool: cheap path for humans, challenge for headless | it's already a pure function in-repo | client-signal based, spoofable; use as a hint, never a hard block |
| **Ship no AXFR, no free-form `@server`, no brute-force enum** | removes the entire legal-grey surface for free | a product decision, zero code | loses parity w/ DigWebInterface; CT covers the enum use case w/ zero packets to the target |
| **`x-ratelimit-*` headers + a stated fair-use line** | NsLookup.io's professionalism at near-zero cost; sets expectations before the ban | trivial | none |
| **Do nothing** | ships fastest | zero | one scripted visitor turns our IP into the thing in someone's abuse report |

**The repo already has the template for a rate-sensitive upstream call: `tools/iptools/shodan.go`.** Worth copying wholesale rather than reinventing. Its load-bearing decisions: a **dedicated `*http.Client` w/ an explicit timeout** (never `http.DefaultClient`, so the timeout can't be mutated by other code); a **self-identifying User-Agent** (`corpberry-iptools/1.0 (+https://ip.corpberry.com)`) so the upstream can attribute & contact us instead of just blocking; **nil-receiver = disabled** (blank env var -> `Lookup` returns `(nil, nil)`, so an upstream we've been cut off from degrades to a missing card, not a broken page); **three distinguishable states** (`nil` = not checked, `Found:false` = checked & empty, `Found:true` = data) so the UI never implies a negative we didn't verify; **best-effort, never blocking the page**; and **live per-request lookups w/ the payload never stored**, which is the compliance posture that made the whole thing defensible. `shodan-internetdb-feasibility.md` also records the self-throttle rationale: docs allowed bursts, but community reports of a 1-hour Cloudflare ban after ~600 rapid requests led to a ~1 req/s design target. Same instinct applies to every DNS upstream, doubly so where the limit is undocumented.

## Hard constraints & failure modes

- **One IP, one reputation.** Everything we send carries the same source address. Cloudflare's own advice to high-volume users is to *"distribute queries across multiple public IPs"*, which a single Hetzner box cannot do. Design for a low ceiling instead.
- **Cloudflare free plan is thinner than it looks:** 1 rate-limiting rule, 10 s counting period, IP-only counting characteristic. Pro gets 2 rules & up to 1 min; NAT-aware counting & richer characteristics are Business+.
- **`c.RealIP()` is only trustworthy because of the deployment invariant.** DEPLOYMENT §4: Cloudflare is the *sole* front door & nginx sets `CF-Connecting-IP`, so a client can't inject it. Any per-IP limiter inherits that assumption; if the origin ever gets a second ingress, the limiter is trivially bypassable.
- **CGNAT & shared egress collapse buckets.** A per-IP limit punishes a whole mobile carrier or office. Keep thresholds generous & prefer challenge over block.
- **Third-party free quotas are per-source-IP**, so any enrichment upstream (HackerTarget et al.) is a **shared** allowance across all our visitors, not per-visitor. Anything metered that way must be cached hard or not shipped.
- **Logging what people look up is a liability, not a feature, unless it's bounded.** Precedent in-repo: `platform/requestlog.go` keeps client IP for **30 d** via a TTL index & never captures Cookie/Authorization; `tools/iptools/history.go` keeps lookups **90 d** w/ the comment *"short enough tool never becomes permanent who-looked-up-what registry."* A DNS history collection stores *domain* + requester IP, which is more sensitive than an IP lookup. Match or beat those TTLs, & consider storing the queried name without the requester IP.
- **Failure modes to handle explicitly:** upstream `429` or silent throttle (fall back to a second resolver, surface "rate limited", never retry-storm); `SERVFAIL` loops against one domain (Cloudflare limits on exactly this, so break the loop ourselves); truncation/TCP fallback; a visitor scripting the JSON path; an abuse report arriving at Hetzner w/ a 24-48h response window.
- **Legal footing, plainly:** no statute governs looking up a DNS record. What binds us is (1) upstream **ToS**, (2) our host's **AUP**, (3) computer-misuse statutes that only realistically bite for AXFR & enumeration aimed at a specific target, (4) data-protection duties for logs tying a visitor IP to a queried domain. Cheapest insurance: a one-line fair-use notice on the page (DigWebInterface's wording is a good model), a reachable abuse contact, a `security.txt`, & not shipping the two features (AXFR, brute-force enum) whose only use case is recon against someone else.

## Verified firsthand vs inferred

**Observed (2026-09-15):** every response size in the amplification table via `dig @1.1.1.1`; `ANY` handling on all three resolvers incl. Cloudflare's `NOTIMP`/42 B & Quad9's 510 B; Google `/resolve` returning `access-control-allow-origin: *` & `cache-control: private, max-age=300`; Cloudflare DoH JSON returning `access-control-allow-origin: *` & `content-type: application/dns-json`; Quad9 wire-format DoH at `:443` answering `200 application/dns-message` while `:5053` JSON timed out from this host; Google's ECS validation (`0.0.0.0/0` accepted, `203.0.113.0/24` -> `Status: 5`); HackerTarget's `x-api-quota: 50` / `x-api-count: 3` / `x-api-boost: 0` & `access-control-allow-origin: *`; `robots.txt` contents for mxtoolbox/dnschecker/dnsdumpster & **403 + Cloudflare JS challenge** for whatsmydns & viewdns; DigWebInterface's full type selector containing `AXFR` & its verbatim CAPTCHA fair-use sentence, plus its `ns`/`useresolver`/`trace`/`nsid`/`norecursive` fields & the Cloudflare/Google/OpenDNS/Quad9/Verisign presets; Turnstile `siteverify` responding `{"error-codes":["missing-input-secret"],…}`; RIPEstat answering w/ `sourceapp=` & `access-control-allow-origin: *`; `corpberry.com` NS on Cloudflare & `ip.corpberry.com` on proxy IPs; a direct authoritative `SOA` query returning `flags: qr aa`; and the absence of any rate-limiting code in this repo.

**Query sizes in the amplification table are computed**, not captured off the wire.

**Docs / primary text, not exercised:** Google's 1500 QPS figure & rate-limit-increase process (re-confirmed against [Google's ISP docs](https://developers.google.com/speed/public-dns/docs/isp)); Cloudflare's operator guidance & ToU §7 (re-confirmed verbatim against [Cloudflare's network-operators page](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/)); Quad9's privacy & anomalous-conditions policies; RFC 5358, 5936, 8482 (AXFR & recursive-service quotes re-checked word-for-word against the RFC text — accurate); Cloudflare rate-limiting plan table (re-confirmed: Free = 1 rule/10 s/IP-only, Pro = 2 rules/≤1 min, Business = 5 rules/≤10 min/NAT-aware, Enterprise = 100 rules/≤65,535 s/full characteristic set, via [Cloudflare's rate-limiting-rules docs](https://developers.cloudflare.com/waf/rate-limiting-rules/)); Echo v5 `RateLimiter*` signatures & the >16k-identifier caveat — this **is** documented in prose (not just inferred from pkg.go.dev): *"The default in-memory implementation is focused on correctness and may not be the best option for a high number of concurrent requests or a large number of distinct identifiers (>16k)"* ([Echo rate-limiter docs](https://echo.labstack.com/middleware/rate-limiter/)); Turnstile token TTL/length; **Turnstile free-plan limits are now primary-sourced, not secondhand** — [Cloudflare's own plans page](https://developers.cloudflare.com/turnstile/plans/) states Free = up to 20 widgets, **10 hostnames/widget**, and **unlimited** challenge/verification requests (no monthly solve cap); this corrects the ~1M-solves/mo figure the previous pass attributed to third-party pricing blogs, which does not appear in current Cloudflare docs and was likely a stale/misread reference to the 2023 Turnstile-GA beta announcement.

**Secondhand & unverified:** Hetzner's AUP stance on outbound scanning — **partially resolved**: [Hetzner's own Terms & Conditions](https://www.hetzner.com/legal/terms-and-conditions/) were retrieved and do prohibit "(d)DOS attacks," spam relaying & "compromis[ing] the integrity and availability of the networks, servers and data of third parties," but contain **no explicit clause on outbound port/network scanning or on nullroute/abuse-response speed** — that specific characterisation remains community-forum-sourced and is downgraded accordingly, not upgraded to verified; MXToolbox's anonymous daily lookup ceiling (third-party review sites estimate ~10-20/day, still no number from MXToolbox itself). **Deliberately not tested:** any AXFR against a third party, and any attempt to trip a quota, captcha or ban.

**Sibling reports cross-referenced rather than re-probed:** `digwebinterface.md`, `dnschecker-org.md`, `nslookup-io.md`, `dnsdumpster-hackertarget.md`, `whatsmydns.md`, `google-admin-toolbox-dig.md`, `subdomain-enumeration-and-ct.md`, `dns-apis-and-pricing.md`, `dns-concepts-and-query-modes.md`, `browser-constraints-dns-2026.md`.

## Sources

- [RFC 5358 / BCP 140 — Preventing Use of Recursive Nameservers in Reflector Attacks](https://www.rfc-editor.org/rfc/rfc5358.txt)
- [RFC 5936 — DNS Zone Transfer Protocol (AXFR)](https://www.rfc-editor.org/rfc/rfc5936.txt)
- [RFC 8482 — Providing Minimal-Sized Responses to DNS Queries with QTYPE=ANY](https://www.rfc-editor.org/rfc/rfc8482.html)
- [Google Public DNS for ISPs — per-IP QPS limits & increase requests](https://developers.google.com/speed/public-dns/docs/isp)
- [Google Public DNS — JSON API for DoH](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Cloudflare 1.1.1.1 — Terms of use](https://developers.cloudflare.com/1.1.1.1/terms-of-use/)
- [Cloudflare 1.1.1.1 — Network operators (rate-limiting guidance)](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/)
- [Cloudflare Website and Online Services Terms of Use](https://www.cloudflare.com/website-terms/)
- [Cloudflare WAF — Rate limiting rules (plan availability)](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [Cloudflare Turnstile — Get started](https://developers.cloudflare.com/turnstile/get-started/)
- [Cloudflare Turnstile — Plans (Free vs Enterprise limits)](https://developers.cloudflare.com/turnstile/plans/)
- [Quad9 — Privacy, data collection and use policy](https://quad9.net/privacy/policy/)
- [Quad9 — Anomalous conditions policy](https://quad9.net/privacy/anomalous-conditions/)
- [Echo v5 middleware — RateLimiter, RateLimiterMemoryStore](https://pkg.go.dev/github.com/labstack/echo/v5/middleware)
- [Echo — Rate Limiter middleware docs (>16k-identifier caveat, config fields)](https://echo.labstack.com/middleware/rate-limiter/)
- [Akamai — Pseudo-random subdomain (PRSD) attacks](https://www.akamai.com/glossary/what-are-pseudo-random-subdomain-attacks)
- [Akamai — NXDOMAIN / DNS water torture](https://www.akamai.com/glossary/what-is-nxdomain-ddos)
- [HackerTarget — IP tools & API quotas](https://hackertarget.com/ip-tools/)
- [HackerTarget — Zone transfer tool](https://hackertarget.com/zone-transfer/)
- [DigWebInterface](https://www.digwebinterface.com/)
- [MXToolbox robots.txt](https://mxtoolbox.com/robots.txt)
- [Hetzner — Terms & Conditions](https://www.hetzner.com/legal/terms-and-conditions/)
- In-repo: `tools/iptools/shodan.go` · `tools/iptools/blocklist.go` · `tools/iptools/history.go` · `platform/requestlog.go` · `platform/app.go` · `docs/DEPLOYMENT.md` §4 · `tools/iptools/docs/reports/shodan-internetdb-feasibility.md`
