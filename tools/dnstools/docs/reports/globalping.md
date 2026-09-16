# Globalping (jsDelivr)

Community-probe measurement network run by **jsDelivr** (Dmitriy Akulov / the CDN people), offering ping, traceroute, mtr, **DNS resolve (dig)** & HTTP from thousands of donated probes. Matters here because it is the only *free, keyless, CORS-open* source of **real multi-vantage-point DNS answers**: the thing that separates a toy "dig from my server" page from a credible propagation / GeoDNS / anycast tool. It is the de-facto free replacement for paid vantage-point networks, and the cheap alternative to RIPE Atlas's credit economy.

- **URL:** https://globalping.io · API root `https://api.globalping.io` · **Category:** distributed real-probe measurement network + REST API + web tool · **Registration:** not required (higher limits if you register) · **Pricing:** free; credits earned by hosting a probe or donating, never sold outright · **API:** public REST, OpenAPI 3.1 at `/v1/spec.yaml`, official **Go client**.
- **Firsthand check (2026-09-15):** `POST https://api.globalping.io/v1/measurements` w/ `type=dns` returned **202 + measurement id, no API key, no account**, headers `x-request-cost: 3`, `x-ratelimit-limit: 250`, `x-ratelimit-remaining: 247`. `GET /v1/probes` returned **5,056 live probes** (2,118,703 B raw, **135,101 B brotli**) w/ `access-control-allow-origin: *`; `OPTIONS /v1/measurements` preflight w/ `Origin: https://ip.corpberry.com` returned 200 + `access-control-allow-headers: Authorization, Content-Type`. A 20-probe worldwide `A` lookup of `corpberry.com` finished in **484 ms** server-side & returned **6 distinct answer sets**. The *website* could not be inspected: `/network-tools/dns` serves an identical 22 KB Ractive.js shell for every tool URL, so curl & WebFetch see no rendered UI; UI claims below are flagged secondhand.

## What it is

Open network of volunteer-hosted **probes** (Docker/Podman container, x86 + ARM) that accept measurement jobs over a WebSocket from a central API. You POST a measurement describing *what* to run & *where*; the API picks matching probes, fans out, collects results, exposes them at a URL for ~7 days. Five test types: `ping`, `traceroute`, `mtr`, `dns`, `http`.

Growth is the headline. The project's own paper (arXiv, Oct 2024) reported **1,102 probes / 339 cities / 82 countries / 437 ASNs**, 300k+ measurements/day, <14 ms avg API response. My live `/v1/probes` pull on **2026-09-15** counted:

| Metric | Observed 2026-09-15 | Paper, Oct 2024 |
|---|---|---|
| Probes online | **5,056** | 1,102 |
| Countries | **120** | 82 |
| Distinct cities | **1,054** | 339 |
| Distinct ASNs | **1,462** | 437 |
| Continent split | EU 2,250 · AS 1,217 · NA 1,169 · SA 219 · OC 136 · AF 65 | n/a |
| Network type | datacenter 3,457 vs **eyeball 1,599** | n/a |

That eyeball/datacenter ratio is the single most useful number for a DNS tool: ~32% of probes sit on residential ISP networks & therefore resolve through **real ISP resolvers**, not 1.1.1.1.

## Registration, access & pricing

Nothing is paywalled. Registration (dash.globalping.io) doubles limits & unlocks credits; OAuth exists but is reserved for official Globalping apps, so third parties use a bearer token from the dashboard.

| | Unauthenticated (per IP) | Authenticated (per user) |
|---|---|---|
| Create measurement | **250 tests/hour** | **500 tests/hour** + credits |
| Probes per measurement | **50** | **500** |
| `GET` a measurement | 2 req/s per measurement | same |
| `GET /v1/probes`, `/v1/limits` | no limit | no limit |

**Credits** (checked 2026-09-15, re-confirmed unchanged on the live page 2026-09-16): 1 credit = 1 test (1 probe × 1 measurement). Earn **150 credits/probe/day** for each probe you host & keep online, or **4,000 credits per $1** donated via GitHub Sponsors, plus a cumulative +5% bonus per $100 donated in the trailing 12 months, capped at 1500%. There is no way to simply buy API access. The OpenAPI *examples* do still show stale 100/250 figures (confirmed at `/v1/spec.yaml` lines ~2387 & 2397: `nonAuthenticatedLimits` example = `limit: 100`, `authenticatedLimits` example = `limit: 250`); the live headers & `/credits` page both agree on 250/500.

## Features, complete inventory

**DNS measurement (the relevant core)**

| Feature | Detail |
|---|---|
| Record lookup from N probes | `type=dns`, one RR type per measurement, `limit` 1..50 (unauth) / 1..500 (auth) |
| Choice of resolver | `measurementOptions.resolver`: IPv4, IPv6 (experimental) or **FQDN**, so you can point every probe at one authoritative NS |
| Probe's own resolver (default) | omit `resolver`; probe uses its DHCP/system resolver, the only way to see what a *real ISP* answers |
| Protocol & port | `protocol: TCP\|UDP` (default UDP), `port` 0..65535 (default 53) |
| IP version | `ipVersion: 4\|6` |
| **Delegation trace** | `trace: true` -> `dig +trace`, returns a `hops[]` array: root NS -> TLD NS -> authoritative, each hop w/ its own `answers[]`, `resolver`, `timings.total` |
| Structured answers | `answers[]` of `{name, type, ttl, class, value}` plus `statusCode` + `statusCodeName` (NOERROR / NXDOMAIN / …) |
| Raw dig output | `rawOutput` string, full dig transcript incl. flags, OPT pseudosection, **NSID**, AUTHORITY section, query time |
| Per-test timing | `timings.total` in ms |
| Probe-side timeout | `timeout` 5..30 s |

**Probe selection**

| Mechanism | Detail |
|---|---|
| Structured location | `continent` (7 codes), `region` (UN M49, 22 names), `country` (ISO-3166-1), `state` (US only), `city`, `asn` (int), `network` (name string) |
| `tags` | `datacenter-network` / `eyeball-network`, cloud region tags (`aws-eu-west-1`, `gcp-us-south1`, `oci`), & `u-<username>` tags identifying a specific donor's probes |
| **`magic`** | one fuzzy string covering all of the above, `+` = AND: `europe+eyeball-network`, `comcast+california`, `AS123`, `US-NY` |
| Per-location `limit` | each location object can carry its own probe count (1..200), mutually exclusive w/ the global `limit` |
| **Reuse a prior measurement's probes** | pass a measurement `id` as `locations` (a string, not an array); same probes, same order, so two record types are directly comparable |
| Live probe inventory | `GET /v1/probes` returns every online probe w/ `{version, location{…}, tags[], resolvers[]}` |

**Other measurement types** (table stakes for this report, one line each): `ping` (ICMP/TCP, packet stats, per-packet RTT/TTL), `traceroute` (ICMP/TCP/UDP), `mtr` (per-hop loss/jitter/stDev), `http` (GET/HEAD/OPTIONS, phase timings DNS/TCP/TLS/firstByte/download, **full TLS certificate** subject/issuer/keyType, own `resolver` option).

**API surface (complete, v1)**

| Endpoint | Method | Notes |
|---|---|---|
| `/v1/measurements` | POST | body: `type`, `target`, `locations`, `limit`, `timeout`, `inProgressUpdates`, `measurementOptions`. Returns 202 + `{id, probesCount}` & a `Location` header |
| `/v1/measurements/{id}` | GET | status + results; ETag / `If-None-Match` supported; public, no auth; retained ~7 days |
| `/v1/probes` | GET | full online probe list, `cache-control: public, max-age=1, stale-while-revalidate=1` |
| `/v1/limits` | GET | `{rateLimit.measurements.create{type,limit,remaining,reset}}`, plus `credits.remaining` when authenticated |
| `/v1/spec.yaml` | GET | OpenAPI 3.1, advertised via `Link: rel="service-desc"` on every response |

Response headers worth wiring into a UI: `X-Request-Cost`, `X-RateLimit-Limit/Consumed/Remaining/Reset`, `X-Credits-Consumed/Remaining`, `Retry-After`, `Deprecation`, `Sunset`. All are in `access-control-expose-headers`, so a browser can read them.

**Clients & integrations** (re-checked against `/integrations` 2026-09-16): web app, **CLI** (apt/dnf/brew/choco/winget), **official Go client** `github.com/jsdelivr/globalping-go`, TypeScript client, Slack app (`/globalping dns … from …`), Discord bot, GitHub bot (comment-triggered tests), **remote MCP server** at `https://mcp.globalping.dev/mcp` (streamable HTTP, SSE fallback, OAuth; unauthenticated GET returns **401** w/ `www-authenticate: Bearer realm="OAuth" … scope="measurements"`), Zapier, **n8n node**, **Helm chart** (deploy probes to a Kubernetes cluster), VS Code extension. Corrects an earlier draft: **GitHub Action, ChatGPT and IFTTT integrations are listed "Coming soon"**, not shipped, so don't count on a GitHub Actions step existing yet. Third-party: Uptime Kuma, Upptime, UptimeFlare, doggo, Checkmate, CraftCMS Cache Igniter. Community libs for Python, Java, .NET/PowerShell, Home Assistant.

**MCP tool list** (from the server's README, since the endpoint 401s unauthenticated so tools were not exercised firsthand): `ping`, `traceroute`, `dns`, `mtr`, `http` (the five measurement types as callable tools), plus `locations` (probe/region filters), `limits`, `getMeasurement`, `compareLocations`, `help`, `authStatus`. Parameter-level schemas per tool are not in the README; still unverified.

**CLI extras worth knowing** (read from `cmd/dns.go` source): `--type`, `--resolver` (or `@1.1.1.1` shorthand), `--port`, `--protocol`, `--trace`, plus shared `--from`, `--limit`, `--latency` (stats only), `--share` (prints a web link), `--json`, `--table`, `--ci`, `--timeout`, `-4/-6`. Session history addressing is the nice bit: `from last`, `from previous`, `from @1`, `from @-2` reuse probes from an earlier command, & `globalping history` lists them.

**Community / network side:** probe adoption (one probe per IP), `/leaderboard` & `/sponsors` pages, hardware probes for $10+/mo sponsors, org listing at 6+ probes, `/network` & `/network-providers` pages.

## Record types & query options supported

**16** RR types, fixed enum, confirmed firsthand by a rejected request (corrects an earlier draft that miscounted this list as 18):

`A · AAAA · ANY · CNAME · DNSKEY · DS · HTTPS · MX · NS · NSEC · PTR · RRSIG · SOA · SRV · SVCB · TXT`

(default `A`). A `CAA` request returns **400** w/ the exact enum echoed back: `"measurementOptions.query.type" must be one of [A, AAAA, ANY, CNAME, DNSKEY, DS, HTTPS, MX, NS, NSEC, PTR, RRSIG, SOA, TXT, SRV, SVCB]"` (re-verified 2026-09-16, matches the spec's `DnsQueryType` enum exactly). I.e. **CAA, NAPTR, TLSA, SSHFP, LOC, CERT are not available**.

Knobs present: resolver (IP or FQDN), protocol TCP/UDP, port, IP version, delegation trace, per-test timeout, raw output always included, TTL always present in structured answers. Knobs **absent**: no DNSSEC `DO` bit / `+dnssec`, no AD-flag verdict, no EDNS Client Subnet, no recursion-desired toggle, no DoH/DoT, no multi-type batching. Observed probe-side dig invocation: `-t A corpberry.com -p 53 -4 +timeout=5 +tries=2 +nofail +nocookie +nosplit +nsid` (no `+dnssec`).

`target` must be a **valid domain name**: `127.0.0.1` is rejected 400, so reverse lookups require hand-building `x.x.x.x.in-addr.arpa` yourself.

## How it works

Server-side & genuinely distributed. Probes hold a persistent **WebSocket** to the API, register IP + node id, are geolocated from MaxMind / IPinfo / Fastly data, & heartbeat. A measurement is validated, enqueued in **Redis** by priority (authenticated users rank higher), fanned out to probes matching the location filter subject to CPU/memory & concurrency caps, w/ failover to another probe in-region if one goes silent. Results land in Redis w/ a TTL, which is why measurements expire in ~7 days. The probe runs a real `dig` binary (I saw BIND `9.16.44`, `9.18.41`, `9.18.49` across three probes), so answers are genuine on-path resolutions, not a re-serve of someone's cache.

**Recursive by default, authoritative on request.** Probes query their configured recursive resolver unless you set `resolver`. `GET /v1/probes` exposes each probe's `resolvers[]`: my sample showed 2,346 probes reporting `["private"]` (an RFC1918 resolver, typically the ISP's CPE), 215 on `["1.1.1.1","8.8.8.8"]`, 192 on `["8.8.8.8","8.8.4.4"]`. When the resolver is private, the API **redacts it** in `rawOutput`: the dig `SERVER:` line reads `x.x.x.x#53(x.x.x.x)`. No caching or dedup of measurements: an identical repeat request costs full price again.

**`+nsid` is on by default**, and that is a quietly excellent detail. The AUTHORITY-adjacent OPT section in `rawOutput` names the actual resolver *instance* that answered: I got `("gpdns-lax")` from a Los Angeles probe, `("nrt01")` from Tokyo, `("lhr19")` from London. Free anycast-PoP identification, no extra request.

## Output & UX

**API output (firsthand).** `POST` -> 202 `{id, probesCount}` in ~30 ms. `GET` -> `{id, type, status, createdAt, updatedAt, target, probesCount, locations, results[]}` where each result is `{probe{continent,region,country,state,city,asn,network,latitude,longitude,tags[],resolvers[]}, result{…}}`. Per-test `status` is one of `in-progress` / `finished` / `failed` / `offline`; a failed test carries an experimental **`failureSource`** of `target` | `resolver` | `internal`. `inProgressUpdates: true` streams partial results (first 5 tests update live). The documented polling contract: re-request 500 ms *after* each response, stop when status is anything but `in-progress`, never exceed 2 req/s.

Structured vs raw is a real trap: **`answers[]` carries the ANSWER section only.** My NXDOMAIN test returned `statusCodeName: "NXDOMAIN"`, `answers: []`, while the SOA in the AUTHORITY section appeared *only* in `rawOutput`. Anything that needs negative-response detail must parse the raw dig text.

**Web UI (secondhand, could not render).** Vendor blog & search results describe a single form at the top of the page: target, location box accepting the magic syntax, `limit`, a cogwheel for advanced settings (port, protocol, record type, resolver), "Run test" button, dig-style result blocks per probe, & **a shareable link per test** (the CLI's `--share` prints the same). Programmatic landing pages exist per tool × location: `/network-tools/dns`, `/network-tools/dns-from-europe`, `/network-tools/dns-from-united-states`, `/network-tools/dns-from-amazoncom`, & the same for ping/traceroute/http, canonical `/network-tools/ping-from-world`. Their `/sitemap/index.xml` currently returns **500** (observed 2026-09-15).

## Monetization, limits & abuse controls

Not monetized. Funded by jsDelivr & donations; credits exist to allocate scarce probe capacity, not to bill. Controls observed or documented: per-IP hourly test budget w/ `X-RateLimit-*` headers & a 429 carrying `rate_limit_exceeded` or `insufficient_credits`; 2 GET/s per measurement; one probe per IP; malware-domain & private-IP blocklists on targets (my `127.0.0.1` target was rejected at validation); Docker resource caps on probes; measurement audit logging. Client guidelines ask non-browser apps to set a descriptive `User-Agent`, request `br`/`gzip`, & use ETags.

## Ideas worth stealing

- **Group by answer set, never report a "% propagated".** My 20-probe world run against one resolver (8.8.8.8) returned **6 distinct A sets**: 9 probes saw `104.21.25.133, 172.67.134.67`, 5 saw `188.114.96.3, 188.114.97.3`, & singletons for `.96.0/.97.0`, `.96.1/.97.1`, `.96.2/.97.2`, `172.64.80.1`. All six are correct: that is Cloudflare GeoDNS doing its job. A naive propagation meter would have screamed "17% propagated". In Go this is one `map[string][]Probe` keyed by `strings.Join(sortedValues, ",")`, rendered as N cards ordered by probe count, w/ a flag only when the *sets disagree on something that should not vary*, e.g. NS or SOA serial. This is the whole feature.
- **Split eyeball vs datacenter as a first-class toggle**, using the `eyeball-network` tag. Datacenter probes mostly resolve via 1.1.1.1/8.8.8.8 & tell you nothing about what a customer's ISP sees; eyeball probes on `private` resolvers do. Firsthand ratio 3,457 : 1,599, so both populations are large enough to sample.
- **Two-phase async maps perfectly onto htmx.** POST returns in ~30 ms, results settle in ~0.5 s for 20 probes. Handler POSTs, renders a fragment w/ `hx-get="/dns/result/{id}" hx-trigger="load delay:500ms" hx-swap="outerHTML"`, & the fragment re-emits the same trigger while `status == in-progress`. Honors their 2 req/s rule by construction, & needs no WebSocket, no JS beyond htmx. Set `inProgressUpdates: true` so the table fills in progressively.
- **Reuse the probe set across record types.** Pass the first measurement's `id` as `locations` for the follow-up A / AAAA / MX / NS / TXT queries. Same probes, same order, so a multi-record page is internally consistent instead of comparing London-for-A against Sydney-for-MX. Cost is still N × probes tests, so pair it w/ a small default probe count.
- **Surface `X-Request-Cost` + `/v1/limits` as a visible budget meter.** "This lookup used 20 of your 250 remaining this hour." Free credibility, & if the calls run server-side it explains why the tool throttles.
- **Three-way failure presentation from `failureSource`.** `target` = the domain's own problem (say so, it is the useful answer), `resolver` = the probe's resolver misbehaved (offer a retry w/ an explicit resolver), `internal` = Globalping's fault (say so, do not blame the user's domain).
- **Keep `rawOutput` behind a `<details>` "raw dig" disclosure.** Costs nothing, & it is the only place the AUTHORITY section, EDNS/OPT block, NSID & the dig flags survive. Power users trust a tool that shows its work.
- **Surface NSID as "answered by".** `gpdns-lax`, `nrt01`, `lhr19` parsed out of the OPT pseudosection turns a flat resolver IP into an identified anycast PoP. Regex over `rawOutput`, ~5 lines of Go, & nobody else in the free tier shows it.
- **One `magic` text input instead of six dropdowns.** Pass the string straight through & let their parser do the work. Caveat worth designing around: matching is genuinely fuzzy, my deliberately-nonsense `{"magic":"atlantis"}` did **not** error, it matched a probe in **Atlantis, South Africa** (AS213481). Echo the resolved probe location back prominently so a silent mis-match is visible.
- **Programmatic landing pages per (record type × location)**, mirroring `/network-tools/dns-from-europe`. One Go handler + a slug table + the existing template gives dozens of indexable pages for a day's work.
- **Session history addressing**, the CLI's `@1` / `last` / `previous`. The iptools Mongo lookup history already stores past queries; adding "re-run against the same probes" is a stored measurement id & one button.

## Gaps & what it does not do

Lookup only, not analysis. **No** DNS health audit (Zonemaster-style delegation/consistency checks), **no** DNSSEC validation verdict or chain walk (you can fetch DNSKEY/DS/RRSIG/NSEC as record types but cannot set the DO bit or get an AD answer), **no** CAA / NAPTR / TLSA / SSHFP, **no** SPF/DKIM/DMARC parsing (TXT returns the string, interpretation is yours), **no** WHOIS/RDAP, **no** reverse-DNS convenience, **no** passive/historical DNS, **no** subdomain enumeration, **no** blocklist or reputation data, **no** monitoring/alerting or scheduling (that is delegated to Zapier/n8n/GitHub Actions/Uptime Kuma), **no** export beyond the JSON API, **no** DoH/DoT testing, **no** EDNS Client Subnet. One RR type per measurement, so an "all records" view is N measurements & N × probes against the hourly budget.

Operational caveats: measurements expire in ~7 days; results are **public to anyone holding the id**, so a shareable link leaks the domain that was looked up (relevant given the IP tool's stored lookup history); no dedup, so repeats cost full price; probe population is volunteer-donated & shifts hour to hour, so probe counts are not reproducible.

## Verified firsthand vs inferred

**Verified by curl, 2026-09-15, spot-checked again 2026-09-16:** keyless POST returning 202 + id; `x-request-cost` / `x-ratelimit-*` header values (live `/v1/limits` re-pulled 2026-09-16 still reads `limit: 250` unauth); `access-control-allow-origin: *` on `/v1/probes`, `/v1/limits`, `/v1/measurements`, & a 200 preflight allowing `Content-Type`; probe count & the country/city/ASN/tag breakdowns (re-pulled 2026-09-16: 5,016 probes, 121 countries, 1,036 cities, 1,466 ASNs, 3,430 datacenter vs 1,586 eyeball, within the hour-to-hour drift the original run already flagged); brotli vs raw payload size; **the 16-type enum** (corrected from a miscounted "18" — re-verified against both `/v1/spec.yaml`'s `DnsQueryType` schema and a live `CAA` request's 400 body, which echoes the same 16-item list) & CAA's 400; the 400 on an IP target; `magic: "atlantis"` matching Atlantis, ZA; NXDOMAIN result shape w/ empty `answers[]`; `trace: true` returning root -> `com.` -> authoritative hops w/ RRSIG & DS records, matching the spec's `FinishedTraceDnsTestResult.hops[]` schema; NSID strings; redacted `SERVER:` line for private resolvers; the 6-distinct-answer-set GeoDNS spread; 484 ms server-side completion for 20 probes; MCP endpoint returning 401 (re-confirmed 2026-09-16, w/ `www-authenticate: Bearer realm="OAuth" scope="measurements"`); the site serving an identical ~22 KB Ractive-based shell for every `/network-tools/*` URL (confirmed `ractive` string present in the shipped `app.js`, & a byte-for-byte diff of `/network-tools/dns-from-world` vs `/network-tools/http-from-world` differs only in the `og:url`/`params` values); `/sitemap/index.xml` returning 500 (still 500 on 2026-09-16); `/credits` page content (server-rendered, readable by curl, all figures below match exactly); the `/integrations` page list (also server-rendered & curl-readable, unlike `/network-tools/*` & `/terms/*`); GitHub API license lookups: `globalping-go` & `globalping-cli` both report `mpl-2.0`, `globalping`/`globalping-probe`/`globalping-mcp-server` all 404 (no LICENSE file GitHub can detect) confirming the OSL-3.0 claim is spec-only, unconfirmed in-repo; the arXiv paper's 1,102/339/82/437/300k-per-day/<14ms figures, re-confirmed by re-fetching the paper.

**Read from primary docs/source, not executed:** the OpenAPI spec's schemas & limit tables; CLI flags & history syntax (read from `cmd/dns.go` in the repo, not run locally); Go client method set (`AwaitMeasurement`, `GetMeasurementRaw`, `Probes`, `Limits`, `CacheExpireSeconds`) from its README; the **MCP tool list** (`ping`, `traceroute`, `dns`, `mtr`, `http`, `locations`, `limits`, `getMeasurement`, `compareLocations`, `help`, `authStatus`) read from the MCP server's README `## Available Tools` table — the endpoint still 401s unauthenticated, so tool schemas/parameters were not exercised.

**Secondhand or inferred:** everything about the **rendered web UI** (form layout, cogwheel advanced settings, shareable-link placement) comes from the vendor blog & search summaries, because browser tooling was off-limits & `/network-tools/*` is client-rendered (re-confirmed: the static HTML is the same shell w/ a `{"params":"..."}` blob, no form markup). The internal architecture (WebSocket probe channel, Redis queue, priority, failover, MaxMind/IPinfo/Fastly geolocation) comes from the project's own arXiv paper & is two years old. The **terms of use** still could not be read: `/terms/terms-of-use` now returns 200 (not a total shell — it's the same site frame w/ a real nav & footer) but the actual policy text loads as "Please wait while the document loads." w/ no fetch URL visible in the static HTML, so acceptable-use & attribution obligations for a public tool built on the API remain **unverified**, & should be confirmed before launch. Credits figures come from the `/credits` page, re-confirmed unchanged 2026-09-16; the paper's "2,000+ tests per $1" is already superseded by the page's 4,000/\$1.

## Open source / reusable

- **`github.com/jsdelivr/globalping-go`** (**MPL-2.0**, confirmed via `GET /repos/jsdelivr/globalping-go/license`), the official Go client. Directly relevant: `NewClient(Config{AuthToken, UserAgent, CacheExpireSeconds, HTTPClient})`, `CreateMeasurement`, `GetMeasurement`, **`AwaitMeasurement`** (polls to final state), `GetMeasurementRaw`, `Probes`, `Limits`, & typed `*HTTPError` / `*MeasurementError` w/ `errors.As`. Its README explicitly asks downstream OSS projects to override `UserAgent` to point at themselves. For a Go+htmx tool this removes essentially all client code; the only judgement call is whether to use `AwaitMeasurement` server-side or drive the polling from htmx.
- **`github.com/jsdelivr/globalping-cli`** (**MPL-2.0**, same GitHub API check, Go/cobra), a working reference implementation. `cmd/dns.go` shows the exact request it builds & is the fastest way to sanity-check option semantics.
- **`github.com/jsdelivr/globalping`**, the API + docs; the OpenAPI `info.license` declares **OSL-3.0**. GitHub's license API returns 404 for `globalping`, `globalping-probe` & `globalping-mcp-server` alike (no detectable root `LICENSE` file), so treat the OSL-3.0 claim as the spec author's stated intent, not a confirmed repo license — check before depending on it for anything beyond calling the public API.
- The **OpenAPI spec itself** (`https://api.globalping.io/v1/spec.yaml`, 2,751 lines) is the best feature reference and is fetchable w/o auth.

## Sources

- [Globalping API OpenAPI 3.1 spec (`/v1/spec.yaml`), fetched 2026-09-15, re-diffed 2026-09-16](https://api.globalping.io/v1/spec.yaml)
- [Globalping API docs (rendered)](https://globalping.io/docs/api.globalping.io)
- [jsdelivr/globalping, main repo & README: measurement types, probe requirements, limits](https://github.com/jsdelivr/globalping)
- [jsdelivr/globalping-go, official Go client](https://github.com/jsdelivr/globalping-go)
- [jsdelivr/globalping-cli `cmd/dns.go`, exact DNS flags & examples](https://raw.githubusercontent.com/jsdelivr/globalping-cli/master/cmd/dns.go)
- [GitHub REST API, repo license lookups for globalping/globalping-go/globalping-cli/globalping-probe/globalping-mcp-server, checked 2026-09-16](https://docs.github.com/rest/licenses/licenses#get-the-license-for-a-repository)
- [Globalping credits page, figures checked 2026-09-15, re-confirmed 2026-09-16](https://globalping.io/credits)
- [Globalping integrations page, full client/integration list, re-checked 2026-09-16 for Helm chart & "Coming soon" items](https://globalping.io/integrations)
- [jsdelivr/globalping-mcp-server README, `## Available Tools` table](https://raw.githubusercontent.com/jsdelivr/globalping-mcp-server/master/README.md)
- [Globalping terms of use, checked 2026-09-16: returns 200 but ships no policy text without JS](https://globalping.io/terms/terms-of-use)
- [arXiv 2411.00124, "Globalping: A Community-Driven, Open-Source Platform for Scalable, Real-Time Network Measurements" (Oct 2024), figures re-confirmed 2026-09-16](https://arxiv.org/html/2411.00124v1)
- [Globalping blog, "How to check DNS propagation worldwide with Globalping"](https://blog.globalping.io/check-dns-propagation-worldwide-with-globalping/)
- [Globalping blog, "Run DNS lookup (dig) with HTTP using the Globalping API"](https://blog.globalping.io/run-dns-lookup-dig-with-http-using-globalping-api/)
- [Globalping CLI product page](https://globalping.io/cli)
