# DNSPerf / PerfOps

The link people paste when the argument is "which DNS host should we use". DNSPerf is the free public face of **PerfOps**, a commercial network-analytics platform now under **DigiCert**. It does not look up *your* domain's records: it continuously benchmarks a fixed roster of **authoritative DNS providers, public resolvers & root servers** from a global node fleet, and ranks them by query time, uptime & "quality". That comparative axis is something no record-lookup tool in the seed list touches. Underneath it sits a **documented, CORS-open, partly key-free REST API** that will happily run live DNS queries from 413 servers worldwide, which is far more interesting to a small Go tool than the leaderboard is.

- **URL:** https://www.dnsperf.com/ (platform: https://perfops.net/, API: `https://api.perfops.net`, docs: https://docs.perfops.net/) · **Category:** continuous comparative DNS benchmark + on-demand global test API · **Registration:** none to read dnsperf.com; none observed for a large part of the API · **Pricing:** free tier, then $99/$299/mo + credit packs (checked 2026-09-16) · **API:** OpenAPI 2.0.0, Swagger UI, `Authorization: <token>` header.
- **Firsthand check (2026-09-16):** curled the site & its JS bundles; read the full OpenAPI spec; ran ~25 unauthenticated API calls across two passes (`/analytics/dns/data`, `/analytics/dns/provider|resolver|continents|countries`, `/node`, `/remaining-credits`); ran **live tests**: `POST /run/dns-resolve` for `example.com` A via 8.8.8.8 (one node, LA), 3-node & 5-node runs, `POST /run/dns-perf` for `corpberry.com` from 3 nodes. Cross-checked one result against local `dig +nsid`; independently re-confirmed the 413/184/74 node/city/country counts, the 37/25 provider/resolver counts, the exact rank-formula & methodology strings, the pricing table, the GitHub repo's star/push/license metadata via the GitHub API, and the acquisition dates via the companies' own press releases (Sources). Used the site's **publicly embedded** anonymous token (shipped in the `<body data-options>` of every page) for exactly 2 calls, to map what it unlocks vs anonymous. Nothing behind a login was touched; the paid control panel at `panel.perfops.net` was **not** opened, so everything about paid-tier UI is docs-only.

## What it is

Free comparison site, commercial platform behind it: three ranked leaderboards on one page (**Authoritative DNS providers**, **Public DNS resolvers**, **DNS root servers**), plus per-entity dossier pages and two on-demand tools. Ownership matters. Built & operated by **Prospect One** (a Ukraine-based dev shop; founder Dmitriy Akulov built DNSPerf/CDNPerf then spun the analytics platform out as PerfOps — per Prospect One's own portfolio pages, not a press release); Tiggee LLC (parent of DNS Made Easy & Constellix) announced acquiring the **PerfOps data suite on 2021-12-02**; DigiCert announced acquiring **Tiggee/DNS Made Easy on 2022-06-09**. Both dates are from the companies' own press releases (Sources). Footers read "© 2024 DigiCert PerfOps", the privacy link points at `privacy.digicert.com/...tiggee-privacy-notice`, and two of the 37 ranked providers are named **"DNSMadeEasy by DigiCert"** & **"Constellix by DigiCert"**. The referee owns two of the teams: worth stating if you cite their numbers.

State of the property: **measurement is live & current** (I pulled Cloudflare's mean query time for *today*: 11.63 ms, uptime 0.99935), **editorial is dormant** (newest blog post May 2022, copyright strings 2023/2024, benchmark page still promises premium plans that perfops.net has sold for years). Also not to be confused w/ `dnsperf`, the ISC/Nominum DNS load-generator CLI.

## Registration, access & pricing

Reading dnsperf.com needs no account. PerfOps plans, **checked 2026-09-16** (prices ex-VAT, these drift):

| Plan | Price | Interval | Geo filter | History | Views | API credits | Extras |
|---|---|---|---|---|---|---|---|
| Essential | **free** | per day | continent | 30 days | 1 | n/a | no CC required |
| Analytics Viewer | **$99/mo** | per hour | country / US state | 30 days | 10 | 1,000 | network tools, raw logs |
| Analytics DevOps | **$299/mo** | per minute/second | + city | unlimited | unlimited | 20,000 | 5 alerts, PDF reports |
| Enterprise | contact | per minute/second | + **ASN/ISP** | unlimited | unlimited | custom | RUM + synthetic continuous monitoring |

Add-ons: alerts **$10/mo each**; on-demand **test credit packs 3,000/$50 · 8,000/$120 · 15,000/$200 · 40,000/$500**. Free access offered to open-source projects & non-profits on request. Two access oddities observed: the **DNS Speed Benchmark is capped at 6 runs**, enforced by a `testLimit: 6` counter in client-side JS; and **dnsmap.io now requires the visitor to paste their own PerfOps API key** (stashed in `localStorage["key"]`, sent as `Authorization`, fallback message "Please enter valid API key."). The free anonymous propagation UI is effectively gone, though the underlying endpoint still answered me without a key.

## Features, complete inventory

**Comparative benchmark (the reason the site exists)**

| Feature | Detail |
|---|---|
| Authoritative provider leaderboard | 37 providers, ranked, w/ query time · uptime · quality |
| Public resolver leaderboard | 12 resolvers (Google, 1.1.1.1, Quad9, NextDNS, Control D, Cisco Umbrella, DNSFilter, SafeDNS, Gcore, FlashStart, UltraDNS, DNS4EU) |
| Root-server leaderboard | all 13 roots (`a`..`m`.root-servers.net) as first-class ranked entities |
| **DNSPerf rank** | published formula: **40% performance + 45% uptime + 15% quality**, over last 30 days |
| Metric toggle | Raw Performance · **Resolver Simulation** · Uptime · Quality (simulation is providers-tab only) |
| Location filter | World / 6 continents / 72 countries (US states & cities on paid tiers) |
| Period picker | Last 30 days, or any calendar month back to **2019-04-01** |
| Sortable provider list | `/dns-providers-list/`, sort by rank, name, uptime, quality, query time |
| Mean-latency time series | per provider, per day, splittable by continent |
| Uptime + quality time series | separate chart, y-axis pinned 90–100% |
| World choropleth/map | latency by region (d3 topojson on the leaderboard, Google Maps in the tools) |

**Per-entity dossier pages** (`/dns-provider/<slug>`, `/dns-resolver/<slug>`, `/dns-root-server/<slug>`): headline **Uptime / Query Time / DNSPerf Rank** trio, "Worldwide Uptime" chart w/ Uptime|Quality toggle, Performance chart, description & homepage link, plus an **"Add resolver" comparator** overlaying a public resolver's curve on the authoritative provider's.

**On-demand tools**

| Tool | What it does |
|---|---|
| **DNS Speed Benchmark** (`/dns-speed-benchmark/`) | A-record lookup for your apex from up to **50 nodes**; picks World / continent / one of ~80 countries; returns per-node latency table + map; **shareable `?id=` result URL**; results retained 30 days; 6 runs free |
| **DNS Propagation checker** (dnsmap.io) | resolves your name against **6 named public resolvers** (Google, OpenDNS, Norton, Verisign, Comodo, Level3) in a table **and** 15 worldwide nodes via each node's own local resolver, plotted as map pins; record type + host encoded in the URL hash |
| Network Tests on Demand (paid UI/CLI) | ping, traceroute, MTR, curl, latency from the same fleet, w/ SEO doorway pages (`/ping-from-europe`, `/traceroute-from-world`, `/mtr-from-europe`, …) |

**Reference data, free & keyless** (the quietly valuable part)

| Endpoint | Returns |
|---|---|
| `GET /analytics/dns/provider` | 37 providers: `id`, `name`, `url`, `description`, `logo`, **`nameServers[]`** (98 NS hostnames), `rank`, `dnssec`, `isCloudFlareProxy` |
| `GET /analytics/dns/resolver` | 25 entries = 12 resolvers + 13 roots, each w/ `nameServers[].ip` & `isRootServer` |
| `GET /node` | **413 measurement nodes**: id, city, country (w/ continent + UN sub-region), lat/long |
| `GET /analytics/dns/countries` | 72 countries w/ continent, region, EU flag, geoname id & a per-country **`tests`** counter (sums to **103,180,896**, period undocumented); siblings `/continents`, `/region`, `/state`, `/city` are the other geo dimension tables |

**API surface** (from the OpenAPI spec, Perfops API v2.0.0, base `https://api.perfops.net/`)

| Endpoint | Notes |
|---|---|
| `GET /analytics/dns/data` | the leaderboard engine. Required: `type` (`provider`\|`resolver`), `dateTimeFrom`, `dateTimeTo`, `groupByTime` (`minute`\|`hour`\|`day`\|`month`), `statFunction` (`mean`,`median`,`resolver_simulation`,`quality`,`uptime`). Optional: `providers`, `nodes`, `continents`, `countries`, `states`, `city`, **`asn`**, **`isp`**, `nameServers`, `groupByNameservers`, `groupBase` (continent\|country\|city\|state\|provider\|resolver\|isp\|asn), `shouldGroupByTime`, `skipMissedPoints`, `timezoneOffset` |
| `GET /analytics/dns/raw-logs` | individual measurements, **max 1-hour window per call**, paginated (`pagelimit` max 200), last week only |
| `POST /run/dns-resolve` → `GET /run/dns-resolve/{id}` | real DNS query from real nodes |
| `POST /run/dns-perf` → `GET /run/dns-perf/{id}` | timing-only variant, `output` = milliseconds |
| `POST /run/{ping,traceroute,mtr,latency,curl}` + matching GET | same async pattern for non-DNS probes |
| `GET /node`, `/node/{id}`, `GET /remaining-credits` | node catalogue, credit balance. Parallel `/analytics/cdn/*` & `/analytics/cloud/*` trees mirror all of the above for cdnperf.com & cloudperf.com |

**Paid platform features** (perfops.net copy, not verified by me): private monitoring of your own DNS/HTTP endpoints, RUM + synthetic continuous monitoring, raw logs in UI & API, alerts on availability/performance degradation, scheduled **white-label PDF reports**, ASN/ISP-level slicing.

## Record types & query options supported

`POST /run/dns-resolve` accepts **A, AAAA, CNAME, MX, NAPTR, NS, PTR, SOA, SPF, SRV, TXT** (spec + the dnsmap.io dropdown agree). Notably **absent: CAA, DS, DNSKEY, RRSIG, TLSA, SVCB/HTTPS, ANY**. `SPF` is the deprecated RR type 99, which tells you how old this list is.

| Knob | Behaviour |
|---|---|
| `dnsServer` | any resolver IP you name; `127.0.0.1` means "use the node's own local resolver"; **empty on `/run/dns-perf` = query the target's own authoritative NS**, resolved automatically |
| `location` | documented as a "smart field": continent, region ("eastern europe"), country, US state, or city |
| `nodes` | explicit node-ID list, mutually exclusive w/ `location` |
| `limit` | max nodes per test (site UI uses 50 for benchmark, 15 for propagation) |
| `ipversion` | 4 (default) or 6, `/run/dns-perf` only, "only some nodes support IPv6" |

Knobs that do **not** exist: no DNSSEC/`+dnssec` flag, no `+trace` delegation walk, no TCP toggle, no EDNS/ECS control, no TTL in the output, no raw `dig` text. Output is a bare array of answer strings (`["172.66.147.243","104.20.23.154"]`) or, for MX, the record text (`"0 ."`).

One thing they return that almost nobody else does: **`nsid`**. `/run/dns-resolve` results carry the decoded EDNS **NSID** option (RFC 5001), e.g. `"67 70 64 6e 73 2d 6c 61 78 (\"gpdns-lax\")"`, naming the exact anycast PoP that answered. Corroborated: their LA node got `gpdns-lax`, my own `dig +nsid A example.com @8.8.8.8` from Europe got `gpdns-fra`, identical A records. The hex-plus-quoted-string format is literally `dig`'s, so they shell out to `dig +nsid` on the node and parse stdout.

## How it works

Methodology, verbatim from the homepage: "All DNS providers are tested every minute from 200+ locations globally. All tests are over IPv4 with a 1-second timeout. The public data is updated once per hour, but contact us for real-time data."

**Synthetic**, not RUM, for DNS (PerfOps markets RUM for the CDN side; the DNS leaderboard is node-driven). Fleet = **413 nodes across 184 cities & 74 countries**, cross-verified twice: `/node` returned exactly 413 records, `/network/` says "DNSPerf maintains a network of 413 testing servers". Density is uneven & telling: Tokyo x11, Singapore x11, São Paulo x11, one node for Kathmandu.

What is measured: PerfOps hosts its own test zone at each provider and times queries against **that zone's nameservers**, exposed in `/analytics/dns/provider` (Cloudflare = `BEN.NS.CLOUDFLARE.COM` + `LARA.NS.CLOUDFLARE.COM`, Route53 = four `awsdns` hosts, DNS Made Easy = `ns10..ns15.dnsmadeeasy.com`). The numbers describe *that* zone on *that* provider's anycast network, not yours.

Metrics, from the spec + the monitoring page: **mean/median** = authoritative query time in ms; **uptime** = fraction of tests answered, provider counts as up if any NS answers; **quality** = the per-nameserver view, which "provide[s] insight on name server outages even when there are multiple redundant name servers in place", so a provider can sit at 99.9% uptime while one of its four NS is dead and quality is what catches it; **resolver_simulation** models what a user behind a recursive resolver experiences rather than raw authoritative RTT, exposed as a UI toggle on the providers tab.

Retention per granularity: **minute 1 week (168 h), hour 3 months (2,160 h), day & month 1 year**. The UI period picker nevertheless reaches back to `2019-04-01`, so monthly rollups go ~6.5 years deep.

On-demand tests are a plain **async job + poll**: `POST` returns `201 {"id":"c716lcemu3vink7"}`, then `GET /run/<kind>/{id}` returns `{id, items[], creditsWithdrawn, finished, requested}`, polled every 100 ms until `finished`. Each item carries the node (id, city, country w/ continent & region, lat/long, **`as_number`**), `output`, `timing.query` in ms, and a per-item `finished`, so partial results render as they land. `creditsWithdrawn` = node count.

Infra from headers: dnsperf.com is a **static Netlify** site (`cache-control: public,max-age=600`), the API sits behind **Cloudflare** w/ an `x-perfops-cache` hit/miss header. Front-end = jQuery 3.5 + Bootstrap 3 + c3.js + Ractive + Google Maps off `cdn.perfops.net`.

## Output & UX

**Leaderboard.** Three tabs, each w/ three selects (Location, Period, Type) plus a Filters control, then a ranked table beside charts. No page reload: everything is XHR against `/analytics/dns/data` w/ client-side caching keyed on the param set. Logos from `img.perfops.net/img/provider/<id>.png`. **Benchmark.** Two columns only: **Latency time** & **Location**, the latter rendered `<flag> Country, City (DC<nodeId>)`. Rows colour-coded by hardcoded thresholds `latencyYellowBreak: 40` / `latencyRedBreak: 60` ms, so <40 plain, 40–59 warning, ≥60 (or non-numeric) danger. Sentinels: `-1` = Timeout, `-2` = Error, `"(empty response)"` rewritten to **"Record Not Found"** once the test finishes. A **"Unique test link"** field appears the moment the job id returns (`…/dns-speed-benchmark?id=<id>`, swapped in via `history.pushState`); reloading replays the stored result for 30 days.

**Propagation.** Fixed 6-resolver table w/ green-tick/red-cross SVG per resolver, plus a Google Map of 15 node pins whose tooltips show the answer records or "Timeout". State lives in the URL hash as `#<TYPE>/<hostname>`, restored on load, so the record type is part of the shareable link.

No CSV/JSON export anywhere in the UI: the API is the export. Empty states are thin, a failed analytics call logs to a bunyan browser logger and leaves the table blank.

## Monetization, limits & abuse controls

Gating is server-side per feature and the 403 bodies are unusually legible. Observed anonymously on 2026-09-16:

| Request | Result |
|---|---|
| `groupByTime=day`, ≤31-day window, continent filter, `groupBase=continent` | **200** |
| window older than 31 days | `403 {"code":403,"message":"You are not allowed to get data older than 31 days"}` |
| `groupByTime=hour` | **403** |
| `groupBase=country` | `403 "You are not allowed to filter by country"` |
| `groupByNameservers=1` | `403 "You are not allowed to group by Nameservers"` |
| same calls w/ the site's embedded token | 46-day window **200**, `groupBase=country` **200** |

The tier ladder in the pricing table maps one-to-one onto API error strings, and the public site ships a token roughly equivalent to the $99 read tier.

On-demand tests are **credit-metered**, and this is now verified as real metering, not decoration: I re-ran the check same-day, unauthenticated. `GET /remaining-credits` alone (no test run) returned `10`, then `9`, then `10` again across three calls seconds apart, i.e. the counter is not perfectly stable/atomic at rest (shared bucket or eventually-consistent cache — mechanism unconfirmed). I then ran a 5-node `dns-resolve` job followed by a 3-node job (`creditsWithdrawn:3` in the poll response, confirming 1 credit/node); `remaining-credits` afterward read `2`, i.e. it dropped by ~8 across the two jobs, consistent with 1 credit per node. I never observed a value above 10, so the **ceiling still looks like 10 for an anonymous IP but the refill window remains unconfirmed** — this narrows, but doesn't fully close, the original gap. Exhaustion is handled in the front-end as HTTP **402**, "Free users can run a limited amount of tests per hour. Please try again in 60 minutes or purchase more tests at perfops.net" — this message string is read from client JS, not triggered firsthand (would need actually exhausting the pool to 0). The 6-run benchmark cap is purely a JS counter, presentational rather than a control. There is reCAPTCHA plumbing in `speedBenchmarkHelper.js` but I did not trigger it and cannot say whether it is active. No `robots.txt` (Netlify 404, confirmed via header check), no rate-limit headers on any response I saw.

**CORS is wide open.** `Access-Control-Allow-Origin` reflects whatever `Origin` you send, `Allow-Credentials: true`, preflight allows `authorization` and all methods. A browser tool on any domain can call this API directly.

## Ideas worth stealing

- **Steal the keyless provider catalogue as a static asset.** `/analytics/dns/provider` + `/analytics/dns/resolver` give names, descriptions, homepages, logos & 98 nameserver hostnames as plain JSON, no key. Vendor into `tools/dnstools/assets/providers.json` at build time, match a zone's NS records by **suffix** (`*.ns.cloudflare.com` → Cloudflare, `*.awsdns-*` → Route53, `*.nsone.net` → NS1), and you answer "who runs this domain's DNS?" w/ a logo & a link, offline, from a Go map. Caveat: the listed hosts are PerfOps's own test-zone NS, so suffix matching is the mechanic, not exact-string matching.
- **Async job + poll, rendered progressively.** `POST` → `201 {id}` → poll `GET /{id}` until `finished`, w/ per-item `finished` so rows appear as nodes report. Exact fit for htmx `hx-trigger="load delay:300ms"` on a `/dns/lookup/{id}` fragment that re-polls itself and swaps a growing table, domain layer holding the job struct. No WebSocket needed.
- **The shareable result URL, done their way.** Job id in the query string plus `history.pushState`, reload replays the stored result for 30 days. You already have Mongo + `platform.EnsureTTLIndex`: a `dnslookup_results` collection w/ a 30-day TTL gives permalinks for free and doubles as the "recent lookups" list, same pattern as iptools history.
- **Hardcoded latency colour bands.** `<40 ms` plain, `40–59` amber, `≥60` red. Two integers turn a column of numbers into something readable at a glance, and they are defensible for DNS.
- **Explicit sentinels instead of nulls, and the record type in the URL.** `-1` timeout, `-2` error, `"(empty response)"` → "Record Not Found": modelling "no answer" as a named outcome beats an empty cell for DNS, where NXDOMAIN, NODATA, SERVFAIL & timeout are four different stories. And dnsmap encodes state as `#A/example.com`; for Go+htmx `/lookup/MX/example.com` is better still, bookmarkable, server-renderable, and content-negotiating to JSON for free under your existing `platform.Respond` rule.
- **Ask for NSID and show it.** Costs nothing extra: `github.com/miekg/dns` sets it w/ an `OPT` RR carrying `EDNS0_NSID`. Rendering "answered by `gpdns-fra`" next to a resolver result explains *why* a user in Frankfurt and one in LA see different latencies from the same "8.8.8.8".
- **Uptime vs quality as two separate numbers.** Their best conceptual idea. "Zone resolves" and "every listed NS resolves" are different questions; querying each NS in the delegation individually and reporting both is a small amount of Go and catches the classic one-dead-nameserver case.
- **Link out rather than reproduce, and say how you measure.** Label the NS set, then link to the DNSPerf provider page for the live rank: comparative angle, no benchmark to run. And copy their 30-word "tested every minute from 200+ locations, IPv4, 1-second timeout, updated hourly" block, which removes every methodology question.

## Gaps & what it does not do

Not a lookup tool. You cannot ask it "what are `example.com`'s records" and get a formatted answer: dnsmap gives you raw strings per resolver, and that is it. No WHOIS/RDAP, no DNSSEC validation or chain-of-trust view, no delegation trace, no zone health audit (no SOA/NS consistency checks, no lame-delegation detection), no email-DNS checks (SPF/DKIM/DMARC parsing), no blocklist/RBL, no reverse or passive DNS, no subdomain enumeration, no CT-log tie-in, no cache-purge tools, no monitoring/alerting on the free side. Record coverage stops before CAA, DS/DNSKEY, TLSA & SVCB/HTTPS, and there is no IPv6 option on the resolve endpoint. The benchmark is IPv4-only by the operators' own statement. The roster is a fixed 37 providers, so a smaller host you actually use probably is not on it. And the whole leaderboard measures PerfOps's zones, not yours, which limits how much you should read into a 3 ms gap.

## Verified firsthand vs inferred

**Verified 2026-09-16:** every HTTP status, header & 403 message quoted above; CORS behaviour; the full OpenAPI path & parameter list; the 413-node count (two independent sources); the 37 provider / 12 resolver / 13 root counts & their nameserver lists; that `dnssec` and `isCloudFlareProxy` are present but `false` for all 37, i.e. both look unpopulated; the rank formula (40/45/15) & methodology text, read off the rendered pages; live `/run/dns-resolve` & `/run/dns-perf` behaviour incl. NSID, `as_number`, `creditsWithdrawn` & the `-1`/`-2`/`(empty response)` sentinels; the credit pool actually decrementing by node-count across two live test runs (10→2 after an 8-node combined spend); all pricing as displayed on perfops.net/pricing, cross-checked against the raw pricing-page markup; `testLimit: 6`, `nodesLimitPerTest: 50`, `latencyYellowBreak: 40`, `latencyRedBreak: 60` from `speedBenchmarkHelper.js`; the six fixed resolvers & 15-node world call from `propagation-check.js`; dnsmap.io's BYO-key flow from `components.js`.

**Docs/marketing only, not exercised:** everything about the paid control panel (per-minute intervals, ASN/ISP filters, alerts, PDF reports, private monitoring, raw-logs UI); I did not log in; the 402 exhaustion message and any active reCAPTCHA are read from client JS, not triggered. **Inferred, flagged:** that the 2/3 `(empty response)` results on my `corpberry.com` benchmark were node-side failures rather than something about the target; the `103,180,896` `tests` figure covers an undocumented period, so treat it as "order of 10^8" only. The `rank` integer in `/analytics/dns/provider` takes values 4–83 across 37 providers (confirmed: 37 distinct values in that range, re-pulled 2026-09-16), so it is **not** a 1..N ranking, its meaning is unclear, and the live DNSPerf rank comes from the analytics data instead. The anonymous credit pool's ceiling looks like 10 (never observed higher) and per-node metering is now confirmed live (a combined 8-node test run took it from 10 to 2), but the counter also showed non-monotonic jitter at rest (10→9→10 with no test run between), and the refill window is still unconfirmed. **Now verified, was previously secondhand:** the Prospect One → Tiggee → DigiCert chain and its dates: Tiggee LLC's own press release dates the PerfOps acquisition 2021-12-02, and DigiCert's own announcement dates the Tiggee/DNS Made Easy acquisition 2022-06-09 (Sources); Prospect One's authorship is confirmed on Prospect One's own portfolio pages (`prospectone.io/portfolio/dnsperf`, `/perfops`), which is still the vendor's own claim about its own work, not a third-party confirmation.

## Open source / reusable

- **`github.com/ProspectOne/perfops-cli`**: official CLI, **written in Go**, 295 stars, last pushed 2025-03-06, not archived. Ships a usable API client package (`perfops/client.go`, `perfops/run.go`) w/ `RunService.DNSResolve`, `DNSResolveOutput`, `DNSPerf`, `DNSPerfOutput`, `Ping`, `Traceroute`, `MTR`, `Curl` and the `TestID`/`RunOutput` types already modelled. **Caveat: GitHub reports no detected licence**, so treat it as read-only reference, not code to vendor.
- **`github.com/ProspectOne/dnsperf-media`**: logo kit only, w/ explicit brand rules ("DO use our logo to link to DNSPerf", "DON'T create any modified versions").
- **`docs.perfops.net`** serves the full OpenAPI document via Swagger UI, fetchable as JSON from `swagger-ui-init.js`: the best spec of the whole surface. Not open source: the node fleet, collection pipeline, rank calculation, website.

## Sources

- [DNSPerf home, leaderboards & measurement methodology](https://www.dnsperf.com/)
- [DNSPerf providers list, w/ the published 40/45/15 rank formula](https://www.dnsperf.com/dns-providers-list/)
- [DNSPerf DNS Speed Benchmark tool](https://www.dnsperf.com/dns-speed-benchmark/) · [DNSPerf network page, 413 testing servers by city](https://www.dnsperf.com/network/)
- [PerfOps API docs, Swagger UI over the OpenAPI 2.0.0 spec](https://docs.perfops.net/)
- [PerfOps pricing, plans, credit packs & add-ons](https://perfops.net/pricing) · [PerfOps private monitoring, uptime vs quality definition](https://perfops.net/monitoring)
- [DNSMap, the PerfOps DNS propagation checker](https://dnsmap.io/)
- [ProspectOne/perfops-cli, Go CLI + API client](https://github.com/ProspectOne/perfops-cli) · [ProspectOne/dnsperf-media, logo kit & brand rules](https://github.com/ProspectOne/dnsperf-media)
- [DigiCert PerfOps platform overview (PDF)](https://www.digicert.com/content/dam/digicert/pdfs/perf-ops-overview.pdf)
- [Tiggee LLC press release, acquisition of the PerfOps data suite, 2021-12-02](https://www.newswire.com/news/tiggee-llc-announces-acquisition-of-perfops-data-4848778-21568489) · [DigiCert press release, acquisition of DNS Made Easy/Tiggee/Constellix, 2022-06-09](https://www.prnewswire.com/news-releases/digicert-acquires-dns-made-easy-extending-its-leadership-in-digital-trust-with-enterprise-grade-managed-dns-services-301564617.html)
- [Prospect One's own portfolio pages for DNSPerf & PerfOps](https://prospectone.io/portfolio/dnsperf) (and `/portfolio/perfops`) · [ProspectOne/perfops-cli repo metadata via GitHub API, re-confirmed 2026-09-16 (295 stars, pushed 2025-03-06, no detected license)](https://api.github.com/repos/ProspectOne/perfops-cli)
- [RFC 5001, DNS Name Server Identifier (NSID) option](https://www.rfc-editor.org/rfc/rfc5001) · [RFC 7505, the "null MX" returned as `0 .` in my test](https://www.rfc-editor.org/rfc/rfc7505)
