# Robtex, Hurricane Electric BGP toolkit & RIPEstat

Three *network-intelligence* DNS tools, as opposed to the resolver-in-a-box crowd (dnschecker, MXToolbox). None exists to answer "what's the A record". All three answer **"what else is connected to this name/IP/prefix"**: Robtex via passive-DNS & reverse relations, HE via TLD-zone census & per-prefix DNS inventory, RIPEstat via RIR registry data + a live-resolving graph API. Relevant to us because two of the three hand out **free, keyless, CORS-open JSON** that a Go+htmx tool can call server-side today, and because they demonstrate the one class of answer `dig` structurally cannot give.

| | Robtex | HE BGP toolkit | RIPEstat |
|---|---|---|---|
| **URL** | robtex.com · freeapi.robtex.com | bgp.he.net | stat.ripe.net |
| **Category** | passive DNS + reverse-relation graph | zone census + BGP/DNS toolkit | RIR/registry + live DNS data API |
| **Operator** | Robtex, Sweden, commercial, ad-supported | Hurricane Electric (AS6939, free goodwill property) | RIPE NCC (RIR, non-profit) |
| **Registration** | none (free tier) | none | none; register if >1k req/day |
| **Pricing** | free tier + paid via RapidAPI | free, no paid tier | free |
| **API** | yes, JSON/NDJSON, CORS reflected | **no** (HTML only, UA-gated) | yes, JSON, `ACAO: *` |

**Firsthand check (2026-09-15 & 2026-09-16, curl/dig from macOS).** ~50 Robtex free-API calls covering 28 distinct endpoints plus the SSE page feed at `/xes/en/dns-lookup/com/google`; ~12 HE page fetches (`/dns/`, `/ip/`, `/net/`, `/AS`, `/report/dns`, `/report/dns/com`, `/report/tophosts`, `/robots.txt`, plus 404 probes); RIPEstat `dns-chain` (IP & hostname), `reverse-dns`, `reverse-dns-ip`, `reverse-dns-consistency`, `zonemaster`, `dns-blocklists`, `whois` x4, `abuse-contact-finder`, the docs endpoint index, plus CORS & 12-way concurrency probes. Everything marked "firsthand" came back on the wire; Robtex's paid tier, corpus provenance and HE's ingestion pipeline are docs/inference only, flagged in place.

## What they are

**Robtex** is a long-running Swedish "swiss army knife internet tool": a crawled corpus of observed DNS records, queryable forward *and backward*, wrapped in an ad-supported site. The 2026 site is a rebuild (SSE-streamed pages, JSON-LD `Dataset` markup, deeply nested canonical URLs) sitting on the same historical corpus, w/ passive-DNS `time_first` values firsthand reaching back to **2009-07-03** for `google.com` NS records. Current ownership is not published: web search surfaced only a business listing in Tyresö, Sweden, no named operator, so treat "who runs it" as unknown.

**HE BGP toolkit** is Hurricane Electric's free marketing/goodwill property, unchanged in look since ~2010 (markup carries an `rmosher 2010 - 2016` comment). Primarily BGP, but it carries a DNS layer most people miss: HE publishes per-TLD domain/record/glue censuses no ordinary lookup tool has.

**RIPEstat** is RIPE NCC's public data platform: a uniform `?resource=` Data API, **59 endpoint pages** in the docs sidebar spanning registry, routing, geo & DNS. The DNS calls are six and two of them are genuinely unusual, and the whole thing is free, keyless & `Access-Control-Allow-Origin: *`.

## Registration, access & pricing

- **Robtex:** site free, ad-funded (firsthand: `adSlot` frame in the page feed). Free API documented at **10 requests/hour per IP**, HTTP 429 + `{"status":"ratelimited"}` on exceed. Firsthand that limit is **not enforced**: ~50 requests inside ~20 minutes from one IP, every one HTTP 200, zero 429 (2026-09-15/16). Do not plan around either number. Paid access routed through RapidAPI ("unlimited access via Robtex on RapidAPI"); **no tier table or price is published**, so paid capacity & cost are unknown.
- **HE:** entirely free, no account, no key, no published API. Access control is a **User-Agent gate**: firsthand, `GET /AS15169` w/ no UA returns **HTTP 403, 9 bytes ("Forbidden")**; identical request w/ a browser UA returns 200. `robots.txt` behaves the same way, serving **47 sitemaps** (`sitemap.dns1`, `sitemap.as1-3`, `sitemap.net1-40`, two `sitemap.asset*`, `sitemap.routeset*`) only to a UA-bearing request. HE also rejects `HEAD` outright: **405** on `/dns/google.com`.
- **RIPEstat:** free, no key. Docs state "no limit on the amount of requests" but ask you to register above **1,000 requests/day**, and say the system caps **8 concurrent requests per IP**. Requests should carry `sourceapp=<your-id>`. `data_overload_limit=ignore` suppresses the soft large-response guard. RIPEstat Service T&Cs apply. Firsthand, **12 parallel** `reverse-dns-ip` calls all returned 200, so the documented concurrency cap did not bite at 1.5x its stated value.

## Features, complete inventory

### Robtex

**Reverse relations** (the core product; each is a section on the domain page, firsthand from the final SSE `toc` frame):

| Section | Answers |
|---|---|
| `PTR for` | which IPs PTR to this name |
| `NS for` / `Previously NS for` | which domains use, or used to use, this host as a nameserver |
| `MX for` / `Previously MX for` | same, for mail exchangers |
| `Subdomains` | observed children of this name |
| `Same first word` / `Similar names` | names sharing the leftmost label; fuzzy neighbours |
| `Previous names` / `Next names` | lexicographic neighbours in Robtex's sorted name index |

**Resolution & audit sections:** `DNS Trace`, `Delegation Chain`, `Authoritative Response`, `DNSSEC Status`, `Timing`, `Records`, `Analysis`, `Hierarchy`, `Name Server Role`, `Mail Server Role`, `IP Addresses`, `Name Servers`, `Mail Servers`, `DNS History`.

**Calling convention matters.** Firsthand, endpoints that take an IP work in **path form** (`/ip_reputation/8.8.8.8`) and are broken in **query form** (`/ip_reputation?ip=...` 301s into the website URL space, then 404s `Unknown endpoint`). Same for `ip_geolocation`, `ip_to_asn`, `ip_network`, `ip_blocklist_check`, `ip_threat_intel`, `pdns_reverse`. Hostname/domain endpoints take `?hostname=` / `?domain=` and work. The docs list is therefore **not** aspirational the way it first looks, it is a calling-convention trap.

**Endpoints verified firsthand, working & useful:**

| Endpoint | Returns |
|---|---|
| `GET /ipquery/<ip>` | `city, country, as, bgproute, asname, asdesc, whoisdesc, routedesc`, plus `pas[]` = passive-DNS hostnames as `{o: name, t: epoch}` |
| `GET /pdns/forward/<domain>` | **NDJSON**, one record per line: `{rrname, rrdata, rrtype, time_first, time_last, count}` (`/pdns_forward?domain=` returns the same data as one JSON array) |
| `GET /pdns/reverse/<ip>` | same shape, every name ever seen resolving to that IP |
| `GET /asquery/<asn>` | `nets[] = [{n: prefix, inbgp: 0\|1}]` |
| `GET /lookup_dns?hostname=` | live `records{NS,MX,A,AAAA,...}` **plus** `history[] = {rrdata, rrtype, active, first_seen, last_seen, observations}`, dates as `YYYY-MM-DD` |
| `GET /domain_shared_ns?hostname=` | co-hosted domains grouped per nameserver |
| `GET /ip_reputation/<ip>` | **the sleeper.** `reputation{listed_count, clean_count, checked_count, listed_on[{rbl, reason[]}]}` over **110-111 DNSBLs**, plus AS `risk_categories` & a `security_ranking` percentile. Firsthand on `45.148.10.80`: 12/111 listed w/ per-RBL prose reasons (Spamhaus SBL/DROP, UCEPROTECT L2/L3, DroneBL, SpamRats, Mailspike, …) |
| `GET /ip_threat_intel/<ip>` | same core + `threat_intel{}` keyed by feed (e.g. `hageziips`), `sources_checked/listed/unlisted/timedout` |
| `GET /domain_rdap?domain=` | parsed RDAP: EPP `status[]`, `rdapServer`, `available`, `tld` |
| `GET /parse_hostname` · `/registered_domain` · `/is_subdomain` · `/tld_info` | PSL work: `tld`, `etld`, `registered_domain`, `subdomain`, `labels[]`, `depth`; `tld_info` adds `classification` + 1,037 sub-suffixes for `com` |
| `GET /dns_a\|aaaa\|mx\|ns\|txt\|cname\|soa\|ptr?hostname=` | single-type live lookup, `{records: [...]}` |
| `GET /lookup_mac?mac=` · `/check_email?email=` · `/ping` | OUI vendor; SMTP probe (`valid, catchAll, mxHost, smtpCode, tls, durationMs`); backend health |

**Verified firsthand as stubs or broken** (they answer 200 but carry no data, so do not design around them): `/ip_to_asn`, `/ip_network`, `/ip_blocklist_check` return only `{status, ip}`; `/domain_reputation` returns `{"domain_info":{}}`; `/domain_ranking` returns all-null (`majestic, tranco, cloudflare_radar, umbrella, crux`); `/domain_blocklist_check` returns null blocklists; `/reverse_lookup_ns?hostname=ns1.google.com` returns `estimated_total: 0` while `/domain_shared_ns` on the same nameserver returns hundreds; `/dns_differential` **500s**.

Docs advertise **59 tools** total, incl. `/pdns_reverse_historic`, historic reverse-lookup variants, `/lookup_as_whois` (RADB), `/as_info`, `/as_prefixes`, `/domain_shared_ip`, `/domain_shared_mx`, **12 Bitcoin/Lightning endpoints**, and note an MCP server, a Claude Code plugin, a ChatGPT GPT and a Slack integration (all four confirmed present in the docs text, none exercised).

### Hurricane Electric

**Per-object pages & tabs** (tab ids read firsthand from markup):

| Page | Tabs |
|---|---|
| `/dns/<domain>` | **DNS**, Certs, Website Info, IP Info, Whois, RDAP |
| `/ip/<ip>` | IP Info (Announced By: Origin AS / Announcement / Description), Whois, RDAP, **DNS**, Certs |
| `/net/<prefix>` | netinfo, whois, rdap, **dnsrecords**, routes, irr, visibility, traceroute, graph, Certs |
| `/AS<n>` | IPv4/IPv6 route propagation graphs, prefixes, peers |

The `/net/<prefix>` **dnsrecords** tab is the distinctive one: a single table, **IP | PTR | A**, enumerating *every address in the prefix* w/ its PTR and every hostname whose A record points at it. Firsthand on `8.8.8.0/24` it listed dozens of unrelated parked & abuse domains per address. That is a shared-hosting census at /24 granularity, and no resolver can produce it.

**Toolkit-wide tools** (firsthand, from the home page & sidebar): BGP Prefix Report · BGP Peer Report · Super Traceroute · Super Looking Glass · Cert Search · Exchange Report · Bogon Routes · World Report · Multi Origin Routes · **DNS Report** · **Top Host Report** · RPKI & ASPA Report · Internet Statistics · Looking Glass (`lg.he.net`) · Network Tools App (`networktools.he.net`) · Going Native (PDF) · Contribute Data · Credits. IPv6 Certification is a **separate property** at `ipv6.he.net/certification/` (200 firsthand) and is not linked from the toolkit; there is no IPv6 progress report on `bgp.he.net` (`/ipv6-progress-report` and `/report/ipv6-progress` both **404**).

**DNS Report** (`/report/dns`, firsthand): **1,595 TLDs** (counted from the per-TLD links), filterable All / Generic / CC / IDN / Inactive / TLD Stats, columns TLD · Description · Up · v4 Glue · v4 NS · v6 Glue · v6 NS. The `.com` report firsthand on 2026-09-16 returned **166,522,192 domains · 146,700,247 A records · 1,566,109 A glue · 30,138,911 AAAA**, stamped "Updated: 15 Sep 2026 04:24 PST", plus Nameserver Status, an **A Record Breakdown** by Range / Prefix / Count, and sample A & AAAA records. The day before it read 166,467,809 / 146,657,307 / 1,567,602 / 30,124,073 / 32,489 AAAA glue, stamped "14 Sep 2026 04:30 PST", so **the census refreshes daily around 04:30 PST** (two consecutive stamps observed). Producing those numbers requires ingesting the full `.com` zone, so HE is running a zone-file pipeline (CZDS or equivalent); **the pipeline is inferred, only the outputs are firsthand**.

**Top Host Report** (`/report/tophosts`, firsthand): top 100 DNS/hosting providers by domain count, three columns Rank · Host · Count. domaincontrol.com **98,051,331** · cloudflare.com **78,832,683** · googledomains.com **40,271,395** · afternic.com 22,121,284 · registrar-servers.com 21,176,857 · hichina.com 20,268,944 · dns-parking.com 14,506,318 · cdns.cn 11,937,898 · wixdns.net · nsone.net. These figures were byte-identical across 2026-09-15 and 2026-09-16, so this report refreshes **less often than the TLD census**.

### RIPEstat

**DNS data calls** (`https://stat.ripe.net/data/<call>/data.json?resource=<r>&sourceapp=<id>`):

| Call | Input | Returns (all firsthand) |
|---|---|---|
| `dns-chain` | hostname **or** IP | `forward_nodes` (name -> targets), `reverse_nodes` (IP -> names), `authoritative_nameservers`, `nameservers` (resolvers used). On a hostname it walks the whole CNAME chain: `www.ripe.net` -> `...edgekey.net` -> `...akamaiedge.net` -> 4 IPs, then PTRs each |
| `reverse-dns-ip` | IP | `{result: ["dns.google"], error: ""}`, ~3 ms. `version: 0.1` |
| `reverse-dns` | prefix/range/IP | `delegations[]` = rDNS objects from the RIR DB, each a **list of `{key, value}` pairs**, not an object: `domain`, `descr`, `admin-c/tech-c/zone-c`, `created`, `last-modified`, `source`, repeated `nserver`, **`ds-rdata`**, `mnt-by`. Multi-valued attributes repeat the key, so parse as pairs |
| `reverse-dns-consistency` | ASN or prefix | per-prefix map of every expected `in-addr.arpa` zone w/ `found: true\|false` + a `complete` rollup, split `ipv4`/`ipv6`. `version: 0.3` |
| `zonemaster` | domain | raw **JSON-RPC 2.0 passthrough** (`{jsonrpc, result, id}`) to Zonemaster; `result[]` is a run history w/ `overall_result: ok\|warning\|error\|critical`, `undelegated`, `created_at`, `id`. `data_call_status: development` |
| `dns-blocklists` | single IP | **resolved: this is the call the docs call "DNS Blocklists"** (`blocklist` and `dns-blocklist` both 404 `unsupported`). Returns a `blocklists{}` catalogue of **10 lists** (Abusix AuthBL/Black/Dblack/Exploit, Spamhaus PBL et al.) w/ operator + URL, and `data{}` of per-list results. **Async**: first call returns `pending_results: true` w/ empty `data`, subsequent calls show per-list `status: "init"`; it did not settle inside three polls, so budget for it or skip it |

**Adjacent calls useful to a DNS tool:** `whois` (RIR/RDAP records; firsthand uncached `process_time` **350-1,328 ms** across four resources, fast enough to sit inline), `abuse-contact-finder` (`abuse_contacts[]`, `authoritative_rir`), `searchcomplete` (typeahead), `whats-my-ip`, `network-info`, `prefix-overview`, `as-overview`, `announced-prefixes`, `related-prefixes`, `routing-status`, `rpki-validation`, `historical-whois`, `looking-glass`, `visibility`, `atlas-probes`, `maxmind-geo-lite`, `rir-geo`.

## Record types & query options supported

| | RR types | Resolver choice | Trace / delegation | DNSSEC | TTL | Raw |
|---|---|---|---|---|---|---|
| Robtex | A, AAAA, NS, MX, TXT, CNAME, SOA, PTR (+ historic) | no | `DNS Trace` + `Delegation Chain` sections | `DNSSEC Status` section | not shown | no |
| HE | SOA (Primary NS, Mailbox, Serial, Refresh, Retry, Expire, Minimum TTL), NS, MX w/ pref, TXT (all), A, AAAA | no | no | no dedicated view; `/dnssec/<domain>` 404s firsthand | no | no |
| RIPEstat | A/AAAA/CNAME chain (via `dns-chain`), PTR, rDNS delegation + `ds-rdata` | no, fixed to RIPE NCC resolvers | `zonemaster` covers delegation tests | `ds-rdata` in `reverse-dns`; Zonemaster runs DNSSEC checks | no | no |

None of the three lets you choose a resolver, force TCP, set EDNS/ECS, or see raw wire output. That is squarely the gap a `dig`-shaped tool fills, and worth noting before copying any of them.

## How it works

**RIPEstat `dns-chain` resolves live, and says so.** Firsthand it returns the resolver IPs it used: `193.0.19.101`, `193.0.19.102` and their v6 equivalents, all RIPE NCC. Two identical calls 1 s apart: first `cached: false, process_time: 160`, second `cached: true, process_time: 8`, w/ `query_time` rounded to the minute both times, so the cache key looks like **(resource, minute)** w/ roughly 60 s TTL (inferred from two observations, not from docs). The clever part is the **closure**: given `8.8.8.8` it does PTR -> `dns.google`, then re-resolves that name forward and returns all four resulting addresses in `forward_nodes` while `reverse_nodes` maps each back. That is forward-confirmed reverse DNS, computed automatically, returned as two adjacency lists, i.e. literally a graph.

**Robtex streams its pages over Server-Sent Events.** Firsthand, `GET https://robtex.com/xes/en/dns-lookup/com/google` returns `content-type: text/event-stream`, `cache-control: private, max-age=3, immutable`, and a sequence of `id:`/`data:` frames each carrying one JSON patch keyed by page region: `title`, `h1`, `breadcrumbs`, `description`, `toc`, `content`, `headldjs.0/1/2/100` (JSON-LD chunks), `parts`, `canonical`, `adSlot`. Interleaved are **progress counters**: `loadedp`, `loadedf`, `loadedx`, `loadedq`, `apiQ`, `loopCnt`, then `prelDone`, `timedOut`, `allDone`. Regions are re-emitted as they fill, e.g. `toc` arrives twice, short then complete. The page is assembled from a stream of keyed HTML fragments w/ a live progress signal, which is exactly the problem a DNS aggregator has (some records answer in 5 ms, some zones time out at 5 s) solved without a SPA. Cost note: that one stream was **8.3 MB**.

Canonical URLs are **deeply nested & reverse-hierarchical**, but not the way a quick look suggests. Domains: `/en/dns-lookup/com/google` (firsthand, 200). IPs are *not* split per octet, they are nested under their AS and prefix: `/en/ip-lookup/8/8/8/8` **301s to** `/en/as-numbers/AS15169/prefixes/8.8.8.0-24/ip-numbers/8.8.8.8`. Legacy `?dns=google.com` **301s** (not 302) onto the canonical domain form, and `www.` 301s to the apex.

**HE is server-rendered and static.** Every tab on `/dns/<domain>` carries `data-load-mode="static"`, and the DNS records are in the initial HTML; the Certs tab is the only one whose *content* is fetched client-side, showing a "Searching certificates..." placeholder in the served markup. Data comes from HE's own zone ingestion & BGP feeds, not from resolving on your behalf, which is why it can show *reverse* facts a resolver cannot.

## Output & UX

- **Robtex:** progressive section-by-section fill, dark-mode CSS variables, a table-of-contents nav generated per page, emoji section markers (🔍 DNS Trace, 📋 Delegation Chain, ✅ Authoritative Response, 🔒 DNSSEC Status, ⏱️ Timing, 📄 Records), and cross-tool "xlink" cards linking sideways into its other reports. Every page is a clean shareable URL. JSON-LD `Dataset` + `WebApplication` markup on each result page. Ads present.
- **HE:** dense sortable tables, tab strip per object, zero async except certs, every object type reachable at a predictable path. Ugly and instant.
- **RIPEstat:** API-first. Uniform envelope on every call: `messages[]`, `see_also[]`, `version`, `data_call_name`, **`data_call_status`** (`supported` / `development` / `unsupported`), `cached`, `query_id`, `process_time`, `server_id`, `build_version`, `status`, `status_code`, `time`, `data`. Bad resources return **400 w/ a `messages` entry naming the accepted resource types**; unknown calls return **404 w/ a `messages` entry pointing at the docs URL**. Both are genuinely good API-error patterns.

## Monetization, limits & abuse controls

Robtex: ads + an unpriced RapidAPI tier; documented 10 req/hr/IP free, unenforced across ~50 requests firsthand; Cloudflare in front (`cf-ray`, `server: cloudflare`, apex A records in AS13335), `cache-control: public, max-age=60` on API responses, `access-control-allow-origin` reflecting the caller's `Origin`. HE: no monetization, no key, defended only by the UA gate, the 405-on-HEAD and by being HTML-only; no rate limit observed across ~12 page fetches. RIPEstat: no monetization; soft 1k/day registration ask, documented 8 concurrent/IP (not enforced at 12), `sourceapp` attribution, `data_overload_limit` guard, public T&Cs.

## Ideas worth stealing

- **Do the FCrDNS closure and show it as a verdict.** RIPEstat's `dns-chain` mechanic in ~20 lines of Go: PTR the IP, forward-resolve each returned name, check the original IP is in the answer set. Render "PTR `dns.google` -> confirmed (A 8.8.8.8 ✓)" or "PTR claims `mail.example.com` -> **not confirmed**". Mail operators care, `dig` won't tell you, and it composes perfectly w/ the existing iptools reverse lookup.
- **Stream the result page over SSE, not one blocking request.** Robtex's exact pattern. Handler kicks off N concurrent resolutions in goroutines, writes `text/event-stream`, emits one frame per RR type as it lands, plus a progress counter frame. htmx has `hx-ext="sse"` w/ `sse-swap` on named events, so each RR-type card swaps in on its own event, no Alpine, no SPA. Best fit for our stack in the whole report: a `dig ANY`-style page where TXT arrives instantly and a dead NS takes 5 s currently forces a choice between a slow page and a JS shell. Keep frames small, Robtex's own stream hit 8.3 MB.
- **Robtex `/ip_reputation/<ip>` is a free 110-DNSBL check w/ reasons.** iptools already ships Spamhaus + IPsum; this one call returns `listed_count / checked_count` and a `listed_on[]` carrying the operator's own prose reason & delisting URL per RBL. Keyless, unmetered in practice, and strictly richer than what we have. Cache in Mongo, render as a badge + expandable list.
- **Reverse-relation sections as first-class page furniture.** "NS for", "MX for", "PTR for" are the questions users actually have after the first answer. We cannot build the corpus, but we can *proxy the question*: for each NS returned, offer "other domains on this nameserver" via `/domain_shared_ns`, and for each A, "other names on this IP" via `/pdns/reverse/<ip>`. The latter is NDJSON and streams line-by-line, which pairs with the SSE point above.
- **Show record age, not just record value.** Robtex's `history[]` gives `first_seen`, `last_seen`, `active`, `observations` per rrdata. "This A record has been stable since 2009-07-03 (17 observations)" vs "first seen 3 days ago" is the highest-signal, lowest-effort enrichment available, and it is free & keyless.
- **Nest canonical URLs so intermediate levels are real pages.** `/dns-lookup/com/google` makes `/dns-lookup/com` a page; Robtex goes further and nests IPs under AS and prefix. Accept a flat legacy form and 301 to the canonical one. Cheap in Echo v5 routing, gives clean shareable results and a tidy sitemap.
- **Per-prefix DNS inventory as a differentiator.** HE's IP | PTR | A table is the killer view. We already have CIDR math in iptools. For a /28 or /29, resolving PTR for every address concurrently is trivially cheap and produces a table nothing else on the small-tool web offers. Cap it hard (say /24 max) and stream it.
- **`data_call_status` on your own responses, and named resource types in your 400s.** RIPEstat labels each endpoint `supported` / `development` / `unsupported` inside the payload, and a bad input gets told exactly which resource types are accepted. Free honesty for a hobby tool shipping half-finished checks.
- **Pick one calling convention and hold it.** Robtex's split between path-form IP endpoints and query-form hostname endpoints silently 301s callers into a 404 that reads like "this feature doesn't exist". An hour of probing to discover. Don't do that to anyone.
- **Delegation-chain table: Zone | Nameservers | Glue.** Both Robtex and HE surface glue separately from NS. Glue-vs-NS mismatch is a real, common misconfiguration and the three-column table explains it without prose. For the checks themselves, don't hand-roll 30 of them: proxy RIPEstat's `zonemaster` call or run the upstream engine.

## Gaps & what they do not do

No resolver selection, no `@ns` authoritative query, no TCP/EDNS/ECS knobs, no raw wire output, no TTL display anywhere. No propagation-across-global-resolvers view (that is dnschecker's niche, absent from all three). No email-specific audit (SPF/DKIM/DMARC parsing): HE dumps TXT verbatim, nobody interprets it. Robtex has no public DNSSEC chain validation beyond a status label; HE has no DNSSEC view at all (`/dnssec/<domain>` firsthand **404**). HE has no API, no JSON, no CORS, rejects HEAD, and UA-gates plain clients, so it cannot be a dependency, only an inspiration. RIPEstat's DNS coverage is six calls deep, resolver-fixed, and one of them (`dns-blocklists`) is async and did not settle while I watched. Robtex's free tier is a documented 10 req/hr that is currently unenforced, which is worse than a real limit: you cannot size against it, and a chunk of its advertised surface (`domain_reputation`, `domain_ranking`, `domain_blocklist_check`, `ip_to_asn`, `ip_network`, `ip_blocklist_check`, `dns_differential`) returns empty, null or 500.

## Verified firsthand vs inferred

**Verified:** every Robtex response shape listed above, incl. the 110-111-RBL `ip_reputation` payload and the stub/broken set; the path-vs-query calling-convention split & its 301 -> 404; the reflected CORS headers & `max-age=60`; the SSE content-type, frame keys, progress counters, re-emitted `toc` & 8.3 MB size; the canonical domain URL, the AS/prefix-nested IP URL and the 301 from `?dns=`; the Robtex DNS-page section list (read from its own `toc`); HE's 403-without-UA, 405-on-HEAD, 47 sitemaps, tool list, `/dns/`, `/ip/`, `/net/` tab sets, the all-static `data-load-mode` w/ client-side certs, the `/net/8.8.8.0/24` IP|PTR|A table, the 1,595-TLD count, the `.com` figures on two consecutive days & the daily ~04:30 PST refresh, the Top Host counts & their day-over-day stability, the `/dnssec/` and IPv6-report 404s; every RIPEstat response shown, incl. the resolver IPs, the cache flip, the FCrDNS closure, the CNAME-chain walk, the `dns-blocklists` name & async behaviour, the `{key,value}` shape of `reverse-dns`, the JSON-RPC shape of `zonemaster`, `whois` at 350-1,328 ms, 12-way concurrency, and the 400/404 envelopes.

**Inferred or docs-only:** Robtex's RapidAPI pricing & quotas (nothing published); Robtex's ownership & current operator (unresolved, only a Swedish business listing found); Robtex's corpus size, crawl cadence & how passive DNS is collected; the ~20 docs-listed Robtex endpoints not probed (Bitcoin/Lightning, historic reverse-lookup, AS-whois families) and the MCP/Claude-Code/ChatGPT/Slack integrations, which are named in the docs but were not exercised; that HE ingests zone files via CZDS (only outputs & cadence are observed); RIPEstat's 60 s cache TTL (two observations, not documented).

## Open source / reusable

RIPEstat's Data API is the only one directly reusable as a dependency: free, keyless, `ACAO: *`, documented, stable envelope, operated by an RIR rather than a startup, and it names its accepted resource types when you get a call wrong. **Zonemaster**, the engine behind RIPEstat's `zonemaster` call, is open source under a **2-clause BSD licence**, written in Perl (Engine, LDNS binding, CLI, Backend; the GUI is JS), developed jointly by **AFNIC** and **IIS**, the `.fr` and `.se` registries, and is self-hostable. That is the realistic path to a serious DNS-health audit without writing the checks. Robtex's free API is usable and, in practice, unmetered, but it is a documented 10 req/hr with no published paid pricing, so treat it as "enrich on demand, behind a button, cache in Mongo", exactly the pattern iptools already uses for Shodan InternetDB. HE is reference only: closed, HTML, UA-gated, and scraping it would be both fragile and rude.

## Sources

- [RIPEstat Data API documentation, data-call index & usage limits](https://stat.ripe.net/docs/data-api/ripestat-data-api)
- [RIPEstat `dns-chain` data call reference](https://stat.ripe.net/docs/data-api/api-endpoints/dns-chain)
- [RIPEstat `dns-blocklists` data call reference](https://stat.ripe.net/docs/data-api/api-endpoints/dns-blocklists/)
- [RIPEstat Service Terms and Conditions](https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions/)
- [Robtex free API documentation, 59 tools & the 10 req/hr limit](https://robtex.com/en/api)
- [Robtex free API base endpoint](https://freeapi.robtex.com/)
- [Hurricane Electric BGP toolkit home, full tool list](https://bgp.he.net/)
- [HE DNS Report, all 1,595 TLDs w/ glue & nameserver columns](https://bgp.he.net/report/dns)
- [HE `.com` TLD census, domain/A/AAAA/glue counts & update stamp](https://bgp.he.net/report/dns/com)
- [HE Top Host Report, top 100 DNS providers by domain count](https://bgp.he.net/report/tophosts)
- [HE per-prefix DNS inventory, IP | PTR | A](https://bgp.he.net/net/8.8.8.0/24)
- [HE IPv6 Certification, separate property from the toolkit](https://ipv6.he.net/certification/)
- [Zonemaster, open-source DNS delegation & zone health checker, 2-clause BSD](https://github.com/zonemaster/zonemaster)
- [htmx SSE extension, `sse-swap` named-event swapping](https://htmx.org/extensions/sse/)
- [RFC 8499, DNS Terminology (glue, delegation, authoritative vs recursive)](https://www.rfc-editor.org/rfc/rfc8499.html)
