# DNSlytics

Dutch **DNS/IP intelligence dataset** w/ a search UI bolted on. Service is DNSlytics, operating company is **Webdevmedia** (both ToS documents are written in Webdevmedia's name); address Den Haag, REG. No. 65179900. Matters to a DNS-lookup builder as the **opposite pole**: it does not resolve anything for you on demand. It crawls the whole domain space on a 14-day cycle, stores 10+ yrs of what it saw, & sells *pivots* over that archive (reverse NS/MX/IP/PTR/SPF, hosting history, domain-to-provider mapping). On **2024-01-01 it deliberately killed its live-query tools** (Ping, Traceroute, Email Test, SPF Lookup) to go all-in on the archive. Read it as the passive-DNS layer that sits *next to* a live lookup tool, not as a competitor to one.

- **URL:** https://dnslytics.com (marketing) + https://search.dnslytics.com (app) · **Category:** passive DNS / domain & IP OSINT dataset · **Registration:** free tier usable anonymously, account needed for premium & monitors · **Pricing:** freemium, "from 30 cents a day"; exact tiers unverified (see below) · **API:** yes, two hosts, one keyless endpoint
- **Firsthand check (2026-09-15, re-verified 2026-09-16):** `curl`'d the marketing site & sitemap (all 200, 44 URLs, static on **BunnyCDN**, `last-modified` 2026-06-18); harvested all 20 API doc pages; **hit the free API live** (`freeapi.dnslytics.net/v1/ip2asn/8.8.8.8` -> `{"ip":"8.8.8.8","announced":true,"cidr":"8.8.8.0/24","asn":15169,"shortname":"Google LLC","country":"US"}`, 200 in 0.66s, no key); confirmed **no CORS header**; confirmed premium host rejects bad keys w/ HTTP 400; `dig`'d their own zone; pulled extension install counts from the **Mozilla AMO & Edge add-ons JSON APIs**. **The app host `search.dnslytics.com` 403s both `curl` and WebFetch behind a Cloudflare managed challenge** (`cf-mitigated: challenge`) — so **no result page was seen firsthand**. Everything about rendered UI below is from their own docs/marketing & is flagged as such. web.archive.org was itself returning "Temporarily Offline" during this pass, so the challenged pages could not be read from an archive either.

## What it is

Self-described OSINT platform for "Domain, DNS and IP-related data and tools", audience named as "IT professional, journalist, lawyer". Scale claims off their own homepage: **330M+ active domains, 60M+ mail servers, 7M+ name servers, 1B+ PTR records, 20M+ Google Tags, 20B+ historical events**, 10+ yrs of history. Domain coverage (stated on `/domain-search/`, not the homepage): full daily zone files for gTLDs & nTLDs, **50–80% for ccTLDs** depending on the ccTLD. Note the vintage: that FAQ words it as "**at the beginning of 2024** we had over 330 million active domains", so the headline number is 2½ yrs old & unrefreshed.
Architecturally the product has collapsed over time: every named "Reverse X Tool" is now a **saved query against one of three datasets**, surviving only as an SEO landing page that deep-links into the search app. Their own API page dates the break: v1 is "based on the previous web interface, which was run by DNSlytics **from 2016 until early 2024**".

## Registration, access & pricing

Free tier anonymous & usable. Premium is a **time pass**, not a seat. Premium page offers a "**Month or Year Pass**"; the monitoring page names two of the tiers explicitly, **Year Pass Lite** & **Year Pass**, and lists all three monitor products as "Included in Year Pass Lite / Year Pass" only. **Read that as monitoring being annual-only, not a general premium feature.** Premium page states "**Subscriptions starts at 30 cents a day**" & what you get: **up to 40 monitors, up to 1,000 pageviews/day, up to 2,500 results**, full historical data, full reports, advanced multi-field search, no ads, priority support, discounts for multiple subscriptions. API is **pay-as-you-go credits**, bought separately from website access at the same challenged `/pricing` page, **valid 12 months**, non-refundable, & **any unused balance is withdrawn when the year ends** (API ToS §5.3, §5.5, §7.2).

> **Pricing caveat, re-checked 2026-09-16:** the real price table lives at `search.dnslytics.com/pricing`, behind the Cloudflare challenge; still HTTP 403, still unread, and the Wayback Machine was offline this pass. A third-party aggregator quotes "$29/mo"; do not build on that number. The only figure sourceable to DNSlytics itself is "30 cents a day". Arithmetic, *inferred not sourced*: 30c/day ≈ **$110/yr**, which is a floor an annual pass can hit & a monthly one cannot, so the "starts at" almost certainly describes the Year Pass.

## Features — complete inventory

### Reports (entity dossiers, path-shaped URLs)

URL shapes below are firsthand: every one appears as a literal deep link in the marketing HTML. The *contents* columns are reconstructed from the API docs, which state each endpoint "is based on the … report displayed on the website" & then enumerate its fields. That is a strong secondhand source, not an observation.

| Report | URL shape | Contents (reconstructed from the matching API doc) |
|---|---|---|
| **Domain report** | `/domain/<domain>` | all data for one domain in one page: DNS records, provider, whois, history, Google Tags, ads.txt. Weakest-sourced row here: no API endpoint mirrors it; only the Whois FAQ confirms whois lives inside it |
| **IP report** | `/ip/<ip>` (v4 & v6) | per IPInfo doc: `asinfo` (asn, ip_start, ip_end, subnet, cidr, shortname), geo (`geoinfo`: country, capital, area, population, continent, currency, tldn), **PTR**, domains hosted (count + max 10), MX hosted (max 10), NS hosted (max 10), hosting-history counts, **/24 subnet neighbours** (max 100 IPs), **`blocklist`/live DNSBL section** (absorbed the retired DNSBL & Geo tools) |
| **CIDR / subnet report** | `/cidr/<cidr>` | per SubnetInfo doc: "**about 700K IPv4 subnets**" from RIR allocations + the global routing table; domain counts, routes, whois, RIR. **API is IPv4-only**, but the *report* is not: their own deep links include `/cidr/2a02:2400::/34` |
| **AS/BGP report** | `/bgp/as<n>` | per ASInfo doc, field for field: shortname, country, rir, rirdate, ndomains, **nadultdomains**, nmxrecords, nnsrecords, **nopenproxies**, **nspamhosts**, `rank` (by IPv4 space allocated), `prefixesv4`/`prefixesv6` arrays |
| **TLD report** | `/tld` | **contents unknown.** Link is real & in the nav; no marketing page, no API mirror, page itself challenged. Do not quote a feature list for it |

### Search datasets (the actual engine)

Three indexes, selected w/ `&d=`: **`domains`** (current), **`history`** (10+ yrs, first/last-seen), **`rdns`** (PTR). One query language across all three, max **4 fields per query**.

### Reverse & pivot tools (all now facets of the above)

| Tool | Pivot | Notes |
|---|---|---|
| **Reverse IP** | IP or CIDR -> domains | A/AAAA of domain **and its `www` label**; 25M+ IPs w/ domains, 8B+ historical IP records |
| **Reverse NS** | NS name or NS's IP -> domains | `ns:` and `ns.ip:`; 4B+ historical NS records |
| **Reverse MX** | MX name or MX's IP -> domains | `mx:` and `mx.ip:`; 3B+ historical MX records |
| **Reverse PTR** | IP, CIDR, domain, or `*keyword*` -> PTR records | **premium only**, **IPv4 only** (FAQ: "only IPv4 addresses are supported"), 1B+ current / 2B+ historical, 30d refresh |
| **Reverse SPF** | SPF string, or IP inside an SPF -> domains | **premium only**, 400M+ current / 500M+ historical SPF records, 14d refresh |
| **Reverse Adsense** | `pub-xxxx` -> domains | 3M+ Adsense IDs, 8+ yrs history; from crawled homepage HTML + **ads.txt** (2M+ files, 5+ yrs) |
| **Reverse Analytics** | Google Tag -> domains | 20M+ IDs, 8+ yrs history. Web FAQ lists **7** prefixes: **AW-, DC-, G-, GT-, GTM-, PUB-, UA-**. The API changelog of 2026-01-23 lists only **6** (no `PUB-`), so the API trails the UI by one |

### Domain tools

- **Domain Search** — keyword/wildcard over 330M active + 500M dropped domains, 200M+ keywords; filters TLD, min/max length, active vs dropped, registration date.
- **Domain Typos** — single-character edits (add/remove/swap/change) of a keyword, cross-referenced against registered domains. Filters TLD & length.
- **Hosting History** — A/AAAA/MX/NS/SPF timeline per domain w/ last-seen dates. Premium. 500M+ dropped domains, 8B+ historical IP records, 4B+ historical NS records.
- **SubDomains** — **premium only**; 1B+ active, 1B+ dropped subdomains, 6B+ historical IP records, 5+ yrs history; monthly refresh; queryable by parent domain, IP, or CIDR (v4 & v6). Own timeline: A only from 2018, AAAA added 2019.
- **Whois Lookup** — domain (1,000+ TLDs), IP (8M+ records), ASN (110K+ records) across AFRINIC/APNIC/ARIN/LACNIC/RIPE. **Live-queried, cached 30 days.** Now folded into the reports.

### Monitoring (recurring, 24h cadence, email, 6-month notification history)

All three are gated to **Year Pass Lite / Year Pass** per the monitoring page, & all promise unlimited email notifications.

- **Basic Brand Monitor** — fires on any new domain containing your keyword, all TLDs; falls back to their own detection where a TLD publishes no zone file.
- **Advanced Brand Monitor (BETA)** — rules: starts-with / contains / not-contains / ends-with, + TLD filter, + **typo detection**.
- **DNS Monitor** — fires when a domain's **A, AAAA, MX or NS** record is added, changed or removed. Pitched as hijack & misconfiguration detection.

### Browser extensions

**IP Address and Domain Information** (Chrome/Opera, Edge, Firefox) — full IP/domain/provider dossier for the current tab without leaving it. **IP Domain Flag** (Chrome/Opera, Edge) — country flag in toolbar, tooltip w/ city/region/country, popup w/ provider, **Alexa ranking** & DomainRank; Alexa was retired in 2022, so that copy is stale. **My IP Address** (Chrome/Opera) — your egress IP, provider, geo, whois, **change alerts & IP history**, blacklist check.

Install counts, **measured 2026-09-16** via the stores' own JSON APIs, against the vendor's "over 150,000+ users" claim for the flagship extension: Firefox **9,561 average daily users** (AMO API, last updated 2025-03-03), Edge **17,942 active installs** (Edge add-ons API, last updated 2026-03-24). Chrome could not be measured: the Web Store 302s to a Google consent interstitial, which I did not accept. So ~27.5K is confirmed across two of three stores & the 150K figure rests entirely on an unmeasured Chrome number.

### API — every endpoint, verbatim

**Free host** `https://freeapi.dnslytics.net`, **no key, no account**, exactly one route: `GET /v1/ip2asn/<ip>` -> `ip`, `announced`, `cidr`, `asn`, `shortname`, `country`. IPv4 **&** IPv6.

**Premium host** `https://api.dnslytics.net`, all `?apikey=<key>`:

| v1 endpoint | Credits | Key params |
|---|---|---|
| `/v1/accountinfo` | free | returns `apicredits`, `apilimits`, `apicalls` |
| `/v1/asinfo/<asn>/summary` | 10 | — |
| `/v1/subnetinfo/<cidr>/summary` | 4 | IPv4 subnets only |
| `/v1/ipinfo/<ip or hostname>` | 3 | IPv4 only; hostname resolves to first A |
| `/v1/domainsearch/<keyword>` | 4 | `active`, `tld`, `minlength`, `maxlength`, `fromdate`, `page` (1–40). Keywords 3–15 chars, pipe-separated, `^`/`$` anchors supported |
| `/v1/domaintypos/<domain>` | 5 | `tld`, `fromdate`, `page` (1–4) |
| `/v1/hostinghistory/<domain>` | 4 | returns `ipv4`, `ipv6`, `mx`, `ns`, `spf` arrays w/ last-seen |
| `/v1/reverseip/<ip or hostname>` | 5 | `page` 1–40 |
| `/v1/reversemx/<mxrecord>` | 5 | `page` 1–40 |
| `/v1/reversens/<nsrecord>` | 5 | `page` 1–40 |
| `/v1/reverseadsense/<pub id>` | 6 | `page` 1–40 |
| `/v1/reverseganalytics/<id>` | 6 | `page` 1–40 |
| `/v1/reversehistory/<type>/<id>` | 20 | `type` ∈ `adsense｜ganalytics｜tag｜ip｜mx｜ns` |
| **v2** `/v2/dataset/domains?q=<query>` | 10 | **Beta** since 2026-02-13; same query language as the web UI, `page` 1–100 |

Paging: 2,500 rows/call (v1) or 1,000 (v2), **100,000 rows max** per query either way.

### Retired, and worth knowing about

**Ping, Traceroute, Email Test** — EOL **2024-01-01**, pages still up reading "<tool> Tool is offline". **SPF Lookup** — same EOL date & same wording, but there is **no `/spf-lookup/` page** (verified 404); the notice survives only as an FAQ entry on `/reverse-spf/`. **DNSBL Lookup** (`/dns-blackhole-list/`) & **IP Geo Location** — not killed, absorbed into the IP report, pages read "has been moved". The stated reason each time: "we shift our focus to developing more advanced search solutions." All five surviving legacy pages are in the sitemap but absent from the nav; the nav instead carries an **"All Legacy Tools"** link to `search.dnslytics.com/tools`, which is challenged & unread.

## Record types & query options supported

This is the sharpest limitation and the most important line in this report for the owner.

**Indexed RR types: `A`, `AAAA`, `MX`, `NS`, `PTR`, and `SPF`.** That is the entire list, and it is corroborated three ways: the HostingHistory API doc ("The following records are supported: A, AAAA, MX, NS and SPF"), the Hosting History FAQ ("in 2012 … only A (IPv4) and NS records. In 2014 … AAAA (IPv6), MX, and SPF"), and the field set of their own deep links. **No `CNAME`, no general `TXT`, no `SOA`, `CAA`, `SRV`, `DS`/`DNSKEY`/`RRSIG`, `TLSA`, `HTTPS`/`SVCB`, `NAPTR`, `LOC`.** Pedantic but load-bearing: "SPF" is **not an RR type** any more. RRTYPE 99 was deprecated by **RFC 7208 §3.1** in 2014; what they index is a `TXT` record whose content starts `v=spf1`, so they parse general TXT & keep only the SPF subset. A live tool gets the other TXT records for free. Alongside DNS they index non-DNS web metadata: **Google Tags**, **Adsense pub IDs**, **ads.txt** lines.

**Query knobs (search app):**

Every row below was extracted by `grep`ing the marketing HTML for `search.dnslytics.com` deep links, so each is a query string DNSlytics itself publishes. The fields are therefore real; the list is still **not** the full grammar, because the three `/help/*-dataset` references are challenged.

| Knob | Syntax observed in their own example links |
|---|---|
| dataset | `?d=domains` · `?d=history` · `?d=rdns` |
| bare term | `q=verizon`, `q=ua-7870337`, `q=188.114.96.3`, `q=myip.report` — fieldless free-text is accepted & appears to be type-sniffed |
| domain name | `name:*dnsly*`, `name:dns*`, `name:*dns` (starts/ends/contains via `*`) |
| TLD | `tld:nl`, `tld:com` |
| typos | `typos:dnslytics` — the Domain Typos tool *is* a field |
| length | `length:4` |
| active flag | `active:false` (dropped domains) |
| IP / subnet | `ip:188.114.96.3`, `ip.cidr:"188.114.96.0/24"`, `ip.cidr:1.1.1.0/24` (quotes optional) |
| nameserver | `ns:ns1.google.com`, `ns.ip:"162.159.24.201"` |
| mail server | `mx:route1.mx.cloudflare.net`, `mx.ip:"162.159.205.11"` |
| SPF | `spf:*_spf.google.com*`, `spf:*1.1.1.1*` |
| PTR string | `ptr:*smtp*` w/ `d=rdns` |
| PTR by domain | `domain:bbc.co.uk` w/ `d=rdns` |
| ads.txt | `adstxt:pub-7232066202917795` |
| page HTML tag | `html.tag:pub-7232066202917795` — separates a tag found in the homepage HTML from one found in ads.txt |
| date math | `activedate:>now-30d`, `activedate:>=yesterday` |
| boolean | `AND`, `OR`, `NOT` (`typos:dnslytics and not name:dnslytics`), parentheses; case-insensitive in their own links; **max 4 fields per query** (API doc gives the worked example `name:*dns* AND name:*lytics* AND (tld:nl OR tld:co)` = 4) |

**Resolver-side knobs a DNS tool would have: none.** No choice of resolver, no authoritative-vs-recursive toggle, no delegation trace, no TCP/EDNS/ECS, no DNSSEC flag, no raw dig output, **no TTLs anywhere**. TTL is meaningless in a 14-day-crawl archive, which is exactly the point.

## How it works

**Crawler + zone files, never on-demand.** Their own published cadences:

| Data | Refresh | Since |
|---|---|---|
| Domain DNS records (A/AAAA/MX/NS/SPF) | **every 14 days** | May 2020 (90d Mar 2012, 60d Mar 2014, 30d Aug 2018) |
| New domains from zone files | **daily, "once a day around 01:00 GMT+1"** | Nov 2014 |
| PTR / RDNS | **monthly** ("every 30 days" in the FAQ) | May 2016 (quarterly from Sept 2013) |
| Subdomain IPs | monthly | 2018 (A only; AAAA from 2019) |
| Homepage HTML + ads.txt | every 60 days | Oct 2018 (homepage twice a year from Jan 2016) |
| Whois | **live query, cached 30 days** | — |
| DNSBL (in IP report) | **live query** | — |

Two separate published timelines, not one: the **DNS/web** timeline on `/hosting-history/` runs **Mar 2012 -> Oct 2022**, the **RDNS** timeline on `/reverse-ptr/` runs **Sept 2013 -> June 2021**. Provenance detail worth noting, & stated in their own words: PTR data ran on **Rapid7 Labs Open Data from Sept 2013 until June 2021**, when they swapped in their own crawler ("No changes in the frequency and data collected"). Credited third-party sources: **GeoNames** (CC-BY 3.0), **MaxMind GeoLite2**, **Spamhaus DROP/EDROP**, **UCEPROTECT**, **RIPE NCC RIS** (BGP), plus a catch-all clause on **whois data** deferring to each source's own licence.

**Infrastructure, verified by `dig` & headers 2026-09-15/16:** apex `dnslytics.com` is static HTML on **BunnyCDN**; its A record is a **per-PoP anycast address, not a fixed host** (I got `185.111.111.156` / `server: BunnyCDN-DE1-1332` on one run & `185.111.111.158` / `BunnyCDN-NY1-885` on the next), served w/ a tight CSP whose `form-action` points at the app host. `search.dnslytics.com`, `api.dnslytics.net` & `freeapi.dnslytics.net` all resolve to **`188.114.96.3` / `188.114.97.3`** behind Cloudflare. Their own zone: 2 Cloudflare NS (`pam`/`cody.ns.cloudflare.com`), Proton MX (`mail`/`mailsec.protonmail.ch`), SPF `include:_spf.protonmail.ch ~all` + Google & Proton verification TXTs. Cute detail: **`cody.ns.cloudflare.com` & `188.114.96.3` are the example values in their own API docs & marketing**, i.e. they dogfood their own records as documentation fixtures. `dev.dnslytics.com` appears in search-engine indexes but **no longer resolves**.

## Output & UX

**Honest scope note: I could not load a single result page.** The app 403s automated clients. What follows is what the URL structure & vendor docs establish, nothing more.

- **Everything is a permalink.** Reports are path-shaped (`/domain/x`, `/ip/x`, `/cidr/a.b.c.d/nn`, `/bgp/as15169`, `/tld`); searches are query-shaped (`/search?q=<query>&d=<dataset>`). Every marketing example is a raw link into a pre-filled query: the query string **is** the sharing mechanism.
- **One search box, one syntax, many doors.** Exactly **12** differently-named landing pages (7 reverse + Domain Search, Domain Typos, Hosting History, SubDomains, Whois Lookup) funnel into `/search` w/ a different `q=` prefilled, each carrying its own stat block, FAQ, and "Preview" vs "Premium Only" example pairs. Several FAQs say so outright: "The Reverse NS Tool is now integrated in the new Domain Search interface."
- **Premium gating is shown, not hidden.** Individual examples *and individual statistics* get an inline "Premium Only" badge in the marketing HTML, so a free user sees exactly which door is locked before clicking. (Observed in the marketing markup, not in the app.)
- **Data-collection timelines** published as a dated changelog on the Reverse PTR & Hosting History pages, each entry naming the cadence change. Unusually transparent for a commercial dataset.
- API output shape: `{"status":"succeed","data":{"question":{…},"typeinfo":"<endpoint>","n<thing>":<count>,"<thing>":[…]}}`, i.e. request echoed back as `question`, and every list carrying its **total count separate from the returned page**.
- Error states verified firsthand: malformed IP -> 400 `{"status":"error","data":"No valid IP address."}`; bad/missing key -> 400 `"Invalid API key."`; unknown path -> 404 plain text; unroutable IP -> **200** `{"ip":"192.168.1.1","announced":false}`; non-`GET` (HEAD, OPTIONS, POST) -> **405** w/ `allow: GET`.

## Monetization, limits & abuse controls

- **Free API: 2,500 req/day. Premium API: 20,000/day & 30/min**, worded as "by default" w/ no stated way to raise it. Documented rate-limit responses: HTTP 403/429 `{"status":"error","data":"Forbidden access denied!"}` / `"Too Many Requests"`, HTTP 503 `"Service Unavailable"` for a global limit. **The 2,500/day cap is documented, not tested** — I made ~10 polite calls total & did not probe the ceiling.
- Website tiers gated on **pageviews/day**, **result count**, **monitors**, history depth, ads. Only the *premium* ceilings are published (1,000 / 2,500 / 40); the free-tier numbers are nowhere on the public site.
- Credits priced by expense: `ip2asn` & `accountinfo` free, `ipinfo` 3, `domainsearch`/`hostinghistory`/`subnetinfo` 4, `domaintypos`/`reverseip`/`reversemx`/`reversens` 5, `reverseadsense`/`reverseganalytics` 6, `asinfo` & `dataset/domains` 10, **`reversehistory` 20**. History costs 4–7x current data, which tells you where their cost sits.
- **Cloudflare managed challenge on the entire app host**: the most effective control here, and the reason this report has no UI observations.
- API ToS constraints that bite a reuser: **caching capped at 24 hours** (§2.6); no copying/redistribution/bulk end-user access (§2.5); **forbidden to include the Webdevmedia/DNSlytics name or logo in any presentation of their data** (§2.8), the inverse of the usual attribution requirement, though §2.7 explicitly lets you restyle the data however you like; no use supporting marketing activities (§2.2); credits die w/ the contract year (§7.2); Dutch law (§9.1), fair-use suspension clause (§2.4). Backwards-compat promise: additive changes within a version, breaking changes bump it, **old version supported ≥6 months**.

## Ideas worth stealing

- **One query language, many named front doors.** Their best structural trick: `search?q=ns:x&d=domains` is the only real feature, "Reverse NS Tool" is a landing page prefilling it. Nearly free in Go+htmx: one handler + one parser, then N thin routes (`/reverse-ns/{ns}`, `/reverse-ip/{ip}`) that build a canonical query & redirect. N SEO surfaces, one code path. Fits the CLAUDE.md layering rule exactly: route -> query struct -> one domain service -> `platform.Respond`.
- **Echo the request back as `question`.** Every response carries a `question` object w/ fully-resolved params *including defaults it filled in* (`page:1`, `tld:"all"`, `active:"all"`). Self-documenting, makes logged/cached responses interpretable standalone, costs one struct field. Steal verbatim for the JSON half of content negotiation.
- **Separate total from page.** Every list endpoint returns `n<thing>` (total matched) *beside* the capped array (`ndomains`, `nevents`, `nmxrecords`, …). Turns "here are some results" into "here are 2,500 of N", & tells the caller whether paging is worth the credits before spending them.
- **`freeapi.` vs `api.` as separate hostnames.** Not a key check inside one service, a **different host exposing exactly one route** (verified: everything except `ip2asn` 404s there). Clean blast radius, trivially cacheable, no auth code on the free path.
- **Absence answered as data, not error.** `{"ip":"192.168.1.1","announced":false}` at HTTP 200. Do this for empty RRsets rather than 404ing.
- **`ip2asn` is usable today, for free.** For iptools, a drop-in second opinion on ASN/prefix alongside the IP2Location BINs: one keyless GET, 0.6–0.8s measured, IPv4 & IPv6, returns `cidr` + `asn` + `shortname` + `country`. **But no `Access-Control-Allow-Origin`, so it cannot be called from the browser**: it must go server-side through the Go binary, and ToS §2.6's 24h cache cap conflicts w/ persisting it in the Mongo lookup history beyond a day.
- **Publish the crawl cadence as a dated timeline.** "March 2012 · 90d -> March 2014 · 60d -> Aug 2018 · 30d -> May 2020 · 14d" builds more trust than any accuracy claim. Live-tool analogue: publish which resolver answered, when, from what cache state.
- **Badge the locked example, don't hide it.** "Preview" link + "Premium Only" pill side by side. Hobby-tool translation: show the expensive query's shape & a truncated result behind an explicit "run full query" click, not a paywall.
- **Reverse-PTR by wildcard keyword** (`*smtp*` across 1B PTR records) finds *infrastructure naming conventions* rather than hosts. A small tool can't hold 1B records, but the same idea scoped to one `/24` reverse zone, walked live, is cheap and nobody else offers it.
- **`ns.ip:` / `mx.ip:` as first-class fields.** Pivoting on *the nameserver's IP* rather than its name catches operators who rotate NS hostnames but not infrastructure. One extra resolution step at index time, a whole new pivot.

## Gaps & what it does not do

- **It is not a DNS lookup tool & has stopped pretending to be one.** No live resolution, no resolver choice, no authoritative query, no delegation trace, no propagation grid, no TTLs.
- **No DNSSEC of any kind**: no `DS`/`DNSKEY`/`RRSIG`, no chain validation, no NSEC walking.
- **No zone-health checking.** None of the intoDNS/MXToolbox category: no glue checks, no parent-vs-child comparison, no SOA sanity, no lame-NS detection, no open-recursion test.
- **No email-auth analysis.** SPF is indexed as a *string to pivot on*; SPF Lookup & Email Test are dead. No SPF flattening or 10-lookup-limit check, no DMARC, DKIM, BIMI, MTA-STS.
- **RR coverage is 5 types plus an SPF-shaped slice of TXT.** No CNAME means CNAME chains are invisible; keeping only `v=spf1` out of TXT means verification records, DMARC & MTA-STS policies are all discarded at index time.
- **PTR is IPv4-only** (their FAQ), **ccTLD coverage 50–80%** (so "no domains found" ≠ "no domains exist"), and **data is up to 14 days stale** (30 for PTR, 60 for HTML metadata). Never quote it as current state.
- **A freshest-possible answer is structurally impossible for them** and trivial for a live tool. That is the differentiation line.
- **The app is unscriptable without a browser.** Cloudflare challenge on every app path; the API is the only programmatic door & covers a narrower surface than the UI (v2 exposes one dataset so far).

## Verified firsthand vs inferred

**Verified by `curl`/`dig`, 2026-09-15, re-run 2026-09-16:** free API live, keyless, returning the documented schema for IPv4, IPv6 & unrouted input; free host exposes **only** `ip2asn` (other v1 paths 404 there); **no `Access-Control-Allow-Origin`** on the free API; `freeapi` allows `GET` only (HEAD/OPTIONS/POST -> 405 `allow: GET`); premium host rejects invalid keys w/ 400 + JSON; marketing site static on BunnyCDN (anycast A record, PoP-dependent) w/ `form-action https://search.dnslytics.com/` in its CSP; sitemap lists exactly 44 URLs incl. 5 legacy tool pages absent from the nav; `/spf-lookup/` **does not exist** (404); Ping/Traceroute/Email Test pages read "offline", DNSBL/IP-Geo read "moved"; their zone uses Cloudflare NS + Proton MX + SPF/verification TXTs; app & API hosts on Cloudflare `188.114.96.3/97.3`; `dev.dnslytics.com` does not resolve. **Measured elsewhere:** extension installs from the Mozilla AMO & Edge add-ons JSON APIs (9,561 & 17,942); Rapid7's `opendata` -> `sonardata` redirect & its commercial-access wording.

**From vendor docs/marketing, not observed:** every dataset size & record count; all crawl cadences & the two collection timelines; premium tier contents & the Year-Pass-only monitor gating; monitoring behaviour; the vendor's 150,000+ extension figure; report section layouts (field-level, these track the matching API doc, which is a strong secondhand source but still secondhand).

**Explicitly not verified, unchanged after a second pass:** any rendered result page, the pricing table, the `/help/*-dataset` query-language references, and the legacy-tools index at `/tools`. **All behind the Cloudflare managed challenge, which returned 403 to both `curl` and WebFetch on both dates**; I did not attempt to defeat it, and web.archive.org was itself offline, so no archived copy either. Also untested: whether the free API's documented 2,500/day cap is enforced (~10 calls made, deliberately). The query-field table is built from DNSlytics' own public deep links, so those fields are real, but the list is certainly **incomplete** vs the full grammar. Chrome Web Store install count unmeasured: it 302s to a consent interstitial I would not accept.

## Open source / reusable

**Nothing is open source.** No public repo, no SDK, no OpenAPI spec, no MCP endpoint. They explicitly disclaim IP over the data (API ToS §4.2: "We claim no intellectual property rights over the data"), which is bound instead by each upstream licence. Some of the reusable part survives: **RIPE NCC RIS** + **RISwhois** for BGP/prefix, **Spamhaus DROP/EDROP** & **UCEPROTECT** for blocklists, **GeoNames** (CC-BY 3.0) & **MaxMind GeoLite2** for geo are all still openly fetchable. iptools already consumes Spamhaus/IPsum, so adding RIS is cheap.

> **Correction worth flagging, verified 2026-09-16:** **Rapid7 Open Data is gone as a free feed.** `opendata.rapid7.com` now 301s to `sonardata.rapid7.com`, which reads "Sign In (**existing accounts only**)", "Access is granted on a **commercial basis** to qualified organizations", and dates the change: "The policies for accessing this data changed on **Feb 10, 2022**." The corpora still exist (FDNS, RDNS, TCP scans, SSL certs, 61.1 TB) & are still updated weekly, but a hobby tool cannot get them. Do **not** plan a bulk-RDNS feature around it. Incidentally this reframes DNSlytics' June 2021 swap to their own crawler: they got off Rapid7 roughly eight months before the door shut.

The one DNSlytics-specific piece worth wiring is the keyless `ip2asn`, subject to the 24h cache cap.

## Sources

- [DNSlytics homepage — scale claims, nav, refresh cadence](https://dnslytics.com/)
- [API index — all endpoint types, credit costs, rate limits, changelog](https://dnslytics.com/api/)
- [IP2ASN API docs — the one keyless endpoint](https://dnslytics.com/api/ip2asn/)
- [IPInfo API docs — full IP dossier fields incl. blocklist & geoinfo](https://dnslytics.com/api/ipinfo/)
- [Dataset/Domains v2 API docs — query language, 4-field limit, paging](https://dnslytics.com/api/dataset-domains/)
- [ReverseHistory API docs — pivot types & Google Tag formats](https://dnslytics.com/api/reversehistory/)
- [ASInfo API docs — the AS/BGP report's field list, verbatim](https://dnslytics.com/api/asinfo/) · [SubnetInfo — "about 700K IPv4 subnets"](https://dnslytics.com/api/subnetinfo/) · [DomainSearch — keyword rules & `question` echo](https://dnslytics.com/api/domainsearch/)
- [Domain Search — ccTLD coverage 50–80%, daily 01:00 GMT+1 zone update, "beginning of 2024" domain count](https://dnslytics.com/domain-search/)
- [Reverse Analytics — the 7 supported Google Tag prefixes incl. PUB-](https://dnslytics.com/reverse-analytics/)
- [Reverse SPF — SPF stats, 14d refresh, & the SPF Lookup EOL notice](https://dnslytics.com/reverse-spf/)
- [SubDomains — counts & 2018/2019 record-type timeline](https://dnslytics.com/subdomains/) · [Whois Lookup — live query, 30-day cache](https://dnslytics.com/whois-lookup/)
- [About us — DNSlytics address & REG. No. 65179900](https://dnslytics.com/about-us/) · [Terms of service — service operated by Webdevmedia](https://dnslytics.com/terms-of-service/)
- [Browser extensions — vendor's 150,000+ claim](https://dnslytics.com/browser-extensions-addons-accelerators/) · [Mozilla AMO API — measured daily users](https://addons.mozilla.org/api/v5/addons/addon/ip-address-and-domain-info/)
- [RFC 7208 §3.1 — SPF RRTYPE 99 deprecated, SPF lives in TXT](https://www.rfc-editor.org/rfc/rfc7208#section-3.1)
- [Hosting History — DNS collection timeline 2012→2022](https://dnslytics.com/hosting-history/)
- [Reverse PTR — RDNS timeline, Rapid7 provenance, IPv4-only](https://dnslytics.com/reverse-ptr/)
- [Reverse IP — crawl methodology & example query syntax](https://dnslytics.com/reverse-ip/)
- [Monitoring — Basic/Advanced Brand Monitor & DNS Monitor specs](https://dnslytics.com/monitoring/)
- [Premium access — tier contents & "30 cents a day"](https://dnslytics.com/premium-access/)
- [Credits — third-party sources (GeoNames, MaxMind, Spamhaus, UCEPROTECT, RIPE RIS)](https://dnslytics.com/credits/)
- [API Terms of Service — 24h cache cap, no-logo clause, credit expiry](https://dnslytics.com/api-terms-of-service/)
- [Ping tool EOL notice — the 2024-01-01 live-tool shutdown](https://dnslytics.com/ping/)
- [RIPE NCC RIS — free BGP/prefix data](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/)
- [Rapid7 Sonar Data (ex-Open Data) — now commercial, "existing accounts only", policy changed 2022-02-10](https://sonardata.rapid7.com/about)
