# DNSDumpster & HackerTarget

Two products, **one company**: DNSDumpster's own `ld+json` names the publisher as *Hacker Target Pty Ltd* (observed). Both are **passive recon** tools, though not uniformly: HackerTarget's `/dnslookup/` and `/zonetransfer/` do resolve live (proven below), everything else is a database read. HackerTarget is the plumbing layer (a family of no-auth plain-text HTTP endpoints at `api.hackertarget.com`); DNSDumpster is the polished domain-recon front end sitting on the same datasets. For someone building a DNS lookup tool these matter for three reasons: (1) HackerTarget's free API is **keyless and CORS-open**, so it is the cheapest possible enrichment backend, including straight from the browser; (2) DNSDumpster's live front end is built on **htmx**, i.e. the owner's exact stack, and is a working reference implementation for the UI; (3) both answer a question `dig` cannot, "what *else* exists under this domain", by joining DNS to passive scan data.

- **URL:** [dnsdumpster.com](https://dnsdumpster.com/) · [hackertarget.com](https://hackertarget.com/ip-tools/) · **Category:** passive DNS recon / OSINT attack-surface discovery · **Registration:** DNSDumpster web UI = none; DNSDumpster API = account + `X-API-Key`; HackerTarget API = **none for free tier** · **Pricing:** DNSDumpster Basic free / Plus $49-yr (advertised as a sale price) / Max $499-yr / Advanced = redirect to HackerTarget / Unplugged = POA; HackerTarget Starter $10-mo → Enterprise from $100-mo, **all billed annually** (checked 2026-09-16) · **API:** both, very different shapes.
- **Firsthand check:** 12 live calls to `api.hackertarget.com` (`dnslookup` ×4, `reversedns` ×2, `hostsearch`, `geoip`, `findshareddns`, `zonetransfer`, `analyticslookup`), plus on DNSDumpster: unauthenticated `POST /htmld/`, `GET /htmld/`, `/quick/` ×2, the `.xlsx` download unzipped & parsed, `GET api.dnsdumpster.com/domain/...` without a key, `robots.txt`, `sitemap.xml`. Cross-checked against `dig @1.1.1.1`. Everything below marked "observed" came out of those responses; "docs" = I read the vendor page's raw text (not a summariser). DNSDumpster's logged-in/Plus views were **not** exercised (no account).

## What it is

**HackerTarget** ("scanning the Internet since 2007") sells hosted vulnerability scanning; the free tool pages & API are the funnel. Their FAQ claims **18 free web tools**, no sign-up, plus third-party integrations (Splunk, Maltego) and an official Chrome extension (docs). Each tool is a thin web form over a CLI (`dig`, `nmap`, `mtr`, `whois`) or over their own dataset, and each has a matching `api.hackertarget.com/<tool>/?q=<target>` endpoint returning **plain text**, no JSON, no envelope.

**DNSDumpster** is the branded consumer face: one input box, one domain, one dashboard. Its A-record table is explicitly labelled *"A Records (subdomains from dataset)"* (observed). Sources per the DNSDumpster FAQ: **certificate transparency logs, search engines, Common Crawl** (that is the whole list on that page, verified in raw HTML). HackerTarget's own pages name a wider set: **scans.io** (Rapid7), **censys.io**, CT logs, and for Domain Profiler also Shodan, Maxmind, Netcraft, Bing, Google. Neither page claims wordlist brute-forcing or zone transfer as a subdomain source for these results; absence of a claim is not proof, so treat "no brute force" as **inferred**.

That dataset provenance is the whole product and the whole caveat. See *Gaps*.

## Registration, access & pricing

| | Free | Paid |
|---|---|---|
| **HackerTarget API** | No account, no key. Docs: "50 API calls per day **(depending on the tool)**", "from a single IP". Results capped at 500 lines | Key via `&apikey=` or `X-API-Key` header (docs). Starter $10/mo ($120/yr, Tools API 500/day) · Pro $25/mo ($300/yr, 1,000) · Business $50/mo ($600/yr, 2,000) · Enterprise from $100/mo (7,500+) |
| **HackerTarget web tools** | 18 tools, ad-hoc form use, capped results | Membership adds 28 vulnerability scanners: Nikto, WhatWeb, WordPress/Joomla/Drupal/SharePoint, SSL/TLS, OpenVAS, Zmap, scheduled scans, Domain Profiler |
| **HackerTarget boost credits** | n/a | 100,000 for $250 · 1,000,000 for $1,400; auto-activate once the daily quota is spent (docs) |
| **DNSDumpster web** | No login for a basic domain search (**observed** — unauthenticated POST returned a full report) | Plus $49/yr · Max $499/yr · **Advanced** (page just points at HackerTarget) · **Unplugged** (self-contained VM for air-gapped networks, gov/approved-corporate only, POA) |
| **DNSDumpster API** | Account required, `X-API-Key` header. Unauthenticated → `401 {"error":"API key is missing"}`, **no CORS header** (observed) | Same tiers |

DNSDumpster limits (docs, 2026-09-16): Basic 50 req/day, 50 subdomains per request, 32 CIDR results · Plus 200/200/254 · Max 2,500/200/4,096. Banner observed in my response: *"Free users are limited to 50 results for a single domain."*

HackerTarget's free quota is **not one number** and the docs contradict themselves. The IP-tools page says a flat 50/day "depending on the tool"; the per-tool pages say `hostsearch` **20/day** (50 results free vs 500,000 member), `findshareddns` **50/day** (500 vs 500,000), `zonetransfer` **100/day**, `analyticslookup` **50/day**. The `x-api-quota` header matches neither cleanly: I observed **50** on `dnslookup`, `geoip`, `findshareddns`, `zonetransfer`, `analyticslookup` and **21** on `reversedns`, `hostsearch` — and `dnslookup` returned 50 *after* `reversedns` returned 21, so it is a per-endpoint allowance, not a shared decrementing counter. `x-api-count` also looks bucketed (stayed 0 across three `dnslookup` calls while `reversedns`/`hostsearch` went 1 → 2). Header semantics per docs: `x-api-quota` = daily allowance, `x-api-count` = calls used today, `x-api-boost` = purchased credits. **Plan against the documented per-tool numbers, not the header.** Rate limit 2 req/s, HTTP 429 over (docs, deliberately untested).

## Features — complete inventory

### HackerTarget — DNS & name endpoints
| Tool | Endpoint | Returns |
|---|---|---|
| DNS Lookup | `/dnslookup/?q=` | Fixed set A, AAAA, MX, NS, TXT, SOA in one shot (observed) |
| Reverse DNS | `/reversedns/?q=` | `8.8.8.8 dns.google` (observed) |
| Host Search (subdomains) | `/hostsearch/?q=` | CSV `host,ip` from passive dataset (observed) |
| Zone Transfer | `/zonetransfer/?q=` | Literal `dig -t axfr @<ns>` output, one block **per NS** (observed against their own domain: two blocks, `; Transfer failed.`) |
| Find Shared DNS Servers | `/findshareddns/?q=ns1.x.com` | Bare newline-delimited domain list, no IPs, no header. Reverse-NS, rare elsewhere (observed) |
| Whois | `/whois/?q=` | Registrar record |

### HackerTarget — IP / network endpoints
`/geoip/?q=` (observed: IP, Country, State, City, Latitude, Longitude) · `/reverseiplookup/?q=` hosts sharing an IP · `/aslookup/?q=` ASN → org + prefixes (observed via DNSDumpster's proxy: CSV header line then one prefix per line, v4 **and** v6) · `/subnetcalc/?q=` CIDR maths · `/bannerlookup/?q=` stored service banners · `/nmap/?q=` TCP scan, `&udp=1` UDP · `/mtr/?q=` traceroute · `/ping/?q=`.

### HackerTarget — web endpoints
`/httpheaders/?q=` · `/pagelinks/?q=` (extract outbound links) · **`/analyticslookup/?q=`** — reverse Google Analytics/AdSense search, accepts a domain *or* a `UA-`/`G-`/`pub-` ID, returns TSV `domain<TAB>ga4<TAB>G-3JZVG4J6QH` (observed). **Free and keyless**, 50/day. Data from their Alexa Top 1M crawls + Common Crawl (docs). This is the one genuinely correlative pivot that is *not* paywalled.

### HackerTarget — membership-only
Domain Profiler: NS + MX + subdomains + banners + **reverse-whois by registrant email** + **Analytics tracking-ID correlation** + CT + ASN-wide banner sweep; sources named on the page as CT, scans.io, Shodan, Maxmind, Netcraft, Bing, Common Crawl, Google; up to **500,000 results**, truncated beyond; delivered as XLS + PNG domain map + interactive table + web network graph, emailed to the account (docs).

### DNSDumpster — single-domain report (all observed in one response)
1. **System Locations** — country histogram driving a `jsvectormap` world map (`{"US":9,"NL":1}`).
2. **Hosting / Networks** — top-5 ASN chart via ApexCharts (`GOOGLE`, `AKAMAI-LINODE-AP`, `CLOUDFLARENET`, `GOOGLE-CLOUD-PLA`, `DIGITALOCEAN-ASN`).
3. **Services / Banners** — open-port-count-by-technology bar chart.
4. **A Records (subdomains from dataset)** table. Header row is six cells: Host · IP · ASN · ASN Name · Open Services (from DB) · RevIP, plus an unlabelled kebab column. The **PTR rides inside the IP cell**, the **netblock CIDR inside the ASN cell**, the **country inside the ASN Name cell** — seven visible facts in four columns.
5. **MX Records** table, same enrichment, priority kept in the host string (`1 aspmx.l.google.com`).
6. **NS Records** table, same columns.
7. **TXT Records** — raw strings (SPF, `google-site-verification`).
8. **Download xlsx** — `/dl/xlsx/<domain>-<uuid>.xlsx`, 200, `content-disposition: attachment`, 8 KB real OOXML (observed). Two sheets, **named `Summary` and `DNS Records`**; `Summary`'s first cells read *"Domain Profiler Summary for <domain>"* + *"Generated on: <UTC ts>"* then Top-5 Banners / Top-5 ASN rollups; `DNS Records` columns are Host · IP · Type · Reverse DNS · Netblock Owner · HTTP Services · Remote Services.
9. **Per-row kebab menu** → six drill-downs (see *Ideas*).
10. **CIDR banner search** — `/banners/{CIDR}`, Plus only, "Class C or maximum of 254 hosts" (docs).
11. **Domain map** — `?map=1` returns a base64-encoded map, Plus only (docs, not observed). `cytoscape.js` is vendored on the homepage, so the modern graph is **probably** an interactive Cytoscape render rather than the old Graphviz PNG; I never saw it render.

## Record types & query options supported

Thin, and this is the headline gap. HackerTarget `/dnslookup/` returns a **fixed bundle**: A, AAAA, MX, NS, TXT, SOA. I passed `&t=MX&type=MX` and got the identical full bundle back, so there is **no record-type parameter** (observed, re-tested 2026-09-16). DNSDumpster's rendered report is thinner still: only A, MX, NS, TXT sections and, in the xlsx, only `Type` values A/MX/NS. **CNAME** appears in the documented API JSON schema (`a`, `cname`, `mx`, `ns`, `txt`, `total_a_recs`) but there is **no CNAME anywhere in the HTML report** (observed: zero matches for "cname" in the response body). Absent across both products: CAA, SRV, PTR-as-a-type, DS/DNSKEY/RRSIG, NAPTR, SVCB/HTTPS, ANY.

No knobs at all: no resolver choice, no authoritative-vs-recursive toggle, no `+trace` delegation walk, no TCP flag, no EDNS/ECS, no DNSSEC/`+dnssec`, no raw `dig` output outside `/zonetransfer/`, and **no TTLs anywhere** in any output I saw. Output is `TYPE : value`, one per line, trailing dot preserved on NS/MX, null MX passed through verbatim (`MX : 0 .` for example.com).

## How it works

Entirely **server-side**. Nothing resolves in the visitor's browser.

`/dnslookup/` is **live, and I proved it**: its SOA serial for `hackertarget.com` (`2412982106`) and for `example.com` (`2414908178`) matched `dig @1.1.1.1` exactly, serial for serial, in the same minute, and the returned A set for `hackertarget.com` matched `dig` exactly. `/zonetransfer/` is live too (literal `dig` text). Which recursive resolver they query is **not disclosed and I could not determine it**.

Everything else, `hostsearch`, `findshareddns`, `reverseiplookup`, `bannerlookup`, `analyticslookup` and every DNSDumpster table, is a **database read**, not a query. HackerTarget's host-record page states the dataset updates **weekly** for free users and **hourly** for members.

I verified that staleness firsthand and it is material (2026-09-16):

| Host | DNSDumpster said | `dig @1.1.1.1` says |
|---|---|---|
| `api.hackertarget.com` | A `34.136.124.210` (Google Cloud) | A `45.33.65.164` (Linode) — **wrong** |
| `static.hackertarget.com` | A `172.104.14.167` | **no A record**; AAAA `2600:3c03::f03c:91ff:fe88:dbd1` — host is IPv6-only now |

Note `api.hackertarget.com` resolved *correctly* via HackerTarget's own `/hostsearch/` (`45.33.65.164`) while DNSDumpster's table showed the stale Google Cloud address. **The two products disagree with each other**, so they read different snapshots. DNSDumpster's A-table is IPv4-only and therefore silently drops IPv6-only hosts.

DNSDumpster fronts Cloudflare (`cf-cache-status: HIT`, `age: 91` on the homepage), sets a tight CSP (`default-src 'self'`; Turnstile in `script-src`/`frame-src`; Stripe + Mailchimp in `form-action`; `frame-ancestors 'none'`; `base-uri 'none'`), `cache-control: private, no-store` on result fragments, and ships `htmx.js`, `cytoscape.js`, `jsvectormap.js`, `worldmap.js`, `apexcharts.js`, `site.js`, all cache-busted with `?v=<hash>` and `defer`. No SPA framework.

## Output & UX

**HackerTarget:** `text/plain`, `access-control-allow-origin: *` (observed, including against an explicit cross-origin `Origin:` header). No JSON, no CSV header row, no status envelope. Trivially pipeable; requires a hand-written parser.

**DNSDumpster:** the search form is
`<form hx-post="/htmld/" hx-target="#results" hx-swap="innerHTML" hx-indicator=".htmx-indicator" hx-headers='{"Authorization": ""}'>`
i.e. one htmx POST returning an HTML fragment that replaces `#results`. Charts get their data from embedded **`<script type="application/json" id="map-data">` / `#asn-data` / `#service-data`** blobs that the vendored JS reads after swap, not from a second API call. Charts render **above** the tables so the shape of the estate lands before the rows. Progressive per-section streaming: none, one swap. Result URLs are **not shareable**: `GET /htmld/?target=...` → **405** and `GET /<domain>` → 404 (observed), with `robots.txt` disallowing `/htmld/`, `/quick/` and `/dl/`. A real weakness worth not copying. Free-tier truncation is an inline banner at the top of the results, doubling as the upsell.

## Monetization, limits & abuse controls

Free tier is generous enough to be genuinely useful, then gates on **volume and depth**: results-per-domain (50 → 200 → 4,096 CIDR), requests/day, pagination, the domain map, CIDR banner search, and dataset freshness (weekly vs hourly). Domain Profiler, the piece that correlates reverse-whois across an estate, is membership-only with no free taste. Abuse controls: per-IP + per-endpoint quotas, 2 req/s on HackerTarget and 1 req / 2 s on the DNSDumpster API with HTTP 429 over (both docs, untested), Cloudflare Turnstile wired into the CSP (not triggered on my requests), `frame-ancestors 'none'` and `x-frame-options: DENY` against embedding.

**Practical warning for a server-side Go tool:** HackerTarget's free quota is keyed to **source IP** ("50 calls per day from a single IP", their words). A tool that proxies every visitor's lookup through one server burns one shared 20-50/day allowance and will 429 almost immediately.

## Ideas worth stealing

- **Per-row kebab → six htmx drill-downs.** The single best mechanic here, and it is already the project's stack. Every row carries `hx-get="/quick/?tool=<tool>&target=<value>"` with `hx-target="#modal-data"` inside `#modal-content`/`#myModal`. Observed tools: `dnslookup`, `aslookup`, `subnetcalc`, `nmap`, `reverseiplookup`, plus a "Goto HT" external link. I called `/quick/?tool=dnslookup&target=www.hackertarget.com` directly and got a bare 6-line A/AAAA fragment, no page chrome; `/quick/?tool=aslookup&target=13335` returned a CSV org line then every prefix. That is one Go handler, one tiny template, `platform.Respond` already doing content negotiation, and **iptools already owns every one of those five lookups**. A DNS result table where each IP opens the existing geo/ASN/Shodan card is nearly free to build and is the thing that makes the two tools one product.
- **Enrich every row, not just the answer.** They never print a bare IP: PTR, ASN, netblock, ASN name, country, known open services, co-hosted-domain count. Note *how* they fit it, two facts stacked per cell rather than ten columns. A DNS answer table with those reads as analysis; a `dig` dump reads as output.
- **Charts above tables, fed by embedded JSON blobs.** `<script type="application/json" id="map-data">{...}</script>` parsed post-swap avoids a second round trip and keeps the Go side rendering one template. Cheap pattern for htmx, and the `<script>` (not `<div>`) wrapper is what keeps the payload out of the rendered DOM.
- **Label dataset-derived rows in the heading itself.** *"A Records (subdomains from dataset)"* sets expectations in four words.
- **The differentiator that falls out of that:** they cannot re-resolve at display time, cheaply, at their volume. A hobby tool can. Show `dataset ✓ live` / `dataset ✗ dead` / `changed: 34.136.124.210 → 45.33.65.164` per row. Both of my staleness findings would have been caught by it. That is a genuinely better product on the one axis that matters, and it is a handful of concurrent `net.Resolver` calls in Go.
- **`findshareddns` as a concept.** "Which other domains use this nameserver" is an unusual, cheap pivot once you store lookups. Mongo lookup history already exists in iptools. Their output is a bare domain list, so the bar for beating it is low.
- **XLSX export with a summary sheet first.** Sheet 1 = generation timestamp + top-5 rollups, sheet 2 = the rows. A plain CSV is the simpler Go move, but the two-sheet shape (summary, then detail) is the idea.
- **Free-tier truncation as an inline top-of-results banner.** Honest, unmissable, not a modal. Same slot works for "showing first N of M".
- **Do show TTLs.** Neither product does, and it is the cheapest possible credibility signal that a result is live.

## Gaps & what it does not do

No record-type selection, no CAA/SRV/DS/DNSKEY/SVCB, no CNAME in the rendered report, **no DNSSEC validation or chain-of-trust view whatsoever**, no TTLs, no resolver picker, no global propagation comparison, no delegation trace, no EDNS/ECS, no email-auth audit (SPF is printed as a TXT string, never parsed; no DMARC or DKIM lookup, no SPF include-count or flattening), no health/lint checks (no NS-consistency, no open-resolver or lame-delegation test), no blocklist/reputation, no monitoring or change alerts, no shareable result URL, no IPv6 in DNSDumpster's A table, no JSON from HackerTarget. Reverse-whois correlation is paywalled; Analytics-ID correlation is **not** (`/analyticslookup/` is free).

## Verified firsthand vs inferred

**Observed:** every `api.hackertarget.com` body & header quoted above, across 12 calls to 7 endpoints, including `access-control-allow-origin: *` under a cross-origin `Origin:`, the `x-api-quota` 50-vs-21 split and its per-endpoint (not decrementing) behaviour, the fixed record bundle ignoring `&t=`/`&type=`, `/zonetransfer/`'s per-NS `dig` output, `/findshareddns/`'s bare domain list, `/analyticslookup/`'s TSV. On DNSDumpster: unauthenticated `POST /htmld/` returning a complete report, `GET /htmld/` → 405, the exact `hx-*` attributes, the `ld+json` publisher name, the vendored JS list, section order, the six `<th>` labels and what rides inside each cell, `/quick/` fragment shapes, the `.xlsx` (200, valid OOXML, both sheet names and every column), zero CNAME in the body, `api.dnsdumpster.com` 401 + no CORS header, CSP/cache headers, `robots.txt`, `sitemap.xml`, and both staleness findings via `dig @1.1.1.1`. That `/dnslookup/` resolves live is **observed**, via matching SOA serials on two domains.

**Docs only (read from raw vendor page text, not purchased or tested):** all membership prices and per-tier credit allowances; boost-credit pricing; the per-tool free quotas (20/50/100/50 per day), which the `x-api-quota` header does not corroborate; `X-API-Key`/`&apikey=` auth; the DNSDumpster JSON schema field names; `?page=` and `?map=1`; `/banners/{CIDR}`; Domain Profiler's contents, sources and 500k cap; weekly-vs-hourly dataset refresh; the 2 req/s and 1-req-per-2s limits and 429 behaviour (deliberately not tested); "18 tools", "28 scanners", Splunk/Maltego/Chrome integrations; `/reverseiplookup/`, `/bannerlookup/`, `/nmap/`, `/mtr/`, `/ping/`, `/httpheaders/`, `/pagelinks/`, `/whois/`, `/subnetcalc/` behaviour (not called). All DNSDumpster logged-in/Plus views (no account).

**Inferred, flagged as such:** that the Plus domain map is a Cytoscape render (from the vendored script + the `map=1` param, never seen); that no wordlist brute-forcing feeds these results (neither vendor claims it, but neither denies it); which recursive resolver HackerTarget queries is **undetermined**, not inferred.

## Open source / reusable

Neither service is open source (DNSDumpster's footer says only "Built with Open Source Software"). Third-party clients exist but target the pre-2023 site: [`PaulSec/API-dnsdumpster.com`](https://github.com/PaulSec/API-dnsdumpster.com) (unofficial Python; repo still returns 200, but GitHub's API rate-limited my metadata call so last-commit and licence are **unchecked** — it scrapes the old CSRF form, which the current `POST /htmld/` flow has replaced, so assume it is broken) and [`ngfw/dnsdumpster`](https://github.com/ngfw/dnsdumpster) (PHP/Laravel, **MIT**, last pushed 2025-11-24, 0 stars — observed via GitHub API). For Go, nothing worth vendoring: `api.hackertarget.com` is `net/http` + `bufio.Scanner` over `strings.Cut(line, " : ")`, and the official DNSDumpster API is one `X-API-Key` header and `encoding/json`. The genuinely reusable asset here is the **UI pattern**, not code.

## Sources

- [HackerTarget IP Tools index — 15 endpoint paths, quota/rate-limit/header table, apikey docs, boost credits, FAQ](https://hackertarget.com/ip-tools/)
- [HackerTarget Find Host Records (Subdomains) — 20/day + 50 results free, weekly vs hourly, scans.io/Censys/CT sources](https://hackertarget.com/find-dns-host-records/)
- [HackerTarget Find Shared DNS Servers — 50/day, 500 vs 500,000 results](https://hackertarget.com/find-shared-dns-servers/)
- [HackerTarget Zone Transfer tool — 100/day, per-NS dig output](https://hackertarget.com/zone-transfer/)
- [HackerTarget Reverse Analytics Search — free `/analyticslookup/` API, Alexa 1M + Common Crawl, accuracy caveats](https://hackertarget.com/reverse-analytics-search/)
- [HackerTarget Domain Profiler — membership-only correlation report, named sources, 500k cap, XLS/PNG/graph output](https://hackertarget.com/domain-profiler/)
- [HackerTarget Scan Membership — tier pricing (annual billing) and Tools API credits](https://hackertarget.com/scan-membership/)
- [DNSDumpster home — htmx form, vendored JS, ld+json publisher](https://dnsdumpster.com/)
- [DNSDumpster Developer/API docs — endpoints, X-API-Key, JSON schema, page/map params, 1 req / 2 s](https://dnsdumpster.com/developer/)
- [DNSDumpster Membership — Basic/Plus/Max/Advanced/Unplugged limits and prices](https://dnsdumpster.com/membership/)
- [DNSDumpster Advanced Access — the "Advanced" tier is a pointer to HackerTarget](https://dnsdumpster.com/advanced-access/)
- [DNSDumpster About & FAQ — CT logs, search engines, Common Crawl; HackerTarget relationship](https://dnsdumpster.com/about-faq/)
- [DNSDumpster robots.txt — /htmld/, /quick/, /dl/ disallowed](https://dnsdumpster.com/robots.txt)
- [PaulSec/API-dnsdumpster.com — unofficial Python client (legacy site)](https://github.com/PaulSec/API-dnsdumpster.com)
- [ngfw/dnsdumpster — Laravel client package, MIT](https://github.com/ngfw/dnsdumpster)
