# DNS lookup APIs & pricing landscape

Survey of the commercial & free API supply for a DNS lookup tool: who sells DNS data, what they charge, and which endpoints a small Go service can call server-side w/o an account. Headline finding: **raw record lookup is a commodity w/ effectively free, keyless, high-quota supply** (DoH JSON front doors on public resolvers, 1500 QPS per IP on Google alone). What vendors sell is the **inverse index** (reverse IP/MX/NS, passive DNS, subdomain discovery) & **history** (what the zone looked like last year). Budget accordingly: a DNS lookup tool needs $0 of API spend for records, & even two of the classic paid adjacencies (subdomain discovery, registration data) have free keyless substitutes, **crt.sh** & **RDAP**.

- **Scope:** WhoisXMLAPI DNS Lookup API · HackerTarget · DNSlytics · Google, Cloudflare, NextDNS, AdGuard & Quad9 DoH JSON · IPinfo · ipapi.co · ip-api.com · api.viewdns.info · RapidAPI DNS listings · crt.sh · RDAP · **Category:** API supply + pricing landscape · **Date of all quoted limits/prices:** 2026-09-16.
- **Firsthand check:** ~55 `curl`/`dig` probes from a macOS host (working `dig`, outbound UDP/53 open). Called Google, Cloudflare, NextDNS, AdGuard & Quad9 DoH, `api.hackertarget.com` (dnslookup/whois/zonetransfer), `freeapi.dnslytics.net`, `ip-api.com`, `edns.ip-api.com`, `ipapi.co`, `ipinfo.io`, `api.viewdns.info`, `crt.sh`, `rdap.org`; checked CORS via `-H "Origin: https://corpberry.com"` on each; read quota headers; tested ECS across four prefixes, NXDOMAIN / DNSSEC-bogus / ANY / IDN / HTTPS-RR edge cases.
- **Could not verify firsthand:** WhoisXMLAPI pricing table (Vue-rendered, no numbers in HTML), `viewdns.info/api/` + `/api/pricing/` + `/api/docs/` (Cloudflare interstitial, **403** to both curl & WebFetch), `search.dnslytics.com/pricing` (**403**), RapidAPI listing pages (SPA, title only), `zero.dns0.eu` (**connect timeout**, network-local, not a service verdict). Flagged inline.

## What it is

Three distinct markets wearing the same "DNS API" label, plus a fourth that nobody labels DNS at all:

1. **Public recursive resolvers w/ a JSON front door.** Google, Cloudflare, NextDNS, AdGuard, Quad9. Free, keyless, no ToS friction, enormous quotas. Answers exactly one question: *what does a recursive resolver return for `name`/`type` right now*.
2. **Recon/OSINT text APIs.** HackerTarget, ViewDNS. Small daily free quota, plain-text or JSON, & crucially they ship **derived** views a resolver cannot give you: reverse DNS on a netblock, host search, AXFR attempt, reverse IP.
3. **Commercial domain-intelligence vendors.** WhoisXMLAPI, DNSlytics, IPinfo. Credit-metered, account-gated, priced per call. Raw lookup is the loss-leader; the product is passive DNS, reverse-* indexes, DNS history, subdomain discovery.
4. **Free public indexes that undercut (3).** Certificate Transparency via **crt.sh** gives subdomain discovery keyless; **RDAP** gives registration data keyless & structured. Both observed CORS-open. Neither is marketed as a DNS API, both compete directly w/ paid tiers.

## Registration, access & pricing

| Service | Auth | Free tier (checked 2026-09-16) | Paid entry | Browser-callable (CORS) |
|---|---|---|---|---|
| **Google DoH JSON** `dns.google/resolve` | none | keyless; "less than **1500 QPS**" per IPv4 / IPv6 /64 is unrestricted use *(docs)* | n/a (free, **no SLA**) | **yes** (`access-control-allow-origin: *` observed) |
| **Cloudflare DoH JSON** `cloudflare-dns.com/dns-query` | none | keyless, no published cap | n/a | **yes** (observed) |
| **NextDNS DoH** `dns.nextdns.io` | none for resolve | resolves keyless; account plan is for *filtering*, not lookup | n/a for lookup | **no** ACAO header observed |
| **AdGuard DoH** `dns.adguard-dns.com/resolve` | none | keyless | n/a | **no** ACAO observed; serves `content-type: application/x-javascript` |
| **Quad9 DoH** `dns.quad9.net` | none | keyless, wireformat on :443; **JSON lives on :5053** | n/a | not established (see caveat) |
| **HackerTarget** `api.hackertarget.com` | none free, `apikey=` / `X-API-Key` for members | **50 calls/day** per IP, **2 req/s**, 429 on breach, results capped at **500 lines** | membership (**no price printed on the page**, confirmed) + boost credits **100,000 / $250** ($0.0025/credit), **1,000,000 / $1,400** | **yes** (ACAO `*` observed) |
| **DNSlytics v1/v2** `api.dnslytics.net` | API key, prepaid credits | **2,500 req/day** free; `AccountInfo` & `IP2ASN` cost **0 credits**; free keyless host `freeapi.dnslytics.net` | prepaid credit packages, **non-recurring**; premium default **20,000 req/day & 30 req/min** *(docs)* | **no** ACAO on `freeapi` (observed) |
| **WhoisXMLAPI DNS Lookup API** | `apiKey` query param | **500** queries on the auto-assigned free plan *(docs)* | credit packages, prices not machine-readable (see caveat) | not checked |
| **ViewDNS** `api.viewdns.info` | `apikey=` (401 w/o, observed) | disputed: see caveat | paid plans exist; **no price could be read** | n/a |
| **IPinfo** | token for paid fields; **keyless calls work** (observed) | Lite: $0 forever, unlimited API, country-level; legacy keyless `/{ip}/json` returns city/ASN w/ a `readme: missingauth` nag (observed 200) | Core **$26/mo** / 150k req; Max **$163/mo** / 250k; overage $0.34 & $1.30 per 1k | n/a |
| **ipapi.co** | keyless allowed | "up-to **1000/day**", ~30K/mo, "not meant for use in production" | Starter **$15/mo** / 60k … Maximum **$399/mo** / 15M | yes (ACAO `*` observed, on a 429) |
| **ip-api.com** | keyless | **45 req/min**, **HTTP only** (HTTPS returns `{"status":"fail"…"SSL unavailable"}`, observed), **non-commercial only** | pro key at members.ip-api.com | **yes** (ACAO `*`) |
| **crt.sh** `?q=%25.domain&output=json` | none | keyless, no published cap (observed 200, 25 KB JSON for `%.example.com`) | n/a | **yes** (ACAO `*` observed) |
| **RDAP** via `rdap.org` | none | keyless bootstrap; **302** to the registry's own RDAP (observed -> `rdap.verisign.com`) | n/a | **yes** (ACAO `*` observed) |
| **RapidAPI** DNS listings | `X-RapidAPI-Key` | per-listing; platform free APIs capped **1000 req/hr & 500K/mo**; a typical freemium BASIC = **500 req/mo** | per-listing overage billing | n/a |

## Features — complete inventory

**Record lookup (all five DoH JSON endpoints, free & keyless).** Single `name`+`type` query -> recursive answer. Table-stakes.

**Google DoH JSON, distinctive extras.** `edns_client_subnet=1.2.3.4/24` (geo-targeted answers from an arbitrary vantage point, no proxy needed; `0.0.0.0/0` is the documented privacy opt-out) · `do=1` returns **RRSIG/NSEC/NSEC3** inline · `cd=1` disables validation so you can show a bogus answer next to a refused one · **`extended_dns_errors[]`** (RFC 8914 EDE, observed `{"info_code":9,"extra_text":"No DNSKEY matches DS RRs of dnssec-failed.org"}`, **not in Google's own JSON docs**) · **`Comment`** field that on a cache miss names the authoritative server IP that answered (observed `"Response from 172.64.32.162."`) · `random_padding` for traffic-analysis resistance · `ct=application/dns-message` for wireformat, `ct=application/x-javascript` to force JSON, on the same URL.

**Cloudflare DoH JSON.** Same core; EDE arrives as a **string inside `Comment[]`** (observed `"EDE(9): DNSKEY Missing no SEP matching the DS found for dnssec-failed.org."`), documented as "List of EDE messages", & there is **no authoritative-server disclosure**. Documents only `name`, `type`, `do`, `cd`.

**NextDNS DoH.** Returns an **`Additional[]` OPT pseudosection** rendered as dig-style text (observed `";; OPT PSEUDOSECTION:\n; EDNS: version 0; flags:; udp: 1232"`), which no other endpoint here does. The NextDNS **REST API** (`api.nextdns.io`, `X-Api-Key`) is a *profile* API, not a lookup API: profile CRUD, `/profiles/:p/analytics/{status,domains,reasons,ips,devices,protocols,queryTypes,ipVersions,dnssec,encryption,destinations}` (append `;series` for time series), `/profiles/:p/logs` w/ `/logs/stream` **SSE** live tail, `/logs/download` & `DELETE /logs`, denylist/allowlist/security/privacy/parentalControl/settings CRUD. No rate limit documented. Nothing to look up a stranger's records; everything to observe *your own* resolution.

**AdGuard DoH.** Non-conforming JSON shape (observed): per-record `class` field, `Extra` where everyone else says `Additional`, `content-type: application/x-javascript`, no CORS header.

**HackerTarget, the recon set** (free, keyless, plain text, `?q=`): `/dnslookup/` (A, AAAA, MX, NS, TXT, SOA in one call, observed) · `/reversedns/` · `/hostsearch/` · `/zonetransfer/` (runs `dig -t axfr` against each NS & reports "Transfer failed", observed) · `/whois/` (**key required**, observed `error valid key required`) · `/geoip/` · `/reverseiplookup/` · `/aslookup/` · `/subnetcalc/` · `/httpheaders/` · `/pagelinks/` · `/bannerlookup/` · `/nmap/` (+`&udp=1`) · `/mtr/` · `/ping/`. Also a **Domain Profiler** (all tools in one pass) & a Chrome extension.

**DNSlytics v1** (`api.dnslytics.net`, credits per call, read from docs): `AccountInfo` (free) · `IP2ASN` (**free**) · `IPInfo` (3) · `SubnetInfo` (4) · `ASInfo` (10) · `DomainSearch` (4) · `DomainTypos` (5) · **`HostingHistory`** (4, historical A/AAAA/MX/NS/SPF) · `ReverseIP` (5) · `ReverseMX` (5) · `ReverseNS` (5) · `ReverseAdsense` (6) · `ReverseGAnalytics` (6) · **`ReverseHistory`** (20, historical reverse across Adsense/Analytics/IP/MX/NS). v2 beta: `Dataset/Domains` (10). Reverse indexes cap at **100,000 domains per MX/NS/ID**.

**WhoisXMLAPI DNS Lookup API.** One endpoint, `GET https://www.whoisxmlapi.com/whoisserver/DNSService`, params `apiKey`, `domainName`, `type` (all three **required**; single, comma-separated, or **`_all`**), `outputFormat` (JSON|XML, **defaults to XML**), `callback` (JSONP). Docs claim "around fifty" RR types. Subdomains must be queried separately (`_dmarc.domain.com`). Their DNS surface continues across separate paid products: DNS Chronicle API, Reverse DNS/IP/MX/NS APIs, Subdomains Lookup API, DNS Database Download, Domain Reputation API.

**ViewDNS.** `api.viewdns.info/<tool>/?…&apikey=…&output=json`; one subscription's query pool spans all tools; `/account/?action=balance` returns limit + usage + prepaid balance. Endpoint list & pricing unverified firsthand (site 403s); only the 401 error envelope was observed.

**crt.sh, the free subdomain index.** `GET https://crt.sh/?q=%25.example.com&output=json` -> JSON array of CT log entries w/ `common_name`, `name_value` (newline-separated SANs, so wildcards & multi-SAN certs fan out), `issuer_name`, `not_before`/`not_after`, `serial_number` (observed 200, ACAO `*`). This is the substitute for WhoisXMLAPI's paid Subdomains Lookup API: it finds names that were certificated, not names that resolve, so it misses internal-only hosts & includes dead ones. Slow (~seconds) & no documented quota.

**RDAP, the free registration index.** `https://rdap.org/domain/<name>` bootstraps by TLD & **302s to the authoritative registry RDAP server** (observed -> `https://rdap.verisign.com/com/v1/domain/example.com`), ACAO `*`. Structured JSON (RFC 9083), no key, no scraping. Substitutes for paid WHOIS endpoints incl. HackerTarget's key-gated `/whois/`. Note the cross-host redirect: a Go client must follow it, & registrar-level detail often needs a second hop.

**IP-centric, no DNS records:** IPinfo (geo/ASN/privacy; **reverse DNS & hosted-domains are Enterprise-only**), ipapi.co & ip-api.com (geo/ASN only).

**`edns.ip-api.com`, the one genuinely unusual mechanic in this set.** `GET https://edns.ip-api.com/json` **302s to a random single-use subdomain** (observed `https://bpgfrna87rrxzznk0qgcf7l7neu7ryr0.edns.ip-api.com/json`), then returns a `dns` object. Observed twice from this host: `{"dns":{"geo":"Germany - Google LLC","ip":"172.253.1.212"}}` then `…"ip":"172.217.34.30"` — a different Google resolver IP each time. **No `edns` key appeared in either probe**, presumably because the upstream resolver forwarded no Client Subnet; the two-key `{"dns":…,"edns":…}` shape is therefore documented-behaviour, not observed here. The implementation is the point: they run the **authoritative nameserver for `edns.ip-api.com`**, so the random label guarantees a cache miss, the query reaches their own auth server, and they log (a) the recursive resolver's source IP and (b) any **EDNS Client Subnet** that resolver forwarded. That needs an authoritative zone, not an API budget.

## Record types & query options supported

| Knob | Google DoH | Cloudflare DoH | HackerTarget | WhoisXMLAPI |
|---|---|---|---|---|
| RR types | numeric **1-65535** or canonical names; verified A, AAAA, MX, TXT, NS, SOA, CAA, HTTPS (type 65, observed w/ `alpn`/`ipv4hint`), SVCB, SRV, NAPTR, DS, DNSKEY, TLSA, PTR, ANY | same core | fixed set (A/AAAA/MX/NS/TXT/SOA) | "around fifty" + `_all` |
| `ANY` | type 255, returns **RFC 8482 HINFO `"RFC8482"`** minimal answer (observed, w/ RRSIG under `do=1`) | same | n/a | `ANY` (255) listed |
| DNSSEC `do` / `cd` | yes / yes | yes / yes | no | no |
| EDNS Client Subnet | **yes** (observed varying answers) | **not documented**; passing it changed nothing observable, so unsupported is *inferred* | no | no |
| Choose resolver | no (it *is* the resolver) | no | no | no |
| **Query a specific authoritative NS** | **no** | **no** | no | no |
| Delegation trace | no | no | no | no |
| TCP / EDNS buffer control | no | no | no | no |
| Raw / wireformat | `ct=application/dns-message` | separate wireformat endpoint | n/a | XML |
| TTL in output | yes, per record | yes | **no** (plain text, no TTL) | yes |
| IDN | **must punycode**; raw UTF-8 `name` returns HTTP **400** (observed) | not tested | not tested | punycode |

The last several rows are the whole story for a lookup tool: **no hosted JSON API lets you pick which server answers, or walk the delegation.** Those are the features `dig @ns1.example.com` and `dig +trace` have, and they are exactly what a Go backend gets for free.

## How it works

DoH JSON endpoints are **recursive resolvers, not authoritative probes**. Answers come from the resolver's cache; TTL in the response is remaining cache TTL, not zone TTL (observed same minute: `example.com` MX TTL **155** from Google, **172** from Cloudflare, **300** fresh from `dig @elliott.ns.cloudflare.com`). Anycast means "which PoP answered" is unknowable from the client. Google discloses the upstream authoritative IP in `Comment` on cache miss; Cloudflare does not.

**ECS is real but fussy.** Against Google, `edns_client_subnet` w/ routable space visibly changes the answer: `www.wikipedia.org` resolved to `208.80.154.224` (Ashburn) via `1.0.0.0/24` & `8.8.8.0/24`, but `198.35.26.224` (San Francisco) via `133.242.0.0/24` (Japan). Documentation/bogon space is **refused**: `203.0.113.0/24` (RFC 5737 TEST-NET-3) returned `Status:5` w/ the scope zeroed to `"203.0.113.0/0"`. Any vantage-point picker must be seeded w/ real allocated prefixes.

HackerTarget & the intelligence vendors are **server-side & cached**: reverse DNS, host search & reverse-IP answers come from their own crawl/passive-DNS corpus, not a live query. DNSlytics states a "minimal logging policy" & offers **no per-call usage history**, so client-side accounting is on you. The free `freeapi.dnslytics.net` host sits behind Cloudflare & returns JSON keyless (observed 200 for `/v1/ip2asn/8.8.8.8`).

## Output & UX

**DoH JSON is close to a wire packet in JSON clothes:** `Status` (DNS RCODE int), `TC`/`RD`/`RA`/`AD`/`CD` flags, `Question[]`, `Answer[]` / `Authority[]` / `Additional[]` each `{name,type,TTL,data}` w/ `type` as a **number**, `data` as the **presentation-format string** (so `"0 ."` for a null MX, an unparsed SOA line, a base64 DNSKEY blob). Note Google returns `Question[].name` **trailing-dotted** (`"example.com."`) while Cloudflare does not (`"example.com"`) — normalize. Empty states are informative: NXDOMAIN = `Status:3` plus the parent SOA in `Authority[]` (observed: `com.` SOA from `a.gtld-servers.net.`); DNSSEC failure = `Status:2` plus a human-readable `Comment` w/ links to dnsviz.net & the Verisign debugger. **No shareable result URLs, no export formats, no HTML** anywhere in this set: these are data planes, the UI is yours to build.

HackerTarget is the opposite extreme: `text/plain`, one `KEY : value` per line for `/dnslookup/`, bare CSV (`host,ip`) for `/reversedns/` & `/hostsearch/`, and literal `dig` stdout for `/zonetransfer/`. Trivial to display, annoying to parse, no TTLs, no error codes.

## Monetization, limits & abuse controls

Uniform pattern: **records are free, indexes are metered.** Resolvers give away lookup because it costs them nothing & buys them query telemetry (Google explicitly: free, no SLA, throttling above 1500 QPS/IP, worse for CGNAT). Recon APIs meter by **day** (HackerTarget 50/day + 2 req/s + 500-line result cap, observed; DNSlytics 2,500/day free, 20,000/day & 30/min premium, docs). Intelligence vendors meter by **credit**, & price the credit by how expensive the index is: DNSlytics charges 0 for IP2ASN, 5 for a reverse lookup, **20** for reverse *history*. Signals to watch in responses: HackerTarget ships `x-api-quota` (daily allowance), `x-api-count` (used today), `x-api-boost` (purchased credits) on every call, observed live as `50 / 2 / 0`. ip-api.com ships `X-Rl` (43 remaining) & `X-Ttl` (56s window). WhoisXMLAPI caps at **30 requests/second** (docs). Free tiers also carry **licence** teeth: ip-api.com free is "strictly limited for a non-commercial purpose", ipapi.co free is explicitly "not meant for use in production".

## Ideas worth stealing

- **Query two resolvers concurrently & diff.** Google & Cloudflare are both free, keyless & CORS-open. Fire both, render a single result, and badge disagreement ("Cloudflare & Google differ on A"). Near-zero cost, catches split-horizon & mid-propagation states, & it is one `errgroup.Group` in the domain service.
- **Surface EDE (RFC 8914) as the DNSSEC error message.** Google hands you `extended_dns_errors[{info_code,extra_text}]`; Cloudflare hands you `Comment[0]` as `"EDE(9): …"`. Normalize both to one `{code, text}` struct in the domain package & render "No DNSKEY matches DS RRs" instead of "SERVFAIL". Highest-value field in the landscape & almost nobody shows it. Caveat: Google's field is undocumented, so guard the unmarshal.
- **Show "answered by" when you have it.** Google's `Comment: "Response from 172.64.32.162."` on a cache miss lets you display which authoritative server actually served the answer. Force a miss w/ a random label when you want it.
- **ECS as a "check from another country" control.** Observed working against Google. Ship it as a resolver-vantage dropdown, but hard-code vantage prefixes from **real allocated space**: bogon/doc prefixes come back REFUSED w/ a zeroed scope.
- **crt.sh instead of a paid subdomains API.** One keyless GET replaces the product WhoisXMLAPI & DNSlytics both charge for. Cross-check each CT name against a live A/AAAA lookup & badge "certificated, not resolving" — that diff is more interesting than either list alone.
- **RDAP instead of WHOIS scraping.** Structured, keyless, CORS-open, redirects to the authoritative registry. No reason to pay for registration data or to key-gate it behind HackerTarget.
- **Copy the quota-header contract.** `x-api-quota` / `x-api-count` / `x-api-boost` on every response is the cheapest possible rate-limit UX. If iptools/dnstools ever gets a JSON API, emit the same triple.
- **Price the feature by the index it needs.** DNSlytics' credit sheet is a free market-research doc: 0 for ASN, 5 for reverse, 20 for reverse-history. Build the 0-credit stuff, link out for the 20.
- **`_all` in one call.** WhoisXMLAPI's `type=_all` & HackerTarget's multi-RR `/dnslookup/` both default to "show me everything". Default the tool to a parallel fan-out over A/AAAA/MX/NS/TXT/SOA/CAA, single query type as the advanced case.
- **Cache-miss forcing.** The `edns.ip-api.com` random-label trick generalizes: prefix a random label to guarantee you are measuring the delegation & not a cache.
- **Dodge the CORS trap.** Only Google, Cloudflare, HackerTarget, ip-api, ipapi.co, crt.sh & rdap.org sent `access-control-allow-origin: *`; NextDNS DoH, AdGuard DoH & `freeapi.dnslytics.net` did **not**. Anything htmx-side must be a server-side call.

## Gaps & what it does not do

**The decisive gap: none of these APIs query an authoritative nameserver, and none trace a delegation.** They are all recursive-resolver or cached-index products. A Go backend w/ `github.com/miekg/dns` does both natively, plus TCP fallback, arbitrary EDNS buffer sizes, AXFR, and per-NS comparison, at zero marginal cost & zero vendor lock-in. **The build/buy answer for record lookup is "build"**; w/ crt.sh & RDAP covering subdomains & registration, the only genuinely paid-only territory left is **passive DNS & historical records**.

Other gaps: no hosted API here returns HTML or a shareable result URL, so all presentation is ours. Nothing returns zone-file TTL (only remaining cache TTL) unless you ask the authoritative server yourself. `ANY` is dead as a discovery mechanism (RFC 8482 minimal responses, observed firsthand). No free API offers multi-geo propagation; ECS on Google is the closest substitute & it is one vendor's non-standard extension. Reverse DNS on IPinfo is Enterprise-tier, so cheap PTR data comes from HackerTarget or your own resolver. HackerTarget's 50/day & 500-line cap makes it a garnish, not a dependency.

## Verified firsthand vs inferred

**Observed:** every DoH JSON shape, flag, param & edge case quoted above (ECS varying answers across 1.0.0.0/24, 8.8.8.0/24 & 133.242.0.0/24; REFUSED + zeroed scope on 203.0.113.0/24; `do`, `cd`, EDE on both Google & Cloudflare, `Comment` cache-miss attribution, NXDOMAIN + parent SOA, ANY/RFC8482, HTTPS RR type 65, IDN 400, Google's trailing dot vs Cloudflare's); CORS headers on every endpoint named in the table, incl. **AdGuard & NextDNS sending none**; HackerTarget's `x-api-quota:50` / `x-api-count:2` / `x-api-boost:0`, the free reachability of `/dnslookup/` & `/zonetransfer/`, and the key-gate on `/whois/`; `freeapi.dnslytics.net/v1/ip2asn/8.8.8.8` returning JSON keyless; ip-api.com's HTTP-only free endpoint & `X-Rl`/`X-Ttl`; `edns.ip-api.com`'s 302-to-random-subdomain & two distinct `dns.ip` samples (**no `edns` key returned in either**); **`ipinfo.io/{ip}/json` returning 200 w/ city/ASN/anycast keyless**; ipapi.co 429 from this host; ViewDNS returning `{"success":false,"error":{"code":401,…}}`; crt.sh 200 + JSON; rdap.org 302 to `rdap.verisign.com`; TTL spread 155 / 172 / 300 across Google / Cloudflare / authoritative.

**Docs only (not observed):** WhoisXMLAPI endpoint, params, `_all`, 500 free queries, 30 req/s, "around fifty" types; Google's 1500 QPS figure (documented on their ISP page, not load-tested); NextDNS REST endpoints (no key exercised); RapidAPI platform caps (listing pages are SPAs returning only a title); DNSlytics credit table & daily limits (no key exercised); IPinfo's plan feature matrix (pricing page read via WebFetch, no token exercised).

**Inferred, not confirmed:** Cloudflare DoH ECS support — passing `edns_client_subnet` produced no observable change & the param is absent from their docs, so "not supported" is inference, not a confirmed negative.

**Unresolved / conflicting:** **ViewDNS pricing could not be established.** `viewdns.info/api/`, `/api/pricing/` & `/api/docs/` all return **403** behind a Cloudflare interstitial to curl *and* WebFetch. Search summaries conflict: one line of sources quotes tiered monthly plans in the $29-$549 range w/ a 250-query sandbox, another (2026) quotes **10,000 free API credits/month, no card**. Treat every ViewDNS number as unknown. **WhoisXMLAPI per-tier prices** could not be read at all: the pricing page is Vue-rendered & contains no price strings in HTML; the widely-quoted "$30/mo for 2,000 queries" / "$3,600/mo for 2M" anchors are for their **WHOIS** API from a third-party review, not the DNS Lookup API. `search.dnslytics.com/pricing` also 403s, so DNSlytics credit-package dollar prices are unknown. **Quad9 JSON**: `dns.quad9.net:5053` **connect-timed-out** from this host while `:443` answered (`"DoH unable to decode BASE64-URL"` to a JSON-shaped query, i.e. wireformat-only there), so the timeout is port-specific & likely local egress filtering, not a Quad9 outage. `zero.dns0.eu` also timed out; same caveat, no verdict.

## Open source / reusable

`github.com/miekg/dns` (**BSD-3-Clause**, v1.1.73 at time of writing) is the reference Go DNS library & covers everything the hosted APIs will not: pick your server, `+trace`, TCP, EDNS0 incl. Client Subnet, DNSSEC validation, AXFR. Go's stdlib `net.Resolver` w/ a custom `Dial` handles the common cases w/o a dependency but will not give you flags, TTLs or arbitrary RR types. The DoH JSON shape itself is a de-facto format w/ **no RFC** (Cloudflare states this outright: the format "does not have a formal RFC, which means behavior might be different between providers", & AdGuard's `class`/`Extra` divergence proves it), so define your own normalized struct in the domain package & write one adapter per upstream rather than unmarshalling any vendor's shape directly. RFC 8484 (DoH wireformat), RFC 8914 (EDE codes), RFC 8482 (minimal ANY) & RFC 9083 (RDAP JSON) are the specs worth reading before designing the result model.

## Sources
- [Google Public DNS: JSON API for DNS over HTTPS](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google Public DNS: information for ISPs (rate limits)](https://developers.google.com/speed/public-dns/docs/isp)
- [Cloudflare 1.1.1.1: DNS over HTTPS JSON format](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [HackerTarget IP Tools & API quotas](https://hackertarget.com/ip-tools/)
- [DNSlytics API: types, credit costs, rate limits](https://dnslytics.com/api/)
- [DNSlytics IP2ASN free endpoint](https://dnslytics.com/api/ip2asn/)
- [WhoisXMLAPI DNS Lookup API: making requests](https://dns-lookup.whoisxmlapi.com/api/documentation/making-requests)
- [NextDNS API reference](https://nextdns.github.io/api/)
- [IPinfo pricing](https://ipinfo.io/pricing)
- [ip-api.com legal/limits](https://ip-api.com/docs/legal)
- [ipapi.co pricing](https://ipapi.co/#pricing)
- [ViewDNS API (403 to curl & WebFetch; listed for provenance)](https://viewdns.info/api/)
- [ViewDNS API pricing (403; listed for provenance)](https://viewdns.info/api/pricing/)
- [DomScan: ViewDNS pricing summary (secondhand, conflicting)](https://domscan.net/pricing/viewdns)
- [RapidAPI subscription plans & pricing](https://docs.rapidapi.com/v2.0.0/docs/api-pricing)
- [crt.sh certificate transparency search](https://crt.sh/)
- [rdap.org bootstrap service](https://rdap.org/)
- [RFC 8914: Extended DNS Errors](https://www.rfc-editor.org/rfc/rfc8914.html)
- [RFC 8482: Providing Minimal-Sized Responses to DNS Queries with QTYPE=ANY](https://www.rfc-editor.org/rfc/rfc8482.html)
- [RFC 9083: JSON Responses for RDAP](https://www.rfc-editor.org/rfc/rfc9083.html)
- [RFC 5737: IPv4 Address Blocks Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737.html)
- [miekg/dns: DNS library in Go (BSD-3-Clause)](https://github.com/miekg/dns)
