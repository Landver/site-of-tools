# WHOIS & RDAP lookup tools

The "who owns this name" panel every DNS tool eventually ships. Relevant to us because the modern answer is **not** scraping who.is and **not** speaking port-43 text: it's **RDAP**, a plain JSON-over-HTTPS protocol w/ a public discovery registry, no API key, and (verified below) `Access-Control-Allow-Origin: *` on every server probed. For a Go binary this is `http.Get` + `encoding/json`. The hard parts are discovery (which server owns `.io`?), the registrar two-hop, and the fact that GDPR gutted the contact data everyone expects to see.

- **URLs:** [rdap.org](https://rdap.org/) · [data.iana.org/rdap/](https://data.iana.org/rdap/) · [who.is](https://who.is/) · [whois.domaintools.com](https://whois.domaintools.com/) · [lookup.icann.org](https://lookup.icann.org/)
- **Category:** registration-data lookup (domains, IPs, ASNs, nameservers) · **Registration:** none for RDAP/IANA/ICANN/who.is web pages; who.is **API** needs a free key; DomainTools gates everything behind an account · **Pricing:** protocol free; who.is API free tier -> $29/$99/$199 per mo; DomainTools quote-only, no public price page · **API:** RDAP itself is the API
- **Firsthand check (2026-09-15, re-verified & corrected 2026-09-16):** pulled all five IANA bootstrap files; followed `rdap.org` -> Verisign -> MarkMonitor for `github.com`; read live RFC 9537 `redacted` arrays from PIR & Identity Digital; ran an 11-server CORS/header matrix incl. all five RIRs; probed RDAP search **and RFC 9536 reverse search** against Verisign/PIR/ARIN/APNIC; ran `whois` port-43 chains; pulled `registrar-ids-1.csv` (4,503 rows) and the IANA RDAP JSON Values registry; read both ICANN announcements at source; enumerated who.is's real URL surface & its API docs. `whois.domaintools.com` answered plain curl w/ `<title>Whois Lookup Captcha</title>`, so **DomainTools detail is read from docs, never observed**.

## What it is

Two protocols doing one job.

**WHOIS** (RFC 3912, 2004; the 1982 original is RFC 812): open TCP/43, send a string, read unstructured text back. No encryption, no auth, no i18n, no schema. Every server invents its own key names. Discovery is a hardcoded guess or a `refer:` line from `whois.iana.org`.

**RDAP**: `GET https://<base>/domain/example.com` -> `application/rdap+json`. Typed object classes, ISO-8601 events, jCard contacts, machine-readable status, and a **bootstrap registry** naming the authoritative server. RFC 7480 (HTTP usage) & 7481 (security) are still current Internet Standards; **RFC 7482/7483/7484 are obsolete**, replaced by **9082** (query), **9083** (responses), **9224** (bootstrap). Verified against the RFC Editor metadata, so cite the 90xx numbers, not the 74xx ones.

ICANN forced the switch, and both dates are **read at source** (the announcements 403 a bare fetch but answer curl w/ a browser UA). Per the 27 Jan 2025 announcement: "As of 28 January 2025, the Registration Data Access Protocol (RDAP) will be the definitive source ... in place of sunsetted WHOIS services." The **Registration Data Policy** took effect **21 August 2025**, concluding a transition window that ran 21 Aug 2024 -> 20 Aug 2025; it replaces the Interim Registration Data Policy and updates the RDAP Response Profile. ccTLDs sit outside ICANN contracts, so WHOIS-only TLDs persist indefinitely. Practical read: **build RDAP-first, keep a port-43 fallback**.

## Registration, access & pricing

| Service | Who runs it | Auth | Cost | Notes |
|---|---|---|---|---|
| IANA bootstrap files | IANA | none | free | 5 static JSON files, `ACAO: *`, `max-age=86400` |
| rdap.org | Gavin Brown, personally ("own time, own cost") | none | free; supporters (Ko-fi) get higher limits | 302 redirector, Cloudflare-fronted, fly.io origin |
| rdap.net | OpenRDAP project (`rdap@skip.org`); operator not named on site | none | free | identical redirect role, nginx + Go/Revel |
| lookup.icann.org | ICANN | none | free | pure browser app, no ICANN query backend |
| who.is web | independent operator | none | free | Next.js, server-rendered |
| **api.who.is** | same | **Bearer key, free to create** | Free $0 · Pro $29/mo · Growth $99/mo · Scale $199/mo | documented REST + OpenAPI; see §B |
| whois.domaintools.com | DomainTools | CAPTCHA for anonymous; account for depth | **no public price page** | see §D, pricing claims are weak |

## Features — complete inventory

### A. Protocol-level, free & keyless (what a Go tool can build w/ zero vendors)

| Capability | Mechanism | Verified |
|---|---|---|
| Domain registration record | `GET <base>/domain/<name>` | yes |
| Nameserver object | `/nameserver/<host>` (ldhName, ipAddresses v4/v6) | yes, via rdap.org redirect |
| IP network record | `/ip/<addr>` -> RIR (start/end, ipVersion, type, parentHandle, org) | yes (ARIN, 8.8.8.8 -> `NET-8-8-8-0-2`, `GOGL`) |
| **Structured CIDR + origin AS** | `cidr0_cidrs` (RFC 9092) & `arin_originas0_originautnums` on ARIN IP responses | yes, both present on `/ip/8.8.8.8` |
| ASN record | `/autnum/<asn>` -> RIR | yes (15169 -> ARIN) |
| Entity / org / registrar record | `/entity/<handle>` | yes (`GOGL-ARIN`, `292-IANA` at root.rdap.org) |
| Reverse-DNS zone record | `/domain/8.8.8.in-addr.arpa` at the **RIR**, not via bootstrap | yes (ARIN 200; rdap.org 404s it) |
| Server capability doc | `/help` | yes (conformance array + ToS/glossary notices) |
| Registrar discovery by IANA ID | IANA `registrar-ids-1.csv`, column **RDAP Base URL** | yes, 3,318 of 3,322 accredited registrars (99.9%) |
| DNSSEC delegation status | `secureDNS` {`delegationSigned`, `dsData[]`} | yes (example.com signed, keyTag 2371, alg 13, digestType 2; github.com `delegationSigned:false`) |
| Status codes w/ glossary links | `status[]` + `notices[].links rel=glossary` -> icann.org/epp | yes, **values are spaced lowercase**, not camelCase (see below) |
| Lifecycle dates | `events[]` (12 registered `eventAction` values, IANA registry) | yes |
| Abuse contact | nested entity `roles:["abuse"]` w/ `tel` + `email` | yes (MarkMonitor abuse phone + email, at the **registry** hop) |
| Redaction disclosure | `redacted[]` (RFC 9537) | yes, PIR + Identity Digital; MarkMonitor omits it |
| Structured errors | `{errorCode, title, description}` | inconsistent: rdap.org & ARIN yes · Verisign **empty 404 body** · PIR returns RFC 9457 `problem+json` |
| Search: entities / IP networks by name | `/entities?fn=Google*` · `/ips?name=GOGL` | ARIN 200 · Verisign 400 |
| Search: nameservers by IP | `/nameservers?ip=8.8.8.8` | **Verisign 200** (returned `NS.BEST.COM`) |
| Search: domains by name/ns | `/domains?name=` · `?nsLdhName=` | Verisign 400 · PIR **501** |
| Sorting/paging & partial response | `count`/`sort`/`limit`/`offset` (RFC 8977), `fieldSet` (RFC 8982) | ARIN accepted both |
| **Reverse search (RFC 9536)** | `/{ips\|autnums}/reverse_search/entity?fn=&handle=&email=&role=` | **ARIN 200, live and free** (see below) |
| Port-43 fallback + server discovery | `whois -h whois.iana.org io` -> `whois: whois.nic.io` | yes, for io/de/us/eu |

**Reverse search is real and the earlier draft of this report had it wrong.** The path grammar is `{searchable}/reverse_search/{related}?{property}=`, not `/domains?fn=`. ARIN's `/help` advertises `reverse_search` in `rdapConformance` and publishes a `reverse_search_properties` array: searchable `ips` and `autnums`, related type `entity`, properties `fn`, `handle`, `email`, `role`. Observed live: `/registry/ips/reverse_search/entity?fn=Google%20LLC` -> **200** w/ `ipSearchResults`, `email=` likewise 200; `handle=GOGL-ARIN` -> RDAP 404 ("not here", i.e. routed & executed); adding `&role=registrant` -> 501. Verisign 400s the path, PIR/APNIC 404 it. So: **an unauthenticated "which IP ranges does this org hold" query exists at ARIN today**, which matters directly to the iptools tool already in this repo. ARIN also advertises `rirSearch1` in its conformance array; the relation path grammar rejected every name I guessed (`up`/`down`/`top`/`bottom` all 400 "You must specify a valid relation"), so treat it as undetermined.

**Status string casing is a real trap.** RDAP `status` uses the IANA RDAP JSON Values registry: 36 spaced-lowercase values, e.g. Verisign returns `["client delete prohibited","client transfer prohibited","client update prohibited"]`. The camelCase `clientTransferProhibited` spelling is the **EPP/port-43 WHOIS** form, which is why who.is (rendering WHOIS text) shows camelCase. A decode map keyed on camelCase matches nothing in RDAP JSON.

### B. who.is (the closest "small tool, big surface" comparable)

Server-rendered Next.js. Per-domain tabs observed live: **Whois · RDAP · DNS Records · Certificate · Uptime · Diagnostics · History · Hide Contact Info · Refresh Data**; top nav adds Uptime · Domain Events · Monitoring · Login. The real URL surface, enumerated from page hrefs (the earlier guessed paths 404'd, these do not): `/whois/<d>` · `/rdap/<d>` · `/dns/<d>` · `/certificates/<d>` · `/history/<d>` · `/privacy/<d>` · `/tools/<d>` · `/uptime/<d>` · `/nameserver/<host>` · `/whois-ip/ip-address/<ip>` · `/domains/events` · `/dns-report` · `/docs/api`, all 200.

WHOIS page content: registrar block (name, WHOIS server, referral URL) · created/updated/expires · **"WHOIS data last fetched September 14, 2026"** cache stamp · nameservers **resolved to IPs and hyperlinked to `/nameserver/<host>`** · status codes hyperlinked to icann.org/epp · **Similar Domains** (11 suggestions) · Raw Registry and Raw Registrar WHOIS shown separately · "About WHOIS" explainer for SEO. Affiliate monetization is now **observed, not inferred**: the "you can still try to buy it here" link is `/out?p=domainagents&d=<domain>&src=whois`, a tracked outbound redirect. The RDAP tab is a genuinely different render (handle, Public ID + **Public ID Type** `IANA Registrar ID`, authoritative server URL, `Last update of RDAP database` **and** its own `RDAP data last fetched` date: two independently-aged caches, both disclosed). The DNS page is a **narrative** rather than a dump, chips for hosting network / managed DNS / email / IPv6 / CAA plus "Sits alongside N other sites on Cloudflare" and "Stable here since we started watching", then the raw record table. Derived state over a longitudinal store, not a single query.

**who.is ships a documented public API** (the earlier draft said it had none). Docs at `/docs/api`, base `https://api.who.is/v1/`, Bearer key (`wis_live_…`) in the `Authorization` header, OpenAPI spec linked. Endpoints: `/whois/{domain}` · `/rdap/{domain}` · `/domains/{d}/history` · `/domains/{d}/history/snapshots` (async) · `/dns/{d}` · `/dns/{d}/changes` · `/certificates/{d}` · `/certificates/{d}/changes` · `/domains/zones/{added,changed,removed}` · `/nameservers` · `/nameservers/{host}` · `/nameservers/{host}/domains`. Published quotas:

| Plan | Price | Req/mo | Req/day | Req/s | Full-history/mo | Live refresh/day |
|---|---|---|---|---|---|---|
| Free | $0 | 500 | 100 | 1 | 0 | 0 |
| Pro | $29/mo | 15,000 | none | 5 | 5 | 500 |
| Growth | $99/mo | 60,000 | none | 5 | 10 | 1,000 |
| Scale | $199/mo | 150,000 | none | 5 | 20 | 2,000 |

Hard caps, no metered overage; `/changes` timelines are paid-only (Free gets `403 plan_required`); `/whois` serves a stored snapshot ≤30 days unless `?live=true`. Firsthand: `api.who.is/v1/whois/example.com` returns **401** w/ an RFC 9457 `problem+json` body, and distinguishes missing key from revoked key. No `ACAO` header on that response, so it is a server-side API only. **The zone-delta endpoints (newly added / changed NS / removed domains) are the interesting part**: that is a capability RDAP itself cannot give you at any price.

### C. ICANN Lookup

Angular SPA at `lookup.icann.org` (index is 1 KB of gzipped shell). `/api/*` paths **302 to the site root**: there is no ICANN query backend, the browser talks to RDAP servers directly. Bundle grep (inferred, see caveats) showed config carrying `dnsBootstrapUrl`, `asnBootstrapUrl`, `ipv4BootstrapUrl`, `ipv6BootstrapUrl`; a `parseServices()` flattening bootstrap `services` arrays into a `{tld, http, https}` table cached in `sessionStorage`; `findRdapServer()` matching by TLD suffix, `findIpServer()` by range; requests w/ `Accept: application/json, application/rdap+json`; `http:` bases rewritten to `https:`. Also in the bundle, worth stealing conceptually: **`displayRDAPWhoisFormat` / `enableWhoisFormatResponse`** (render RDAP JSON back out as classic WHOIS `key: value` text), `enableWhoisContactTemplate`, `fallbackToWhois` w/ `whoisBackendUrl` and a `domainsWhoisFallbackDisabled` blocklist, and a redaction UI (`commonSec.redactionPartial`, `mockRedactedResponseNew.json`). I never saw a WHOIS fallback request fire and never extracted the backend URL value, so that fallback is an identifier-level inference only.

### D. DomainTools (docs-read, never observed)

Free page is CAPTCHA-walled to non-browsers. Endpoint paths confirmed to exist on `docs.domaintools.com` (all 200): WHOIS Lookup `/api/lookups/whois-lookup/` · **WHOIS History** `/api/lookups/whois-history/` · **Reverse WHOIS** `/api/lookups/reverse-whois/` · Reverse IP `/api/lookups/reverse-ip/` · Reverse Nameserver `/api/lookups/reverse-nameserver/` · **Hosting History** `/api/lookups/hosting-history/` · Domain Profile `/api/lookups/domain-profile/`. Plus Iris investigation, Farsight DNSDB passive DNS, threat feeds w/ RPZ, Python SDK, OpenAPI specs, MCP server. The moat is the **multi-decade archive + pivots**, exactly what a small tool cannot copy.

**Pricing: do not plan against a number.** `domaintools.com/pricing` 404s; there is no public price list. Third-party figures conflict badly: aggregator listicles cite a ~$99/mo entry tier, while a SC Media product test puts the Iris platform at "$35,000" (almost certainly annual). The earlier "Iris $250+/mo" figure is unsupported and has been cut. Treat DomainTools as quote-only.

### E. rdap.org ecosystem (all OSS, all worth reading)

`rdap.org` bootstrap redirector (PHP, BSD-3) · **`client.rdap.org`** browser-only RDAP client that talks straight to RDAP servers w/o a proxy · **`validator.rdap.org`** response validator · **`deployment.rdap.org`** daily per-TLD dashboard, observed header row **TLD / Type / Domains / RDAP / Added / HTTPS? / DNSSEC? / DANE?** (the page's own prose still describes a "Port 43" column that the table no longer renders) · **`root.rdap.org`** RDAP frontend to the root zone & accredited registrars (`/domain/com` -> 302 to `rdap.iana.org`, `/entity/292-IANA` -> 200) · `openapi.rdap.org` · `backend-data.rdap.org`.

## Record types & query options supported

RDAP object classes and their load-bearing members (RFC 9083): **domain** (ldhName, unicodeName, variants, nameservers, secureDNS, entities, status, publicIds, events, port43, network) · **nameserver** (ldhName, ipAddresses.v4/.v6) · **entity** (handle, vcardArray/jCard, roles, publicIds, networks, autnums) · **ip network** (startAddress, endAddress, ipVersion, type, parentHandle, country) · **autnum** (startAutnum, endAutnum, type). Note `port43` is optional in practice: Verisign omits it, MarkMonitor sends it.

Don't hand-roll the vocabularies. **IANA publishes them as a machine-readable registry** (`rdap-json-values-1.csv`, 121 rows): 12 `event action` values (registration, reregistration, last changed, expiration, deletion, reinstantiation, transfer, locked, unlocked, last update of RDAP database, registrar expiration, enum validation expiration), 36 `status`, 11 `role`, 17 `redacted name`, 7 `notice and remark type`, 5 `domain variant relation`. Vendor that CSV alongside the bootstrap files.

Knobs that exist vs knobs that work: `Accept: application/rdap+json` negotiation is universal; `fieldSet` and `count`/`sort`/`limit`/`offset` were accepted by ARIN; **reverse search works at ARIN and nowhere else I probed**. gTLD registries mostly do not implement plain search (Verisign 400s `domains?name=`, PIR answers 501) while RIRs do. Verisign is the exception w/ `nameservers?ip=`, a real reverse-NS-by-IP capability sitting in public, free.

## How it works

**Discovery.** `https://data.iana.org/rdap/{dns,ipv4,ipv6,asn,object-tags}.json`. `dns.json` on 2026-09-16: 71,106 bytes uncompressed, `publication 2026-09-09T23:00:03Z`, **590 service groups covering exactly 1,200 TLDs**, each group `[[tlds...],[base urls...]]`. `ipv4`/`ipv6`/`asn` map CIDR & ASN ranges to the 5 RIRs; `object-tags` maps handle suffixes to servers. Served w/ `ACAO: *`, `Cache-Control: max-age=86400` and a weak ETag, so daily refresh + conditional GET is the correct client.

**The two-hop, and why the registrar CSV is mandatory.** `.com` is a **thin** registry: Verisign's `domain/github.com` gives status, events, nameservers, `secureDNS` and one `registrar` entity (handle `292`, publicId type `IANA Registrar ID`) w/ a nested `abuse` sub-entity, and no registrant. Its only registrar link is `rel:"about"` -> `http://www.markmonitor.com`, a **marketing site, not an RDAP base**; an earlier draft of this report claimed that link carried `https://rdap.markmonitor.com/rdap/` and it does not. The only reliable join is **IANA ID -> `registrar-ids-1.csv`**, which for row 292 gives exactly `https://rdap.markmonitor.com/rdap/`.

**"Thick registry = one hop" does not hold for contacts.** PIR (.org) is thick in the EPP sense, but its public RDAP response carries a **registrar entity only**: verified on example.org, wikipedia.org, mozilla.org and eff.org, all four returning `entities: [registrar]` and nothing else. So .org costs the same two hops as .com if you want anything contact-shaped, and PIR's `redacted[]` discloses only the removed Registry Domain ID, not the absent contacts. Budget **bootstrap (cached) + registry + registrar = 2 live requests** for every gTLD.

**Coverage gap, and it is large.** Absent from `dns.json` on 2026-09-16: **io, de, us, eu, it, es, ru, cn, jp, ch, se, dk, me, be, at, ro, nz, za, mx, kr, tr, ir, il, pt, gr, hu, sk, ie, lt, lv, ee, hr, rs, bg, edu, mil, arpa** (37 checked, 37 missing; only com & org of the sampled set are present). `rdap.org` 404s all of them, and its own about page says why: it "only knows about RDAP servers that are registered with IANA". But `.io` **does** have a working server, `https://rdap.identitydigital.services/rdap/domain/nic.io` -> 200 w/ an 11-entry `redacted` array; it simply is not bootstrapped. A small supplementary TLD->base map beats a pure-bootstrap client on exactly the TLDs a developer audience cares about.

**CORS matrix, `Origin: https://corpberry.com`, 2026-09-16.** `ACAO: *` from **all eleven** endpoints probed: rdap.org, rdap.net, rdap.verisign.com, rdap.publicinterestregistry.org, rdap.arin.net, **rdap.db.ripe.net**, rdap.apnic.net, rdap.lacnic.net, rdap.afrinic.net, rdap.iana.org, data.iana.org. **This corrects an earlier claim that RIPE sends no ACAO header**: RIPE returns `access-control-allow-origin: *` plus `access-control-allow-credentials: false` on `/ip`, `/autnum`, `/entity` and `/help`. One caveat, RIPE's `OPTIONS` preflight answers 200 with **no** CORS headers, so a plain GET (a CORS-simple request, `Accept: application/rdap+json` is safelisted) works but anything triggering preflight will not. Browser-side RDAP is therefore broadly viable; server-side Go still wins on caching and on port-43 fallback.

**Caching.** rdap.org sets `public, max-age=28800` on its redirect (8 h). Registry payloads carry `last update of RDAP database` as an event, the honest freshness stamp to surface.

## GDPR redaction: what you actually get back

Post-GDPR, contact data is gone by default and the interesting part is **how** its absence is disclosed. Live shapes, all observed:

- **PIR (.org)** — minimal, one entry: `{"name":{"type":"Registry Domain ID"},"prePath":"$.handle","pathLang":"jsonpath","method":"removal"}`. The missing registrant is not disclosed at all.
- **Identity Digital (.io)** — 11 entries: Registry Domain ID, Registry Registrant ID, Registrant Name/Street/City/Postal Code, Registrant Phone/Fax/Email, plus two entries that use `name.description` rather than `name.type` (technical and administrative contact), `rdapConformance` includes `redacted`.
- **MarkMonitor (registrar)** — **no `redacted` array at all**; stuffs literal `REDACTED REGISTRANT` into the jCard `fn` and attaches a `contact-uri` to a request form. Inconsistent w/ the RFC but common. Note what survives: `org: "GitHub, Inc."` and `adr` country `US` are still present, so **organization and country often outlive the redaction of the natural person**.

RFC 9537 defines four methods (`removal`, `emptyValue`, `partialValue`, `replacementValue`) w/ JSONPath `prePath`/`postPath`/`replacementPath` and a `reason`. A client that parses this can say **"registrant email withheld by server policy, request form here"** instead of rendering a blank row. (The `replacementValue` shape, registrant email swapped for a `contact-uri`, was described in an earlier draft from a GoDaddy response that I did not re-observe on this pass; treat it as a documented RFC method rather than a verified GoDaddy behaviour.)

## Output & UX

who.is renders server-side so results are in the first HTML response (no spinner, deep-linkable). ICANN Lookup renders client-side against a `sessionStorage`-cached bootstrap table. Both disclose data age; who.is shows two different fetch dates on two tabs for the same domain, which is unusually honest. Error semantics are the sharp edge: **Verisign's 404 body is empty** (0 bytes, verified again on a nonexistent `.com`), **PIR returns RFC 9457 `problem+json`** (`{"type":…,"title":"Not Implemented","status":501}`, no `errorCode`), and **rdap.org returns a proper RDAP error** (`{"errorCode":404,"title":"No RDAP service is available for this resource"}`). rdap.org's 404 means *no server known*, Verisign's means *domain not registered*. Those mean opposite things and conflating them is the single easiest bug to ship here. A parser must handle three error encodings, not one.

## Monetization, limits & abuse controls

rdap.org: Cloudflare-enforced **"maximum of 10 requests in 10 seconds"**, 429 on breach, higher limits for supporters via [Ko-fi](https://ko-fi.com/rdaporg) (quoted from the about page, deliberately not tested). Logging is aggregate only, by originating /24 or /48, user agent, HTTP result code, HTTP origin and enclosing TLD; the page states individual queries are not logged and points at `lib/logger.php` to prove it. Registry/registrar servers publish no numeric limits but rate-limit in practice and attach ToS notices to every response. who.is monetizes three ways: registrar affiliate redirects (`/out?p=domainagents`), a login-gated monitoring product, and the tiered API above. DomainTools monetizes the archive and the pivots, CAPTCHA-walling anonymous clients.

## Ideas worth stealing

- **Bootstrap as a cached, versioned artifact.** Fetch the 5 IANA files on boot + daily w/ `If-None-Match`, flatten to a `map[string]string` TLD->base, keep the parsed table in memory and the raw JSON in Mongo w/ its `publication` date. Falls back to the last-known table when IANA is unreachable. The domain-package-returns-a-struct shape the repo already uses.
- **Vendor the IANA JSON Values CSV too.** 121 rows give you every legal `status`, `role`, `eventAction` and redacted-field name, so decoding is a table lookup rather than a hand-written map that silently misses values. Key it on the **spaced-lowercase** RDAP spelling.
- **Supplementary TLD map as a committed file.** 37 of 37 popular TLDs I sampled are missing from bootstrap and at least `.io` has a live server. A tiny `tlds_supplement.json` (TLD -> RDAP base, plus TLD -> port-43 host from `whois.iana.org`) turns the most embarrassing gaps into hits. Date-stamp it and re-verify.
- **Two-hop w/ the registrar CSV, not the `rel:about` link.** Parse `registrar-ids-1.csv` once (4,503 rows, `ID,Registrar Name,Status,RDAP Base URL`), embed it, resolve IANA ID -> registrar RDAP base. The `about` link is a marketing URL and will not work. Fire hop 2 as an **htmx lazy fragment** so hop 1 paints immediately: exactly the case rule #4 allows htmx for.
- **Render the `redacted[]` array, do not hide it.** Per redacted field show the field name, the method in plain words, the stated reason, and the `contact-uri` when one exists. Also surface what survived: org name and country usually do. Pure JSON parsing, and nobody in the free tier does it well.
- **Dual render: JSON + "WHOIS format".** ICANN's `displayRDAPWhoisFormat` turns RDAP JSON back into `key: value` text for people who read WHOIS. One more template over the same domain struct, and content negotiation already gives us HTML + JSON. **Disclose data age twice**, the server's `last update of RDAP database` event *and* our own fetch timestamp. Cheap, and it inoculates against "this is stale" complaints.
- **Status pills + a DNSSEC chip from `secureDNS`.** Decode `status[]` w/ the icann.org/epp link (same pill pattern the iptools Shodan card uses); `delegationSigned` + DS keyTag/algorithm arrives in the same registry response, a free DNSSEC indicator w/o a DNS query that cross-checks whatever the DNS half resolves.
- **Two free reverse lookups worth wiring into iptools.** `rdap.verisign.com/com/v1/nameservers?ip=<ip>` answers "which .com nameservers live on this IP", and `rdap.arin.net/registry/ips/reverse_search/entity?fn=<org>` answers "which ARIN networks does this org hold". Both unauthenticated, both 200 today. ARIN IP responses also carry `cidr0_cidrs` and `arin_originas0_originautnums`, i.e. structured prefix + origin AS for free.
- **Nameservers resolved to IPs inline**, who.is-style, linked to a per-nameserver page. The DNS half of the tool already has a resolver.
- **Reuse the Mongo lookup-history pattern** for per-domain registration snapshots: store each RDAP response hash + fetch time w/ a TTL index, so "changed since you last looked" is a diff, not an archive. The only honest version of history a hobby tool can offer.

## Gaps & what it does not do

- **No contact data.** Registrant name/email/phone are redacted essentially everywhere for gTLDs, at the registrar hop as well as the registry hop. Any UI promising "find the owner" will disappoint.
- **No history, and no zone deltas.** RDAP is point-in-time. "Newly registered domains", "nameserver changed", "domain dropped" require a longitudinal store; that is who.is's paid API and DomainTools' moat, and it cannot be reconstructed from the protocol.
- **Plain search is mostly unimplemented** at gTLD registries (400/501 observed), so "find all domains w/ this nameserver" does not generalize off `.com`.
- **Reverse search exists only at ARIN** among servers probed, and only for `ips`/`autnums` by entity. No domain-side reverse search anywhere.
- **37 of 37 sampled significant TLDs have no bootstrap entry**, incl. `.io`, `.de`, `.us`, `.eu`. Full coverage needs a port-43 fallback: raw TCP client plus per-TLD text parsing.
- **Error semantics are inconsistent** across three encodings (empty body, RDAP error object, RFC 9457 problem+json) and 400 vs 501 for unsupported search.
- **ccTLDs are not bound by the ICANN profile**, so response shape varies and `redacted[]` may be absent even where data is withheld.

## Verified firsthand vs inferred

**Verified (2026-09-15/16, curl/whois/Bash):** bootstrap file bytes, publication date, 590 groups / 1,200 TLDs and the 37-TLD missing list · rdap.org and rdap.net redirect behaviour, status codes, ACAO and cache headers · the Verisign -> MarkMonitor two-hop for `github.com`, incl. the `rel:about` link's real value and the absence of a registrant · PIR returning a registrar-only entity list on four separate `.org` domains · `redacted[]` from PIR and Identity Digital, and MarkMonitor's literal-string alternative · the 11-server CORS matrix **including RIPE sending `ACAO: *`**, and RIPE's headerless OPTIONS preflight · the search matrix (Verisign 400/200, PIR 501, ARIN 200) · **ARIN RFC 9536 reverse search returning 200 `ipSearchResults`**, and its `reverse_search_properties` help array · ARIN `cidr0_cidrs` / `arin_originas0_originautnums` · Verisign's 0-byte 404 body and PIR's problem+json 501 · RDAP status strings being spaced lowercase · `registrar-ids-1.csv` shape, 4,503 rows, 3,322 accredited, 3,318 w/ RDAP base, and row 292 resolving to MarkMonitor's real base URL · the IANA RDAP JSON Values registry counts · RFC 7480/7481 still Internet Standard and 7482/83/84 obsoleted, from RFC Editor metadata · **both ICANN dates read at source** (28 Jan 2025 quoted verbatim; 21 Aug 2025 w/ its 2024-2025 transition window) · deployment.rdap.org's live header row and the 165,942,005 `.com` figure · who.is's full URL surface, WHOIS/RDAP page content, cache stamps, the `/out?p=domainagents` affiliate redirect, and the `/docs/api` plan table · `api.who.is` returning RFC 9457 401s and distinguishing missing from revoked keys · `whois.domaintools.com` returning a CAPTCHA title to curl and its docs endpoint paths all returning 200 · port-43 discovery for io/de/us/eu · Go library metadata via the GitHub API.

**Inferred, read-only or explicitly unresolved:** DomainTools' feature list is read from `docs.domaintools.com` w/ no authenticated use, and its **pricing is unresolved**, there is no public price page and third-party figures disagree by two orders of magnitude, so no number in this report should be planned against. rdap.org's rate limit, logging policy and supporter tiers are quoted from its about page, not tested (hammering a volunteer service to confirm a 429 is not acceptable). ICANN Lookup's `fallbackToWhois` / `whoisBackendUrl` behaviour is an identifier-level inference from the minified bundle; no WHOIS fallback request was observed firing and the URL value was never extracted. The `.com` count is deployment.rdap.org's own figure, described there as approximate. RFC 9083's member lists were read from the RFC, not exhaustively exercised. ARIN's `rirSearch1` path grammar was **not** determined. Verisign's empty 404 body was observed for `.com` domain objects only. rdap.net's operator is not named on openrdap.org, so "same author as the Go client" is dropped. who.is quota enforcement and response shapes are read from its docs; I created no API key and made no authenticated call.

## Open source / reusable

- **[openrdap/rdap](https://github.com/openrdap/rdap)** — Go, **MIT**, 413 stars, pushed 2026-09-04 (GitHub API). CLI **and** importable library. Full bootstrapping from data.iana.org or a custom URL, object-tag support, optional on-disk bootstrap cache, auto query-type detection, all query types incl. searches, output raw JSON / text / **WHOIS format**. Close to a drop-in for the whole discovery + fetch layer.
- **[likexian/whois](https://github.com/likexian/whois)** — Go, **Apache-2.0**, 494 stars. Port-43 client for the fallback path; companion `whois-parser` handles per-TLD text.
- **[domainr/whois](https://github.com/domainr/whois)** — Go, **MIT**, 419 stars. Alternative port-43 client w/ a large built-in server map.
- **[rdap-org/rdap.org](https://github.com/rdap-org/rdap.org)** — PHP, BSD-3. The redirector; read it for gap handling rather than to run it.
- **[rdap-org/client.rdap.org](https://github.com/rdap-org/client.rdap.org)** — browser-only RDAP client, no proxy. Reference implementation for the client-side variant, and the CORS matrix above says that variant is viable.
- **[rdap-org/validator.rdap.org](https://github.com/rdap-org/validator.rdap.org)** — response validator; useful as a test oracle for our parser.
- **Data files, not code:** `data.iana.org/rdap/*.json` (5 files), `iana.org/assignments/registrar-ids/registrar-ids-1.csv`, and `iana.org/assignments/rdap-json-values/rdap-json-values-1.csv`. All stable, all cacheable, all worth vendoring w/ a refresh job.

## Sources

- [RFC 9082: RDAP Query Format](https://www.rfc-editor.org/rfc/rfc9082.html)
- [RFC 9083: JSON Responses for RDAP](https://www.rfc-editor.org/rfc/rfc9083.html)
- [RFC 9224: Finding the Authoritative RDAP Service (bootstrap)](https://www.rfc-editor.org/rfc/rfc9224.html)
- [RFC 9537: Redacted Fields in the RDAP Response](https://datatracker.ietf.org/doc/html/rfc9537)
- [RFC 9536: RDAP Reverse Search (path grammar, registered properties)](https://www.rfc-editor.org/rfc/rfc9536.html)
- [RFC 7482 status page, showing obsoletion by RFC 9082](https://www.rfc-editor.org/rfc/rfc7482.json)
- [IANA RDAP bootstrap registries (dns/ipv4/ipv6/asn/object-tags)](https://data.iana.org/rdap/)
- [IANA RDAP JSON Values registry (status, role, eventAction, redacted name)](https://www.iana.org/assignments/rdap-json-values/rdap-json-values-1.csv)
- [IANA registrar IDs registry, incl. RDAP Base URL column](https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv)
- [RDAP.ORG about page: operator, endpoints, rate limits, logging](https://about.rdap.org/)
- [RDAP Deployment Dashboard: per-TLD RDAP/HTTPS/DNSSEC/DANE status](https://deployment.rdap.org/)
- [ARIN RDAP /help: rdapConformance and reverse_search_properties](https://rdap.arin.net/registry/help)
- [OpenRDAP: Go client, library and rdap.net service](https://openrdap.org/)
- [openrdap/rdap on GitHub (Go, MIT)](https://github.com/openrdap/rdap)
- [rdap-org organisation: bootstrap server, web client, validator, root frontend](https://github.com/rdap-org)
- [ICANN Lookup](https://lookup.icann.org/)
- [ICANN: Launching RDAP; Sunsetting WHOIS (27 Jan 2025)](https://www.icann.org/en/announcements/details/icann-update-launching-rdap-sunsetting-whois-27-01-2025-en)
- [ICANN: Registration Data Policy now in effect (21 Aug 2025)](https://www.icann.org/en/announcements/details/icann-registration-data-policy-now-in-effect-for-contracted-parties-21-08-2025-en)
- [who.is](https://who.is/)
- [who.is API docs: endpoints, auth, plans & quotas](https://who.is/docs/api)
- [DomainTools API documentation](https://docs.domaintools.com/)
- [SC Media product test citing Iris platform pricing](https://www.scworld.com/product-test/domaintools-iris-investigation-platform)
- [Verisign RDAP service](https://rdap.verisign.com/com/v1/help)
