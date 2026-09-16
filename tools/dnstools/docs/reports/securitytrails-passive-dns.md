# SecurityTrails & passive/historical DNS

Passive DNS (**pDNS**) is the one DNS capability a live resolver structurally cannot provide: **what a name resolved to before now**, and **what else shares that answer**. Sensors on recursive resolvers capture cache-miss responses, dedupe them into `(rrname, rrtype, rdata)` tuples stamped w/ `first_seen` / `last_seen` / observation `count`, and index the result **both directions**. SecurityTrails is the consumer-facing face of this category (clean web UI, self-serve API); DNSDB, CIRCL, Validin & Silent Push are the serious datasets behind it. Relevant here because history is where every free dig-clone stops, and because one usable free pDNS source turns a "current records" page into something nobody else on the shelf has.

- **URL:** [securitytrails.com](https://securitytrails.com/) · API `api.securitytrails.com/v1` · docs [docs.securitytrails.com](https://docs.securitytrails.com/) · **Category:** commercial DNS/domain intelligence (pDNS + WHOIS + cert + ASM) · **Registration:** account + API key mandatory, incl. any free tier · **API:** REST, JSON, **read-only**, `APIKEY` header or `?apikey=` (docs discourage the query-string form)
- **Firsthand check, re-run 2026-09-16:** **every `securitytrails.com` web page still 403s me.** curl & WebFetch get `403` w/ `server: cloudflare`, `cf-mitigated: challenge` on `/`, `/dns-trails`, `/corp/pricing`, `/app/signup`. I could **not** observe the UI or the pricing table, and did not attempt to defeat the challenge. Verified instead: `api.securitytrails.com/v1/ping` -> **401** `"Please check user credentials"` (no anonymous API path); `docs.securitytrails.com` **is** reachable & serves machine-readable OpenAPI (`llms.txt` index, `.md` per page), source of every endpoint below. Separately ran live `dig` + live queries vs **mnemonic's open pDNS API**, and probed DNSDB / CIRCL / Validin / Silent Push / OTX / HackerTarget / crt.sh docs & auth walls.

## What it is

**Origin.** pDNS is Florian Weimer's 2005 construction: don't query authoritative servers, just record what recursives already saw. Consequence that matters: coverage is a function of sensor placement, not of the zone. A record no sensor observed does not exist in pDNS; a record deleted years ago still does.

**SecurityTrails.** Acquired by **Recorded Future** (announced **4 Jan 2022, $65M**; Recorded Future itself acquired by Mastercard, announced 2024). Today it is both a standalone API/UI and a Recorded Future "intelligence card extension". Recorded Future's own support page states coverage of current & historical DNS/domain data "dated back to **2008**", plus historical **reverse DNS resolution from IP addresses up to 120 days** (both quoted verbatim, fetched firsthand). That 120-day figure is the most useful published number in this report: forward history is deep, **reverse history is shallow** even at the premium vendor. **Staleness signal worth weighing before you integrate:** public API docs carry `updatedAt: 2025-06-05`, every core operationId is suffixed `-old-1`, the changelog's newest entry is from 2020, and the `/v1/domain` schema still ships `alexa_rank` (Alexa retired 2022). The v1 surface reads frozen, w/ active development moved into the project/ASM endpoints & Recorded Future proper.

**Live dig vs pDNS, measured 2026-09-16.** `dig +short example.com A` returns `172.66.147.243`, `104.20.23.154`. mnemonic pDNS returns **21 distinct A answers spanning 2013-07-30 -> today**:

| answer | first seen | last seen | obs count |
|---|---|---|---|
| `93.184.216.119` | 2013-07-30 | 2014-12-10 | 490 |
| `93.184.216.34` (EdgeCast) | 2017-01-29 | 2024-04-18 | 334,652 |
| `93.184.215.14` | 2024-04-18 | 2025-01-14 | 11,688 |
| `96.7.128.175` / `.198` (Akamai) | 2025-01-15 | 2025-08-22 | 61,474 |
| `23.192.228.80` / `23.215.0.136` … | 2025-01-15 | 2025-12-16 | ~97,222 |
| `104.18.26.120` / `.27.120` (Cloudflare) | 2025-12-19 | 2026-04-10 | 9,545 |
| `104.20.23.154` / `172.66.147.243` (Cloudflare) | 2026-04-10 | 2026-09-16 | 14,007 |

A full CDN migration history, reconstructed for free, that `dig` can never show. **The honest other half:** the same 21 rows also include `127.0.0.1` (12 observations, 2019-2021), `74.117.222.18` (1 observation), `210.211.113.133` (1), `103.74.119.182` (1). pDNS corpora carry poisoned, misconfigured & one-off garbage answers alongside the real timeline. Any UI that renders these rows undifferentiated will confidently show a user that `example.com` once pointed at localhost.

## Registration, access & pricing

Numbers checked **2026-09-16**. All pricing drifts; re-verify before quoting.

| Service | Free tier | Paid | Notes |
|---|---|---|---|
| **SecurityTrails** | a free API key exists (docs assume self-serve key retrieval from the control panel); **the quota is unknown** | usage tiers, enterprise = contact sales | **No first-party number obtainable.** Pricing page 403s. Secondhand aggregators give **three mutually contradictory** free-tier figures: 50 queries/mo, 2,000/mo, 10,000 credits/mo. Plan for "unknown", not for 50 |
| **Validin** | **Community, free w/ account:** 10 queries/day, 50/mo, 250 results/query, >4 yrs DNS history, 11 RR types, wildcard + CIDR | **Personal $49/mo** ($499/yr), **Professional $399/mo** ($3,990/yr, 500/day, 3,000/mo, 2,500 results), Enterprise custom (20,000+ results) | Best free-tier *capability* in the category, **read off the live page firsthand**. Page disagrees w/ itself: plan card says Personal "Monthly: 250", comparison table says 500. WHOIS/RDAP **Registration** & alerting/collaboration are **Enterprise-only** |
| **DNSDB** (Farsight -> DomainTools) | none public; trial via sales | quota-metered keys (time-based / block / unlimited) | The reference dataset. Docs public & excellent |
| **CIRCL pDNS** | none, "restricted to trusted partners… not free" | request w/ affiliation + intended use | `/pdns/query/example.com` -> **401 firsthand** |
| **Silent Push** | **Community Edition**, free w/ registration | Enterprise, per-subscription API call budget | PADNS + risk scores + feeds. Community-tier query limits not published; `silentpush.com` 403s, deep API ref is behind login |
| **mnemonic pDNS** | **fully open, no key, no account** | n/a | `api.mnemonic.no/pdns/v3/<term>` -> **200 JSON firsthand** |
| **HackerTarget** | documented **50 calls/day, 2 req/s**, `429` on overrun | credit packs (100k credits / $250) | `hostsearch` / `reverseiplookup`; **`access-control-allow-origin: *` confirmed firsthand**. Firsthand headers read `x-api-quota: 21`, `x-api-count: 0`, so the effective per-IP allowance differs from the documented 50 |
| **AlienVault OTX** | free **but key-gated**; anonymous -> `429` | n/a | Firsthand: `"Anonymous access to this endpoint is limited. Please authenticate."`, `X-Remote-User-Name: Anonymous`, and `Access-Control-Allow-Origin: *`. Still alive behind a free account key, just not keyless |

## Features, complete inventory

### SecurityTrails API: every documented v1 endpoint (from `docs.securitytrails.com/llms.txt`)

**Current DNS & domain.** `GET /v1/domain/{hostname}`: current A / AAAA / MX / NS / SOA / TXT, each record type stamped w/ one `first_seen` and each *value* carrying a co-occurrence stat (`ip_count`, `host_count`, `nameserver_count`, `email_count`) = "how many other domains share this value". SOA values also carry `ttl` (the only TTL in the schema). Also `/subdomains` (bare labels) · `/tags` · `/associated` (related domains, paged) · `GET /v1/ping` (auth test) · `GET /v1/account/usage` -> `{current_monthly_usage, allowed_monthly_usage}`

**History, the paid core.** `GET /v1/history/{hostname}/dns/{type}`, `type` ∈ **a, aaaa, mx, ns, soa, txt** (enumerated in the OpenAPI), paged. Each record is `{first_seen, last_seen, values[], organizations[]}` -> **the hosting org name is attached per historical window**, not just the IP. Plus `GET /v1/history/{hostname}/whois`, paged.

**WHOIS, certs, IP.** `GET /v1/domain/{hostname}/whois` (current, merged w/ stats) · `/ssl` (current **and historical** certs; `include_subdomains`, `status`) · `GET /v1/ips/{ipaddress}/whois` · `/useragents` (**user agents observed from that IP**, unusual; nobody else in this set ships it) · `GET /v1/ips/nearby/{ipaddress}` (neighbouring IPs w/ per-IP hosted-domain counts, CIDR mask allowed in the path)

**Search / pivot**
- `POST /v1/domains/list`: filter keys `ipv4` (CIDR ok), `ipv6`, `apex_domain`, `keyword`, `mx`, `ns`, `cname`, `subdomain`, `soa_email`, `tld`, `whois_email`, `whois_name`, `whois_organization`, `whois_telephone`, `whois_fax`, `whois_city`, `whois_postalCode`, `whois_street1`–`street4`. `?include_ips`, `?page`
- `POST /v1/domains/stats`: result counts for the same filter (**count before you pay to fetch**)
- `POST /v1/domains/list-backup`: DSL search, e.g. `whois_email = 'x@y.com'`, `?scroll`, `?include_ips`, `?page`
- `POST /v1/ips/list` (IP DSL, e.g. `ptr_part = 'ns1'`) · `POST /v1/ips/stats` · `GET /v1/scroll/{scroll_id}` (bulk cursor, DSL only)

**Feeds, bulk & reports.** `GET /v1/feeds/domains/{type}` zone-file feed (`?filter=cctld|gtld`, `?tld=`, `?ns=true`, `?date=YYYY-MM-DD`, default latest) · `GET /v1/feeds/subdomains/{type}` (`?filter`, `?tld`, conditionally required) · `GET /v1/reports/{project_id}/{report_type}` (sync) · `GET /v1/reports_async/...` -> `uuid` -> poll `GET /v1/downloads/status/{uuid}` (`downloading` / `completed` / `error` / 404) -> signed temporary `csv_file.link` / `json_file.link` · `GET /v1/company/{domain}/associated-ips`

**Attack-surface (SurfaceBrowser/project layer).** Projects list; asset search (`POST .../_search`) & find (cursor, `limit` max 1000, `sort_by` default `exposure_score`); read asset; list asset exposures (ports, signature detail, extracted versions); get filters (`asset_type`, `custom_tags`, `ip_owner`, `severity`, `open_port_number`, `certificate_expires_at`) returned UI-ready w/ `name`/`query`/`path`; per-asset & bulk tagging w/ async `task_ids`; list exposures / exposure assets; static-asset rules (bulk add/remove, max 1000/request).

### Category inventory: what the others add that SecurityTrails does not

| Capability | Where | Detail |
|---|---|---|
| **Bailiwick** metadata | DNSDB | "closest enclosing zone delegated to a nameserver which served the RRset". Distinguishes "answer from the real zone" from "answer via a hijacked or open resolver" |
| **Aggregated vs unaggregated, & provenance** | DNSDB `?aggr=false` | aggregated = one row per RRset w/ total count, unaggregated = distinct timestamped observations. Separate `zone_time_first`/`_last` vs `time_first`/`_last` keeps zone-file & sensor origin apart; at least one pair always present |
| **Summarize, Flexible Search, raw hex** | DNSDB | `/dnsdb/v2/summarize/…` gives counts & time bounds **without** streaming rows; glob + regex over rrnames & rdata; `TYPE=raw` on both rrset & rdata queries by wire-format octet string |
| **Rdata (inverse) lookups** | DNSDB `/dnsdb/v2/lookup/rdata/{name\|ip\|raw}/VALUE[/RRTYPE]` | IP single / prefix (`10.0.0.1,24`, **comma not slash**) / range (`a-b`) / IPv6 w/ `%3A`-encoded colons. Returns individual records, **no bailiwick**: re-query rrset if you need it |
| **Lookalike search** | Validin `/api/lookalike/domain/{domain}`, `/api/lookalike/regex` | newly-observed domains at **Levenshtein distance ≤ 2** by default; `similarity`, `depth`, `lookback`, `exclude` are tunable |
| **Host-response & cert pivots** | Validin `/api/axon/…/pivots` | pivot categories incl. JARM, FAVICON_HASH, BODY_SHA1, HEADER_HASH, CERT_CN/O/SERIALNUMBER/FINGERPRINT, TITLE, SERVER, ETAG, GTAG_ID, ONION_LOCATION |
| **Reputation & threat-actor index** | Validin | `…/reputation/quick` for domain & IP, bulk OSINT context, named threat groups w/ reports & indicators. Also fetches the artifact behind a hash: HTML by body SHA1, favicon by MD5, cert by SHA1 |
| **On-demand active scan & YARA** | Validin, Silent Push | start an HTTP/S scan of a host/IP on an arbitrary port & path, then poll; Validin also runs YARA over live + historical crawl telemetry, incl. retrohunt |
| **Subdomain enumeration** | Validin `/api/axon/domain/subdomains/{domain}` | first-class endpoint, Community tier incl. |
| **Live WHOIS/RDAP passthrough** | Validin `/api/axon/{domain,ip,cidr}/registration/live` | historical archive *and* on-demand live lookup behind one API. **Enterprise tier only** per the pricing comparison table |
| **nshash / mxhash** | Silent Push | hash the whole NS-set or MX-set, track & pivot on the hash. A registrar or mail-provider migration becomes one event |
| **Domain density / IP diversity** | Silent Push PADNS density lookup | unique domains per IP/ASN/NS, unique IPs per domain, as scored metrics (low diversity -> suspicious, high -> CDN) |
| **Self-hosted & dangling DNS** | Silent Push, own tab + query builder | "domains where nameservers are hosted on the same IP" (phishing tell); plus CNAME/A pointing at de-provisioned infra, flagged `expired` / `unresolved` |
| **Live DNS resolution beside the archive** | Silent Push "Tools - Live DNS Lookup" | real-time A/AAAA/CNAME/MX resolution inside the same query builder as PADNS |
| **Risk scores from daily IPv4 scanning** | Silent Push | domain, IP & **nameserver** reputation scores; JARM / HTTP-header / cert / ssdeep pivots off the same scan. Exports CSV/JSON/TXT/**RPZ**/STIX; SPQL query language is **alpha** per its own docs |
| **COF output over ndjson** | CIRCL | `application/x-ndjson`; v2.0 (Nov 2023) added pagination & filtering headers. CIDR unsupported |

## Record types & query options supported

| Axis | SecurityTrails | DNSDB | Validin | Silent Push | mnemonic |
|---|---|---|---|---|---|
| History RR types | a, aaaa, mx, ns, soa, txt | **any** RRtype; `ANY` excludes DS/RRSIG/NSEC/DNSKEY/NSEC3/NSEC3PARAM/DLV/CDS/CDNSKEY/TA, pseudo-mnemonic `ANY-DNSSEC` returns exactly those | A, AAAA, NS, NS_FOR, CNAME(+`_FOR`), MX(+`_FOR`), SOA_MNAME/RNAME(+`_FOR`), TXT, CAA(+issuer/wild), SRV(+target), HTTPS, PTR, NX, plus `WAYWARD_*` malformed variants | A, AAAA, CNAME, MX, NS, PTR4, PTR6, SOA, TXT, ANY | `rrType=` filter; `a`/`cname`/`ns` observed |
| Reverse (rdata -> names) | `/ips/nearby`, `ipv4` filter, 120-day window | first-class `rdata` index | `/api/axon/ip/dns/history/{ip}`, `…/hostname`, CIDR variants, `*_FOR` types | reverse A + density queries | **same endpoint, bidirectional** (below) |
| Wildcards | `keyword`, `subdomain` filters | `*.example.com` (left, expensive), `www.example.*` (right, cheap) | `?wildcard=` | regex filters | no |
| CIDR | `ipv4` filter, `ips/nearby` | `10.0.0.1,24` or `a-b` | `/api/axon/ip/dns/history/{ip}/{cidr}`, CIDR PTR/pivot/OSINT/crawl | yes | **no, 404 firsthand** |
| Time fencing | none, paging only | `time_first_before/after`, `time_last_before/after` | `first_seen`, `last_seen`, `lookback` | timestamp filters | none documented |
| Output knobs | JSON only | `limit` (`0`=max), `offset`, `aggr`, `humantime` (RFC3339 vs epoch), `swclient`/`version`/`id` client tagging, `Accept: application/x-ndjson` | `limit`, `time_format`, `annotate`, `exclude_nx` | SPQL (alpha) | `limit`, `offset`, `rrType` |
| Resolver choice, +trace, TCP, EDNS/ECS, DNSSEC flag | **none of it** | none | none | **live lookup exists as a separate tool**, not as pDNS options | TTL *is* carried: `minTtl`/`maxTtl` |

**Blunt point for the owner:** every dig-style knob (pick resolver, +trace, +tcp, +dnssec, ECS) is **structurally absent** from a pDNS query, because pDNS has no resolver to aim. But note Silent Push ships a live resolver *beside* its archive in one query builder, so "history and live in one product" is a validated shape, as long as the two are separate controls and separately labelled results, not one blended list.

## How it works

**Collection.** Sensors sit on recursive resolvers (vendor-operated plus partner-contributed) and capture the *responses* to cache misses. DNSDB additionally imports **zone files**, which is why its records carry two independent timestamp pairs, and why a zone-file-only record has no sensor timestamps at all. Validin layers first-party HTTP/S crawling, CT-log ingestion, WHOIS/RDAP normalization & ~650 OSINT sources onto the DNS spine (source: its own pricing page). Silent Push's docs repeatedly describe "a daily scan of the Internet's IPv4 infrastructure" feeding its risk scores.

**Storage shape: two indexes, not one.** **rrset** (forward, keyed on owner name, whole RRsets + bailiwick) and **rdata** (inverse, keyed on the answer value, individual records, **no bailiwick**). DNSDB documents the split and tells you to re-query rrset on any rrname an rdata lookup returned. Everything else in the category is a variation on those two indexes. **Firsthand detail worth copying: mnemonic's index is bidirectional on one path.** `GET /pdns/v3/{term}` matches `term` against **both** the `query` and the `answer` field:
- `/pdns/v3/example.com?rrType=a` -> 21 rows, `query=example.com` (forward)
- `/pdns/v3/93.184.216.34` -> 1,000 rows, `query=platelet.rxrx.io, answer=93.184.216.34` (reverse-IP)
- `/pdns/v3/elliott.ns.cloudflare.com?rrType=ns` -> `query=ww940.us.kg, answer=…` (reverse-NS)

One route, one handler: forward + reverse + reverse-NS. The result cap is **1,000 rows and the API says so**: `?limit=5000` returns **HTTP 412** w/ `"Maximum result limit for public usage is 1000"`, and a capped 200 response tags every row `flags:["partialResult"]`. CORS: it returns `access-control-allow-headers`/`-methods` but **no `access-control-allow-origin`**, so a browser cross-origin fetch fails; a Go server calling it is fine.

**Freshness.** pDNS is append-only observation, not a cache. `last_seen` ticking today means a sensor saw it today, not that the record is live now. A record can be live and absent (no sensor saw it) or dead and present (`last_seen` months old); both states must be renderable.

## Output & UX

**SecurityTrails UI: not observed** (403 on every page, no exceptions). What the OpenAPI *schema* implies, and nothing more: a domain view of record-type sections, each value carrying a **co-occurrence count**, and history as a paged per-record-type list. The co-occurrence stat is the interesting UX primitive: the documented example prints `nameserver_count: 5213` next to `ns4.dnsmadeeasy.com`, turning every value into a visible pivot w/ a size hint before you click. Treat layout, shareable URLs, progressive rendering, export UX & empty states as **unknown**.

**Streaming & framing (DNSDB, documented).** Responses are **JSON Lines** framed w/ control objects: `{"cond":"begin"}` … `{"obj":{…}}` … terminating in `{"cond":"succeeded"}` or `{"cond":"limited","msg":"Result limit reached"}`; empty `{}` objects are keep-alives during slow scans. A long query renders progressively and **states explicitly that it was truncated** instead of silently returning a short list. **Validin's response envelope** is the cleanest small-tool model found: `{query_opts, query_key, status, records:{A:[{key,value,value_type,first_seen,last_seen}]}, records_returned, limited}`, timestamps as Unix epoch seconds. `limited: true` is a first-class boolean, `records` is a type-keyed map of uniform observation objects, trivially renderable as one table per RR type.

**Exports.** SecurityTrails async reports (uuid -> poll -> signed temporary CSV/JSON URLs); DNSDB a bulk Export product + the `dnsdbq` CLI; Silent Push CSV/JSON/TXT/RPZ/STIX; Validin webhooks (beta) plus Splunk / Cortex XSOAR / MISP / Synapse.

## Monetization, limits & abuse controls

**What is sold is depth, breadth & freshness, not the lookup.** Current records are free everywhere. **History is the paywall**, gated on three axes at once: *time depth* (Validin Community ">4 years", SecurityTrails claims 2008, reverse capped at 120 days), *result width* (Validin 250 -> 1,000 -> 2,500 -> 20,000+ rows by tier), and *query volume* (Validin 10/day free -> uncapped enterprise). Whole *datasets* are gated too: Validin puts WHOIS/RDAP registration search on Enterprise alone.

**DNSDB's quota model** is the most instructive. Three quota kinds: **time-based** (resets 00:00 UTC), **block** (purchased pool w/ an expiry), **unlimited**. Plus an independent **burst** quota (`burst_size` requests per `burst_window` seconds, e.g. 5/360s). `GET /dnsdb/v2/rate_limit` returns `{limit, remaining, reset, expires, results_max, offset_max, burst_size, burst_window}` and, the good part, **does not count against quota**. `results_max` silently overrides a larger `?limit`. `offset_max` can be `"n/a"`, meaning offset is forbidden for that key, and exceeding it yields **HTTP 416**, not a generic error.

**Abuse controls.** SecurityTrails fronts everything w/ a **Cloudflare bot challenge** (`cf-mitigated: challenge`), confirmed firsthand, which is why this report has no UI observations. CIRCL gates on *identity* rather than volume. DNSDB warns left-hand wildcards are "more expensive and slower", pricing query *shape* as well as count. mnemonic enforces its cap in-band w/ a `412` and a plain-English message, the friendliest of the lot.

## Ideas worth stealing

- **Ship the history table as the headline result, not a tab.** The example.com table above is ~7 rows of `answer / first seen / last seen / count` and it beats the entire live-record panel above it. Build that view first.
- **One bidirectional route.** Copy mnemonic exactly: `/pdns/{term}` where `term` is a name **or** an IP, matched against both key & value. One handler, one domain method, one template, and it yields forward lookup, reverse-IP & reverse-NS for free. Content-negotiate to JSON per golden rule #2.
- **`limited: bool` in the envelope, plus an in-band error for over-limit requests.** Steal Validin's field verbatim and mnemonic's `412 "Maximum result limit … is 1000"`. When a result set is capped, say so in the payload and render a visible "truncated at N" row.
- **Render the junk as junk.** Single-observation answers, RFC1918/loopback rdata and answers whose window never overlapped the domain's registration are noise. Sort by `count`, dim or fold the one-offs, and never let `127.0.0.1` sit in the same visual weight as a 334k-observation CDN row.
- **Aggregated vs unaggregated as one toggle.** One checkbox, two renderings of the same rows: collapsed (one row per distinct answer, total count, min first / max last) vs expanded (every observation window). DNSDB charges for this distinction; for you it is a `GROUP BY`.
- **Co-occurrence count, and the org, beside every value.** SecurityTrails' `nameserver_count` idea computes fine over your own accumulated lookup history ("this NS seen on 12 of your past lookups"), one aggregation against the existing Mongo collection (CLAUDE.md rule #5). Its history records also carry `organizations[]`: "Akamai -> Cloudflare" is the story, a column of raw IPs is not, and `tools/iptools` already resolves ASN/org.
- **`nshash` / `mxhash`.** Silent Push's cheapest good idea: hash the *sorted set* of NS records (and of MX records) into a short digest, store it w/ each lookup, and a provider migration becomes one diff event instead of four record diffs. Roughly 15 lines of Go, gives "DNS provider changed on 2026-04-10" as a first-class timeline entry.
- **Build your own pDNS from your own traffic, in COF field names.** The tool already stores lookup history; persisting `(rrname, rrtype, rdata, time_first, time_last, count, bailiwick, sensor_id, origin)` per resolution makes the site a tiny honest passive-DNS sensor after a few months, and those exact names (newline-delimited as `application/x-ndjson`, like CIRCL) make the JSON interoperable w/ PyPDNS & passivedns-client on day one. Free, no vendor, no key, the only history nobody can take away.
- **`humantime` toggle, count-before-fetch, provenance per row.** DNSDB's `?humantime=t` (Validin's `time_format`) flips epoch seconds to RFC3339: one bool, and it decides whether a human can read your JSON. `POST /domains/stats` mirrors `/domains/list`; a `?count_only=1` lets an htmx page show "1,204 results" instantly and defer the render behind a click. And DNSDB separates zone-file from sensor timestamps: if you merge live dig + a pDNS API + your own history, tag each row w/ its origin and render the tag, never blending "I resolved this just now" w/ "someone's sensor saw this in 2019".

## Gaps & what it does not do

- **No resolver control, no trace, no DNSSEC validation, no EDNS/ECS, no TCP toggle, no propagation check** in a pDNS query itself. It cannot say what `8.8.8.8` returns vs `1.1.1.1` right now, cannot walk a delegation chain, cannot validate a signature. Complement to a dig tool, never a replacement.
- **TTL is mostly lost** (only mnemonic surfaced TTLs firsthand, `minTtl`/`maxTtl` per observation; SecurityTrails' schema carries `ttl` only inside SOA values), and **reverse history is shallow even where forward history is deep**: 120 days at SecurityTrails, per Recorded Future's own page.
- **Coverage is sensor-shaped.** Low-traffic, internal & split-horizon records may be entirely absent. Absence is never evidence of non-existence, and the UI must not imply otherwise.
- **Nothing here is free at scale.** The one genuinely open source (mnemonic) caps at 1,000 rows, sends no `access-control-allow-origin`, publishes no rate limit or SLA (its public site `passivedns.mnemonic.no` did not even render for me), and could close tomorrow. Any decision resting on it needs a graceful-degradation path.
- **No DNS health auditing & no email-auth checks** in the core pDNS products; reputation/blocklist scoring exists only where a vendor bolts it on (Silent Push, Validin). And SecurityTrails is the worst-documented option for a hobby build, precisely because the number you must plan against sits behind the one page you cannot read.

## Verified firsthand vs inferred

**Verified firsthand (2026-09-15/16, curl/dig from this machine).** `securitytrails.com` `/`, `/dns-trails`, `/corp/pricing`, `/app/signup` all **403**, `server: cloudflare`, `cf-mitigated: challenge`; WebFetch 403s too. `api.securitytrails.com/v1/ping` **401** `"Please check user credentials"`. `docs.securitytrails.com` reachable, `llms.txt` + per-page `.md` OpenAPI: **every SecurityTrails endpoint, path template, parameter, enum & filter key above was read out of that OpenAPI**, incl. the `a/aaaa/mx/ns/soa/txt` enum, the `/feeds/domains/{type}` & `/ips/nearby/{ipaddress}` paths, the `organizations[]` / `*_count` / `alexa_rank` response fields, and the `updatedAt: 2025-06-05` staleness markers. `www.circl.lu/pdns/query/example.com` **401** (HTTP basic). `api.mnemonic.no/pdns/v3/…` **200 JSON**, no auth, bidirectional matching, 21 A rows for example.com w/ the dates & counts tabled above, `?limit=5000` -> **412** `"Maximum result limit for public usage is 1000"`, `flags:["partialResult"]` at the cap, CIDR path -> **404**, no `access-control-allow-origin`. `app.validin.com/pricing` **200**: all Validin prices, limits & tier gating above read off that live page, incl. its internal 250-vs-500 contradiction; all Validin endpoint paths & query params read from `docs.validin.com` OpenAPI. **`api.validin.com` is NXDOMAIN** while Validin's own API overview tells integrators to open outbound HTTPS to it; the OpenAPI `servers` default is `app.validin.com`. `api.hackertarget.com` **200** w/ `access-control-allow-origin: *`, `x-api-quota: 21`, `x-api-count: 0`, `x-api-boost: 0`. `otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns` **429**, `X-Remote-User-Name: Anonymous`, `Access-Control-Allow-Origin: *`. `crt.sh/?q=%25.example.com&output=json` **200**, ~25 KB JSON, no key (one transient 404 during probing, so treat it as best-effort). Live `dig example.com A` results quoted above. OSS licences below read from each repo's `LICENSE` / source headers.

**Documentation-only, no query executed.** **DNSDB**: every quota, framing, path-template, bailiwick, `ANY`/`ANY-DNSSEC` and HTTP-416 claim comes from docs.domaintools.com (pages dated **31 Mar 2026**); no API key, nothing run. **Silent Push**: help.silentpush.com renders for me and is the source of the PADNS record types, nshash/mxhash, density, dangling DNS, Live DNS Lookup, Live Scan, SPQL & export formats; the interactive API reference sits behind login, so **no endpoint path template below the base URL and no Community-tier quota is known**. `silentpush.com` itself **403**s. **Validin runtime behaviour**: paths & parameters from the public OpenAPI, no query executed.

**Still unverified, do not build on it.** SecurityTrails' **free-tier quota**: three secondhand figures (50/mo, 2,000/mo, 10,000 credits/mo) that contradict each other, no first-party source reachable. **Whether SecurityTrails still offers self-serve signup at all**: `/app/signup` 403s; the docs still describe self-service key retrieval, which is suggestive, not proof. **SecurityTrails paid tier prices & what each tier gates**: pricing page unreachable. **The "10.19 trillion historical DNS lookups" / "2.6 billion hostnames" marketing figures**: attributed to `/dns-trails`, which 403s; cut from this report rather than repeated. **Whole SecurityTrails web UI**: never seen. **mnemonic's terms of use & retention policy**: no public documentation found, and its own site did not load.

## Open source / reusable

- **[PyPDNS](https://github.com/CIRCL/PyPDNS)** (CIRCL, **BSD-2-Clause**): Python client for COF-speaking pDNS servers. Read it for client-side field handling.
- **[analyzer-d4-passivedns](https://github.com/d4-project/analyzer-d4-passivedns)** (D4 project, **AGPL-3.0**): a pDNS *server*: ingest, dedupe, expose COF. The reference implementation if you ever store your own tuples. **Read the licence before vendoring anything**: AGPL reaches network use, which is exactly what corpberry.com is.
- **[passivedns-client](https://github.com/chrislee35/passivedns-client)** (**MIT**, last pushed 2021): multi-provider abstraction layer; its provider list is a free survey of who still exists, but it is effectively unmaintained.
- **[passivedns](https://github.com/gamelinux/passivedns)** (gamelinux, **GPL-2.0 per source headers, no `LICENSE` file in the repo**): the classic C sensor. Shows exactly what a sensor captures & what it discards.
- **[draft-dulaunoy-dnsop-passive-dns-cof](https://datatracker.ietf.org/doc/html/draft-dulaunoy-dnsop-passive-dns-cof)**: the Common Output Format. Short, readable, the right field names to copy. Latest revision **-13** (submitted 29 Aug 2024), now **expired & archived** (2 Mar 2025), but it remains the de-facto interop format.

## Sources
- SecurityTrails: [docs index (`llms.txt`)](https://docs.securitytrails.com/llms.txt) · [overview](https://docs.securitytrails.com/docs/overview) · [authentication](https://docs.securitytrails.com/docs/authentication) · [DNS history by record type (OpenAPI)](https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1) · [Get Domain (OpenAPI)](https://docs.securitytrails.com/reference/get-domain-old-1)
- [Recorded Future support, SecurityTrails](https://support.recordedfuture.com/hc/en-us/articles/360053545614-SecurityTrails) · [Recorded Future acquires SecurityTrails, $65M (SecurityWeek)](https://www.securityweek.com/recorded-future-acquires-securitytrails-65m-deal/)
- [DNSDB RRset lookups (DomainTools)](https://docs.domaintools.com/api/dnsdb/lookups/rrset-lookups/) · [Rdata lookups](https://docs.domaintools.com/api/dnsdb/lookups/rdata-lookups/) · [service limits & quotas](https://docs.domaintools.com/api/dnsdb/rate-limits/) · [other query parameters](https://docs.domaintools.com/api/dnsdb/query-parameters/other-parameters/)
- [Validin pricing](https://app.validin.com/pricing) · [API documentation index (`llms.txt`)](https://docs.validin.com/llms.txt) · [API overview](https://docs.validin.com/docs/overview-3) · [standard response format](https://docs.validin.com/docs/standard-response) · [Domain DNS History (OpenAPI)](https://docs.validin.com/reference/getdnshistory)
- [Silent Push API capabilities](https://help.silentpush.com/docs/api) · [PADNS queries](https://help.silentpush.com/docs/passive-dns-queries-1) · [Live DNS Lookup](https://help.silentpush.com/docs/tools-live-dns-lookup) · [Dangling DNS tab view](https://help.silentpush.com/docs/dangling-dns-tab-view) · [docs index (`llms.txt`)](https://help.silentpush.com/llms.txt)
- [CIRCL Passive DNS service](https://www.circl.lu/services/passive-dns/) · [HackerTarget IP tools & API limits](https://hackertarget.com/ip-tools/) · [Passive DNS Common Output Format (IETF draft, expired)](https://datatracker.ietf.org/doc/html/draft-dulaunoy-dnsop-passive-dns-cof)
- [mnemonic PassiveDNS public API (probed directly at `api.mnemonic.no/pdns/v3/`)](https://passivedns.mnemonic.no/)
