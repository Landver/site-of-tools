# DNS monitoring, change alerting & historical records

Every DNS tool gives away the lookup and sells the *second* lookup: scheduled re-checks, a diff against last known state, an alert when NS/MX/A moves, and an archive of what the domain used to point at. This report inventories that premium tier so the owner can pick which slices a DNS-lookup feature should carry, and decides one structural question up front: **monitoring is the only part of DNS tooling that needs persistent state + a scheduler**, so it is the argument for (or against) this being more than a stateless page.

- **Scope:** scheduled re-check & diff mechanics, alert-worthy record classes, historical/passive-DNS archives, what the named services store & charge. · **Why it matters for our build:** we already own every primitive this needs (nil-safe Mongo repo, `platform.EnsureTTLIndex`, a daily-ticker sync w/ staleness guard) so the *cheap* version is days, not weeks. The expensive part is alert delivery, not detection.
- **Firsthand check:** `dig` against public resolvers & authoritative NS (SOA serials, NS-set divergence, RRSIG windows, CAA/DMARC); `curl` against SecurityTrails, CompleteDNS, MXToolbox, ViewDNS, mnemonic pDNS, crt.sh, RDAP, DoH-JSON & RIPEstat to establish which need keys and which set CORS. All numbers below checked **2026-09-15** unless stated.

## The mechanics

**A "DNS change" is an RRset diff, not a string diff.** Unit of comparison is `(qname, type)` -> *set* of rdata, unordered. Naive detection compares the previous answer text to the current one & fires on every reorder. Canonicalize first: lowercase names, absolute trailing dot, sort rdata, drop TTL from the compared value (TTL is metadata, worth tracking separately), then hash the sorted set. One `sha256` per `(name,type)` is the whole change primitive, & it is the same shape as botcheck's `Signals.FingerprintHash()`.

**SOA serial is not a usable change signal.** It is the obvious idea and it is wrong on managed DNS. Firsthand, across seven zones:

| zone | authoritative SOA serial | reading |
|---|---|---|
| `cloudflare.com` | `2414895867` | CF epoch-ish counter, moves |
| `stackoverflow.com` | `2414936629` | CF, moves |
| `corpberry.com` | `2413098639` | CF, moves |
| `shopify.com` | `2414983861` | Foundation DNS, moves |
| `wikipedia.org` | `2026060420` | classic `YYYYMMDDnn` |
| `github.com` | `1` | **Route 53: frozen at 1** |
| `netflix.com` | `1` | **Route 53: frozen at 1** |

Route 53 never increments it, so a serial-watcher is blind on a large slice of the internet. Worse, `github.com` runs two providers & they disagree *by design*: its four NS1 servers answer serial `1656468023` while its four Route 53 servers answer `1`. A cross-NS serial comparison flags that zone as broken forever. Uptrends markets SOA-serial monitoring as a feature; treat that as a legacy-zone feature, not a general one.

**"The answer changed" is not "the record changed."** The load-bearing failure mode. `netflix.com`, queried at one instant against its own four authoritative Route 53 servers, returned **three different A sets**:

```
ns-1372.awsdns-43.org.    3.251.50.149  54.155.178.5    54.74.73.31
ns-1984.awsdns-56.co.uk.  18.200.8.190  54.155.246.232  54.73.148.110
ns-659.awsdns-18.net.     52.214.181.141 54.170.196.176 54.246.79.9
ns-81.awsdns-10.com.      18.200.8.190  54.155.246.232  54.73.148.110
```

Public resolvers split the same way (1.1.1.1 / 9.9.9.9 / AdGuard saw one set, 8.8.8.8 / OpenDNS / Yandex another). Latency-routed, weighted & geo-routed names churn their A rdata continuously. Any diff engine that treats churn as change will alarm hourly. Mitigations, in ascending cost: exclude `A`/`AAAA` from alerting by default & watch `NS`/`MX`/`TXT`/`CAA`/`SOA`/`DS` (the records that actually signal takeover); or learn a rolling **value pool** per name & alert only on a value never seen before; or alert only when the *entire* set is disjoint from the previous set.

**Baseline acquisition.** AXFR is the clean way to enumerate a zone & is refused by essentially every public zone (DNS Spy offers it as an *opt-in* for zones you control). Without it: probe a fixed type list at the apex plus a wordlist of common labels, or import names from CT logs & passive DNS. Both of the latter are free and CT is CORS-open (below).

**Re-check cadence.** TTL is the natural floor: re-checking faster than TTL just reads your resolver's cache. `corpberry.com` A carries TTL 300, `github.com` MX 107. Commercial intervals run from Uptime Kuma's effectively-unbounded floor (`MIN_INTERVAL_SECOND = 1`, verified in its source; the UI just nags under 20s and demo mode clamps to 20s) to Oh Dear's **2h default** (which auto-skips `A`/`AAAA` once it detects Cloudflare nameservers, i.e. it already ships the churn mitigation below). For change detection (not uptime), hourly-to-daily is honest; sub-minute is an uptime product, a different thing.

**History has two distinct data models, and tools blur them.**
- **Active-snapshot archive**: the vendor resolves the name on a schedule & stores each snapshot. SecurityTrails, CompleteDNS, DNS Spy. Authoritative truth, but only for names the vendor knew to ask about.
- **Passive DNS (pDNS)**: sensors record *observed* resolver answers & aggregate to `(query, answer, rrtype, first-seen, last-seen, count)`. Sees names you never submitted, incl. long-dead subdomains, but never proves absence.

## What the popular tools actually do about it

| service | watches | interval | alerts via | history | price (checked 2026-09-15) | provenance |
|---|---|---|---|---|---|---|
| **DNS Spy** | records, WHOIS lifecycle, TLS, typosquats (Phishing Sentinel), RFC lint | not published | email (all), + Slack/Discord/PagerDuty on Enterprise | per-record change log + zone backup | Personal from **€4.99/mo**, 10 domains; Enterprise 100 + 50-packs | search-result summaries, cross-corroborated across 3 independent queries (`/pricing`, `/features`, `/features/notifications`); vendor site still 403s curl & WebFetch directly |
| **Oh Dear** | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA per exact hostname; auto-skips A/AAAA once it detects Cloudflare NS | **2h default**, adjustable | per-hostname routing, separable "records changed" vs "check failed" | before/after side-by-side, newest-first, names the disagreeing NS; API-readable | n/a (bundled w/ uptime) | WebFetch of vendor feature page (fetched twice, consistent) |
| **MXToolbox** | "DNS Zone Protect": record + subdomain changes; 100+ RBLs; mailflow | "instant"; web checks 5 min | email (free tier) | change log | Free = **1 monitor**, top 30 RBLs, **checked weekly**; Delivery Center **$129/mo**, Plus **$399/mo** | free-tier limit confirmed firsthand via vendor's own `mxtoolbox.com/c/products/matrixdos` page (200); the two dollar figures are secondary (search-corroborated 3x, but `mxtoolbox.com/pricing` 404s — that URL doesn't exist) |
| **whatsmydns.net** | records + NS across ~20 country resolvers; selective or full zone import | not published | email; webhooks on paid | change notifications | Free = **3 monitors**; Starter **$9/mo** (unconfirmed — see note) | site 403s curl & WebFetch; a fresh search turned up **no independent corroboration** and one result suggests the "$9/mo Starter" figure may be bleeding in from an unrelated vendor (Site24x7 has its own identical "$9/mo Starter" plan in the same result set) — treat this row as low-confidence, possibly wrong |
| **SecurityTrails** | n/a (data API, not a monitor) | n/a | n/a | DNS + WHOIS + SSL history, subdomains | two separate products, not a contradiction: general free API plan = **10,000 credits/mo**; a distinct researcher-only, non-commercial "OSINT Toolkit" = **2,500 queries/mo** | endpoints & auth verified firsthand; both quota figures are search-corroborated (pricing page still 403s) |
| **CompleteDNS** | nameserver changes only | daily | n/a | **2.2B NS-change records since 2002**, parked detection, 5,000-domain bulk | 3 free reports; `reports-left` header | API auth behaviour verified firsthand |
| **Uptime Kuma** | A/AAAA/CAA/CNAME/MX/NS/**PTR**/SOA/SRV/TXT (10 types) vs expected value, chosen resolver | **1s hard floor** (`MIN_INTERVAL_SECOND` constant); UI warns and demo mode clamps under 20s | ~90 notification providers | status page | free, self-hosted | **verified firsthand**: `src/util.ts` and `src/pages/EditMonitor.vue` on GitHub (`louislam/uptime-kuma`, fetched directly) |
| **Uptrends / Dotcom / Catchpoint** | resolution time + availability from 30 to 184 checkpoints | sub-minute | integrations | 36-month retention (Dotcom) | $16.20/mo to $39.95/mo entry | secondary roundup |

**Distinctive mechanics worth the paragraph.**

*Oh Dear splits the alert taxonomy*, and this is the detail most tools get wrong. A **check failure** (authoritative NS disagree, NS unreachable, records not found) is blocking & pages you. A **record change** is a separate notification you can mute independently, per hostname. Config lint (`+all` in SPF, two SPF records on one name, DMARC on the wrong name) is advisory only & never fires. Three severity classes, three routes. It also auto-drops `A`/`AAAA` from the watch set the moment it sees a Cloudflare NS delegation, which is exactly the churn mitigation this report's mechanics section argues for independently, i.e. a shipped vendor already validates that approach. Copying the taxonomy + the Cloudflare special-case is free and is most of the perceived product quality.

*DNS Spy's original pitch was "SSL Labs for DNS"*: a public letter-grade across connectivity (v4/v6 parity), performance, resilience (multiple providers, DNSSEC, CAA) & security (SPF/DMARC, TTL sanity, NS alignment), plus AXFR-seeded baselines, CNAME resolving and NS-mismatch warnings. Its current site adds **Phishing Sentinel**: per search summaries of its own `/features` page, it runs a `dnstwist`-style permutation engine (17+ techniques: repetition, TLD swap, hyphenation, insertion, homograph…), scores each hit 0–100 by attack technique + live infrastructure (hosting, MX, TLS), and only surfaces domains that actually resolve. Worth knowing: the permutation engine it's presumably built on, [`elceef/dnstwist`](https://github.com/elceef/dnstwist), is **Apache-2.0** (its `LICENSE` file fetched directly, verified firsthand) and free to self-host — Phishing Sentinel's differentiator is the scoring/infra-enrichment/lifecycle wrapper around a freely available primitive, not the permutation logic itself. Ownership moved from Mattias Geniar to SecurityTrails in Sept 2020; the present site reads like a later relaunch, and I could not read it firsthand to confirm who runs it now.

*CompleteDNS sells one field.* It stores **nameserver** history only, not A/MX/TXT, and that narrowness is the product: 2.2B change events back to 2002, which is what domain investors & takedown researchers actually query. API is a single endpoint, `GET https://api.completedns.com/v2/dns-history/{domain}?key=…`, quota returned in a `reports-left` response header. Verified firsthand: no key -> `500`, bogus key -> `401 {"error_type":"api_key_not_valid"}`.

*SecurityTrails is the history layer everyone else resells.* Verified endpoints (OpenAPI via `docs.securitytrails.com/llms.txt`, auth header `APIKEY` or `?apikey=`): `GET /v1/history/{hostname}/dns/{type}` with type in **a, aaaa, mx, ns, soa, txt**; `GET /v1/history/{hostname}/whois`; `GET /v1/domain/{hostname}/subdomains`; `GET /v1/domain/{hostname}/ssl` (current + historical certs); `/v1/ping`, `/v1/usage`. Unauthenticated calls return `401 "Please check user credentials"`, confirmed.

**Table-stakes, one line each:** record-type selection · before/after diff view · email alerts · webhook alerts · domain-expiry reminder · TLS-expiry reminder · NS-set change alert · MX change alert · resolution-failure alert · public status page · maintenance/snooze windows · bulk import · API access to history · retention depth as the paid axis.

**Free, keyless sources I confirmed work** (this is what makes a cheap imitation possible):

| source | gives | auth | CORS | firsthand result |
|---|---|---|---|---|
| **RDAP** `rdap.org/domain/{d}` | expiry & last-changed events, EPP status, registrar, NS set, `secureDNS.delegationSigned` | none | `Access-Control-Allow-Origin: *` | 200; `corpberry.com` expiry `2027-06-26`, status `client transfer prohibited` |
| **crt.sh** `?q=%25.{d}&output=json` | every CT-logged cert, `not_before`/`not_after`, SAN names | none | `*` | 200; **89 distinct names** under `corpberry.com` from 366 rows (re-checked 2026-09-16; CT logs grow, so exact counts drift day to day — don't hardcode a number, hardcode the query) |
| **mnemonic pDNS** `api.mnemonic.no/pdns/v3/{d}` | `query, answer, rrtype, firstSeenTimestamp, lastSeenTimestamp, times, min/maxTtl, tlp` | none | **no `allow-origin`** -> server-side only | 200; 62 records / **60 distinct qnames** for `corpberry.com`, incl. dead subdomains & two retired A records |
| **DoH JSON** `dns.google/resolve`, `cloudflare-dns.com/dns-query` | live answers as JSON | none | yes | 200 both |
| RIPEstat `dns-chain` · networkcalc · hackertarget | convenience resolution | none | varies | 200 each |

Contrast: SecurityTrails `401` · ViewDNS `401` · MXToolbox API `401` · VirusTotal `401` · AlienVault OTX `429` anonymous · bgp.tools `307` to login · dnshistory.org `403` Cloudflare challenge.

## Options for us, w/ trade-offs

| option | what it buys | cost/complexity | risk |
|---|---|---|---|
| **A. Passive lookup history** (mirror `tools/iptools/history.go`): store `(name, type, rdata-hash, sorted rdata, ts)` on every user lookup, TTL-indexed | "last seen 3 days ago, MX changed since" for free, on anything anyone looked up; zero scheduler | ~1 file, 1 collection, reuses `EnsureTTLIndex` & the background-goroutine write | low. Sparse by nature: history exists only where traffic did |
| **B. Diff view on repeat lookup** (needs A) | the actual wow moment: look a domain up twice, see what moved, w/ before/after | one Mongo read + set-diff in domain pkg, htmx fragment | low. Needs the canonicalization rules above or it lies |
| **C. Opt-in watchlist w/ daily re-check** | real monitoring; reuses `runDailySync`/`ShouldSync`/`time.NewTicker` already in `iptools/blocklist.go` | new collection + bounded worker + per-domain caps | medium. Now we make recurring outbound queries on a schedule; unbounded list = abuse vector |
| **D. Alert delivery: Atom/RSS feed per watched domain** | alerting w/ **zero** SMTP, deliverability, bounce or unsubscribe surface; readers poll us | one handler, one template | low. The right first channel for a hobby tool |
| **E. Alert delivery: user-supplied webhook** | Slack/Discord/n8n compatible in one field | one POST w/ timeout + retry cap | medium. SSRF: outbound POST to an arbitrary URL from our box needs scheme/IP-range filtering |
| **F. Alert delivery: email** | what users expect | SMTP provider, DKIM/SPF on corpberry.com, bounce handling, unsubscribe | high for the value; skip until B–D prove demand |
| **G. Free history enrichment**: RDAP + crt.sh + mnemonic pDNS cards | instant "history" without owning any archive; pDNS surfaces forgotten subdomains, CT dates every cert | 3 small server-side fetchers w/ cache; RDAP & crt.sh could even go client-side (CORS `*`) | medium. Third-party uptime & rate limits; mnemonic needs a proxy. Label every value "observed by X", never "current" |
| **H. Config lint / letter grade** (DNS Spy's angle) | differentiator, pure computation, no storage | domain-pkg rules over an already-fetched record set. Prior art beyond DNS Spy: **intoDNS** and **Zonemaster** (Zonemaster is itself open source, per its GitHub link) run the same style of check publicly & for free; a typosquat/homograph pass can lean on **dnstwist** (Apache-2.0, self-hostable, confirmed above) instead of reimplementing permutation logic | low. Grades invite argument; keep advisory, like Oh Dear |
| **I. DNSSEC RRSIG expiry countdown** | genuinely rare in the roundups | parse RRSIG expiration, subtract now | low. Needs `+dnssec` queries & a validating path |

Lean: **A + B + G + H first** (no scheduler, no delivery, no abuse surface, and G alone makes the page look like it has years of data). **C + D** as the second beat if the diff view gets used. Skip F.

## Hard constraints & failure modes

- **Alert fatigue kills the feature**, and geo/latency-routed A records are the cause. Default the watch set to `NS, MX, TXT, CAA, SOA, DS`; make `A`/`AAAA` opt-in with a value-pool rule.
- **SOA serial is unreliable** (Route 53 pins it at `1`) and **cross-provider serial comparison is meaningless** (`github.com`: `1656468023` vs `1` simultaneously).
- **Resolver caching hides changes.** Querying `1.1.1.1` shows you a cached view up to TTL old. Ground truth means querying the zone's own NS, which is N queries per check, not one, & the answers may legitimately differ (netflix above). Budget for it.
- **DNSSEC signatures expire on a short clock**: firsthand, `cloudflare.com` A RRSIG ran inception `20260914195623` -> expiration `20260916215623`, a **~2-day window**. A zone whose signer stalls goes SERVFAIL for validating resolvers while plain `dig` looks fine.
- **Outbound scheduled queries from a Hetzner box** are the same class of traffic that shelved the port scanner. DNS is far tamer than port scanning, but a watchlist is unbounded-by-default: cap domains per visitor, cap total watches, cap per-tick query volume, honour TTL as the floor.
- **Webhooks are SSRF.** Deny private/link-local/loopback ranges & non-HTTPS schemes before the first POST.
- **We would be storing what people looked up.** iptools already accepted this w/ a 90-day TTL & a deliberately narrow projection; botcheck's corpus stores a one-way hash & 30-day TTL. A DNS history collection should follow: minimal fields, TTL index, no requester identity.
- **Third-party freebies can vanish.** mnemonic, crt.sh & RDAP are gifts, not contracts. Each enrichment must be nil-safe & render an empty card on failure, exactly like `BlockList.Check` does today.
- **crt.sh is slow & sometimes 502s** under load; cache aggressively.

## Verified firsthand vs inferred

**Verified firsthand (`dig` / `curl` / raw GitHub fetches, re-checked 2026-09-16):** every SOA serial in the table, re-confirmed a day later (`github.com` NS1 side still answers `1656468023` off `dns1.p08.nsone.net`, still dual-provider w/ 4 awsdns + 4 nsone NS); `netflix.com`'s divergent authoritative A sets (re-checked, still splits — one NS answered a *different* triple than a day earlier, which is the churn claim proving itself, not a contradiction of it); `cloudflare.com` RRSIG inception/expiration window; `github.com` CAA & `_dmarc` TXT; TTLs quoted. RDAP `200` w/ `Access-Control-Allow-Origin: *`, expiry/EPP/`secureDNS` fields. crt.sh `200`, CORS `*`, 366 rows / 89 names for `corpberry.com` (re-run today, see caveat above). mnemonic pDNS `200` no auth, full field list, **no** `access-control-allow-origin`, 62 records / 60 qnames for `corpberry.com`. Google & Cloudflare DoH-JSON `200`. RIPEstat, networkcalc, hackertarget `200`. Auth walls: SecurityTrails `401 "Please check user credentials"`, ViewDNS `401`, MXToolbox API `401`, VirusTotal `401`, OTX `429`, bgp.tools `307`, dnshistory.org `403`. CompleteDNS: no key `500`, bogus key `401 api_key_not_valid`. SecurityTrails endpoint paths & the `a, aaaa, mx, ns, soa, txt` type list read from its published OpenAPI. **New this pass:** Uptime Kuma's interval floor (`MIN_INTERVAL_SECOND = 1` in `src/util.ts`) and its full DNS-type dropdown (`src/pages/EditMonitor.vue`: `["A","AAAA","CAA","CNAME","MX","NS","PTR","SOA","SRV","TXT"]`, 10 types — the prior draft's list was missing `PTR`), both pulled directly from `louislam/uptime-kuma`'s source on GitHub, not docs. `elceef/dnstwist`'s `LICENSE` file (`200`, Apache-2.0). MXToolbox's free-tier limit (1 monitor, top-30 blacklists) confirmed on the vendor's own `mxtoolbox.com/c/products/matrixdos` page via WebFetch — that page just doesn't carry dollar prices. Oh Dear's Cloudflare-NS auto-exclusion of A/AAAA, confirmed on a second WebFetch of its own feature page.

**Resolved this pass:** SecurityTrails' "contradictory" quota wasn't a contradiction — search results now show 10,000 credits/mo is the general free API plan, and 2,500 queries/mo belongs to a separate, non-commercial "OSINT Toolkit" restricted to security researchers. Both figures are still search-corroborated, not read off the (still-403) pricing page directly, so treat the exact numbers as probable-not-certain.

**Could not verify firsthand, and downgraded further:** **dnsspy.io** and **whatsmydns.net** still return Cloudflare's JS interstitial or a flat 403 to both `curl` w/ a browser UA and WebFetch. DNS Spy's numbers (price, plan limits, notification tiers, Phishing Sentinel mechanics) are now cross-corroborated across three independently-worded searches hitting what look like distinct vendor subpages (`/pricing`, `/features`, `/features/notifications`) with consistent, specific figures each time — moderately more trustworthy than a single search summary, but still not a page this session read directly. **whatsmydns.net is the opposite**: a fresh search for its pricing surfaced no independent corroboration at all, and one result's phrasing ("$9/month" for a "Starter" plan) is suspiciously identical to Site24x7's own $9/mo Starter tier appearing in the *same* result set — plausible cross-contamination between two "Starter $9/mo" products. Do not build against the whatsmydns.net numbers in this report without reading the vendor page directly first. **mxtoolbox.com/pricing does not exist** (`404`) — whoever wrote the original Sources link either mistyped it or the page moved; the $129/$399 figures are search-corroborated across 3 queries but still secondary. **archive.org's own site loads (`200`)**, but its Wayback Availability API returned `429 Too Many Requests` for all three blocked URLs on both this pass and the original one, a day apart, while a control URL (`example.com`) resolved fine — so the fallback is specifically unavailable for these three lookups, not "archive.org is down." Oh Dear's interval/behaviour still comes from its own feature page (now fetched twice, consistent both times), not a live account. The Uptrends/Dotcom-Monitor/Catchpoint/Site24x7/Datadog row is unchanged: docs + a vendor-authored roundup, not run firsthand. DNS Spy's current ownership after the 2020 SecurityTrails handover is still unconfirmed.

## Sources
- https://ma.ttias.be/dns-spy-launched/
- https://ma.ttias.be/a-new-start-for-dns-spy/
- https://dnsspy.io/pricing (403 to automated fetch; figures via search summaries of this and `/features`, `/features/notifications`, cross-corroborated)
- https://ohdear.app/features/dns-monitoring (WebFetched directly, twice)
- https://knowledgebase.mxtoolbox.com/home/monitoring
- https://mxtoolbox.com/emailhealth
- https://mxtoolbox.com/c/products/matrixdos (WebFetched directly; confirms free-tier limit, no $ figures shown — `mxtoolbox.com/pricing` 404s, does not exist)
- https://www.whatsmydns.net/ (pricing/monitoring pages 403 to automated fetch; figures unconfirmed, possibly conflated w/ an unrelated vendor — see report body)
- https://completedns.com/dns-history/
- https://completedns.com/api/documentation/v2
- https://docs.securitytrails.com/llms.txt
- https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1.md
- https://docs.securitytrails.com/reference/whois-history-by-domain-old-1.md
- https://docs.securitytrails.com/docs/authentication.md
- https://securitytrails.com/corp/api
- https://github.com/louislam/uptime-kuma
- https://raw.githubusercontent.com/louislam/uptime-kuma/master/src/util.ts (fetched directly: `MIN_INTERVAL_SECOND = 1`)
- https://raw.githubusercontent.com/louislam/uptime-kuma/master/src/pages/EditMonitor.vue (fetched directly: full `dnsresolvetypeOptions` array)
- https://betterstack.com/community/comparisons/dns-monitoring-tools/
- https://github.com/elceef/dnstwist (LICENSE fetched directly: Apache-2.0)
- https://zonemaster.net/en/ (WebFetched: free, open source)
- https://intodns.com/
- https://api.mnemonic.no/pdns/v3/
- https://crt.sh/
- https://rdap.org/
- https://dns.google/resolve
- https://cloudflare-dns.com/dns-query
- https://stat.ripe.net/data/dns-chain/data.json
- https://networkcalc.com/api/docs//dns/
