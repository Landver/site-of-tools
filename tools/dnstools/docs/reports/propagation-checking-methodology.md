# How propagation checkers actually work

whatsmydns.net & dnschecker.org present "DNS propagation" as a wave spreading across a world map. Mechanically there is no wave: there is a curated list of recursive resolvers, queried in parallel, answers compared against a reference. Everything the map shows is **resolver cache age, anycast PoP identity, GeoDNS steering & local filtering policy**. This report establishes what the mechanism really is, what the incumbents render on top of it, & which of those features a single Go binary can build *honestly*. Decision it informs: whether a propagation grid belongs in our DNS tool at all, and if so which of ~24 enumerable features to pick.

- **Scope:** the multi-resolver comparison mechanism & its UI conventions. Not DNSSEC validation chains, not zone health scoring (separate reports). · **Why it matters for our build:** propagation checking is the single highest-traffic DNS-tool feature on the web, and it is also the one most often built wrong. Getting the *semantics* right is cheap differentiation; the fan-out itself is ~80 lines of Go.
- **Firsthand check:** `dig` fan-outs to 14 public anycast resolvers + 40 sampled from public-dns.info + 15 from trickest/resolvers; EDNS Client Subnet sweeps via UDP & Google DoH; NXDOMAIN-rewrite & filtering probes; TTL-decay and TTL-cap measurement; parent-vs-child delegation compare; CORS probes on 8 DoH endpoints; latency budget for a 14-way fan-out. Raw output inline below. **Both incumbent sites 403'd every request** (`cf-mitigated: challenge`), so their UI/feature claims here are secondhand & marked as such.

## The mechanics

**Step 1, the list.** A propagation checker keeps a hand-curated set of recursive resolvers, one or a few per country, each tagged w/ a flag & city. Historically sourced from **public-dns.info** (open-resolver census, running since 2009) or scraped equivalents. Step 2, **fan-out**: same QNAME/QTYPE to every resolver in parallel, short timeout, no retry. Step 3, **compare**: each answer set vs a reference, render green/red.

That is the entire algorithm. The interesting part is what the three steps *cannot* distinguish, because four independent effects all produce "resolver A ≠ resolver B":

**1. Cache age (the only one that is actually propagation).** RFC 1035 TTL semantics: an authoritative change is invisible to a resolver until its cached copy expires. Reported TTL = remaining seconds, so `authTTL - reportedTTL` = **seconds since that cache last fetched**. Observed decay on one name, `example.com` A, auth TTL 300:

```
8.8.8.8 Google      TTL 300   (cold / just refetched)
1.1.1.1 Cloudflare  TTL 179
9.9.9.9 Quad9       TTL 8     (about to expire)
64.6.64.6 Verisign  TTL 8
```

**2. Anycast: one IP is not one cache.** `8.8.8.8` is thousands of machines. Six back-to-back queries from one host:

```
8.8.8.8   q1 ttl=66  q2 ttl=66  q3 ttl=79  q4 ttl=300  q5 ttl=300  q6 ttl=300
1.1.1.1   q1 ttl=107 q2 ttl=106 q3 ttl=112 q4 ttl=112 q5 ttl=112 q6 ttl=112
```

TTL **went up** between q3 & q4 on the same IP from the same client. Impossible for a single cache -> consecutive queries landed on different cache instances w/ different ages. Querying `8.8.8.8` "from Frankfurt" & "from São Paulo" therefore samples two unrelated caches, and *even one vantage point cannot reproduce its own result*. This alone invalidates the "wave" model.

**3. GeoDNS steering.** Authoritative servers return different answers per client location (RFC 7871 EDNS Client Subnet). Proven firsthand w/ a single resolver & a varying claimed client subnet:

```
dig @8.8.8.8 example.com A +subnet=8.8.8.8/24    -> 104.20.23.154, 172.66.147.243
dig @8.8.8.8 example.com A +subnet=77.88.8.0/24  -> 8.47.69.8,     8.6.112.8
;; OPT PSEUDOSECTION:  CLIENT-SUBNET: 77.88.8.0/24/24
```

Same resolver, same second, different answers. This matched a live "mismatch" in the plain fan-out: Yandex `77.88.8.8` & `77.88.8.7` both returned `8.47.69.0/8.6.112.0` while the other 12 resolvers returned `104.20.23.154/172.66.147.243`. A naive checker paints that red. It is a correct, DNSSEC-signed, geo-appropriate answer. **The scope field in the echoed CLIENT-SUBNET option is the machine-readable tell**: scope `/24` (non-zero) means the authoritative tailored this answer to that prefix, so cross-location divergence is expected, not lag. Costs one EDNS option to read & is the single highest-value mechanic in this report.

**4. Resolver policy (the "lying resolver").** Filtering resolvers return deliberately wrong data. Observed:

```
doubleclick.net   8.8.8.8      -> 142.251.20.100,142.251.20.101,142.251.20.139
                  94.140.14.14 -> 0.0.0.0                 (AdGuard blackhole, NOERROR)
pornhub.com       8.8.8.8      -> 66.254.114.41
                  208.67.222.123 -> 146.112.61.106        (OpenDNS FamilyShield block page)
```

Note both are `NOERROR` w/ a synthetic A record, not NXDOMAIN, so status-code checks miss them. NXDOMAIN *rewriting* is however largely dead: a random nonexistent `.com` returned clean NXDOMAIN from all 10 resolvers tested (Google, Cloudflare, Quad9, OpenDNS, Yandex, AdGuard, CleanBrowsing, Level3, AliDNS, HiNet). Today the lie is a substituted answer, not a substituted rcode.

**Bonus mechanic, TTL is not comparable across resolvers.** One record (`. NS`, authoritative TTL 518400) as reported by each resolver:

```
OpenDNS 518400 · Cloudflare 514387 · Google 87203 · Level3 86396
AliDNS 57163 · AdGuard 51111 · Quad9 30516 · Yandex 5879
```

Spread of 5,879 -> 518,400 for one RRset. Resolvers cap max TTL at their own ceilings. A "TTL" column in a propagation grid is therefore **not** a property of the zone.

**And the old answer can outlive its TTL entirely.** RFC 8767 serve-stale lets a resolver keep serving expired data when authoritatives are unreachable, w/ a suggested **maximum stale timer of 1 to 3 days** and stale answers handed out w/ a **30 second** TTL. "Wait for the TTL and it will be consistent" is not guaranteed.

## What the popular tools actually do about it

**Provenance warning:** `whatsmydns.net` & `dnschecker.org` returned **HTTP 403 w/ `cf-mitigated: challenge`** to every request incl. `robots.txt`/subpages (whatsmydns) and `sitemap.xml` (dnschecker), from curl (default UA), curl (browser UA), and WebFetch — checked 2026-09-15 **and reconfirmed 2026-09-16**, same result both days. Everything about those two sites in this subsection is secondhand: help-center docs, third-party write-ups, and Google-indexed snippets of their own subpages (titles like `/dns-lookup/a-records`, `/dns-lookup/srv-records` resolve the record-type list below, but the pages themselves also 403). `nslookup.io` and `dnschecker.website` *were* curl-readable directly (no UA tricks needed) and are quoted firsthand below; note nslookup.io's checker now lives at `/dns-propagation-checker/` — `/dns-checker/` 301-redirects there.

| Behaviour | What they do | Verdict |
|---|---|---|
| Resolver list | curated, one or few per country; whatsmydns cited at 21-30 locations (secondhand, corroborated by 2+ independent write-ups, not by Wix), nslookup.io states **"more than 30 DNS resolvers on six continents"** (curl-verified firsthand on the live page), dnschecker.website **18** (curl-verified firsthand: its widget literally shows `Results 0 / 18` before a check runs — the report's earlier "20+" was an unverified guess), dnschecked.com "more than 100 global DNS servers" (its own marketing copy, not independently counted) | table-stakes, and the counts are marketing |
| Display | flag/city grid + world map; green tick vs red cross | table-stakes |
| Reference answer | user-supplied "expected value" field, else majority/first answer | table-stakes |
| Record types | dnschecker.website, curl-verified firsthand: **A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA** (10). nslookup.io, curl-verified firsthand: those 10 plus **DNSKEY, DS, NAPTR, TLSA** (14) — the widest set seen. whatsmydns' own type list could not be fetched directly; search-engine snippets of its per-type lookup pages suggest the same core 8-9 (A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SRV), but that is inferred, not read off the site. dnschecker adds CAA, DS, DNSKEY per third-party write-ups | table-stakes, but **DNSKEY/DS/NAPTR/TLSA are a gap in our record-type selector plan** below |
| Timeouts | red X conflates "no record" w/ "resolver unreachable" — whatsmydns' own help text says a red X means "either no records have propagated, or a communication issue exists between whatsmydns.net and the server" | **honest failure they chose not to disambiguate** |
| Anycast / GeoDNS | not addressed. nslookup.io's page (curl-verified firsthand, zero hits for "anycast"/"geodns"/"ecs"/"client subnet") does not mention anycast or GeoDNS at all | **the gap worth attacking** |
| Semantics | nslookup.io is the honest one, curl-verified firsthand: propagation "can't be 'pushed'", "no service can reach into third-party resolver caches", and its FAQ literally defines green = "resolver returns the same value as your authoritative name servers", amber = "stale", red = "no answer" | genuinely distinctive vs the rest |
| Public API | whatsmydns: none (devRant thread + 2026 web search both still say no). dnschecker: none documented; third parties resell scrapes | — |
| Cache-flush links | nslookup.io already ships this as an outlink list (Google + Cloudflare + OS `flushdns`) in its FAQ — the report's "distinctive feature" idea below is validated by an incumbent doing it, not untried | not novel, but cheap and worth keeping |

**The buy-instead-of-build option, w/ real numbers, curl-verified firsthand (a plain curl got 403; a browser User-Agent got 200 — Akamai/Cloudflare-style bot filtering on the marketing page, not a dead endpoint).** APIVoid DNS Propagation API: `POST https://api.apivoid.com/v2/dns-propagation`, body `{host, dns_types}` (comma-separated from A, AAAA, MX, NS, TXT, SOA, SRV, CAA), response `{host, propagation:[{continent_code, continent_name, country_code, country_name, city_name, response:[{dns_type, records[]}]}], elapsed_ms}` — all field names confirmed against the page's own example payload. **"Consumes 5 credits per API call"** is the page's exact wording. No free tier documented for this product specifically (checked 2026-09-15 & 2026-09-16). **RIPE Atlas** is the only source of genuinely real vantage points: public read API open & unauthenticated (`GET https://atlas.ripe.net/api/v2/measurements/?type=dns`, `/api/v2/probes/?status=1` — **15,097 connected probes on 2026-09-15, 15,075 on 2026-09-16**; this is a live count that drifts day to day, not a fixed spec number), and the credit rates are curl-verified firsthand off `atlas.ripe.net/docs/getting-started/credits/`: DNS/DNS6 measurements cost **10 credits/result over UDP, 20 over TCP for a periodic (ongoing) measurement**, and a one-off costs exactly 2x that (**20 UDP / 40 TCP** — the page states one-offs are "twice as expensive... due to the overhead of scheduling and storing metadata"). Hosting one connected probe earns **~21,600 credits every 24 hours** (page's own wording). Quotas, also curl-verified off `atlas.ripe.net/docs/getting-started/user-defined-measurements/`: **up to 100 simultaneous measurements, up to 100,000 results/day, up to 1,000 probes/measurement, up to 1,000,000 credits/day**.

## The resolver-list problem, measured

This is where the incumbents' model quietly rots, and it is measurable.

**public-dns.info**, the canonical source everyone cites, is a **frozen dataset**. `nameservers.csv` is 8.2 MB, 62,790 rows, 194 country codes, columns `ip_address,name,as_number,as_org,country_code,city,version,error,dnssec,reliability,checked_at,created_at`. `Last-Modified` was today. But the newest `checked_at` inside is **2023-08-17**; there are **zero** rows dated 2024, 2025 or 2026, while the homepage still says the list is "checked continuously". File freshness ≠ data freshness.

I sampled **40 rows w/ `reliability = 1.00`**, one per country across the 40 best-represented countries, one query each:

```
reachable = 1   dead = 39   (of 40)
```

The one survivor was `88.221.162.66` (Akamai, NL). Not my network: three anycast resolvers *not* in any earlier test (`149.112.112.112`, `8.26.56.26`, `84.200.69.80`) all answered normally, and `172.104.237.140` accepted TCP/53 while refusing to recurse, i.e. it is alive but no longer an open resolver. Open resolvers get closed over time; that is the correct outcome for the internet and a fatal one for a stale list.

Contrast **`trickest/resolvers`** (`raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt`, 11,862 entries on 2026-09-15, **12,202 on a 2026-09-16 recheck** — the file genuinely churns day to day, unlike public-dns.info's frozen count, which is itself evidence it's validated on a schedule): **15 of 15** sampled answered. **But**: the sample was heavy w/ `108.162.x`, `162.159.x`, `172.64.x` (Cloudflare), `45.90.30.x` (NextDNS). Those are anycast front doors, not vantage points. **Resolver count ≠ vantage count** — an 11,862-entry list may represent a few dozen actual networks.

## Options for us, w/ trade-offs

Our stack: single Go binary, Echo v5, htmx, no Node, optional Mongo, Hetzner box behind Cloudflare + nginx. Relevant prior decision: the live port scanner was shelved because outbound probing risks a Hetzner abuse complaint, and the same reasoning applies to unsolicited UDP/53 to thousands of third-party hosts.

| Option | What it buys | Cost/complexity | Risk |
|---|---|---|---|
| **A. UDP/53 fan-out to ~20 well-known anycast resolvers** | the familiar grid, sub-2s | low: `miekg/dns` or stdlib, goroutine per resolver | low. Anycast operators expect query traffic. Measured: serial 5s vs **parallel 2s** for 14; RTT 24ms (Yandex) -> 530ms (HiNet TW), `114.114.114.114` hard-timed-out |
| **B. UDP/53 fan-out to a large scraped list** | more flags on the map | medium: liveness re-validation cron, Mongo store | **high.** 39/40 dead in my sample means mostly timeouts; and unsolicited traffic to thousands of random hosts is exactly the Hetzner-complaint shape we already avoided once |
| **C. ECS sweep on one resolver** | separates GeoDNS from lag; a "what does this look like from Brazil/Japan/Kenya" view w/ no fleet | low: `+subnet` over UDP, or `edns_client_subnet=` on Google DoH JSON | low. Only works where the authoritative honours ECS; Cloudflare-hosted zones do (proven above) |
| **D. Authoritative-only compare** | the *honest* propagation check: parent delegation -> every child NS -> diff RRsets & SOA serials | low: a handful of `+norec` queries | low. Zero third-party resolver load. Doesn't produce a world map |
| **E. Browser-side DoH fan-out (htmx/Alpine)** | zero server egress; client's own network is the vantage | medium: CORS-limited. Measured ACAO `*`: **Google `dns.google/resolve`, Cloudflare `cloudflare-dns.com/dns-query`, AliDNS `dns.alidns.com/resolve`**. No ACAO: AdGuard, NextDNS (200 but no header), Quad9:5053; OpenDNS & Mullvad 400 on `name=` (wireformat only) | low, but 3 providers is not a map |
| **F. RIPE Atlas one-off** | real probes on real consumer networks, the only true global answer | high: API key, credit accounting, async result polling | medium: costs credits; results arrive seconds-to-minutes later, so needs htmx polling |

**Recommended shape:** **D + C + A**, in that order of prominence. D is the correct answer to "did my change go out", C explains every mismatch A will produce, and A supplies the grid users came for. B is the one to refuse.

## Feature inventory (pick from this list)

Table-stakes, one line each: resolver × answer grid · country flags/city labels · world map · green/red match colouring · user-supplied expected value · record-type selector — **A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR are the floor** (dnschecker.website, firsthand); **nslookup.io firsthand-confirmed also ships DNSKEY, DS, NAPTR, TLSA (14 types total)**, so that's the bar to match, not exceed, if we want parity · shareable permalink · auto-refresh/re-poll · CSV/JSON export (**free for us** — house rule #2 gives JSON via content negotiation).

Distinctive, worth the implementation detail:

- **ECS scope badge.** Read the echoed `CLIENT-SUBNET` scope on every answer. Scope > 0 -> label the row "geo-steered, divergence expected" instead of red. Nobody surveyed does this. ~15 lines.
- **Cache-age column instead of TTL column.** Show `authTTL - reportedTTL` = "this cache is N seconds old", plus "consistent in ≤ N seconds" = max remaining TTL across responders. Fixes the incomparable-TTL problem shown above.
- **Three-state cells, not two.** `current` / `stale-but-valid` (old RRset, still within TTL) / `no answer` — and split that last one into `NXDOMAIN`, `REFUSED`, `SERVFAIL`, `timeout`. whatsmydns explicitly conflates them.
- **Filtering-resolver classification.** Match answers against known sinkholes (`0.0.0.0`, `127.0.0.1`, `::`, OpenDNS block-page range around `146.112.61.0/24`) and label "blocked by resolver policy", not "not propagated".
- **Parent vs child delegation diff.** Query the TLD server w/ `+norec` for the NS set, then the zone's own NS set, and diff. Firsthand find on `example.com`: `.com` delegates to `hera`/`elliott.ns.cloudflare.com`, yet `a.iana-servers.net` still answers **w/ the `aa` flag** and a completely different zone (`23.192.228.80` et al., SOA `ns.icann.org` serial `2026091001` vs Cloudflare's `2414908178`). An orphaned authoritative server serving live, wrong, authoritative-looking data. **Rechecked 2026-09-16, 24h later: identical answer, identical serial** — this is a standing misconfiguration, not a one-off blip. Also surface parent TTL vs child TTL (observed 172800 vs 86400).
- **SOA serial agreement across all authoritatives.** The real "has it gone out" signal. Both Cloudflare NS agreed at `2414908178` (reconfirmed 2026-09-16).
- **Negative-TTL surfacing.** Most "it isn't propagating" reports are a cached NXDOMAIN, governed by the SOA MINIMUM field (RFC 2308), not by the record's TTL. Observed: `example.com` & `corpberry.com` 1800s, `github.com` 3600s. Show it as "a wrong NXDOMAIN will stick for up to 30 min".
- **DNSSEC AD column.** Rules out resolver tampering, but don't build a green badge on it naively. `example.com` **is** DNSSEC-signed (RRSIG/DNSKEY present, firsthand-confirmed). Over plain UDP, `dig @8.8.8.8`, `dig @1.1.1.1` and `dig @77.88.8.8` (Yandex) all set the `ad` flag. But the **JSON APIs disagree by default**: `dns.google/resolve?name=example.com&type=A` returns `AD:true` with no extra parameters, while `cloudflare-dns.com/dns-query?name=example.com&type=A` returns `AD:false` for the identical query — reproduced twice. The fix, also firsthand: adding `&do=1` (DNSSEC OK) to the Cloudflare JSON call flips it to `AD:true`. So Cloudflare's JSON endpoint validates either way but only *reports* AD when the client asks for DNSSEC data; Google's endpoint reports it unconditionally. **A fan-out that queries these two JSON APIs identically will show Cloudflare as "not validating" when it is — the `do=1` param is required per-provider, and that quirk belongs in code comments, not just this report.**
- **Honest denominator.** "12 of 14 resolvers answered" in the header, w/ the 2 named. The incumbents silently hide dead list entries.
- **Which authoritative node answered.** Google's DoH JSON returns a `Comment` field like `"Response from 108.162.195.228."` — free anycast evidence to show beside a geo-divergent row.
- **Cache-flush outlinks.** `dns.google/cache` (HTTP 200, a human form, not an API), `cachecheck.opendns.com` (200), `1.1.1.1/purge-cache/` (301). Cheap, genuinely useful, no infrastructure.
- **Check history + diff** (Mongo, rule #5 pattern already in `tools/iptools/history.go`): "vs your check 40 minutes ago, 3 resolvers flipped".

## Hard constraints & failure modes

- **Hetzner abuse exposure.** Option B sends unsolicited UDP to thousands of hosts that mostly no longer want it. Same risk class that shelved the port scanner. Cap the list at well-known anycast operators.
- **Our box is one vantage point.** Fanning out from Hetzner reaches each anycast operator's *nearest PoP to Hetzner*, not their Tokyo or São Paulo cache. A "Japan" flag next to a query our German box sent to `8.8.8.8` is a lie. Either label rows by resolver operator rather than country, or use ECS/Atlas for the geo claim.
- **Non-reproducibility.** Proven above: the same IP gives different cache ages on consecutive queries. Any cached/permalinked result must be timestamped and must not be presented as re-checkable.
- **Serve-stale (RFC 8767).** Old data can legitimately persist 1-3 days past TTL. Never promise "consistent after TTL".
- **TTL caps** make cross-resolver TTL comparison meaningless (5,879 -> 518,400 observed for one RRset).
- **CORS caps the browser-side design at ~3 providers** (Google, Cloudflare, AliDNS). Not a map.
- **Cloudflare sits in front of us too.** We are behind CF + nginx; outbound DNS is unaffected, but note the incumbents block automated readers exactly as we could be blocked, so don't build anything that depends on scraping them.
- **List rot is permanent, not a one-off.** Any scraped list needs a revalidation cron or it becomes public-dns.info. Budget for it or don't ship option B.

## Verified firsthand vs inferred

**Verified firsthand, 2026-09-15 (egress in MSK timezone, macOS `dig 9.10.6`), with a 2026-09-16 recheck on the highest-stakes items (noted inline):** the 14-resolver agreement matrix & the Yandex divergence · ECS sweep over UDP & over Google DoH, incl. the echoed `/24` scope · TTL decay, the TTL going *up* on repeat queries to 8.8.8.8 and 1.1.1.1, and the cross-resolver TTL cap spread (root `. NS` TTL re-dug 2026-09-16: Google still 87203s — above a naive 86400 cap, confirming resolvers use their own ceilings, not a shared standard) · AdGuard `0.0.0.0` & OpenDNS FamilyShield block-page answers · clean NXDOMAIN from all 10 resolvers tested · public-dns.info file size (8,192,574 bytes)/row count (62,790)/country count (194, re-parsed w/ a proper CSV reader, not naive `awk -F,`)/`checked_at` ceiling of 2023-08-17 and the 1-of-40 reachability sample, re-verified 2026-09-16 (`Last-Modified` header was that day's date, data ceiling unchanged) · trickest 15-of-15 (file itself grew from 11,862 to 12,202 lines between the two check dates) · parent/child delegation split on `example.com` incl. the `aa`-flagged orphan at `a.iana-servers.net`, **reproduced identically 24h later** (same SOA serial `2026091001`, same A records) — no longer flagged as possibly transient · SOA serials & negative TTLs, reconfirmed · CORS headers + status codes on Google, Cloudflare, AliDNS (all ACAO `*`), AdGuard & NextDNS (200, no ACAO header), OpenDNS & Mullvad (400 on wireformat `name=` GET) — Quad9:5053 timed out from this sandbox and is genuinely untested, not confirmed either way · Google's DoH `Comment` field showing the answering anycast node · the DNSSEC `AD` flag: `example.com` **is** signed, all three resolvers set `ad` over plain UDP, but Cloudflare's JSON API (`cloudflare-dns.com/dns-query`) only returns `AD:true` when the query includes `&do=1` — reproduced twice, this is a real per-API quirk, not the "APIs disagree on validation" claim in an earlier draft of this section · cache-flush endpoints `dns.google/cache` (200), `cachecheck.opendns.com` (200), `1.1.1.1/purge-cache/` (301) · RIPE Atlas public read API, connected-probe count (15,097 on 09-15, 15,075 on 09-16 — a live, drifting figure, not a spec constant), credit rates (DNS/DNS6: 10 UDP / 20 TCP periodic, 2x for one-off, off the credits doc's own worked example) and quotas (100 simultaneous measurements, 100,000 results/day, off the UDM doc) · APIVoid's `/v2/dns-propagation` endpoint, request/response shape and "5 credits per API call" wording, read directly off the page (plain curl 403'd; a browser User-Agent got 200 — page-level bot filtering, not a dead product) · RFC 8767 §5 read directly: RECOMMENDED 30s TTL on stale answers, maximum-stale-timer "suggested value... between 1 and 3 days" · RFC 7871 SCOPE PREFIX-LENGTH semantics, RFC 2308 SOA-MINIMUM-governs-negative-caching, both read directly off the RFC text · nslookup.io's page, fetched directly by curl at its real URL (`/dns-propagation-checker/`, not the `/dns-checker/` alias): the "more than 30 DNS resolvers on six continents" line, the green/amber/red FAQ definitions, zero mentions of anycast/GeoDNS/ECS anywhere on the page, its 14 record types (A, AAAA, CAA, CNAME, DNSKEY, DS, MX, NAPTR, NS, PTR, SOA, SRV, TLSA, TXT), and its existing Google/Cloudflare cache-flush outlinks · dnschecker.website's page, also curl-readable directly: its live resolver-count widget reading `Results 0 / 18` (not "20+", correcting the earlier estimate) and its 10 record types (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA) · fan-out latency (serial 5s / parallel 2s, RTT 24-530ms, one timeout).

**Corroborated by 2026 web search results (search-engine snippets, not a direct fetch of the source page — flagged accordingly):** whatsmydns.net's per-type lookup subpages (`/dns-lookup/a-records`, `/srv-records`, etc. all 403 directly) implying the same record types as dnschecker.website; dnschecker.org's own "all DNS records" page implying it adds SRV, CAA, DS, DNSKEY; dnschecked.com's homepage copy, "a complete list of more than 100 global DNS servers," which is the actual source for the "100+" figure (not independently counted by us); whatsmydns.net still has no public API as of 2026 (independent corroboration beyond the 2018 devRant thread).

**Inferred or secondhand, flagged as such:** everything else about whatsmydns.net & dnschecker.org — both still 403 w/ a Cloudflare managed challenge on every attempt (plain curl, browser-UA curl, and WebFetch, both check dates), so their map/grid rendering and timeout-handling copy come from help-center pages and third-party write-ups, not from the sites. **Correction from an earlier draft:** their exact record-type list was previously attributed to a Wix help-center article; that article only mentions "Name Servers, A record, CNAME" as examples in passing and never lists AAAA/MX/PTR/SOA/TXT at all (confirmed absent by full-text search of the fetched page) — the 8-type list was an unsupported claim dressed as sourced. It's now attributed to search-snippet evidence instead, per above, and downgraded accordingly. Their internal resolver lists are not published and were not extracted.

**Not tested:** whether any resolver in the set is actively serving stale per RFC 8767 (needs an authoritative outage to observe); whether the incumbents re-validate their resolver lists on any schedule; any authenticated API; Quad9's DoH endpoint on port 5053 (timed out from this environment, inconclusive either way).

## Sources
- https://public-dns.info/ · https://public-dns.info/nameservers.csv
- https://github.com/trickest/resolvers · https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
- https://www.nslookup.io/dns-propagation-checker/ (curl-verified directly; `/dns-checker/` 301s here)
- https://dnschecker.website/ (curl-verified directly, incl. its `Results 0 / N` resolver-count widget)
- https://dnschecked.com/ (curl-verified reachable at the apex; `www.` subdomain NXDOMAINs)
- https://www.whatsmydns.net/ (403, cf-mitigated: challenge, both plain & browser-UA curl, and WebFetch)
- https://dnschecker.org/ (403, cf-mitigated: challenge, incl. `/sitemap.xml`)
- https://support.wix.com/en/article/checking-your-domains-dns-records-using-whatsmydnsnet (does not actually list whatsmydns' record types — see correction above)
- https://devrant.com/rants/1839783/i-find-the-whatsmydns-net-website-very-useful-too-bad-that-they-dont-have-an-api
- https://www.apivoid.com/api/dns-propagation/ (curl-verified w/ browser UA; plain curl 403s)
- https://atlas.ripe.net/docs/getting-started/credits/ · https://atlas.ripe.net/docs/getting-started/user-defined-measurements/ · https://atlas.ripe.net/api/v2/probes/?status=1 · https://atlas.ripe.net/api/v2/measurements/?type=dns
- https://developers.google.com/speed/public-dns/docs/doh/json · https://dns.google/cache · https://dns.google/resolve
- https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/ · https://1.1.1.1/purge-cache/ · https://cloudflare-dns.com/dns-query
- https://cachecheck.opendns.com/
- https://www.rfc-editor.org/rfc/rfc8767.html (serve-stale, §5 read directly for timer values) · https://www.rfc-editor.org/rfc/rfc7871.html (EDNS Client Subnet, SCOPE PREFIX-LENGTH read directly) · https://www.rfc-editor.org/rfc/rfc2308.html (negative caching, SOA MINIMUM read directly) · https://www.rfc-editor.org/rfc/rfc1035.html (TTL)
