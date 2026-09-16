# RIPE Atlas

Global, research-grade active-measurement network run by **RIPE NCC**: ~15k connected hardware/software probes + ~1.8k anchors, scriptable via REST, w/ **DNS as a first-class measurement type**. Matters to a DNS-lookup tool for two opposite reasons. (1) It is the yardstick: when an operator says "check propagation from 30 locations", Atlas is the thing they'd actually trust, and every propagation checker is implicitly measured against it. (2) Its **read API is fully open, unauthenticated, CORS-permissive, and holds ~37.5M past public DNS measurements w/ raw wire-format answers**, so a small tool can *mine* other people's measurements for free instead of owning any vantage points at all.

- **URL:** https://atlas.ripe.net · **Category:** distributed active-measurement platform (research infrastructure, not a consumer lookup site) · **Registration:** none for reads, RIPE NCC Access account + **credits** to run your own · **Pricing:** free, credit-economy (no money) · **API:** REST `/api/v2/`, WebSocket/SSE stream, bulk archive.
- **Firsthand check (2026-09-16):** ~40 `curl` calls against `atlas.ripe.net/api/v2/`, an 8s capture of `atlas-stream.ripe.net`, `dig @193.0.14.129 . SOA`, plus base64+struct decode of a real `abuf`. All reads 200 w/o auth; writes & account endpoints 401. **The `type=dns` filter is genuinely honoured** (see counts below), resolving the open question from discovery. The web UI and DNSMON could **not** be inspected firsthand: `atlas.ripe.net/measurements/10001/` and `dnsmon.ripe.net/` both return a ~1.8 KB client-rendered SPA shell to `curl`, and the docs site (`/docs/**`) is a Vite SPA whose raw HTML contains zero occurrences of `query_type`. UI and docs detail below is therefore docs/secondhand, flagged in place.

## What it is

Started 2010, descendant of RIPE's TTM. Volunteers host a **probe** (small USB-powered device, or a software probe on Linux/Docker); probes idle-run **built-in measurements** (root-server DNS/ping/traceroute) and execute **user-defined measurements (UDMs)** scheduled by other users. Results are public by default and archived indefinitely. The DNS type answers "what does *this* name resolve to, *from here*, right now" across thousands of real residential/enterprise/datacentre vantage points, which is exactly the primitive a propagation checker fakes w/ a handful of public resolvers.

| Firsthand network size | Value (2026-09-16) |
|---|---|
| Registered probes | **60,617** |
| Connected probes (`status=1`) | **15,073** (NL alone: 771) |
| Anchors | **1,790** |
| Anchor measurements | 12,768 |
| Probe tag vocabulary | 162 tags (incl. `datacentre`, `nat`, `mobile`, `system-dns-problem-suspected`) |

## Registration, access & pricing

No money changes hands. **Reads need nothing** (verified: no key, no cookie, no referer). **Writes need a RIPE NCC Access account + an API key + credits**; every write/account endpoint I hit returned `401 {"code":104,"title":"Unauthorized"}`: `POST /measurements/`, `GET /credits/`, `GET /measurements/my/`, `GET /measurements/{id}/tags/`.

Credit economy (RIPE's own credits page, quoted directly, but not exercised since I have no account): probe host earns **15 credits/min connected ≈ 21,600/day**; anchor hosts earn **10x = 150/min ≈ 216,000/day**; RIPE NCC members can claim monthly free credits (amount not stated); credits are transferable between users. **DNS result unit cost: "10 credits/result" over UDP, "20 credits/result" over TCP** (RIPE's exact wording). The API confirms the periodic case per-measurement: msm 10001 (`interval: 1800`, i.e. periodic) reports `credits_per_result: 10`. Critically, the same page states **"a one-off measurement result is twice as expensive than a periodic measurement result"** — a detail the first pass missed.

So a one-off DNS/UDP query from 50 probes costs **~1,000 credits** (20/result × 50, not 500 — periodic pricing does not apply to one-offs), and a non-probe-host w/ no sponsor has ~0. **Practical consequence: you cannot schedule Atlas measurements on behalf of anonymous visitors, and one-off "check this domain now" UX is the expensive path.** The open read side has no such gate. For scale, other measurement types' unit costs (also from the credits page): ping 3/result, traceroute 30/result, SSLCert 10/result — DNS/UDP is cheap relative to traceroute, expensive relative to ping.

## Features — complete inventory

### Measurement creation (auth + credits)
| Feature | Detail |
|---|---|
| DNS measurement type | `POST /api/v2/measurements/` w/ `definitions[].type = "dns"` |
| One-off vs recurring | `is_oneoff: true`, or `interval` seconds (msm 10001 runs at `interval: 1800`) |
| Scheduling window | `start_time`, `stop_time`, `spread` (jitter results over the interval) |
| Probe selection | `probes[]` of `{requested, type, value}` w/ type = `area` (`WW`/`West`/`North-Central`/`South-Central`/`North-East`/`South-East`), `country`, `asn`, `prefix`, `probes` (explicit IDs), `msm` (reuse another measurement's probe set) |
| Probe churn control | `auto_topup`, `auto_topup_prb_days_off`, `auto_topup_prb_similarity` (observed on live objects). Tagging/grouping via `tags[]`, `group_id`, `is_all_scheduled` |
| Public/private | `is_public`. Private costs the same but is excluded from the open archive; public results are readable by anyone, forever |

### Reading measurements (no auth), the part that matters here
| Endpoint | Notes (all verified 200 w/o auth) |
|---|---|
| `GET /api/v2/measurements/?type=dns` | **37,489,274** DNS measurements. Paginated `count`/`next`/`previous`/`results` |
| `GET /api/v2/measurements/{id}/` | full definition object, 57 fields |
| `GET /api/v2/measurements/{id}/results/` | archived results, `start`/`stop` unix ts, `probe_ids=` CSV, `format=json\|txt` |
| `GET /api/v2/measurements/{id}/latest/` | most recent result per probe. msm 10001 → **14,260 results, 8.7 MB, one call** |
| `GET /api/v2/probes/` (+ `/archive/`, `/tags/`) | probe metadata: ASN v4/v6, prefix, country, `geometry` (GeoJSON point), tags, status, uptime. `/archive/` = 47 MB full snapshot; `/tags/` = the 162-tag vocabulary |
| `GET /api/v2/anchors/` (+ `/anchor-measurements/`) | anchors w/ FQDN, city, company, v4/v6, **`tlsa_record`**; 12,768 anchor-mesh measurement links |
| `GET /api/v2/measurements/{id}/status-check/` | alerting endpoint. **403 for DNS, see Gaps** |

### Search / filter knobs on the measurement archive
Verified honoured (each narrowed the count): `type`, `target`, `target_ip`, `target_asn`, `af`, `protocol`, `status`, `interval`, `tags`, `id__in`, `current_probes`, `search`, `description__contains`, `description__startswith`, `start_time__gt`, `stop_time__lt`, plus `sort=`, `fields=`, `page_size=` (**max 500**; 1000 → HTTP 400).

Verified **ignored**: `query_type`, `query_argument`, `is_public`, `participant_count__gte`, `tls`, and arbitrary junk params. Critically the API *tells you*, in a `warnings` array alongside a 200: `"warnings":[{"source":{"parameter":"tls"},"detail":["Filtering by this field is not implemented, this parameter has been ignored."]}]`.

Sample counts, 2026-09-16: all types **195,367,654** · `type=dns` **37,489,274** · `ping` 118,506,684 · `traceroute` 24,314,946 · DNS `status=2` (Ongoing) ~9,150 · DNS `protocol=TCP` 78,631 · DNS `af=6` 808,869 · DNS `target_ip=8.8.8.8` 218,250 · DNS `target_asn=15169` 303,688 · DNS `tags=dnsmon` 6,775. Counts drift upward in real time (37,489,274 → 37,489,327 over ~2 min of probing, i.e. **new public DNS measurements land continuously**).

### Live result stream (no auth)
`atlas-stream.ripe.net/stream/?streamType=result&type=dns` over plain HTTPS GET, or `wss://atlas-stream.ripe.net/stream/` w/ `atlas_subscribe`/`atlas_unsubscribe` frames. Firsthand: **16,168 DNS results, 11.8 MB, in an 8s capture, from 1,132 distinct measurements and 1,518 distinct probes**, no key. Stream types: results, probe connect/disconnect, measurement metadata.

### Bulk archive
`data-store.ripe.net/datasets/atlas-daily-dumps/<YYYY-MM-DD>/` holds hourly `.bz2` dumps (`connection-2026-09-08T0100.bz2`), ~30 days of dirs visible. `ftp.ripe.net/ripe/atlas/` holds `anchors/`, `measurements/`, `probes/archive/`, `region-meshes/`; `measurements/` covers **2015..2025** as daily `meta-YYYYMMDD.txt.bz2`. Both hosts 400'd my research UA and 200'd a browser UA: UA-sniffing, not auth.

### Visualisation products built on the DNS type
- **DNSMON**: long-running (since 2001) root + TLD nameserver availability/latency matrix, rewritten and rehomed to `dnsmon.ripe.net` in July 2025. Time on x-axis, servers on y, cells coloured by response. Source: docs + RIPE Labs, **not** verified firsthand (SPA shell).
- **DomainMON**: wizard that points DNSMON-style monitoring at *your* zone: auto-reads NS records, builds per-nameserver v4/v6 targets, **max 50 probes**, spends your credits, iframe-embeddable, ~10 min refresh. Docs-only, no alerting per docs.
- LatencyMON / TraceMON / probe & coverage maps (adjacent, not DNS).

## Record types & query options supported

`query_type` per the current Magellan CLI reference (re-checked 2026-09-16, still 19 types, matches the original list exactly): **A, SOA, TXT, SRV, SSHFP, TLSA, NSEC, DS, AAAA, CNAME, DNSKEY, NSEC3, PTR, HINFO, NSEC3PARAM, NS, MX, RRSIG, ANY** (default A). `query_class`: **IN or CHAOS** (CHAOS matters: `version.bind`/`hostname.bind` TXT is how you fingerprint an anycast instance).

**Missing: HTTPS/SVCB (RFC 9460) are not in the allow-list, and Atlas still won't take arbitrary/integer RRTYPEs.** A [ripe-atlas mailing-list thread from 2026-05-06](https://mailman.ripe.net/archives/list/ripe-atlas@ripe.net/message/NXMI27ND2MB27XDH4L3DLRODZGZHO5FJ/) (Petr Špaček, ISC) asks RIPE to add HTTPS/SVCB, or accept the full IANA RRTYPE registry, or accept raw integers; per that thread the filter already special-cases NS/DS/ANY/RRSIG's "weird corner cases," so the ask is low-risk. As of this pass it is still an open request, not shipped — a tool wanting HTTPS/SVCB records (increasingly relevant for HTTPS-record-based routing) cannot mine or schedule them on Atlas.

| Knob | Field | What it buys |
|---|---|---|
| Recursive vs authoritative | `use_probe_resolver` (bool) | `true` = ask the probe's own resolver (the real end-user view); `false` = query `target` directly. Docs: setting it silently forces `set_rd_bit: true` |
| Explicit server | `target` / `target_ip` | query one named authoritative NS or one public resolver |
| Transport | `protocol` UDP\|TCP, `port`, `tls` | TCP + `tls` + port 853 ⇒ **DoT**. No DoH type |
| DNSSEC | `set_do_bit`, `set_cd_bit`, `set_ad_bit` | full DNSSEC-OK / CD / AD control |
| Recursion | `set_rd_bit` | RD flag |
| Server identity | `set_nsid_bit` | EDNS NSID ⇒ which anycast instance answered |
| EDNS size | `udp_payload_size` | 512..4096 (observed: 512 typical, 4096 occasionally) |
| Raw wire | `include_abuf` (default on), `include_qbuf` | **base64 answer/question wire messages in the result** |
| Client subnet | `default_client_subnet` | ECS |
| Robustness | `retry`, `timeout`, `ttl` | retries/timeout |
| Naming & cookies | `use_macros`, `prepend_probe_id`, `resolve_on_probe`, `cookies` | `$p`-style macros, per-probe unique qname (cache-busting), resolve hostname at the probe, DNS cookies (RFC 7873) |

**What people actually measure** (firsthand profiling): the 500 newest public DNS measurements are 100% one-off `A`/`IN`/`UDP` via `use_probe_resolver`, i.e. pure propagation/resolver-view checks. A Jan-2025 window (18,288 measurements, 500 sampled) is more varied: A 272 / AAAA 224 / TXT 4, af4 273 / af6 227, `use_probe_resolver` on 92, top targets `8.8.8.8`, `1.1.1.1`, `2606:4700:4700::1111`, `208.67.222.222`. `set_do_bit` was null in both samples: **DNSSEC-flagged public measurements are rare**, so mining won't cover DNSSEC.

## How it works

Server-side and distributed, the opposite of a one-box resolver. The user (or RIPE) writes a definition; the scheduler hands it to selected probes; each probe sends the query **from its own network** and ships the result back; results land in the archive and on the stream. Probes are the measurement point, so the answer reflects that probe's ISP, resolver, and path, not RIPE's.

The result record is the interesting part. Firsthand, one record from msm 10001 (`k.root-servers.net` SOA every 30 min since 2011):

```
{"prb_id":1,"from":"45.138.229.91","src_addr":"192.168.178.26","dst_addr":"193.0.14.129","af":4,
 "proto":"UDP","fw":4790,"lts":2,"msm_id":10001,"timestamp":1789547402,"stored_timestamp":1789547474,
 "result":{"rt":20.089,"size":92,"ID":39275,"QDCOUNT":1,"ANCOUNT":1,"NSCOUNT":0,"ARCOUNT":0,
   "abuf":"mWuEAAABAAEAAAAAAAAGAAEAAAYAAQABUYAAQAFhDHJvb3Qtc2VydmVycwNuZXQ...",
   "answers":[{"NAME":".","TYPE":"SOA","TTL":86400,"MNAME":"a.root-servers.net.",
     "RNAME":"nstld.verisign-grs.com.","SERIAL":2026091600}]}}
```

I base64-decoded that `abuf` myself: 92 bytes, `id=39275 flags=0x8400 QR=1 AA=1 RD=0 AD=0 CD=0 RCODE=0`. **The full DNS wire message is in the public archive.** Note `src_addr` (RFC1918) vs `from` (public egress) are both present, and `lts` = seconds since the probe last synced its clock, a data-quality signal.

Archive depth, firsthand, 5-min windows on msm 10001: 2015-01 → 7,437 results · 2020-01 → 7 · 2024-01 → 2,112 · 2026-01 → 2,227. A 2011-10 window (the measurement's own `start_time`) returned 0, so I confirm retrieval back to **2015**, not to 2011. **CORS is wide open for reads.** `Access-Control-Allow-Origin` echoed my `Origin: https://corpberry.com` on both GET and OPTIONS preflight, `Access-Control-Allow-Credentials: false`, `Access-Control-Allow-Methods: GET, HEAD, OPTIONS`. A browser can call the read API directly; no proxy needed. No `RateLimit-*` or `Retry-After` headers were returned on any call.

## Output & UX

API output is plain paginated JSON w/ `format=json|txt` (`txt` is newline-delimited JSON, not human text) and a `fields=` projection that trims the 57-field measurement object to what you asked for. Error shape is consistent and worth stealing verbatim: `{"error":{"detail":"...","status":403,"title":"Forbidden","code":104}}`, used by every failure I triggered (401, 403, 400, 405).

The web UI I **could not inspect**: every UI route (`/measurements/10001/`, `/probes/1/`, `/dnsmon/`, `/results/maps/network-coverage/`) serves the same ~1.8 KB SPA shell to `curl`, and browser tooling was out of scope for this pass. From docs and RIPE Labs write-ups: per-measurement pages carry a map of participating probes, a latency/result time series, a raw-results tab, and a share-friendly permalink `atlas.ripe.net/measurements/<id>/`; DNSMON/DomainMON render the server×time matrix. Treat all of that as secondhand.

## Monetization, limits & abuse controls

Not a business. Controls are the credit economy plus platform caps. Firsthand: no rate-limit headers, no throttling across ~40 calls, `page_size` capped at 500, writes hard-gated at 401. Secondhand (RIPE docs / ripe-atlas mailing list, numbers vary by account and are adjustable on request): ~**100 concurrent measurements**, ~**500–1,024 probes per measurement**, a sliding-24h **daily credit spending limit** (1,000,000 credits cited on the list), and a daily result-flow cap. The real abuse control is that measurements run from volunteers' home connections, so RIPE's acceptable-use posture is conservative: measure infrastructure, not people.

## Ideas worth stealing

- **The headline mechanic: answer "what did the world see?" without owning probes.** Given a domain, `GET /api/v2/measurements/?type=dns&target=<domain>&fields=id,description,start_time,status` (89 hits for `example.com`, firsthand), then pull `/latest/` on the interesting ones and decode each `abuf`. You get real answers from real networks, free, no credits, no account, at zero marginal infrastructure. Concretely in Go: `dns.Msg.Unpack(base64decode(abuf))` from `miekg/dns` gives you a full parsed message you can render exactly like your own `dig` output. Frame it as a "seen in the wild" panel next to your live lookup, labelled w/ each result's `timestamp`, never as live.
- **`fields=` projection on your own JSON responses.** One query param that trims the payload. Trivial in Go (build the struct, then marshal a filtered map), and it makes an htmx fragment endpoint and a JSON API endpoint the same handler.
- **The `warnings` array.** Instead of silently ignoring an unrecognised query param, return 200 + `warnings:[{source:{parameter:"..."},detail:["..."]}]`. Cheap, and it turns "why is my filter not working" into a self-answering response. Directly applicable to a CIDR/DNS form w/ optional knobs.
- **Three cheap result-panel mechanics.** (a) `src_addr` vs `from`: report both the querying host's internal address and its observed public egress, which makes NAT/split-horizon obvious and reuses what iptools already resolves. (b) `lts` (seconds since the probe last synced its clock) as a **per-row freshness badge**, not a global "may be cached" disclaimer. (c) Render `AA`/`RD`/`AD`/`CD`/`RCODE` as flag pills plus `QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT`; all free from decoding the wire message, and what separates a DNS tool from a "type domain, get IP" box.
- **CHAOS `version.bind` / `hostname.bind` + EDNS NSID as a "which server answered" card.** Two extra queries, both cheap, both something no consumer checker shows. Pair w/ `prepend_probe_id`-style nonce labels when you want authoritative behaviour rather than cache state.
- **Cache mined results in Mongo below the domain service.** TTL indexes (`platform.EnsureTTLIndex`) fit "keep the last N days of mined Atlas results" exactly. Atlas's open CORS means you *could* fetch client-side instead, but a server-side TTL cache keeps the feature nil-safe and stateless-degradable like the rest of the app.
- **Error envelope.** `{"error":{detail,status,title,code}}`: one struct answers "what does the JSON side return on failure" for a content-negotiated handler.

## Gaps & what it does not do

- **Not a lookup tool.** No "type a domain, press enter" path. Zero synchronous query API. Everything is schedule-then-poll, or mine-the-archive.
- **No DNSSEC validation**, only flags. Atlas gives you DO/CD/AD and the raw answer; chain validation is yours (or DNSViz's).
- **`status-check` does not support DNS.** Firsthand, on both a built-in and a user-defined ongoing DNS measurement: `403 "There are no status checks available for this type of measurement"` (distinct from the built-in-only refusal `"Built-in measurements are not available for status-checks"` returned for a ping measurement). Atlas's Nagios/Icinga-friendly alerting is effectively ping/latency-shaped, so **DNS alerting is a real gap** anyone could fill.
- **No DoH** (DoT only, via TCP+TLS+853), and **no propagation UX**: Atlas gives the raw ability, the "green ticks on a world map" product is DNSChecker/whatsmydns.
- **Archive filtering is coarse.** You cannot filter measurements by `query_type` or `query_argument` (both ignored), so "find every public DNSKEY measurement for example.com" requires fetching by `target`/`search` and filtering client-side. Combined w/ `set_do_bit` being null across both my samples, DNSSEC mining is weak.
- **No WHOIS/RDAP, no reputation, no email/SPF/DMARC scoring, no subdomain enumeration.** Pure measurement. And recent public DNS measurements are monotonous (500/500 one-off A/UDP/probe-resolver), so a naive mine over the newest records returns a wall of near-identical A lookups.
- **No HTTPS/SVCB query type**, and no path to arbitrary RRTYPEs (see Record types section above) — open feature request as of 2026-05, not shipped.
- **One-off queries are the expensive path.** A one-off DNS/UDP result costs 2x a periodic one (20 vs 10 credits), so "let a visitor check one domain right now" burns credits twice as fast as a recurring monitor would per-result — worth knowing before pricing any on-demand mining feature against someone's credit balance.

## Verified firsthand vs inferred

**Verified by curl/dig/decode, re-checked again on 2026-09-16 (second pass, independent calls):** read API needs no auth; **`type=dns` filter is honoured** (fresh count 37,497,781 of 195,488,750 unfiltered — both drifted up from the first pass as expected, `ping`/`traceroute` still return their own disjoint counts); which filters are honoured vs ignored, incl. the `warnings` array text; `page_size` max 500, 1000 still 400; writes and account endpoints still 401; CORS still echoes arbitrary Origin, GET/HEAD/OPTIONS only, credentials false, no `RateLimit-*`/`Retry-After` headers; measurement/result/probe/anchor JSON shapes, incl. the anchor object's `tlsa_record` field; `/latest/` behaviour; the unauthenticated stream; `abuf` decoding; archive retrieval at 2015/2020/2024/2026; `status-check` still 403 for DNS (re-confirmed on msm 10001) vs the distinct built-in-refusal text on a ping msm; network size counts (probes 60,629 total / 15,071 connected, anchors 1,792, anchor-measurements 12,780 — all within normal drift of the first pass); probe tag vocabulary re-confirmed at exactly 162 via `/api/v2/probes/tags/`; `OPTIONS` on `/measurements/` confirmed to return only `{name, description, renders, parses}`, no field schema; the Go library's `go.mod` on Codeberg (`main` branch, not `master`) depending on `miekg/dns` v1.1.50 exactly; the GitHub mirror confirmed `archived: true`, `pushed_at: 2026-02-04`, license MIT via the GitHub API; `sagan`/`cousteau`/`ripe-atlas-tools`/`dnsmon` all confirmed GPL-3.0 via their LICENSE files / GitHub API; `ripe-atlas-community-contrib` confirmed 177 stars.

**Docs, now fetched directly from RIPE's own pages (not observed live, but primary-source, not third-hand):** every credit figure — 15/min, 21,600/day, anchor 10x = 150/min = 216,000/day, DNS unit cost 10 credits/result UDP vs 20 TCP (RIPE's exact wording), ping 3/traceroute 30/SSLCert 10 for comparison — plus a correction the first pass missed: **a one-off result costs 2x a periodic one**, so the "~500 credits for a 50-probe one-off" estimate was wrong and is now ~1,000; `credits_per_result: 10` remains the one figure directly visible in the API (for a periodic measurement). The full `query_type` allow-list was re-verified against the current (2026-09-16) Magellan CLI docs and is unchanged from the first pass; a 2026-05-06 ripe-atlas mailing-list thread additionally confirms **HTTPS/SVCB are still not supported** and the allow-list still can't take arbitrary RRTYPEs, a gap the first pass didn't surface. DoT port-853 specifics, DNSMON's 2001 origin and its July 2025 rewrite (independently corroborated via RIPE Labs' "DNSMON Gets a Makeover" and RIPE's own news post), and DomainMON's behaviour (auto NS discovery, 50-probe cap, `/embed` iframe URL, no alerting, ~10 min visualisation refresh) were all re-fetched from RIPE's docs/Labs pages directly and are consistent with the first pass, but remain doc-sourced: every UI route is still an SPA shell to `curl` and browser tooling stayed out of scope, so no web UI claim is firsthand. `use_probe_resolver` silently forcing RD is still docs-only, not re-verified (would need an authenticated measurement to exercise).

**Not attempted:** creating any measurement (no account, and I would not spend a stranger's credits), any authenticated endpoint, any AXFR, any streaming beyond the original 8s sample, opening any UI route in a real browser.

## Open source / reusable

| Project | Lang | License | Use here |
|---|---|---|---|
| [`DNS-OARC/ripeatlas`](https://codeberg.org/DNS-OARC/ripeatlas) | **Go** | MIT | **The one to read.** `Atlaser` interface over File/Http/Stream; `measurement/result.go` decodes `Abuf()`/`Qbuf()` into `*miekg/dns.Msg`. GitHub mirror archived Feb 2026, moved to Codeberg; `go.mod` pins `miekg/dns` v1.1.50 (old, but the decode pattern is ~20 lines you can lift rather than vendor) |
| `RIPE-NCC/ripe-atlas-sagan` | Python | GPL-3.0 | reference for every result edge case + abuf parsing; read it for the field semantics, don't port it |
| `RIPE-NCC/ripe-atlas-cousteau` | Python | GPL-3.0 | API + streaming client, 68★ |
| `RIPE-NCC/ripe-atlas-tools` (Magellan) | Python | GPL-3.0 | the `ripe-atlas measure dns` CLI; its flag list is the best plain-text spec of the DNS options |
| `RIPE-NCC/dnsmon` · `RIPE-Atlas-Community/ripe-atlas-community-contrib` | JS / Python | n/a | the rewritten DNSMON matrix visualisation; hackathon scripts incl. Nagios/Icinga glue (177★) |

GPL-3.0 on the RIPE-owned libraries is worth noting before copying code into a proprietary-ish personal project; the MIT Go library is the safe one.

## Sources

- [RIPE Atlas](https://atlas.ripe.net/)
- [RIPE Atlas REST API manual](https://atlas.ripe.net/docs/apis/rest-api-manual/) (SPA; read via rendering fetcher, not raw HTML)
- [Measurement definitions / the `definitions` array](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/creating-measurements/definitions/)
- [Credits](https://atlas.ripe.net/docs/getting-started/credits)
- [Status Checks](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/status-checks/) · [Streaming API](https://atlas.ripe.net/docs/apis/streaming-api/) · [DomainMON](https://atlas.ripe.net/docs/tools-and-code/domainmon/)
- [DNSMON](https://dnsmon.ripe.net/) · [DNSMON source](https://github.com/RIPE-NCC/dnsmon)
- [RIPE Atlas Tools (Magellan), `measure dns` flags](https://ripe-atlas-tools.readthedocs.io/en/latest/use.html)
- [`DNS-OARC/ripeatlas`, Go bindings, MIT](https://codeberg.org/DNS-OARC/ripeatlas) · [`RIPE-NCC/ripe-atlas-sagan`, result/abuf parsing](https://github.com/RIPE-NCC/ripe-atlas-sagan)
- [Bortzmeyer, *DNS measurements with RIPE Atlas*](https://www.ripe.net/media/documents/DNS-Measurements-with-RIPE-Atlas.pdf)
- [Bortzmeyer, finding popular anycast instances w/ Atlas UDMs (NSID/CHAOS technique)](https://labs.ripe.net/author/stephane_bortzmeyer/using-ripe-atlas-user-defined-measurements-to-find-the-most-popular-instances-of-a-dns-anycast-name-server/)
- [Atlas daily dumps](https://data-store.ripe.net/datasets/atlas-daily-dumps/) · [FTP archive](https://ftp.ripe.net/ripe/atlas/)
- [Guidelines for best practices](https://atlas.ripe.net/docs/howtos/best-practices/)
- [HTTPS/SVCB query-type request, ripe-atlas mailing list, 2026-05-06](https://mailman.ripe.net/archives/list/ripe-atlas@ripe.net/message/NXMI27ND2MB27XDH4L3DLRODZGZHO5FJ/)
- [DNSMON Gets a Makeover, RIPE Labs, 2025-07-21](https://labs.ripe.net/author/stephen_suess_1/dnsmon-gets-a-makeover/) · [RIPE NCC Launches Redesigned DNSMON](https://www.ripe.net/about-us/news/ripe-ncc-launches-redesigned-dnsmon/)
