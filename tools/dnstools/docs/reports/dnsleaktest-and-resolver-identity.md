# DNS leak tests & resolver identity
> dnsleaktest.com · bash.ws · ipleak.net · browserleaks.com/dns · dnscheck.tools · 1.1.1.1/help: the class of DNS tool that answers "**which resolver is *this visitor* actually using?**"

Every other report in this folder covers tools answering questions **about a domain**. This cluster inverts it: input = the visitor, output = **the set of recursive resolvers their queries came out of**, plus transport (Do53 / DoH / DoT), IPv4-vs-IPv6 egress, ECS behaviour, DNSSEC & QNAME-minimisation posture. It's the only DNS aspect that **cannot be computed server-side from a domain name**: it needs the client to emit real DNS traffic. That makes it the highest-differentiation feature available to a small self-hosted DNS tool, and the only one where owning an authoritative zone *is* the product.

- **URLs:** [dnsleaktest.com](https://www.dnsleaktest.com/) (IVPN Ltd) · [bash.ws/dnsleak](https://bash.ws/dnsleak) (macvk) · [ipleak.net](https://ipleak.net/) (AirVPN) · [browserleaks.com/dns](https://browserleaks.com/dns) · [dnscheck.tools](https://dnscheck.tools/) (Brian Shea) · [one.one.one.one/help](https://one.one.one.one/help/) (Cloudflare)
- **Category:** client-observed resolver identification · **Registration:** none anywhere · **Pricing:** all free, no keys, no published quotas (re-checked 2026-09-16); three of six are VPN lead-gen · **API:** bash.ws, ipleak.net, BrowserLeaks & Cloudflare's beacons all serve no-auth JSON w/ `Access-Control-Allow-Origin: *`; dnscheck.tools answers over DNS itself.
- **Firsthand check:** heavy, re-run 2026-09-16. Ran the ipleak beacon end-to-end, the full bash.ws cycle (`/id` -> dig -> `?json` -> `?txt`), fetched live BrowserLeaks `dns4`/`dns6` beacon bodies, read `dns.js` / `index.js` / the help page bundle, dug `test.dnscheck.tools`, and pinned down **two mechanisms the previous pass had wrong** (BrowserLeaks' v4/v6 split, and where Cloudflare's conditional answer comes from). **Still not observed:** dnsleaktest.com's rendered results page. `results.html` is POST-only (`GET` -> 405) and I don't submit third-party forms; the *submission contract* is read off the landing page's own markup, the *rendering* is not.

## What it is

Six independent implementations of one mechanism. Three are **VPN marketing assets** (dnsleaktest.com's footer says **IVPN Limited**; ipleak.net is "powered by" **AirVPN**; bash.ws runs on donations + an Android app), one is a **privacy-research suite** (BrowserLeaks, ads + remark42 comments), one is a **vendor self-diagnostic** (Cloudflare's help page, whose stated purpose is producing a shareable URL for forum support posts), and one is **an open-source protocol test rig** (dnscheck.tools). The privacy framing matters less than the plumbing: underneath, all six are **an authoritative nameserver w/ a wildcard zone and a query log**.

## Registration, access & pricing

Nothing to register, nothing to pay, no keys. No rate-limit headers observed on any endpoint.

| Service | Auth | CORS | Documented API | Machine output |
|---|---|---|---|---|
| bash.ws | none | `ACAO: *` | yes, via the MIT CLI | JSON + pipe-delimited text |
| ipleak.net | none | `ACAO: *` (+ methods/headers allow-lists) | partial | JSON |
| browserleaks.com | none | `ACAO: *`, `ACAH: *` | no (beacon internal) | JSON |
| dnscheck.tools | none | no `ACAO` on the site | **yes**, a documented label grammar | DNS TXT |
| every1dns.net (CF) | none | `ACAO: *` on `map`; HEAD -> 400 | no | JSON body, `content-type: text/plain` |
| dnsleaktest.com | none | CSP `connect-src 'self' https://www.dnsleaktest.com` | no | none, HTML only |

## How it works: wildcard zone + authoritative logging

The whole trick, stated precisely, because it's cheap to build and nothing else in DNS tooling yields data you can't get elsewhere.

1. **Own a zone, run its authoritative NS yourself.** dnsleaktest.com runs `ns1`/`ns2.dnsleaktest.com`, both glued to the *same* IP `23.239.16.110`; ipleak.net delegates to `dns1`/`dns2.dnsleak.net`, both `95.85.16.212`; BrowserLeaks' four NS names all resolve to one host (`104.236.69.55` / `2604:a880:800:10::e6:b001`). Redundancy isn't the point, the query log is.
2. **Wildcard it.** `dig A zzrandomtest12345.dnsleaktest.com` -> `23.239.16.110` (TTL 300); `*.ipleak.net` -> `95.85.16.212` (TTL 21600); `*.bash.ws` -> `94.130.181.15` (TTL 60); BrowserLeaks beacons TTL 60. Any label answers.
3. **Mint a random hostname per session** so no cache absorbs the query. ipleak: 40 chars `[a-z0-9]` via **`Math.random`**. BrowserLeaks: 12 chars from `abcdefghijkmnopqrstuvwyz0123456789` (34 symbols, **l & x omitted**, confusable-safe) via `crypto.getRandomValues` w/ a `Math.random` fallback. Cloudflare: a UUIDv4. bash.ws: 16-char id from `GET /id`, then `1..N.<id>.bash.ws`.
4. **Make the client resolve it.** In a browser, `fetch('https://<random>.<zone>/')` forces stub -> recursive -> authoritative. The bash.ws CLI instead runs `ping -c 1 -W 1 <random>.<id>.bash.ws`: the ping failing is irrelevant, **the name resolution is the beacon**. Clean trick for a CLI w/ no HTTP dependency.
5. **Log the query's source IP at the authoritative** (= the recursive resolver's egress, obtainable no other way), then **join back over HTTP** on the session id embedded in the hostname. ipleak's join is purely client-side: I invented my own 40-char label, and `/dnsdetection/` echoed it back verbatim as `session`. No server-side allocation step at all.

Two build consequences. You need a **wildcard TLS cert** for an HTTPS beacon: ipleak.net presents `CN=*.ipleak.net` from Let's Encrypt (`openssl s_client -servername abc123test.ipleak.net`). And **one hostname yields more than one authoritative query**, consistent w/ the resolver asking A and AAAA. Three live rounds on one session, the set growing as the pool is sampled:

```
step 1: {"172.69.154.98":1,"162.158.245.13":1,"162.158.245.14":1}
step 2: {"162.158.245.13":2,"162.158.245.14":2,"172.69.154.98":1}
step 3: {"162.158.245.14":4,"162.158.245.13":2,"172.69.154.98":1}
```

One hostname is never enough, because big resolvers are **pools**. dnsleaktest.com's explainer: "if you configure Google DNS then you will often find 6-10 Google DNS servers"; my bash.ws run surfaced 10 distinct Google egress IPs. Hence every implementation fires many probes.

### Cloudflare's variant: transport-conditional resolution

1.1.1.1/help does something materially smarter than counting resolver IPs. Beacon zone = **`help.every1dns.net`**, separately delegated to `duke`/`nora.ns.cloudflare.com` (the `every1dns.net` apex sits on a different CF pair). The page builds four names and, for each `is-*` name, does nothing but `fetch('https://<name>/cdn-cgi/trace')` and record `r.ok` as a boolean:

| Name | Renders as | Resolves only when |
|---|---|---|
| `<uuid>.is-cf.help.every1dns.net` | "Connected to 1.1.1.1" | query came via a Cloudflare resolver |
| `<uuid>.is-doh.help.every1dns.net` | "Using DNS over HTTPS (DoH)" | client reached the resolver over DoH |
| `<uuid>.is-dot.help.every1dns.net` | "Using DNS over TLS (DoT)" | client reached the resolver over DoT |
| `<uuid>.map.help.every1dns.net` | AS Name / AS Number | always (JSON endpoint) |

Verified firsthand, one random uuid throughout:

```
is-cf  @8.8.8.8                      -> NXDOMAIN
is-cf  @1.1.1.1 (Do53)               -> NOERROR, CNAME target.every1dns.net (TTL 0)
is-doh @1.1.1.1 (Do53)               -> NXDOMAIN
is-doh over cloudflare-dns.com DoH   -> Status 0, CNAME target.every1dns.net
is-dot over DoH                      -> Status 3 (NXDOMAIN)
is-cf/-doh/-dot @duke|nora (the zone's own NS) -> NXDOMAIN
```

That last line is the correction. **The positive answer is not a record the zone's authoritative will serve you.** Same uuid, same instant: 1.1.1.1 says NOERROR, the zone's delegated nameservers say NXDOMAIN, and 8.8.8.8 says NXDOMAIN. The verdict exists only on Cloudflare's own resolver path, which is exactly why no third party can reproduce it. *Still not fully settled:* recursive synthesis vs an authoritative view that only trusts CF resolvers, because direct-to-NS probing is itself filtered (`map` returns NODATA at `duke` yet resolves normally through 8.8.8.8). Either way the build consequence is identical, see Gaps. TTL 0 on the CNAME stops any caching of a verdict.

The `map` sibling is the richest undocumented endpoint in the cluster. `GET https://<uuid>.map.help.every1dns.net` (served `text/plain`, `ACAO: *`) returned:

```json
{"ip":"2a00:1450:4001:c07::12b","ip_version":2,"protocol":"udp","dnssec":true,"edns":0,
 "client_subnet":-1,"qname_minimization":false,"isp":{"asn":15169,"name":"Google LLC"}}
```

A **per-resolver capability profile**: the resolver's own egress address (`ip_version` 1 = v4, 2 = v6, both observed), transport, DNSSEC-DO, EDNS version, whether ECS was sent (`-1` = none), and **QNAME minimisation**. The help bundle reads `isp.name` / `isp.asn` straight into the AS Name / AS Number rows.

## Features, complete inventory

### dnsleaktest.com (IVPN)
Server-rendered, no JS needed for the test. The landing page greeted a bare `curl` with "**Hello 89.222.123.81 / from Berlin, Germany**" + flag: geo-IP before any interaction. Whole document is 6 KB.

- **Submission contract, read off the markup:** `<form action="results.html" method="POST">` w/ two submit buttons sharing `name="type"`, values `Standard test` and `Extended test`. No hidden fields, no token.
- **Standard test:** 1 round of 6 queries, 6 total. **Extended test:** 6 rounds of 6, **36 total**, "ensures that all DNS servers are discovered", costs 10-30s longer. The pre-2014 original did 3.
- **"What's the difference?"** sits directly under the two buttons. Best UX detail on the site: the mode chooser is one click from its own rationale.
- Explainers (*What is a DNS leak?*, *How to fix a DNS leak*) incl. a **transparent DNS proxy** section (ISPs intercepting :53 and proxying results) and an honest passage that a browser's *default* DoH provider "could be considered to be a leak". **WebRTC leak test** sibling page.
- Self-hosted **Matomo** (`/ana/matomo.js` -> 200, `/ana/` -> 404), no third-party analytics. Hardened headers: CSP w/ `connect-src 'self' https://www.dnsleaktest.com`, `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` denying geolocation/mic/camera. `HEAD /` -> 405.
- **No API, no export, no shareable result URL, no JSON.** Weakest machine surface of the six.

### bash.ws
Most engineering-friendly of the six, and the contract worth copying outright.

| Endpoint | Returns |
|---|---|
| `GET /id` | 16-char test id, `text/plain`, `ACAO: *` |
| *(client resolves `1..N.<id>.bash.ws`)* | |
| `GET /dnsleak/test/<id>?json` | array of `{ip, country, country_name, asn, org, type}` |
| `GET /dnsleak/test/<id>?txt` | `ip\|cc\|country\|asn\|type` per line |
| `GET /dnsleak/test/<id>` | HTML |

`type` ∈ `ip` (your egress) · `dns` (each resolver found) · `conclusion`. The conclusion row reuses the `ip` field for the verdict string; live output was `DNS may be leaking.| | | |conclusion`. Ugly, but one parser handles every row. `org` exists in JSON only.

- **Reference client** [macvk/dnsleaktest](https://github.com/macvk/dnsleaktest) v1.4.0, **MIT** (confirmed via the GitHub API), 489 lines of POSIX sh + py/bat ports, compiled binaries, Docker. Flags: `-i/--interface`, `-p/--probes` (30), `-j/--parallel` (30), `-s/--short`, `-w/--watch SECONDS` (min 10), `-v/--verbose info|trace`, `--log-file` (implies `--verbose info`), `--raw-output`, `--request`, `--head`, `--silent`, `--monochrome-output`.
- **Anonymity rating**, an aggregate score (~25% on my connection) w/ a details page.
- **Export row:** Share URL · Copy · Embed · RAW · HTML+highlight · JSON.
- Sibling tools, from the live nav: Email leak · WebRTC leak · Torrent leak · IP blacklist check · Open port check · My IP · Traceroute · Nslookup · Host · Ping · Dig · Geoiplookup · Refs.
- WordPress plugin `macvk/vpn-leaks-test` (**GPL-3.0**), Android app.

### ipleak.net (AirVPN)
- **DNS detection:** beacon `https://<40-char session>-<step>.ipleak.net/dnsdetection/` returns `{"session":"…","ip":{"<resolverIP>":<hitCount>}}`. Per-resolver **hit counts**, not just a set.
- **Adaptive probe cadence** (`index.js`): `timeout = 1` ms until step 100, then 1000 ms, then `0` at step 300 = hard stop. Fast convergence, then a slow tail that keeps finding pool members while you read.
- Heading string, built in the `complete` handler: `DNS Address[es] - N server[s] detected, M tests`, w/ `, K errors.` appended **only if** K != 0.
- **IP addresses:** "Browser default" vs "Fallback" rows, exposing IPv4/IPv6 divergence.
- **WebRTC detection** (STUN). **Torrent address detection:** point a torrent client at a generated hash, it reports the IP your BitTorrent traffic arrived from. Genuinely distinctive. **Two geolocation maps:** browser Geolocation API (permission-gated, opt-in) vs IP-derived.
- **IP details:** IP, ISP, **"AirVPN: No"**, ASN, country/region/city, timezone, lat/lon, accuracy radius (20 KM), last-data-update timestamp. MaxMind-sourced.
- **Forced-family hosts** `ipv4.ipleak.net` (95.85.16.212) / `ipv6.ipleak.net` (2a03:b0c0:0:1010::509:d001), plus **alternate ports 8000 and 62222** (both answered 200): a cheap port-blocking/censorship probe.
- **JSON API:** `GET /json/` (self), `/json/<ip>`, `/json/<hostname>` (resolves, returns an `ips{}` map keyed by address). Fields: `as_number, isp_name, country_code/name, region_code/name, continent_code/name, city_name, postal_code, postal_confidence, latitude, longitude, accuracy_radius, time_zone, metro_code, level, cache, ip, reverse, query_text, query_type, query_date`. `query_type` self-describes as `myip` / `ip`. Geo fields come back `null` for infrastructure addresses (`/json/1.1.1.1` had ASN + ISP only). `level` returned `"min"` on every response; meaning still undocumented.

### browserleaks.com/dns
Most rigorous probe design of the six, and the one whose mechanism is most often described wrongly (including by the previous pass of this report).

- **50 beacons per run, 25 IPv4 + 25 IPv6**, verified in `dns.js`, not from the marketing copy: `for(t=0;t<50;t++) name = <12 rand>.dns + (t%2==0 ? "4" : "6")`. Even index -> `dns4`, odd -> `dns6`, exactly 25 each.
- **Two apex domains, alternating:** a counter starts at 4, so the first 4 requests go to `browserleaks.net` and the remaining 46 to `browserleaks.org`. Both apexes are on the *same* Cloudflare NS pair, so this hedges against one **name** being blocked or cached, not against an authority outage.
- **15 parallel workers** draining a 50-item queue (`Array.from({length:15}, …)`).
- **The v4/v6 discriminator is transport, not record type.** `dns4`/`dns6` are separately delegated to self-run `ns1`/`ns2.browserleaks.{net,org}`, all four names pointing at one dual-stacked host. Queried direct over IPv4: `*.dns4.…` -> NOERROR + A, `*.dns6.…` -> **REFUSED**. Via a dual-stacked recursive, `*.dns6.…` answers an ordinary **A** record (`104.236.69.55`, TTL 60). So what's measured is whether the **resolver** could reach the authoritative over IPv6, and the client's own IPv6 support is irrelevant. A label that merely "answers AAAA only" would measure something else entirely.
- Beacon returns `{"<resolverIP>":["<CC>","<City, Country>","<ISP>"]}`, accumulated & deduped across all 50 (`ACAO: *`, `ACAH: *`). Live bodies, fetched firsthand:
  - `dns4` -> `{"172.217.34.23":["DE","Germany, Frankfurt am Main","Google LLC"],"162.158.245.141":["DE","Germany, Berlin","Cloudflare"],…}`
  - `dns6` -> `{"2a00:1450:4001:c07::120":["DE","Germany, Frankfurt am Main","Google LLC"],"2400:cb00:67:1024::a29e:f52a":["DE","Germany, Berlin","Cloudflare"],…}`
- Live counter: `Found N Servers, X ISP, Y Locations`, rewritten on every response. Results table: **IP Address · ISP · Location**, IPv4 sorted numerically by octet then IPv6 by hextet appended after, sortable headers, and a **column swap below 740px** (ISP first on mobile) instead of horizontal scroll.
- Page also carries an **IP Address Lookup** box (-> `/ip/<addr>`) and a remark42 comment thread (count is JS-loaded, not in the HTML).

### dnscheck.tools (Brian Shea)
The one the previous pass missed, and the most important of the six for a builder: **the authoritative side is open source Go.**

- Browser page reports **your IPs · whether your resolvers advertise ECS · your resolvers · DNSSEC validation**, plus a status bar of IPv6 / EDNS / DNSSEC / **ECH** / average RTT / total DNS requests analysed.
- **The API is DNS itself**, documented: `dig txt [OPTIONS.]test[-DNSSEC][-NET].dnscheck.tools`. Live TXT response, dug firsthand 2026-09-16:
  ```
  "ECS: 89.222.123.0/24 (Datacamp Limited) (Berlin, State of Berlin, DE)"
  "FROM: 172.217.33.219#40643 (Google LLC) (Frankfurt am Main, Hesse, DE) (UDP)"
  "EDNS: version: 0; flags: do; udp: 1400"
  "ID: 48427"
  ```
  Source port, transport, EDNS buffer & DO flag, ECS prefix, query ID, all geo/registrant-enriched, in four TXT strings and zero HTTP.
- **Fault injection in the label** (per its help page): `badsig`, `expiredsig[t]`, `nosig`, `nullip`, `nxdomain`, `refused`, `truncate`/`notruncate`, `compress`, `txtfill n`, `random`. `badsig` observed firsthand -> **SERVFAIL** through my validating resolver, which is a working DNSSEC-validation test in one dig.
- **DNSSEC algorithm selector** `-alg13` (ECDSA P-256, default) / `-alg14` (P-384) / `-alg15` (Ed25519) / **`-alg18` (ML-DSA-44, post-quantum)**; `-ipv4` / `-ipv6` force the offered NS family.
- `/watch/<id>` streams the requests arriving for that id. RDAP for registrant grouping, reverse DNS for hostnames. Stated privacy policy: no personal data, no cookies.

### 1.1.1.1/help (Cloudflare)
- Checks, read from the bundle: booleans `isCf` · `isDoh` · `isDot` · `isWarp` · one per resolver IP; values `datacenterLocation` · `ispName` · `ispAsn`.
- **Connectivity to resolver IPs**, one row each: `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001`, each tested by `fetch('https://<addr>/cdn-cgi/trace')` and reduced to `r.ok`. Isolates "resolver unreachable" from "resolver not selected".
- **WARP is a composite, not a probe:** `isWarp = ("on" === t.warp || "plus" === t.warp) && !(isDoh || isDot)`. One displayed row derived from three signals.
- **`/cdn-cgi/trace`**, free anycast telemetry on every Cloudflare zone, `ACAO: *`, plain `k=v` lines: `fl h ip ts visit_scheme uag colo sliver http loc tls sni warp gateway rbi kex`. `colo` is the PoP (`TXL` for me), and **`sni=plaintext` vs `encrypted` is the entire ECH check**, one field.
- **Shareable result URL w/ zero server state:** `shareUrl = window.location.href + "#" + btoa(JSON.stringify(results))`. Base64 JSON in the **fragment**, so it never reaches the server. Framed as "Please include this URL when you create a post in the community forum."
- **Purge Cache** at `/purge-cache/`: flush 1.1.1.1's cache for one name, w/ an 18-type selector (A, AAAA, CAA, CNAME, DNSKEY, DS, HTTPS, LOC, MX, NAPTR, NS, PTR, SPF, SRV, SVCB, SSHFP, TLSA, TXT). Plus per-OS setup guides, FAQ, apps.

### Adjacent: resolver-identity RRs & DoH JSON
Not products, but the cheapest version of this feature, w/ no zone to own. All dug firsthand 2026-09-16:

| Query | Result |
|---|---|
| `TXT o-o.myaddr.l.google.com @8.8.8.8` | `"172.217.33.209"` + `"edns0-client-subnet 89.222.123.0/24"`: resolver egress **and** the ECS prefix it forwarded |
| `TXT whoami.ds.akahelp.net` | labelled triple `"ns"` (resolver egress) / `"ecs"` (`89.222.123.0/24/24`) / `"ip"` |
| `TXT resolver.dnscrypt.info` | `"Resolver IP: …"` + `"CD flag set (Checking Disabled)"`, human-readable |
| `A whoami.akamai.net` | resolver egress as a plain A record, no TXT parsing |
| `CH TXT id.server @1.1.1.1` | `"txl01"` (NSID, RFC 5001: the PoP) |
| `CH TXT id.server @9.9.9.9` | `"res711.qbre1"` |
| `CH TXT id.server @8.8.8.8` | no answer |
| `TXT whoami.cloudflare @1.1.1.1` | **NXDOMAIN**. The widely-cited trick is dead as of 2026-09-16 |

On akahelp's `ip` field: across three resolvers it always landed inside the `ecs` /24 that the same response advertised, never matched my observed HTTP egress, and **vanished entirely against Quad9**, which sends no ECS (only `ns` came back). *Inferred:* it's ECS-derived rather than an independent observation. Akamai documents none of it, so don't build a "your real IP" claim on it.

**DoH JSON**, the transport a browser-side tool would use: `https://cloudflare-dns.com/dns-query?name=&type=&do=&cd=` w/ header `accept: application/dns-json`, and `https://dns.google/resolve?name=&type=`. Both return `Access-Control-Allow-Origin: *` on GET. Google additionally returns `"Comment":"Response from 173.245.58.162."`, naming the authoritative it used. The `ct=application/dns-json` query-param alternative returned **HTTP 400, zero-length body**; only the `Accept` header worked. `dns.google/dns-query` w/ that header also 400s: the JSON path there is `/resolve`.

## Record types & query options supported

Mostly minimal. Five of the six query *for* the client, not on the client's behalf: A/AAAA only, implied by the beacon hostname. dnscheck.tools is the exception, exposing a real option grammar over TXT, and Cloudflare's `/purge-cache/` an 18-type selector (cache management, not lookup). The user-facing knobs:

- **Probe count / rounds:** dnsleaktest Standard(6) vs Extended(36); bash.ws `-p` default 30; ipleak auto-escalating to 300; BrowserLeaks fixed 50.
- **Address family:** BrowserLeaks `dns4`/`dns6` delegations, ipleak `ipv4.`/`ipv6.` hosts, dnscheck `-ipv4`/`-ipv6`. **Transport:** Cloudflare's `is-doh`/`is-dot`/`is-cf` triple, ipleak's ports 8000/62222. **Source interface:** bash.ws CLI `-i/--interface`, to test a specific tunnel. **Protocol faults:** dnscheck's `badsig` / `truncate` / `refused` / `txtfill` family.

## Output & UX

- **Progressive, never blocking.** ipleak renders "DNS detection - Pending, please wait" then grows the list w/ hit counts; BrowserLeaks starts empty and injects the table on first response; Cloudflare shows a pending state per row and flips each independently. Nobody waits for all probes.
- **Live counters in the heading:** ipleak's `N servers detected, M tests`, BrowserLeaks' `Found N Servers, X ISP, Y Locations`. Progress and result in one string, no spinner.
- **Two-tier verdict:** raw resolver list plus a plain-language conclusion (`DNS may be leaking.`, `isWarp: Yes/No`). Never only one. And **geo/ASN enrichment inline** on every resolver IP, because a bare `172.253.1.219` tells a non-expert nothing.
- **Share/export:** Cloudflare's fragment-encoded URL (stateless, private), bash.ws's RAW / HTML / JSON / Embed row. The rest offer neither. **Empty states are the hard part** and none of them solve it: a resolver that never queries (fully cached, blocked, or no DNS at all) is indistinguishable from a slow one.

## Monetization, limits & abuse controls

None charge. dnsleaktest.com -> IVPN, ipleak.net -> AirVPN, 1.1.1.1/help -> Cloudflare's own resolver: the tool *is* the ad. bash.ws runs donations + Android app + GA w/ `anonymize_ip`. BrowserLeaks runs ads + community. dnscheck.tools runs a GitHub FUNDING link. No published rate limits, keys or quotas on any endpoint, and no limit headers seen, which is **not** proof there is no limit. Abuse control is structural: beacon zones return tiny fixed responses, TTLs are short (0-300s) so caches can't serve stale verdicts, and session ids are long enough (40 chars / UUIDv4) that enumerating someone else's results is impractical.

## Ideas worth stealing

Ordered by value-to-effort for a Go + htmx tool.

- **Read [brianshea2/addr.tools](https://github.com/brianshea2/addr.tools) before writing a line.** It is the authoritative-side query logger, in Go, on a `miekg/dns` fork, w/ the zone logic, TTL store and JSON bridge already factored (`cmd/addrd`, `internal/zones`, `internal/dns2json`, `internal/ttlstore`). **AGPL-3.0**, so copying code into corpberry would make the whole served binary AGPL. Read it, don't vendor it, unless that's an accepted outcome.
- **Own a wildcard subzone and log it. This is the feature.** Delegate e.g. `probe.corpberry.com` to a small Go authoritative answering `*` w/ one A + one AAAA and writing `(qname, source IP, qtype, transport, EDNS, timestamp)` to Mongo. `platform.EnsureTTLIndex` prunes it; a 10-minute TTL is plenty. Everything below builds on this one component.
- **Session id in the hostname, joined over HTTP.** No cookies, no server session, no allocation endpoint: the client invents `<40-char id>-<step>.probe.corpberry.com`, then `GET /probe/<id>`. ipleak proves the id needs no server round-trip at all. Fits the layered rule exactly, repository below a domain service, handler parses the id.
- **`Respond(...)` gives you the bash.ws contract free.** One domain call, three renderings: htmx fragment for progressive fill, JSON for scripts, and a **pipe-delimited text** variant, `ip|cc|country|asn|type` w/ a trailing `conclusion` row. One-parser simple, and `curl corpberry.com/probe/<id>?txt` becomes a real CLI without shipping a CLI.
- **Answer the whole profile as TXT** (dnscheck.tools). `dig txt test.probe.corpberry.com` returning source IP, port, transport, EDNS/DO, ECS is a complete API w/ no HTTP, no CORS, no JS, and it works from any shell on earth. Cheapest "API" this repo could ever ship.
- **Per-resolver hit counts, not a set** (ipleak). `{"1.2.3.4": 7}` shows which pool member dominates, turning a boolean into a distribution for free.
- **Adaptive probe cadence** (ipleak): burst the first ~20 back-to-back, back off to ~1/s, keep going while the user reads. Converges instantly *and* keeps finding pool members. Trivial in JS, no server cost.
- **Split the v4 and v6 beacons by NS reachability, not by record type** (BrowserLeaks). Delegate `v6.probe.…` to a nameserver that listens on IPv6 only and `v4.probe.…` to one on IPv4 only. That reveals the **resolver's** IPv6 path regardless of whether the visitor has IPv6. Serving AAAA-only from a dual-stacked NS would not.
- **Fault-injection labels** (dnscheck.tools). `badsig.probe.…` serving a broken signature turns "is your resolver validating DNSSEC?" into one query w/ a SERVFAIL/NOERROR answer. Same pattern for `truncate` (UDP->TCP fallback) and `refused`.
- **Report resolver capability, not just identity.** Your authoritative already sees every query: log transport, EDNS version & buffer size, DO bit, presence and width of ECS, whether the qname arrived minimised. A **resolver capability card** costing nothing beyond parsing what already arrived.
- **Stateless shareable results in the URL fragment** (Cloudflare): `location.href + "#" + btoa(JSON.stringify(results))`. No database, no expiry, and the result never touches the server. Ideal for shareable output without storing anyone's resolver data.
- **Two named modes w/ the rationale one click away** (dnsleaktest): "Quick (6 probes)" / "Thorough (36 probes)" plus a "what's the difference?" link *under the buttons*. Cheaper and clearer than a slider.
- **`ping` as the beacon for CLI users** (bash.ws): `for i in $(seq 1 20); do ping -c1 -W1 $i.$ID.probe.corpberry.com & done` makes the tool scriptable anywhere, zero dependencies. And **surface Extended DNS Errors** (RFC 8914) verbatim on failure; almost no consumer tool does.
- **`/cdn-cgi/trace` as a format**, not a service: a plain `k=v` text endpoint exposing what the server sees about the connection (IP, TLS & HTTP version, SNI plaintext/encrypted, PoP). `cut -d=` for scripts, zero markup.
- **Enrich every resolver IP w/ ASN + geo**, which the iptools domain package already does. This feature is largely a new front door onto code that exists.

## Gaps & what it does not do

- **No domain-side DNS at all** in five of six. None of the leak tests will look up an arbitrary name: no record viewer, no DNSSEC chain, no propagation map, no email audit. Only dnscheck.tools takes a query, and only against its own zone.
- **The tested resolver is the *browser's*, not the *system's*.** Chrome/Firefox DoH bypasses the OS stub, so results reflect the browser's resolver. dnsleaktest.com is the only one that says so plainly.
- **Client-side transport is invisible to everyone but the resolver operator.** Cloudflare's `is-doh`/`is-dot` verdicts are not authoritative records: the zone's own NS answer NXDOMAIN for the same name that 1.1.1.1 answers. An independent tool can report *its* leg (UDP/TCP, v4/v6, ECS, DO, EDNS) but **cannot** tell whether the user reached their resolver over DoH. Don't build a UI row that implies otherwise.
- **`whoami.cloudflare` is gone** (NXDOMAIN, re-checked 2026-09-16). Anything citing it is stale.
- **Egress IP churn breaks naive correlation.** My own egress moved across `89.222.123.{35,78,81,96,169}` and even into a neighbouring /24 within minutes on a NAT pool, so "your IP's ASN == your resolver's ASN, therefore no leak" is fragile. bash.ws hedges w/ "DNS **may** be leaking."
- **No pool-completeness guarantee** (ipleak caps at 300 probes and still only samples), and **no published free-tier limits anywhere**.

## Verified firsthand vs inferred

**Verified (probed 2026-09-15 and re-probed 2026-09-16):** wildcard + NS layout & TTLs for all five beacon zones incl. BrowserLeaks' `dns4`/`dns6` sub-delegations and their IPv4-REFUSED / IPv6-only behaviour; the `CN=*.ipleak.net` Let's Encrypt cert; ipleak `/dnsdetection/` full cycle (incl. client-chosen session ids), its cadence & `makeID` source, `/json/` in all three forms + CORS, and ports 8000/62222; the bash.ws `/id` -> `?json` -> `?txt` cycle, CORS, live nav, and the v1.4.0 script's flags, line count, MIT licence & `ping` beacon; BrowserLeaks `dns.js` probe construction (50 names, `t%2` parity, 4/46 apex split, 15 workers, charset) plus live `dns4`/`dns6` bodies + CORS; the every1dns.net conditional matrix **including NXDOMAIN from the zone's own NS**, the `map` JSON schema & content-type, the `/cdn-cgi/trace` field set, `/purge-cache/`'s 18 types, and the help bundle's check list, `isWarp` formula & `shareUrl` construction; dnscheck.tools' live TXT profile, `badsig` -> SERVFAIL, and the repo's AGPL-3.0 licence / Go / `miekg/dns` dependency; all eight resolver-identity RR results; DoH JSON CORS and the `ct=` 400; dnsleaktest.com's SSR greeting, POST form markup, headers, 405s, Matomo path and Standard/Extended query counts.

**Inferred or secondhand, flagged in place:** dnsleaktest.com's *rendered* results page (POST-only, form not submitted; the submission contract is observed, the output is not); whether Cloudflare's conditioning is recursive synthesis or a restricted authoritative view (narrowed, not settled, since direct-to-NS probing is itself filtered); ipleak's `level` field meaning; akahelp's `ip` semantics (observed to track ECS and to disappear without it, but undocumented); dnscheck.tools' full option grammar and DNSSEC algorithm list beyond `badsig`, taken from its help page. One earlier claim is **withdrawn**: an RFC 8914 Extended DNS Error seen through 1.1.1.1 on a `dns6` AAAA query did not reproduce on 2026-09-16 (NOERROR/NODATA instead), so treat it as a transient, not as normal behaviour.

## Open source / reusable

- **[brianshea2/addr.tools](https://github.com/brianshea2/addr.tools)**, **AGPL-3.0**, Go (go 1.27.1, `miekg/dns` v1.1.73 via a personal fork). Runs dnscheck.tools, myaddr.tools, challenges.addr.tools and friends from one `addrd` daemon. This is the piece every other service in this cluster keeps closed: the query-logging authoritative, its zone synthesis, its TTL store and its DNS->JSON bridge. The AGPL is the catch, its network-use clause reaches a hosted binary.
- **[macvk/dnsleaktest](https://github.com/macvk/dnsleaktest)**, MIT. The client is the useful part: a complete, readable reference for the probe-then-poll contract in 489 lines of POSIX sh, plus Python/batch ports and a Docker image. Server side closed. Companion `macvk/vpn-leaks-test` WordPress plugin is GPL-3.0.
- **ipleak.net `index.js` / browserleaks `dns.js`**: not licensed for reuse, but readable enough to learn the mechanism from, which is what matters. The logic is ~40 lines either way.
- **Cloudflare's beacon zone and `map` endpoint are wholly undocumented**, so the schema above is observed behaviour that can change without notice.

## Sources

- [dnsleaktest.com, Standard vs Extended test explainer (query counts)](https://www.dnsleaktest.com/what-is-the-difference.html)
- [dnsleaktest.com, What is a DNS leak? (transparent DNS proxy, browser DoH caveat)](https://www.dnsleaktest.com/what-is-a-dns-leak.html)
- [bash.ws, DNS leak test page & mechanism FAQ](https://bash.ws/dnsleak)
- [macvk/dnsleaktest, MIT reference client `dnsleaktest.sh` v1.4.0](https://github.com/macvk/dnsleaktest/blob/master/dnsleaktest.sh)
- [ipleak.net `index.js`, DNS detection beacon & cadence](https://ipleak.net/static/js/index.js)
- [BrowserLeaks `dns.js`, probe construction (50 names, parity split, apex alternation)](https://browserleaks.com/js/dns.js)
- [dnscheck.tools help, label grammar, DNSSEC algorithms & fault injection](https://dnscheck.tools/help)
- [brianshea2/addr.tools, AGPL-3.0 Go source for the authoritative test server](https://github.com/brianshea2/addr.tools)
- [Cloudflare 1.1.1.1 help page](https://one.one.one.one/help/)
- [Cloudflare, DNS over HTTPS JSON API reference (`name`, `type`, `do`, `cd`)](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Cloudflare, ECH protocol docs (`sni=plaintext` vs `encrypted`)](https://developers.cloudflare.com/ssl/edge-certificates/ech/)
- [RFC 8484, DNS Queries over HTTPS (DoH)](https://www.rfc-editor.org/rfc/rfc8484.html)
- [RFC 7858, DNS over TLS (DoT)](https://www.rfc-editor.org/rfc/rfc7858.html)
- [RFC 7871, EDNS Client Subnet](https://www.rfc-editor.org/rfc/rfc7871.html)
- [RFC 8914, Extended DNS Errors](https://www.rfc-editor.org/rfc/rfc8914.html)
- [RFC 5001, DNS Name Server Identifier (NSID) Option](https://www.rfc-editor.org/rfc/rfc5001.html)
- [RFC 9156, DNS Query Name Minimisation](https://www.rfc-editor.org/rfc/rfc9156.html)
- [miekg/dns, Go DNS library for the authoritative logger](https://github.com/miekg/dns)
