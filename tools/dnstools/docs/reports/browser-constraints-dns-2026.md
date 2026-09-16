# What a browser can and cannot do for DNS in 2026

Platform rules deciding which parts of a DNS-lookup tool can execute in the visitor's browser & which must execute in our Go binary. Not a competitor report. Informs the feature-selection decision before anyone writes a handler, and (secondarily) the ip-subdomain-vs-own-subdomain question, since the one feature that needs new infra (resolver identification) needs a **delegated DNS zone**, not a new web subdomain.

- **Scope:** browser-side DNS capability surface — DoH over `fetch()`, unique-subdomain beacons, Resource Timing, NEL, WebRTC, `navigator.connection` — & the CORS/permission gates on each. · **Why it matters for our build:** every feature that can run client-side costs corpberry zero outbound traffic, zero rate-limit exposure & zero blocklist risk, exactly as the iptools port-scanner analysis concluded for scanning. Every feature that can't must be justified against server cost.
- **Firsthand check (probes run 2026-09-15, re-verified 2026-09-16 from a macOS host, `curl`/`dig`):** CORS-probed 11 DoH endpoints across 10 providers w/ `Origin:` set, plus `OPTIONS` preflights; ran RFC 8484 wireformat GETs; exercised Google & Cloudflare JSON params (`do`, `cd`, `type=65`, `edns_client_subnet`); resolved `whoami.ds.akahelp.net` three ways to show what resolver identity a browser-side lookup actually reports; `dig NS corpberry.com` + wildcard test to check whether a beacon zone is even possible today.

## The mechanics

### 1. No raw DNS sockets, and no API that returns one

There is no JS API that opens UDP/53, TCP/53, DoT, DoQ or mDNS. `fetch`/XHR/WebSocket/WebTransport are the only network primitives, all HTTP(S)-shaped. There is also **no API that reports the OS resolver config** — nothing analogous to `/etc/resolv.conf`, no `navigator.dns`. The browser resolves hostnames for you as a side effect of loading a URL & tells you almost nothing about how it did it. Everything below is a workaround for those two facts.

### 2. DoH over `fetch()` — the one real client-side resolver

RFC 8484 DoH is plain HTTPS, so a page can query a public resolver directly *if* that resolver sends CORS headers. Most do not. Firsthand matrix, `curl -H 'Origin: https://example.com'`, re-run 2026-09-16:

| Provider | Endpoint | Format probed | `access-control-allow-origin` | Browser-usable |
|---|---|---|---|---|
| Cloudflare | `cloudflare-dns.com/dns-query` | JSON + wireformat GET | `*` | **yes, both** |
| Google | `dns.google/resolve` (JSON), `dns.google/dns-query` (wire) | JSON + wireformat GET | `*` | **yes, both** |
| Quad9 | `dns.quad9.net/dns-query` | wireformat GET | `*` | **yes, wire only** |
| DNS4EU | `protective.joindns4.eu/dns-query`, `unfiltered.joindns4.eu/dns-query` | wireformat GET | `*` | **yes, wire only** (JSON `?name=` -> HTTP 400). EU co-funded, operated by Whalebone; 5 filtering variants incl. `unfiltered` |
| AliDNS | `dns.alidns.com/resolve` | JSON | `*` | yes, **JSON only** — its `/dns-query` wireformat endpoint sends no ACAO (CN-hosted, latency) |
| AdGuard | `dns.adguard-dns.com/resolve` | JSON, HTTP 200 | *absent* | no |
| Mullvad | `dns.mullvad.net/dns-query` | wireformat GET, HTTP 200 | *absent* | no |
| NextDNS | `dns.nextdns.io/dns-query` | wireformat GET, HTTP 200 | *absent* | no |
| OpenDNS | `doh.opendns.com/dns-query` | wireformat GET, HTTP 200 | *absent* | no |
| Quad9 JSON | `dns.quad9.net:5053/dns-query` | JSON | n/a | no — :5053 did not complete from this host; the main host answers `?name=` w/ HTTP 400 `DoH unable to decode BASE64-URL`, i.e. **Quad9 speaks no JSON** |
| dns0.eu | `zero.dns0.eu` | — | n/a | **gone.** `zero.dns0.eu` is NXDOMAIN, firsthand (`dig`/Google DoH both `Status: 3`, `Authority` SOA `ns1.gandi.net.`/`dns0.eu.`); the service announced an "immediate" shutdown ~2025-10-20 per press coverage, no exact cutover date published |

So the realistic client-side resolver set is **Cloudflare + Google + Quad9 + DNS4EU (+ AliDNS)**. Enough for a "compare N resolvers" feature, which is the interesting one. Only Cloudflare & Google speak JSON; Quad9 & DNS4EU are wireformat-only, so a fan-out across all of them forces a JS wireformat decoder anyway.

**Preflight mechanics, verified, & they differ per provider.** `OPTIONS https://cloudflare-dns.com/dns-query` returns 200 w/ `access-control-allow-methods: POST, GET` & `access-control-allow-headers: content-type`. **`OPTIONS https://dns.google/dns-query` returns HTTP 501**, and `OPTIONS https://dns.google/resolve` returns 400. Practical consequences:

- **JSON GET is a *simple* request** (`Accept: application/dns-json` is CORS-safelisted) -> one round trip, no preflight.
- Wireformat **GET** (`?dns=<base64url>`) is also simple -> no preflight. Works on Cloudflare, Google, Quad9 & DNS4EU, all confirmed w/ `Origin:` set.
- **POST wireformat requires a preflight** (`Content-Type: application/dns-message` is not safelisted). Cloudflare allows it; **Google fails the preflight (501), so POST wireformat is not usable from a browser against `dns.google`** even though `curl -X POST` to it returns 200 (curl does not preflight).

So: build the query packet in JS & use **wireformat GET** everywhere. Never POST.

**Parameters actually available** (both free, no key, no account):

| | Cloudflare JSON | Google JSON |
|---|---|---|
| Endpoint | `https://cloudflare-dns.com/dns-query` (needs `Accept: application/dns-json`) | `https://dns.google/resolve` (no header needed) |
| Params | `name`, `type`, `do`, `cd` | `name`, `type`, `cd`, `ct`, `do`, `edns_client_subnet`, `random_padding` |
| Response | `Status`,`TC`,`RD`,`RA`,`AD`,`CD`,`Question`,`Answer`,`Authority`,`Additional`,`Comment`; error responses add `error` | same set (**Google does return `Authority`** — observed on NXDOMAIN/NODATA, though its doc page lists only `Answer`), plus `edns_client_subnet` echo, `Comment` naming the responding authoritative, & `extended_dns_errors[]` |
| Firsthand extras | `do=1` returns **RRSIG (type 46) inline** alongside the answer; EDE arrives as **`Comment: ["EDE(9): ..."]`, an array of strings** | `Comment` is a **plain string** (`Response from 162.159.4.8.`); **structured `extended_dns_errors[{info_code,extra_text}]` present in responses though absent from the JSON doc page** |

Three firsthand results worth designing around:

- **DNSSEC failures are legible, in two incompatible shapes.** `dns.google/resolve?name=dnssec-failed.org` returned `Status: 2`, `AD: false`, & `extended_dns_errors: [{"info_code":9,"extra_text":"No DNSKEY matches DS RRs of dnssec-failed.org"}]`. Cloudflare, same name, returned `Status: 2` & `Comment: ["EDE(9): DNSKEY Missing no SEP matching the DS found for dnssec-failed.org."]`. Both carry RFC 8914 EDE, but Google's is **structured** while Cloudflare's is **prose inside `Comment`** that must be regex'd for the code. Worse, `Comment` is a *string* on Google, an *array of strings* on Cloudflare, & absent on both in the happy path: type-check it before touching it.
- **Modern rrtypes work.** `type=65` (HTTPS/SVCB) returned parsed rdata: `1 . alpn=h3,h2 ipv4hint=... ipv6hint=...`. Both providers.
- **TXT rdata is formatted incompatibly.** For `whoami.ds.akahelp.net` TXT, Cloudflare returned `"ecs" "89.222.120.0/24/24"` (quoted, space-separated character-strings) & Google returned `ecs89.222.123.0/24/24` (concatenated, unquoted). Any TXT viewer, SPF parser or DKIM check must normalize per provider. Not documented anywhere I found, only observed.

**`edns_client_subnet` is the sleeper feature.** Google's JSON accepts an arbitrary ECS prefix, so a page can ask "what does this name resolve to for a client in *that* network." Firsthand on `www.wikipedia.org`:

| ECS sent | ECS echoed | Answer |
|---|---|---|
| `8.8.8.8/24` | `8.8.8.0/23` | `208.80.154.224` (US) |
| `196.10.52.0/24` | `196.10.52.0/22` | `185.15.58.224` (EU/AF edge) |
| none (this host) | none | `185.15.59.224` |
| `203.0.113.0/24` | `203.0.113.0/0` | *empty*, & **`Status: 5` (REFUSED)** — TEST-NET, scope zeroed |

Geo-steering inspection, entirely client-side, no scanner infra. The `/0` scope plus `Status: 5` on a reserved prefix is the honest failure mode to handle. Cloudflare's JSON accepts no ECS param at all (its documented set is `name`, `type`, `do`, `cd`), so **this feature is Google-only**.

**What DoH-from-the-browser does *not* tell you:** it reports the DoH provider's view, not the visitor's. Same TXT name, three ways, firsthand: via Cloudflare DoH `ns = 162.158.245.129` (Cloudflare egress), via Google DoH `ns = 2a00:1450:4001:c07::127` (Google egress), via local `dig` `ns = 172.217.33.150` (also Google — this host's `/etc/resolv.conf` is `8.8.8.8`, so the local path *coincides* w/ the Google path rather than diverging from it; the clean demonstration is Cloudflare vs Google). The `ns` value also moves between runs within one provider's own anycast pool, so it identifies the **provider**, never a stable server. A client-side "which resolver am I using" feature is **structurally impossible** through DoH. Which is why the next mechanic exists.

### 3. The unique-subdomain beacon: the only way to see the visitor's own resolver

Mechanic: mint a random label, make the browser resolve `<uuid>.p.corpberry.com`, & read the query off **our own authoritative nameserver**. Because the label is unguessable, no cache can answer it; the recursive resolver must walk to our NS, & the source address on that query *is the resolver*. Our NS logs `uuid -> {resolver src IP, ECS prefix}`; the page then polls `GET /api/beacon/<uuid>` on the normal origin to read it back. Repeating w/ N labels enumerates a resolver pool rather than one member of it (the public leak-testers fire on the order of 30).

Implementation details that matter for us:

- **No TLS cert needed on the beacon leg.** DNS resolution happens before the TLS handshake, so `fetch("https://<uuid>.p.corpberry.com/", {mode:"no-cors"})` triggers the lookup & then fails at TLS, which is fine, we never read that response. `<link rel="dns-prefetch">` is the lighter trigger but is a hint browsers may ignore, so it is not a reliable primitive. *(Ordering is spec-obvious; I could not exercise it in a browser here.)*
- **corpberry.com cannot host this as-is.** Firsthand: `dig NS corpberry.com` -> `lisa.ns.cloudflare.com.` / `dion.ns.cloudflare.com.`, and a random `<uuid>.corpberry.com` already resolves to `188.114.96.3 / 188.114.97.3` (Cloudflare wildcard). Cloudflare is authoritative, so Cloudflare sees the resolver & we do not. A beacon requires **delegating a subzone** (`p.corpberry.com. NS ns1.p.corpberry.com.` + glue A to the Hetzner box) & running a small authoritative responder there, on UDP/53, outside the Cloudflare proxy.
- **In 2026 the beacon answers "which resolver does the *browser* use", not "which resolver does the *machine* use".** Chrome's Secure DNS defaults to automatic-upgrade mode (same provider, upgraded to DoH when it supports it) & Firefox enables DoH by default in launched regions w/ a regional default resolver. The tool's answer can legitimately differ from `dig` on the same box. Surface that as the finding, not as an error.

### 4. Timing: only for resources we serve

`PerformanceResourceTiming.domainLookupEnd - domainLookupStart` is the browser's own DNS phase, widely available since 2017 & exposed in workers. But it returns **`0` for cross-origin resources without `Timing-Allow-Origin`, and `0` for anything served from cache**. None of the DoH endpoints I probed sent `Timing-Allow-Origin`, so we cannot time a third-party resolver this way. We *can* time lookups of our own hostnames, because we control the TAO header: a beacon subdomain plus Resource Timing gives a real, honest "your resolver took N ms cold" number. Generic cache-probe inference ("did this visitor previously resolve X") is possible in principle, noisy in practice, and is a privacy attack rather than a feature. Skip it.

### 5. NEL: DNS failures reported to our collector

Network Error Logging defines four DNS-specific report types, per the W3C spec: `dns.unreachable` (DNS server unreachable), `dns.name_not_resolved` (server responded but could not resolve the name), `dns.failed` (catch-all for anything the other two miss — the spec does **not** map it to SERVFAIL specifically), `dns.address_changed` (resolved IP changed since the NEL policy was received). All carry `phase: dns`. Reports are sent by the browser to a Reporting API endpoint we nominate via headers. **Chromium-only** (Firefox & Safari do not implement; no share figure verified here). This is the only channel that tells us *why* a visitor's resolution of our own names failed. Genuinely useful for the beacon's error path, useless for looking up third-party domains.

### 6. WebRTC: dead end for DNS

Host ICE candidates are mDNS-obfuscated (`<uuid>.local`) in Chrome, Edge, Firefox & Safari, and mDNS resolution is LAN multicast that never reaches a unicast resolver. Server-reflexive candidates still reveal the public egress IP, which our Go server already sees on the TCP connection. WebRTC contributes nothing a DNS tool wants. One line, closed.

### 7. `navigator.connection`: not a DNS signal

Chromium-only per caniuse (Chrome/Edge yes, Firefox & Safari unsupported; exact share not verified here). `rtt` is quantized to 25 ms & `downlink` to 25 kbps, and both describe recent HTTP transport, not DNS. Only legitimate use: pick a sane client-side timeout & warn on `effectiveType: 'slow-2g'`. Table stakes.

## What the popular tools actually do about it

| Tool | Where the DNS actually happens | Tell |
|---|---|---|
| dnsleaktest.com, bash.ws/dnsleak | server-side authoritative NS + unique-subdomain beacons | only the browser's *trigger* is client-side |
| browserleaks DNS leak test | same beacon pattern | reports resolver IP + ECS |
| `1.1.1.1/help` | Cloudflare's own edge answers about your connection to it | firsthand: `https://1.1.1.1/help` 301s to `https://one.one.one.one/help`, `text/html` w/ `access-control-allow-origin: *`, no documented JSON contract |
| whatsmydns.net, dnschecker.org | server-side probe fleet in N locations | propagation grids need many vantage points, not a browser |
| Google Admin Toolbox dig, MXToolbox | server-side `dig` | can target a specific authoritative NS, which DoH cannot |
| DNSViz | server-side full delegation + DNSSEC chain walk | the hardest thing on this list & the least browser-portable |

Two adjacent APIs that *are* browser-reachable, both confirmed firsthand w/ `Origin:` set: **RDAP** (`rdap.org/domain/<d>` 302s to the registry, e.g. `rdap.verisign.com`, both hops `access-control-allow-origin: *`) for registrar/creation/expiry/status, and **crt.sh** (`crt.sh/?q=%25.example.com&output=json`, `access-control-allow-origin: *`, 25,835 bytes for that query) for CT-log subdomain enumeration. Neither needs a key. Note the **cross-host 302 on RDAP**: the redirect target must also send ACAO or the browser fetch dies on hop 2, which Verisign does but not every registry will. crt.sh returned HTTP **502** on one of two probes minutes apart, so treat it as best-effort, never load-bearing.

## Options for us, w/ trade-offs

| Option | What it buys | Cost / complexity | Risk |
|---|---|---|---|
| **A. Client-side DoH only** (CF/Google/Quad9 fan-out) | all rrtypes, DNSSEC AD+RRSIG+EDE, ECS geo-steering, resolver-disagreement view, from the visitor's IP. Zero server outbound | vendored JS + a wireformat encoder/decoder (**mandatory**, not optional: Quad9 & DNS4EU speak no JSON, & POST is preflight-blocked on Google so it must be GET `?dns=`); Go serves static only | breaks rule #2 (feature must speak JSON too) unless the same logic also exists server-side; provider CORS could be withdrawn silently, & **providers vanish outright** — dns0.eu was a credible EU resolver in 2025 & is NXDOMAIN today |
| **B. Server-side resolver in Go** (`miekg/dns` from the Hetzner box) | target a *specific* NS, delegation trace from root, SOA-serial diff across a zone's NS set, EDNS/TCP-fallback probes, full DNSSEC chain. Fits the layering rule cleanly & gets Mongo history for free | one domain package + handler; outbound UDP/53 from our box | our IP gets rate-limited or blocklisted by authoritatives under abuse; needs per-IP throttling & a query cap |
| **C. Both, same domain contract** | domain service resolves server-side & returns structs; the page optionally re-runs the same query client-side & shows "from your network" vs "from our server" side by side | highest: two implementations of the same query, one Go one JS | divergence bugs; two TXT-formatting quirks to normalize instead of one |
| **D. Add the beacon zone** | the only resolver-identification feature, plus honest cold-lookup timing via TAO | delegate `p.corpberry.com`, run authoritative responder + short-TTL Mongo store for `uuid -> resolver`; UDP/53 open on Hetzner | exposes the origin IP outside Cloudflare; an open-facing NS invites reflection/amplification unless it answers only our zone, never recurses, & is rate-limited |
| **E. Enrichment only** (RDAP + crt.sh from the browser) | registration data & CT-log subdomains w/ no key, no quota, no server traffic | trivial | third-party availability; crt.sh is slow & occasionally down |

Lean: **C for the core lookup, E bolted on, D only if resolver identification is a feature the owner actually wants** — it is the single most distinctive thing a DNS tool can offer & the only one requiring new infrastructure.

## Hard constraints & failure modes

- **No raw DNS sockets, ever.** No DoT, DoQ, mDNS, zone transfer, or querying a named NS from the browser. DoH picks the resolver for you.
- **CORS is the whole gate, and it is undocumented.** Cloudflare & Google publish JSON API docs w/ no CORS statement; the `*` header is observed, not promised. Mullvad/NextDNS/AdGuard/OpenDNS return 200 to `curl` & would fail in a browser, which is exactly the trap. **Preflight is a second, separate gate**: Google answers `OPTIONS /dns-query` w/ 501, so anything non-simple fails there regardless of the ACAO on the GET.
- **No `Timing-Allow-Origin` on any probed DoH endpoint** -> cross-origin DNS timing reads `0`. Timing features only work against our own hostnames.
- **Browser DoH shifts the ground under the beacon.** Chrome auto-upgrade & Firefox regional default-on mean the resolver we identify may not be the OS resolver. State that in the UI or the tool looks wrong.
- **ECS leaks the visitor's /24.** Firsthand, every path: local `dig`, CF DoH & Google DoH all returned `ecs … /24` for this host. If we ship ECS features, say so, & offer Google's `edns_client_subnet=0.0.0.0/0` opt-out.
- **Provider rate limits are real but unnumbered.** Google's security page says only that "each server imposes per-client-IP QPS and average bandwidth limits" and that excess queries "will be dropped"; no figure. Cloudflare publishes no number either, but its network-operators page does warn that "security scanning use-cases or proxied traffic may be rate limited" and advises spreading queries across IPs rather than tunnelling from one. The 100 QPS figure circulating in Google's public-dns group is **unconfirmed in vendor docs and describes UDP/TCP, not DoH** — do not size anything on it. Client-side fan-out spends the *visitor's* quota (argument for option A/C); server-side spends ours from one Hetzner IP, which is exactly the "proxied traffic from one address" shape Cloudflare names.
- **Reserved/odd inputs return REFUSED, not an empty success.** ECS `203.0.113.0/24` echoed scope `/0` w/ no `Answer` **and `Status: 5`**. Separately, a NODATA name returns `Status: 0` w/ no `Answer` but an `Authority` SOA. So three states to handle distinctly: `Status != 0`, `Status == 0` + empty `Answer`, and `Status == 0` + `Answer`.
- **TXT rdata formatting differs per provider.** Cloudflare returns `"ecs" "89.222.120.0/24/24"` (quoted, space-separated character-strings), Google returns `ecs89.222.123.0/24/24` (concatenated, unquoted). Normalize before parsing SPF/DMARC/DKIM. Wireformat GET sidesteps this entirely, which is another argument for decoding packets in JS rather than consuming either provider's JSON.
- **A beacon zone must be hardened**: authoritative-only, no recursion, answers restricted to the delegated zone, per-source rate limit, tiny TTL, and a Mongo TTL index on the `uuid -> resolver` records (`platform.EnsureTTLIndex` already exists for this).
- **NEL is Chromium-only**; Firefox & Safari visitors produce no reports. Never present NEL coverage as complete.

## Verified firsthand vs inferred

**Verified** (curl/dig, 2026-09-15, re-run 2026-09-16): the full CORS matrix above, incl. the four providers that lack ACAO, DNS4EU's `*`, AliDNS's JSON-yes/wire-no split, Quad9 rejecting JSON w/ HTTP 400, & `zero.dns0.eu` returning NXDOMAIN; Cloudflare's OPTIONS preflight allowances **and Google's `OPTIONS /dns-query` -> 501**; wireformat GET working on Cloudflare/Google/Quad9/DNS4EU/Mullvad; Google structured `extended_dns_errors` & Cloudflare `Comment: ["EDE(9): …"]` on `dnssec-failed.org`; Cloudflare inline RRSIG under `do=1`; `type=65` rdata; the four-row ECS geo-steering table incl. the `Status: 5` on TEST-NET; `Authority` present in both providers' JSON; the `whoami.ds.akahelp.net` Cloudflare-vs-Google divergence; absence of `Timing-Allow-Origin` on every DoH response inspected; `corpberry.com` NS = Cloudflare & the existing `*.corpberry.com` wildcard; RDAP (both redirect hops) & crt.sh sending `access-control-allow-origin: *`; the `1.1.1.1/help` 301.

**Fact-check pass (2026-09-16):** every CORS/preflight cell in the DoH table above was re-curled independently, incl. rebuilding the wireformat `?dns=` payload from scratch — the first attempt used padded standard-base64 and produced false `400`s on Mullvad/NextDNS/OpenDNS/Quad9; a correct unpadded base64url payload (RFC 8484 §6) reproduced every cell as originally reported. Quad9's JSON-rejection text (`DoH unable to decode BASE64-URL`, HTTP 400, ACAO `*` even on the error) was reproduced verbatim over forced HTTP/2 (Quad9 answers HTTP/1.1 with `505`, requiring `--http2`; a handful of connection attempts over both protocols also hit bare `SSL_ERROR_SYSCALL`, so treat the endpoint as occasionally flaky, not just protocol-picky). The DNSSEC EDE shapes, ECS geo-steering table (incl. the `/0`-scope `Status: 5` on TEST-NET), the two TXT-formatting quirks, `type=65` rdata, RDAP's cross-host redirect+ACAO, and crt.sh's 200 w/ exactly 25,835 bytes were all reproduced byte-for-byte. Cloudflare's & Google's JSON API doc pages were re-fetched and confirmed to state no CORS policy and no rate-limit number; Google's security page and Cloudflare's network-operators page were re-fetched and their rate-limiting sentences quoted verbatim (§ Hard constraints) — neither names DoH specifically or gives a figure. The W3C NEL spec's four `dns.*` types and the "not SERVFAIL-specific" catch-all reading of `dns.failed` were confirmed against the spec text directly. One factual error was found and fixed: the original table asserted dns0.eu "resolution ceased 2026-01-15", a specific date not supported by either cited article (both report only an "immediate" shutdown announced ~2025-10-20, no cutover date) — corrected to what the sources actually say, with the NXDOMAIN status independently re-confirmed via both `dig` and Google DoH.

**Inferred / secondhand, still not observed in a browser:** Resource Timing zeroing on cross-origin/cached resources, NEL report emission, the `dns-prefetch` hint being ignorable, and the DNS-before-TLS ordering the beacon relies on — **no browser was driven for this report or the fact-check pass**, so these are read off MDN/the NEL spec, not measured. `navigator.connection`'s 25ms/25Kbps quantization and Chromium-only support, and WebRTC's mDNS `.local` ICE obfuscation now shipping in Chrome/Edge/Firefox **and Safari**, are corroborated by caniuse and multiple independent write-ups (search, not a driven browser) but remain unmeasured on our own pages. The claim that a browser would be served JSON by Quad9's :5053 is untested; the endpoint did not complete from this host at all, on either pass. Beacon end-to-end behaviour is **design-inferred**: no beacon zone exists, nothing about it was measured. Whether Chrome's Secure DNS auto-upgrade or Firefox's regional default-on resolver applies to a given visitor is not detectable from the page; that stays a caveat, not a capability. Google's 100 QPS figure remains **unconfirmed** — absent from Google's own security page on re-check — and is excluded from any sizing. Provider CORS & preflight behaviour is observed, not contractual, in neither vendor's docs; re-probe before shipping, and note dns0.eu as the precedent for a provider disappearing between a report and a release. Firefox has an "intent to prototype" a preffed-off NEL subset in progress as of this pass; treat NEL as Chromium-only until that ships stable.

## Sources

- [Cloudflare — DNS-over-HTTPS JSON API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Google Public DNS — DoH JSON API reference](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google Public DNS — Security benefits (rate-limiting language)](https://developers.google.com/speed/public-dns/docs/security)
- [RFC 8484 — DNS Queries over HTTPS (DoH)](https://www.rfc-editor.org/rfc/rfc8484)
- [RFC 8914 — Extended DNS Errors](https://www.rfc-editor.org/rfc/rfc8914)
- [RFC 7871 — Client Subnet in DNS Queries (ECS)](https://www.rfc-editor.org/rfc/rfc7871)
- [WHATWG Fetch — CORS-safelisted request headers / preflight](https://fetch.spec.whatwg.org/#cors-safelisted-request-header)
- [MDN — PerformanceResourceTiming.domainLookupStart](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceResourceTiming/domainLookupStart)
- [MDN — Timing-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Timing-Allow-Origin)
- [MDN — Network Error Logging (dns.* report types)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Network_Error_Logging)
- [Reporting API App — Network error report types](https://www.reporting-api.app/en/docs/report-types/network-errors)
- [MDN — NetworkInformation](https://developer.mozilla.org/en-US/docs/Web/API/NetworkInformation)
- [caniuse — Network Information API](https://caniuse.com/netinfo)
- [BlogGeek.me — PSA: mDNS and .local ICE candidates](https://bloggeek.me/psa-mdns-and-local-ice-candidates-are-coming/)
- [Chromium — DNS over HTTPS (Secure DNS automatic upgrade)](https://www.chromium.org/developers/dns-over-https/)
- [Mozilla Support — Configure DNS over HTTPS protection levels in Firefox](https://support.mozilla.org/en-US/kb/dns-over-https)
- [MozillaWiki — Trusted Recursive Resolver policy](https://wiki.mozilla.org/Security/DOH-resolver-policy)
- [DNSDOH.ART — How the DNS leak test works (unique-subdomain beacon)](https://dnsdoh.art/guides/how-the-dns-leak-test-works.html)
- [bash.ws — DNS leak test](https://bash.ws/dnsleak)
- [W3C — Network Error Logging spec (predefined `dns.*` types)](https://w3c.github.io/network-error-logging/)
- [Cloudflare — 1.1.1.1 for network operators (rate-limiting language)](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/)
- [DNS4EU — public resolver endpoints](https://www.joindns4.eu/for-public)
- [BleepingComputer — DNS0.EU shuts down over sustainability issues](https://www.bleepingcomputer.com/news/security/dns0eu-private-dns-service-shuts-down-over-sustainability-issues/)
- [Cybernews — European public DNS resolver DNS0.EU shuts down](https://cybernews.com/news/european-public-resolver-shuts-down/)
- [Akamai `whoami.ds.akahelp.net` resolver/ECS TXT probe](https://developer.akamai.com/)
- [crt.sh — certificate transparency search (JSON output)](https://crt.sh/)
- [rdap.org — RDAP bootstrap redirector](https://rdap.org/)
