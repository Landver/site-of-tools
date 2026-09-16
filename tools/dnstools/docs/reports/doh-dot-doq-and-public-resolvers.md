# DoH / DoT / DoQ & the public resolver landscape

Encrypted-DNS transports (DoH, DoT, DoQ, DoH3, and the two side-transports DNSCrypt & ODoH) and the eight public resolvers worth querying from a lookup tool. Covers the two incompatible DoH request formats, which endpoints a **browser** can actually reach (CORS), which need a key (none of them), and what the *same name* resolves to across resolvers. That last point is the decision this report really informs: a single-resolver "dig in a textarea" is table-stakes and already exists a hundred times over. A **multi-resolver diff** is a feature nobody in our size class ships, and the firsthand data below shows the answers genuinely differ.

- **Scope:** Google, Cloudflare, Quad9, NextDNS, AdGuard, OpenDNS, Mullvad, **ControlD**. Transport & API surface only, not DNS record semantics (separate report). · **Why it matters for our build:** decides server-side vs browser-side, whether we hand-roll a wire codec in Go, and which resolvers are safe to put behind a UI.
- **Firsthand check:** ~120 polite requests on **2026-09-15** plus a full adversarial re-probe on **2026-09-16**: RFC 8484 wire GET+POST to 17 endpoints, JSON GET to 8, `curl -H 'Origin:'` CORS + OPTIONS preflight on 13, raw-TLS DoT to 8 on :853, DDR SVCB via `dig` to 6, ECS steering via Google JSON, EDE extraction from OPT RRs. Both passes egressed from the **same** DE network (`89.222.123.78` / `.81`, CF PoP `TXL`), so the re-probe corroborates behaviour but is **not** an independent geographic vantage. Scripts live in the scratchpad, not the repo.

## The mechanics

**Two DoH request formats, one path.** RFC 8484 defines `GET /dns-query?dns=<base64url wire msg>` (padding stripped) and `POST /dns-query` w/ `content-type: application/dns-message`. Both verified working on Google & Cloudflare. Separately, Google invented a **JSON** shape (`?name=&type=`) that Cloudflare, AdGuard & NextDNS cloned. It has **no RFC**; Cloudflare's own docs say so and steer critical use to wireformat. The shapes are *not* drop-in compatible:

| | Google | Cloudflare | AdGuard | NextDNS |
|---|---|---|---|---|
| path | `/resolve` **only** (`/dns-query`+JSON -> 400) | `/dns-query` + `accept: application/dns-json` (no header -> 400) | `/resolve` **only** | `/dns-query` |
| names | trailing dot (`example.com.`) | **no** trailing dot, root = `""` | trailing dot | trailing dot |
| `Comment` | **string** | **array of strings**, carrying EDE text | absent | absent |
| extras | `edns_client_subnet` echo; undocumented `extended_dns_errors[{info_code, extra_text}]` | — | numeric `class` field, `Extra` key (`null` when empty) | `Additional` w/ rendered OPT pseudo-section |
| content-type | `application/json` | `application/dns-json` | `application/x-javascript` | `application/dns-json` |

A Go struct written against Cloudflare will silently mis-key Google's names, and `Comment` alone needs a custom `UnmarshalJSON` because it is a string on one and an array on the other. Budget for a normalizer. ControlD & the rest are **wire-only**: ControlD ignores `accept: application/dns-json` and returns wire bytes, OpenDNS & Mullvad answer JSON params w/ 400.

**DoT (RFC 7858)** is plain DNS-over-TCP framing (2-byte length prefix) inside TLS on **:853**. Trivial to speak from Go w/ `crypto/tls` + a wire codec, no HTTP. All 8 answered over **TLS 1.3** w/ valid publicly-trusted certs. Side effect worth a feature: the cert identifies the node. Mullvad's presented `CN=gb-lon-dns-301.mullvad.net`, naming the actual London box behind the anycast address (re-confirmed 2026-09-16); the others present generic service names (`dns.google`, `dns.quad9.net` w/ `O=Quad9`, `dns.adguard-dns.com`, `dns.nextdns.io`, `doh.opendns.com` w/ `O=Cisco Systems Inc.`, ControlD's shared `ecdsa.controld.com`). Cloudflare's :853 leaf carries no CN in the subject, so LibreSSL printed nothing to identify it.

**DoQ (RFC 9250)** is DNS straight over QUIC, on UDP :853. It removes TCP head-of-line blocking and the HTTP layer. **Not spoken from this host** (system curl 8.7.1 has no HTTP/3, no `kdig`/`q` installed, and I did not add deps to probe it). Support is machine-verifiable *without* a QUIC client via DDR, below, which is the only evidence here.

**DoH3** = ordinary DoH carried on HTTP/3. Detectable from the `alt-svc` response header. Present on **Google** (`h3=":443"; ma=2592000`, plus `h3-29`), **Cloudflare** (`ma=86400`), **Quad9** (`h3=":443"`). Absent on AdGuard, NextDNS, Mullvad, OpenDNS and **ControlD**, though ControlD's DDR record advertises `alpn=h3`: the two signals disagree, so trust DDR over `alt-svc` here.

**DDR (RFC 9462) is the sleeper.** Query `SVCB` (type 64) for `_dns.resolver.arpa` and the resolver hands back the encrypted endpoints it designates for itself: priority, target name, `alpn`, `port`, `dohpath`, address hints. Decoded firsthand:

```
9.9.9.9   -> 1 dns.quad9.net. alpn=dot
             2 dns.quad9.net. alpn=h3,h2 dohpath=/dns-query{?dns}
             3 dns.quad9.net. alpn=doq            <- only evidence of Quad9 DoQ
94.140.14.14 -> 1 dns.adguard-dns.com. alpn=h3,h2,http/1.1 port=443 dohpath=/dns-query{?dns}
                2 alpn=dot port=853 · 3 alpn=doq port=853
76.76.2.0 (ControlD) -> 1 freedns.controld.com. alpn=h3,h2,http/1.1 port=443 dohpath=/unfiltered{?dns}
                        2 unfiltered.freedns.controld.com. alpn=dot port=853
                        3 unfiltered.freedns.controld.com. alpn=doq port=853
dns.google   -> 1 dns.google. alpn=dot · 2 alpn=h2,h3 dohpath=/dns-query{?dns}     (no doq)
1.1.1.1      -> 1 one.one.one.one. alpn=h2,h3 port=443 dohpath=/dns-query{?dns}
                2 alpn=dot port=853                                                (no doq)
208.67.222.222 -> 5 dns.opendns.com / dns.umbrella.com alpn=dot port=853
                  10 same names alpn=h2 dohpath · 20 doh.opendns.com / doh.umbrella.com alpn=h2
45.90.28.0 (NextDNS) -> NXDOMAIN · 194.242.2.2 (Mullvad) -> REFUSED
```

**EDE (RFC 8914) is how you tell "blocked" from "broken".** Option code 15 in the OPT RR, carrying a numeric code (15 Blocked, 16 Censored, 17 Filtered, 6 DNSSEC Bogus, 7 Signature Expired, 9 DNSKEY Missing…) plus optional text. Critical implementation detail confirmed twice: **a wire query must carry an OPT RR w/ the DO bit or you get nothing back.** A pass w/o EDNS reported "no EDE" from every resolver; the identical queries w/ DO set produced EDE on 6 of 8. Same for the **AD** flag: w/o EDNS, all 8 returned `AD=false` for signed `cloudflare.com`; w/ DO set, all 8 returned `AD=true`. **The JSON paths are the exception and this matters for the build:** Google's `/resolve` returns structured `extended_dns_errors` and Cloudflare folds `EDE(9): …` into `Comment` **w/o any `do` param**, so browser-side EDE is available from those two w/ no wire codec at all.

**ECS (RFC 7871)** leaks a truncated client prefix to the authoritative so CDNs can geo-steer. It is the single biggest source of "why do I get a different IP than you". Google honours it *and echoes the scope it actually used*; Cloudflare ignores the parameter entirely. Firsthand, `www.wikipedia.org` (A values move between runs, the echoed scope does not):

| ECS sent to Google | answer | scope echoed |
|---|---|---|
| `133.130.0.0/24` (JP) | `198.35.26.224` | `133.130.0.0/9` |
| `200.160.0.0/24` (BR) | `195.200.68.224` | `200.160.0.0/15` |
| `0.0.0.0/0` (opt out) | `185.15.59.224` | `0.0.0.0/0` |
| same param -> Cloudflare | `185.15.59.224` | *(no echo, no `edns_client_subnet` key)* |

## What the popular tools actually do about it

Endpoint inventory, all re-checked **2026-09-16**. **No resolver in this table requires an API key or account for public lookups.**

| Resolver | DoH wire | JSON | **CORS (ACAO)** | DoT :853 | DoQ | DoH3 | Key |
|---|---|---|---|---|---|---|---|
| **Google** | `dns.google/dns-query` | `/resolve` | **`*`**, simple GET only (OPTIONS 200 but emits no CORS headers) | ✓ | no (per DDR) | ✓ | none |
| **Cloudflare** | `cloudflare-dns.com/dns-query`, `1.1.1.1/dns-query`, `security.`/`family.` | same path | **`*` + full preflight** (`allow-methods: POST, GET`, `allow-headers: accept`) | ✓ | not advertised | ✓ | none |
| **Quad9** | `dns.quad9.net`, `dns10.` (no blocklist), `dns11.` (ECS) | `:5053` **unreachable**; :443 rejects JSON | **`*`**, but OPTIONS -> 400, so simple GET only | ✓ | DDR-advertised | ✓ | none |
| **ControlD** | `freedns.controld.com/{p0,p1,p2,p3,family}`, aliases `/unfiltered`,`/malware`,`/ads`,`/social`,`/family` | none (wire even w/ JSON accept) | **`*` + `allow-headers: *`, `allow-methods: OPTIONS, GET`** | ✓ | DDR-advertised | DDR only, no `alt-svc` | none |
| **AdGuard** | `dns.adguard-dns.com`, `family.`, `unfiltered.` | `/resolve` | **none** | ✓ | DDR + vendor docs (`quic://`) | no | none |
| **NextDNS** | `dns.nextdns.io/dns-query`, `/<profileID>` | same path | **none**, preflight 405 | ✓ | no (DDR NXDOMAIN) | no | none for lookups |
| **OpenDNS** | `doh.opendns.com`, `doh.familyshield.` | none (400 HTML) | **none** | ✓ | no | no | none |
| **Mullvad** | `dns.mullvad.net` + `adblock.`/`base.`/`extended.`/`family.`/`all.` | none (400) | **none** | ✓ | no | no | none |

**Two side-transports the inventory would otherwise miss.** **DNSCrypt v2** (not an IETF standard, `sdns://` stamp addresses) is documented by AdGuard for all three of its servers, and offered by OpenDNS, Quad9 & ControlD. **ODoH** (RFC 9230, Oblivious DoH) is live at `odoh.cloudflare-dns.com`: `/.well-known/odohconfigs` returned a real HPKE config blob w/ `ACAO: *`, verified firsthand. Neither is worth speaking from our tool (both need crypto deps), but both are worth *displaying* as capability rows.

**Mullvad is being shut down.** Vendor blog dated **2026-09-03** confirms discontinuation on **2026-11-02**, w/ Mullvad financially sponsoring Quad9 instead. Six weeks out. Include it only as a historical curiosity, or not at all.

**Filtering & blocking is where resolvers stop being interchangeable.** Same names, same minute, 17 endpoints, DO bit set. Baseline unfiltered answer for the Cisco test domains is `146.112.59.12`:

| Name | Who diverges & how |
|---|---|
| `doubleclick.net` | AdGuard default **&** family -> `0.0.0.0` + **EDE 17 Filtered**; ControlD `p2`/`family` -> `0.0.0.0` w/ **no EDE**; Mullvad `adblock`/`all` -> **NXDOMAIN, empty authority** (no SOA); everyone else answers, w/ 6 different Google IP sets by PoP |
| `ads.doubleclick.net` | AdGuard -> `0.0.0.0` + **EDE 17**; all others pass through the genuine upstream **NXDOMAIN** w/ SOA |
| `exampleadultsite.com` | CF-family -> `0.0.0.0` + **EDE 17**; AdGuard-family -> `94.140.14.35` (own block page); OpenDNS FamilyShield -> `146.112.61.106` (Cisco block page); **all others pass it through**, incl. ControlD `family` |
| `internetbadguys.com` | OpenDNS **both** default & FamilyShield -> `146.112.61.108` (phishing block page); all others pass through |
| `examplemalwaredomain.com` | Quad9 `9.9.9.9` -> **NXDOMAIN + EDE 17**; Quad9 `dns10` -> real answer; **CF-security, AdGuard, Mullvad-all, NextDNS, ControlD all pass it through** |
| `dnssec-failed.org` | all 17 -> **SERVFAIL**, but the *explanation* differs: Google **EDE 9** "No DNSKEY matches DS RRs of dnssec-failed.org", Cloudflare **EDE 9** "no SEP matching the DS found", Quad9/AdGuard/OpenDNS bare **EDE 6** (`dns11` bare **EDE 7**), **Mullvad, NextDNS & ControlD emit no EDE at all** |

Five distinct block mechanisms in one table: **null sinkhole** (`0.0.0.0`), **vendor block-page IP**, **synthetic NXDOMAIN**, **upstream NXDOMAIN passthrough**, **silent pass**. Cloudflare Families, AdGuard **and Quad9** label the block machine-readably w/ EDE 17; ControlD sinkholes w/o EDE and OpenDNS FamilyShield blocks *silently*, indistinguishable from a real answer unless you know `146.112.61.x` is theirs. That asymmetry is the feature: a tool that classifies the mechanism tells a user something they cannot get from any single resolver.

**One test domain characterizes nothing.** `examplemalwaredomain.com` is blocked by Quad9 and by literally nobody else in the set, including Cloudflare's *security* endpoint. Blocklists are not a shared commodity.

**Table-stakes, one line each.** All resolvers DNSSEC-validate by default, **including Quad9 `dns10`**: its "unsecured" label refers to the malware blocklist only, and both Quad9's own service matrix and a firsthand `dnssec-failed.org` probe (SERVFAIL + EDE 6) confirm validation stays on. Google & Cloudflare both implement **RFC 8482** for `ANY` (return a minimal `HINFO "RFC8482"` rather than the zone, verified). Both JSON APIs decode **HTTPS/SVCB (type 65)** to presentation format for you: `1 . alpn=h3,h2 ipv4hint=… ipv6hint=…`. Both return the `Authority` SOA on NXDOMAIN. Google's `/resolve` supports `ct=application/dns-message` to get **wire bytes back from the JSON path**, verified, alongside `cd`, `do`, `edns_client_subnet` and an ignored `random_padding`.

**Rate limits.** Nobody publishes a DoH number. Google's ISP guidance sets **1500 QPS per client IP** as the threshold below which you need not request an increase, allows short bursts, and says >1% unanswered means you are being throttled; its JSON reference documents no limit at all. Cloudflare publishes no number, says typical use "should not encounter any rate limiting", flags security scanning and proxied traffic as the rare exception, and lists `resolver@cloudflare.com` for volume. Firsthand I hit **repeated silent drops from Quad9** across both passes (~8 no-responses on day one, 2 more on the re-probe, recovering after 1.5-3s spacing) while the other seven never dropped once, which reads like per-IP rate limiting but I did not isolate it from transient loss. **NextDNS** free tier: **300,000 queries/month**, unlimited devices & configurations, and per the pricing page exceeding it does not cut you off, it downgrades you to plain unfiltered/unlogged resolution. Pro is **£1.79/mo · £17.90/yr** as rendered to a EU client (the page localizes currency, checked 2026-09-16). That quota governs *your profile*, not the keyless public endpoint.

**Adjacent endpoints worth stealing.** `https://1.1.1.1/cdn-cgi/trace` returns `text/plain` key=value w/ **`access-control-allow-origin: *`**: client IP, CF PoP (`colo=TXL`), `loc`, `tls`, `kex`, `warp=on|off`, `gateway`, `sni`. Browser-readable, no key. `https://on.quad9.net/` is an HTML "are you using Quad9" canary (no CORS). NextDNS has a documented REST API at `api.nextdns.io` (`/profiles`, `/profiles/:p/analytics`, `/profiles/:p/logs`, `;series` suffix for time series) behind an `X-Api-Key` header, for managing *your own* profile, not a lookup API, not useful to us.

## Options for us, w/ trade-offs

| Option | What it buys | Cost / complexity | Risk |
|---|---|---|---|
| **A. Browser-side fan-out** (htmx/Alpine -> Google `/resolve`, CF `/dns-query` JSON, Quad9 + ControlD wire) | Zero Go work for the query path; **each visitor queries from their own IP**, so no shared-IP rate limit; results reflect *their* geo/PoP; Google JSON hands back structured EDE w/ no codec | Parsing 2 JSON shapes in JS + wire decode for the 2 wire-only ones; limited to the 4 CORS-clean resolvers | Vendors can drop `ACAO: *` any day & the feature dies silently; no Mongo history unless we POST results back |
| **B. Server-side fan-out from the Go binary (DoH wire over `net/http`)** | All 8+ resolvers incl. the CORS-blocked ones; one code path; results are diff-able server-side; fits rule #1 (domain pkg returns structs) & rule #2 (HTML+JSON free) | Need a **DNS wire codec**. `miekg/dns` is a new dep not in the pinned list; hand-rolling encode + decode for A/AAAA/CNAME/MX/TXT/SOA/NS/SVCB/OPT is ~300-400 LOC of pure Go, testable, no deps (the Python equivalent used for this report is ~80 lines) | **All queries egress from one Hetzner IP.** Same shared-IP problem the port scanner shelving flagged. Quad9 already dropped me at low volume |
| **C. Server-side DoT on :853** | No HTTP layer, `crypto/tls` + the same codec; the peer cert is free extra data to display | Codec still required; connection pooling per resolver to avoid a TLS handshake per lookup | Same shared-IP exposure as B; :853 outbound could be filtered in some environments |
| **D. Plain UDP/TCP :53 via Go stdlib** | Simplest transport | Still needs the codec (`net.Resolver` gives you names, not RRs/flags/EDE) | Loses the whole point: no EDE w/o EDNS plumbing, no privacy story, on-path tampering is exactly what we'd want to *show* |
| **E. Hybrid: B for the canonical result + cached fan-out, A for the "from your own network" column** | Strongest product. Server shows what *the internet* sees; browser shows what *you* see; the delta is the story | Two code paths, two parsers, htmx swap to merge them | Most build effort of the five |
| **F. DoQ / DNSCrypt / ODoH support** | Novelty; nobody's web tool speaks them | Each needs a new heavyweight dep (`quic-go`, DNSCrypt, HPKE) and only Quad9, AdGuard & ControlD advertise DoQ | Poor payoff. **Advertise** these via DDR & vendor docs instead of speaking them |

**Lean:** E, built B-first. The wire codec is the one real investment and it unlocks B, C and every EDE/flag/SVCB feature; option A alone permanently caps the tool at 4 resolvers and, outside Google/Cloudflare JSON, no EDE.

**Feature inventory to pick from** (distinctive first, table-stakes last):

1. **Multi-resolver diff.** Same name, N resolvers, highlight rows that disagree. The flagship. Firsthand data above proves it produces real output, not empty tables.
2. **Block-mechanism classifier.** Label each divergence `sinkhole 0.0.0.0` / `block-page IP` / `synthetic NXDOMAIN` / `EDE 17 Filtered` / `passthrough`. Needs a small table of known block IPs (`94.140.14.35`, `146.112.61.x`).
3. **EDE decoder.** RFC 8914 code -> plain English + the resolver's own text. Turns SERVFAIL from a dead end into an explanation. Requires DO bit on the wire path; free from Google & Cloudflare JSON.
4. **DNSSEC panel.** `AD` w/ DO set, plus `SERVFAIL + EDE 6/7/9` as the failure narrative; optional DS/DNSKEY/RRSIG chain view.
5. **DDR lookup.** `_dns.resolver.arpa` SVCB, rendered as "this resolver designates: DoH3, DoT, DoQ". Genuinely rare in a web tool, and the only way to evidence DoQ without a QUIC client.
6. **ECS geo-steering explorer.** Google-only, but lets a user type a prefix (or pick a city) and watch the CDN answer move. Show the echoed *scope* to explain the authoritative's granularity.
7. **HTTPS/SVCB decode.** `alpn`, `ech`, `ipv4hint`, `port`, `dohpath`. Both JSON APIs pre-render it.
8. **Transport comparison.** Same name over DoH / DoT / (DoH3) w/ timings + the DoT peer certificate (issuer, node name). Mullvad's per-node CN is the demo case, right up until it shuts down.
9. **"Which resolver am I actually on".** `1.1.1.1/cdn-cgi/trace` (CORS-clean) for CF PoP + client IP + WARP state; optionally the Quad9 canary.
10. **Latency race.** Cold-connection cost measured firsthand at **250-570 ms** for all 7 (full TLS handshake per request, no reuse; warm RTT will be far lower and is the number worth showing).
11. **Raw wire inspector.** Hex dump + parsed sections. Cheap once the codec exists, and the thing every other web tool hides.
12. Table-stakes, one line: A/AAAA/CNAME/MX/TXT/NS/SOA/CAA/PTR/SRV lookup, TTL display, reverse lookup, `ANY` (explain RFC 8482 rather than pretending), permalink, and **reuse of iptools' existing Mongo lookup-history repo** per rule #5.

## Hard constraints & failure modes

- **CORS is the architectural fork.** Only **Google, Cloudflare, Quad9, ControlD** send `ACAO: *`. AdGuard, NextDNS, OpenDNS, Mullvad send none, so a browser fetch fails at the CORS check regardless of status code. Of the four, only **Cloudflare & ControlD** answer a preflight properly. Google's OPTIONS returns 200 w/ **no** CORS headers and Quad9's returns **400** (w/ `ACAO: *`, which does not save it), so on those two you must stay inside the "simple request" envelope: `GET`, no custom `Accept`. That means Google JSON `/resolve` and Quad9 **wire** `?dns=` w/ the `Accept` header omitted. Both verified working w/ an `Origin` header present.
- **`accept: application/dns-json` is itself a CORS-preflight trigger.** Fine on Cloudflare, fatal on Google's `/resolve` (which doesn't need it anyway).
- **No EDNS in a wire query -> no EDE and no AD.** Verified both ways, twice. If we send bare queries the whole DNSSEC/blocking story silently returns "unknown".
- **Shared-egress rate limiting.** Server-side fan-out multiplies: 1 user action -> 8-17 queries from one Hetzner IP. Quad9 dropped me at trivial volume on both passes. Mandatory: per-resolver response caching (respect the TTL), a client-side debounce, a concurrency cap, and a per-IP request budget in our handler.
- **Mullvad dies 2026-11-02.** Do not build a row for it.
- **Quad9's JSON endpoint on :5053 is unusable from this host.** TCP :5053 **accepts the connection**, then the TLS handshake never completes past ClientHello — a **2026-09-16** re-check (3/3 `curl --max-time 10`) got a plain **timeout**, not the reset (`errno 54`) an earlier pass logged, so the failure mode itself is inconsistent run-to-run. HTTP/1.1 and cleartext both fail the same way. Whether the service is retired or refusing this vantage is still undetermined. Its :443 endpoint rejects JSON w/ `DoH unable to decode BASE64-URL`. Treat Quad9 as **wire-only**.
- **JSON has no RFC.** Cloudflare says so in its own docs, and Google's JSON reference does not document the `extended_dns_errors` field it actually returns. Shapes can drift w/o a version bump. Wire format cannot.
- **Nothing here is authenticated**, so nothing is a supply-chain risk in the credentials sense, but equally nothing is contractual: no SLA, no notice period, no ToS we've accepted. Google & Cloudflare both explicitly reserve the right to throttle.
- **We must not present a resolver's block as a fact about the domain.** `0.0.0.0` from AdGuard means "AdGuard's list has it", not "this domain is malicious". Copy needs to say which resolver's opinion it is.

## Verified firsthand vs inferred

**Verified firsthand** (2026-09-15, re-probed 2026-09-16, DE egress `89.222.123.78`/`.81`): every row of the endpoint table (wire GET to 17 endpoints, JSON to 8, CORS + preflight headers, `alt-svc`); RFC 8484 POST on Google & Cloudflare; DoT TLS 1.3 handshake + query/response on all 8 incl. cert subject/issuer (Mullvad's `gb-lon-dns-301` node name re-confirmed); the full filtering-divergence table incl. every EDE code quoted; EDE presence/absence w/ and w/o the DO bit; AD-flag behaviour w/ and w/o DO on all 8; ECS steering & scope echo on Google vs ignored on Cloudflare; DDR SVCB from Quad9, AdGuard, ControlD, Google, Cloudflare, OpenDNS (and NXDOMAIN from NextDNS, REFUSED from Mullvad); HTTPS/SVCB decode; `ANY` -> RFC 8482; `ct=application/dns-message`; NXDOMAIN JSON & wire shapes incl. SOA; `1.1.1.1/cdn-cgi/trace` w/ CORS; ODoH config blob w/ CORS; Quad9 `dns10` validating DNSSEC (re-confirmed 2026-09-16, 3/3 `dig +dnssec` tries: SERVFAIL + EDE 6); Quad9 :5053 TCP-open-then-TLS-stalls; ControlD's five keyless profile paths; cold-connection latencies. **Independently re-verified 2026-09-16** by decoding the DDR SVCB RRs as raw `TYPE64` (the resolving host's `dig` 9.10.6 predates named SVCB support): the alpn/port/dohpath values for all 8 resolvers, and specifically that **Cloudflare's and Google's DDR records carry no `alpn=doq`**, match the table byte-for-byte.

**Corrected on re-check:** an earlier draft repeated Quad9's "unsecured" wording as **`dns10` skipping DNSSEC validation**. It does not: `dns10` is the no-blocklist variant, Quad9's service matrix lists DNSSEC validation as enabled on it, and `dnssec-failed.org` returns SERVFAIL + EDE 6 there. The claim that only Cloudflare Families & AdGuard emit EDE 17 was also wrong; Quad9 does too.

**Not verified / inferred:**
- **DoQ was never spoken.** No QUIC client available and I added no deps. Quad9, AdGuard & ControlD DoQ support rests on their own DDR `alpn=doq` records plus vendor docs (`quic://` addresses). A secondhand 2026 write-up claims Cloudflare supports DoQ; **Cloudflare's own DDR record does not advertise it**, so I am not repeating that claim. DNSCrypt & ODoH availability is likewise doc-level plus, for ODoH, a live config fetch — no session was ever established over either.
- **Quad9 drops = rate limiting** is my reading of the pattern, not a confirmed mechanism; I saw no 429 and no error body, just empty responses, in both passes.
- **AdGuard plan limits** are JS-rendered; curl got the tier names only, no numbers. Irrelevant to the public resolvers, which are free & keyless. ControlD's free-DNS page is likewise JS-rendered: the profile *endpoints* here came from probing and DDR, not from reading the page.
- **Rate-limit numbers for Cloudflare DoH** do not exist publicly; the "~10 req/s" figure floating in community threads is user anecdote, not policy, and I did not test it.
- **`dns0.eu` is not a live ninth candidate — it shut down in October 2025**, not merely unreachable from this vantage as an earlier draft assumed. The apex now resolves to `217.70.184.38`, reverse-DNS `webredir.vip.gandi.net` (Gandi's parking redirector), and TLS stalls there and on the old anycast `193.110.81.0` alike — a decommissioned service, not a filtered one. Its own team (also behind NextDNS) cited funding and pointed users at **DNS4EU**, the EU-Commission-funded successor at `joindns4.eu`; firsthand here only as far as `86.54.11.100:443` accepting TLS and answering `ACAO: *`, its DoH shape unconfirmed (`doh4.dns4eu.net` didn't resolve from this egress) — identified, not vetted.
- Geo-dependence: both passes ran from the **same German network**, so the re-probe is corroboration, not an independent vantage. IP-valued results (especially Google/CDN A records, which moved between the two passes) will differ from a US box. The *behaviours* (CORS, EDE, block mechanism) should not.
- Latency figures of 250-570 ms are cold-connection costs including a full TLS handshake per `curl` invocation, not warm query RTT, and were not re-measured.

## Sources

- [RFC 8484 — DNS Queries over HTTPS (DoH)](https://datatracker.ietf.org/doc/html/rfc8484)
- [RFC 7858 — DNS over TLS](https://datatracker.ietf.org/doc/html/rfc7858)
- [RFC 9250 — DNS over Dedicated QUIC Connections](https://datatracker.ietf.org/doc/rfc9250/)
- [RFC 9230 — Oblivious DNS over HTTPS (ODoH)](https://datatracker.ietf.org/doc/html/rfc9230)
- [RFC 8914 — Extended DNS Errors](https://datatracker.ietf.org/doc/html/rfc8914)
- [RFC 9462 — Discovery of Designated Resolvers (DDR)](https://datatracker.ietf.org/doc/html/rfc9462)
- [RFC 8482 — Providing Minimal-Sized Responses to DNS Queries with QTYPE=ANY](https://datatracker.ietf.org/doc/html/rfc8482)
- [RFC 7871 — Client Subnet in DNS Queries (ECS)](https://datatracker.ietf.org/doc/html/rfc7871)
- [Google Public DNS — DoH JSON API reference (params, response fields, no documented rate limit)](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google Public DNS for ISPs — 1500 QPS per-IP threshold, burst & throttling guidance](https://developers.google.com/speed/public-dns/docs/isp)
- [Cloudflare 1.1.1.1 — DNS-JSON API docs ("no formal RFC")](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Cloudflare 1.1.1.1 — Network operators, rate limiting & resolver@cloudflare.com](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/)
- [Quad9 — service addresses & features (9.9.9.9 / dns10 / dns11 matrix, DNSSEC on all three)](https://www.quad9.net/service/service-addresses-and-features/)
- [Quad9 — enabling DoH3 and DoQ, 31 Mar 2026](https://quad9.net/news/blog/quad9-enables-dns-over-http-3-and-dns-over-quic/)
- [AdGuard DNS — public servers, DoH/DoT/DoQ/DNSCrypt addresses](https://adguard-dns.io/en/public-dns.html)
- [Control D — free DNS resolvers (profile descriptions; endpoints are JS-rendered)](https://controld.com/free-dns)
- [Mullvad — DoH/DoT help page, incl. the 2 Nov 2026 discontinuation notice](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)
- [Mullvad blog — shutting down public encrypted DNS, sponsoring Quad9 instead (3 Sep 2026)](https://mullvad.net/en/blog/shutting-down-our-public-encrypted-dns-servers-and-sponsoring-quad9-instead)
- [NextDNS — pricing, 300,000 queries/month free tier](https://nextdns.io/pricing)
- [NextDNS — official API documentation](https://nextdns.github.io/api/)
- [Cisco — understanding OpenDNS FamilyShield](https://www.cisco.com/c/en/us/support/docs/security/umbrella/225803-understand-opendns-familyshield.html)
- [Cisco Umbrella — DNS over HTTPS / DoT support announcement](https://umbrella.cisco.com/blog/enhancing-support-dns-encryption-with-dns-over-https)
- [BleepingComputer — DNS0.EU private DNS service shuts down over sustainability issues, Oct 2025](https://www.bleepingcomputer.com/news/security/dns0eu-private-dns-service-shuts-down-over-sustainability-issues/)
- [Cybernews — European public resolver DNS0.EU shuts down immediately due to "limited resources"](https://cybernews.com/news/european-public-resolver-shuts-down/)
- [DNS4EU — free public DNS resolver for Europe, EU-Commission-funded](https://joindns4.eu/for-public)
