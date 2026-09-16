# DNS query modes & concepts a lookup tool must get right
> Protocol semantics separating a toy "type name, print IPs" page from a tool people bookmark. Every item below is a place the naive implementation is silently, confidently wrong.

Covers what the resolver actually returns & how much of it must reach the screen. Informs **feature selection**, not architecture: each concept is a candidate UI element (badge, column, panel) w/ a stated cost. Nothing here assumes `ip.corpberry.com` vs own subdomain.

- **Scope:** query semantics (recursive/authoritative, delegation, glue), answer semantics (NXDOMAIN vs NODATA, wildcards, CNAME/ALIAS), transport (EDNS0, truncation, ECS, 0x20), caching (TTL, negative TTL), names (IDN, trailing dot, case). · **Why it matters for our build:** roughly half are *free*, already in the wire response, we just have to not throw them away. The other half cost real engineering. Knowing which is which is the whole decision.
- **Firsthand check:** ~120 `dig` probes from macOS (system `dig 9.10.6`) against `8.8.8.8` / `1.1.1.1` / `9.9.9.9`, the root (`a.root-servers.net`), `.com` gTLDs (`a.gtld-servers.net`), ICANN/Verisign/Cloudflare/Google authoritatives, plus `curl` against Google / Cloudflare / AdGuard / NextDNS DoH JSON, RFC texts, the IANA EDE registry & Google Admin Toolbox's dig backend. Raw output quoted inline; all observations dated **2026-09-15/16**.

## The mechanics

### Recursive vs authoritative, delegation & glue

**Recursive** answer = from cache: `ra` set, `aa` clear, TTL counting down. **Authoritative** = from the zone's own server: `aa` set, full TTL, `ra` clear. Firsthand, same name, same minute: `@elliott.ns.cloudflare.com -> example.com. 300 IN A` (aa, full TTL), `@8.8.8.8 t=0 -> 300`, `@8.8.8.8 t=4s -> 295`. That 300 -> 295 countdown is the cheapest credibility signal a DNS tool has, & "is my change live yet?" is what users are actually asking. Naive tools print both as 300, or drop TTL entirely.

The **delegation walk** (`dig +trace`) is iterative: ask the root, get a **referral** (NOERROR, ANSWER 0, NS in AUTHORITY) not an answer, repeat at each zone cut. Firsthand at the root for `corpberry.com`:

```
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27
com. 172800 IN NS a.gtld-servers.net. ... (13 NS)
a.gtld-servers.net. 172800 IN A 192.5.6.30 / AAAA 2001:503:a83e::2:30 ... (27 glue RRs)
```

`ANSWER: 0` + AUTHORITY w/ NS and **no SOA** is the referral signature, exactly how RFC 2308 says to tell a referral from a NODATA (which carries an SOA). A tool keying only on RCODE cannot tell them apart.

**Glue** = address records the *parent* serves for nameservers it cannot otherwise reach. Two cases, both observed at `.com`. **In-bailiwick, mandatory:** `google.com NS ns1.google.com` is circular, so `.com` must carry `ns1.google.com. A 216.239.32.10` or the zone is unreachable (4 NS + 8 glue RRs returned). **Sibling glue, optional:** `corpberry.com NS lisa.ns.cloudflare.com` lives in another zone so glue isn't required, but `.com` served 12 RRs anyway because `ns.cloudflare.com` is also under `.com`. Missing or stale glue is a top-tier real outage and is **invisible to every tool that only queries a recursive**; only a parent-side `+norec` query at the TLD surfaces it. Good tools show parent NS vs child NS side by side & diff them.

### TTL semantics & caching

TTL is per-RRset, set by the zone, decremented by every cache. Three different numbers matter: **authoritative TTL** (configured), **remaining TTL** (what a recursive hands you), **negative TTL** (below). A CNAME chain has a TTL per hop and the *shortest* governs perceived propagation: firsthand `www.bing.com` is CNAME -> CNAME -> CNAME -> A, TTLs `21088, 60, 20896, 20` on 09-15 and `2237, 7, 19794, 8` on 09-16. The numbers are cache-position artefacts and change every probe; the *shape* is the stable finding, a single-digit leaf under a five-figure head. The leaf is what users see change; the head is what makes their edit look stuck.

### CNAME-at-apex, ALIAS & flattening

RFC 1034 forbids a CNAME coexisting w/ any other RRset at a name. The apex always has SOA + NS, so **apex CNAME is illegal**. Vendors work around it server-side: Cloudflare **CNAME flattening** resolves the chain inside the authoritative and returns **A/AAAA**, never a CNAME. Firsthand, Cloudflare-hosted `example.com` answers `A 104.20.23.154 / 172.66.147.243` at the apex, & `dig CNAME example.com` is a clean NODATA. Route 53 and DNSimple `ALIAS` do the same under other names. Consequence, specific and unintuitive: **you cannot see the apex's configured target over DNS**. The flattened A is the truth on the wire while the user's dashboard says `CNAME -> foo.example.net`. A tool reporting "no CNAME found" is right and useless. Better: label the apex "flattened / ALIAS (provider-side)" when apex A records resolve to a known CDN ASN, and surface the documented failure mode, a **dangling flattened CNAME returns NODATA**, indistinguishable from "not propagated yet."

### Record types the naive path renders as hex: SVCB/HTTPS, PTR, CAA

Three traps the fan-out walks straight into. **SVCB/HTTPS (RFC 9460, types 64/65)** carries what browsers act on: ALPN, ECH, address hints. Same Cloudflare-apex record, two renderings:

```
dig TYPE65 cloudflare.com     -> \# 61 0001000001000602683302683200040008681084E5...  (unknown-type hex)
dns.google/resolve?type=HTTPS -> "1 . alpn=h3,h2 ipv4hint=104.16.132.229,... ipv6hint=2606:4700::6810:84e5,..."
```

System `dig 9.10.6` has no SvcParam parser & `dig +short HTTPS cloudflare.com` silently printed **A records** instead: one more argument against shelling out to the OS binary, and for DoH JSON or `miekg/dns`, which both present the params. `_dns.resolver.arpa SVCB` (RFC 9462) is a free demo name (`2 dns.google. alpn=h2,h3 dohpath=/dns-query{?dns}`).

**PTR** is name construction, not lookup: `8.8.8.8` -> `8.8.8.8.in-addr.arpa`, IPv6 -> 32 reversed nibbles under `ip6.arpa` (both -> `dns.google.` firsthand). Botch the v6 expansion & the tool reports NXDOMAIN for a fine address, which users read as "no reverse DNS". Sub-/24 delegations use the RFC 2317 CNAME trick, so a PTR answer legitimately arrives via a CNAME chain. **CAA does not climb**: `CAA google.com` -> `0 issue "pki.goog"`, `CAA www.google.com` -> clean **NODATA**. The tree-walk to the apex is the *CA's* algorithm, not the resolver's, so "no CAA policy" on a subdomain is true and misleading. Walk it ourselves, name the label that answered.

### ANY is dead (RFC 8482)

RFC 8482 (Jan 2019, Standards Track) lets an authoritative answer QTYPE=255 with a **synthesised HINFO** whose CPU field is `"RFC8482"` and OS field is the null string, instead of zone contents. Firsthand, same query class, five different shapes of nothing:

| Target | Query | Result |
|---|---|---|
| `ns3.cloudflare.com` (auth) | `ANY cloudflare.com` | NOERROR, `HINFO "RFC8482" ""`, + EDE 21 (`OPT=15: 00 15 ...` = `"Type ANY Queries not supported here, RFC8482"`) |
| `1.1.1.1` (recursive) | `ANY cloudflare.com` | **NOTIMP**, ANSWER 0, + EDE 21 w/ empty EXTRA-TEXT (`OPT=15: 00 15`) |
| `ns1.google.com` (auth) | `ANY google.com` | TC set -> TCP retry -> **35 answers**, full old-style dump (re-confirmed 09-16) |
| `8.8.8.8` | `ANY isc.org` | NOERROR, 2 answers: SOA + RRSIG only |
| `9.9.9.9` | `ANY isc.org` | varies per anycast instance: 5 answers on 09-15, **11** on 09-16 |

Two implementation notes from those probes. RFC 8482 §4 lists exactly three permitted responder behaviours (subset of RRsets / synthesized HINFO / best-guess records) and **NOTIMP is not among them**; Cloudflare's recursive chose it anyway. And system `dig 9.10.6` does **not** decode EDE: it prints the raw option bytes, so `00 15` = INFO-CODE 21 is our arithmetic, not dig's. Ship a bare "ANY" button and users file bugs against us for someone else's policy. Distinctive handling: keep ANY, **detect the `HINFO "RFC8482"` sentinel & the NOTIMP/EDE-21 pair, render an explainer**, then offer a **"query all common types" fan-out** (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, DS, DNSKEY, PTR, SVCB/HTTPS, and DANE/SSHFP types where asked) as what the user actually wanted. That fan-out is the highest-value single feature in this document.

### Truncation, TCP fallback & EDNS0 buffer sizes

Plain DNS/UDP caps at 512 bytes. EDNS0 (RFC 6891) adds an OPT pseudo-RR advertising a larger acceptable payload; over that the server sets **TC=1** and returns a stub, and the client retries over TCP. Forcing it against the root's DNSKEY set:

```
DNSKEY . @a.root-servers.net
+dnssec +bufsize=512 +notcp +ignore  ->  ;; flags: qr aa tc rd;  ANSWER: 1   (1 of 4 RRs)
+dnssec (TCP allowed)                ->  ;; Truncated, retrying in TCP mode.
                                         ;; flags: qr aa rd;     ANSWER: 4   MSG SIZE rcvd: 1139
```

**1232 bytes** was the DNS Flag Day 2020 default (derivation: IPv6 minimum MTU 1280 minus 48 bytes of IPv6+UDP header, RFC 9715 Appendix A). It is **not current**: RFC 9715 itself (Jan 2025) supersedes it, §3.1/§3.2 (R3/R5) now **RECOMMEND 1400 bytes**, reasoning that most backbone paths carry a 1500-byte Ethernet MTU and 1232, sized for IPv6's *minimum-guaranteed* MTU, leaves capacity on the table. So "1232" is the 2020 position, the spec's live position is 1400, and real resolvers have not caught up: our probe still shows old-regime values only. Advertised size is also **not** a per-resolver constant either way, which is the other build-relevant part: it's a property of the *responding instance*, not the anycast address. Observed `1.1.1.1` 1232 consistently, `8.8.8.8` **512** consistently, `9.9.9.9` **512 twice then 1232** within the same minute, `a.root-servers.net` **4096** — none at 1400 yet. Cache the value per response, never per resolver, and print the one this answer actually carried. Silently falling back to TCP hides a real diagnostic, since **UDP-truncating + TCP-blocked** is a common broken-firewall symptom and DNSSEC-signed zones w/ big DNSKEY sets trip it first. Good tools show a `TC` badge & the transport actually used.

The `9.9.9.9` per-instance variance above has a named cause: **EDNS NSID (RFC 5001, option code 3)**, a free identifying-string a resolver can request back in the OPT record. Firsthand, `dig +nsid`: `1.1.1.1` -> `"waw03"` (Warsaw PoP), `9.9.9.9` -> `"res710.qbre1"`, `8.8.8.8` -> `"gpdns-fra"` (Frankfurt). One line to request, and it turns "the buffer size changed between two of my queries" from a mystery into "you hit two different anycast nodes" — cheap enough to fold into the same TC/transport badge.

### EDNS Client Subnet (RFC 7871, option code 8)

ECS forwards a truncated prefix of the client address to the authoritative so CDNs can geo-steer. The option carries FAMILY, **SOURCE PREFIX-LENGTH**, **SCOPE PREFIX-LENGTH**, ADDRESS; RFC 7871 (May 2016, Informational) does not mandate a length, its privacy section *strongly encourages* truncating to **24 bits for IPv4** and **recommends 56 bits for IPv6** (citing RFC 6177). The load-bearing, universally-ignored field is **SCOPE**: the authoritative telling the cache *how finely to key this answer*. One client subnet, three names:

```
dig +subnet=8.8.8.8/24 @8.8.8.8
  example.com                 ; CLIENT-SUBNET: 8.8.8.0/24/24   <- per-/24 answer
  www.wikipedia.org           ; CLIENT-SUBNET: 8.8.8.0/24/23   <- per-/23 answer
  e86303.dscx.akamaiedge.net  ; CLIENT-SUBNET: 8.8.8.0/24/0    <- scope 0: same for everyone
```

Scope 0 means "not subnet-specific", so the different IPs Akamai returned for different `+subnet` values were resolver-side selection, **not** ECS steering. A tool claiming "your ECS changed the answer!" without reading scope is making that up. Two free reflector names expose what the authoritative actually saw & belong in the tool as a one-click check: `whoami.ds.akahelp.net TXT` -> `"ecs" "89.222.123.0/24/24"` + `"ns" "<resolver egress IP>"` + `"ip" "<your IP>"`, and `o-o.myaddr.l.google.com TXT` -> `"edns0-client-subnet 89.222.123.0/24"` + resolver egress IP. Per-resolver policy, re-observed 2026-09-16: `8.8.8.8` sent ECS /24; `9.9.9.9` sent **none** (`"ns"` only); `1.1.1.1` **did** send ECS (`"ecs" "89.222.120.0/24/24"`). That last one is not a contradiction: Cloudflare's 1.1.1.1 FAQ states it "does not send the EDNS Client Subnet header" and names exactly one exception, *"the Akamai debug domain `whoami.ds.akahelp.net`, which is used for cross-provider debugging"*, adding that it sends no ECS to Akamai production domains. Doc & probe agree; the reflector reading is a debug-path artifact and must be labelled as one in any UI, or we teach users the opposite of Cloudflare's actual behaviour.

### NXDOMAIN vs NODATA vs referral, & RFC 9824 erasing the distinction

**NXDOMAIN** = name does not exist (RCODE 3, SOA in AUTHORITY). **NODATA** = name exists, this type does not (RCODE 0, ANSWER 0, SOA in AUTHORITY; not a real RCODE, inferred). **Referral** = RCODE 0, ANSWER 0, NS in AUTHORITY, **no SOA**. All three read as "no results" to a naive tool and mean three different things to someone debugging: typo, wrong record type, delegation boundary.

Worse, the distinction is being actively erased. **RFC 9824, Compact Denial of Existence in DNSSEC (Sept 2025, Standards Track, Cloudflare authors)** lets signed zones *never* return NXDOMAIN; they return NOERROR/NODATA plus an NSEC whose type bitmap contains meta-type **NXNAME (TYPE 128)**. Observed live on `example.com` and `cloudflare.com`, RCODE NOERROR both:

```
zz9q-random.example.com. 1800 IN NSEC \000.zz9q-random.example.com. RRSIG NSEC TYPE128
```

That bitmap entry is the only thing separating "does not exist" from "exists but empty". RFC 9824 App. B names the deployers: **Cloudflare, NS1, Amazon Route 53 & Knot DNS's online-signing module** for the NSEC form, plus **Oracle Cloud using NSEC3 since Oct 2024**, which carries no NXNAME tell at all, so a TYPE128 check is necessary but not sufficient. Two parsing traps, both observed: the mnemonic is rendered **`TYPE128` by old `dig` and by Google's DoH JSON, `NXNAME` by Cloudflare's DoH JSON**, so match on both spellings; and RFC 9824 §3.5 says an explicit query *for* NXNAME may draw **EDE 30, Invalid Query Type**. A tool printing "NOERROR, no records" for a typo'd hostname on a Cloudflare domain is wrong today, on the most common hosting provider in our likely user base. Parsing the bitmap and rendering **"NXDOMAIN (compact denial)"** is genuinely distinctive; almost no consumer tool has it.

### SERVFAIL, & Extended DNS Errors (RFC 8914)

SERVFAIL is a garbage bucket: DNSSEC validation failure, lame delegation, unreachable authoritatives, resolver internal error, policy block. Alone it tells the user nothing. **EDE (RFC 8914, Oct 2020, option code 15)** fixes that w/ a 16-bit INFO-CODE + UTF-8 EXTRA-TEXT, and may ride on *any* RCODE including NOERROR. Firsthand on `dnssec-failed.org`:

```
@1.1.1.1  SERVFAIL  + OPT=15: 00 09 ... ("no SEP matching the DS found for dnssec-failed.org.")
@8.8.8.8  SERVFAIL  ; with +cd -> NOERROR  dnssec-failed.org. 85 IN A 96.99.227.255
```

Code 9 = **DNSKEY Missing**. The `+cd` (checking-disabled) retry returning a good A record proves the failure is validation, not availability: a two-query diagnostic worth exactly one checkbox of UI. Do **not** hardcode the 0-24 range RFC 8914 shipped with: IANA now assigns **0-35** (36-49151 unassigned, 49152+ private), and the late additions are exactly what a public lookup tool hits: **30** Invalid Query Type (RFC 9824), **31** Rate Limited & **32** Over Quota when we query too fast, **35** Blocked by Upstream DNS Server on filtered corporate resolvers. Codes **15-18** (Blocked, Censored, Filtered, Prohibited) let us honestly distinguish **"your resolver blocked this"** from "this domain is broken", the most-misdiagnosed DNS situation among non-experts. Ship the table as data, keyed by number w/ an "unknown code N" fallback.

### IDN & punycode

DNS carries **A-labels** (`xn--mnchen-3ya`); humans type **U-labels** (`münchen`). IDNA2008 conversion is the client's job & failing it is silent. Demonstrated by the tool on this machine:

```
$ dig A münchen.de @8.8.8.8      ;; IDN support not enabled
  ;m\195\188nchen.de.  IN A       <- raw UTF-8 on the wire -> NXDOMAIN
$ dig A xn--mnchen-3ya.de @8.8.8.8
  xn--mnchen-3ya.de. 8630 IN A 194.246.166.100
```

macOS system `dig 9.10.6` is built without IDN support & put literal UTF-8 bytes in the QNAME. Google's DoH JSON is stricter: a raw UTF-8 `name` param returns **HTTP 400 HTML**, docs require punycode. Both directions matter: convert U->A on input, A->U on *output* w/ a "show punycode" toggle, because `xn--ls8h.la` meaning 💩.la is information users want. Go's `golang.org/x/net/idna` is the right package & `golang.org/x/text` is already an indirect dep, so cost is near zero. Homograph safety: show the U-label but always the A-label alongside, since mixed-script labels are how phishing domains hide.

### Trailing dot, case preservation & 0x20

The trailing dot makes a name absolute. Without it a stub applies the **search list** (this machine: `search domain[0] : lan`), so `foo` may become `foo.lan`. A web tool has no search list, correct but surprising to users comparing against their laptop; normalising input to an FQDN & saying so is one line of Go that prevents a class of "your tool is broken" reports. Names are case-insensitive for matching but **case-preserving** on the wire: confirmed both hops, `ExAmPlE.CoM. 300 IN A 172.66.147.243` echoed verbatim by Cloudflare's authoritative, `GoOgLe.CoM. 57 IN A 142.251.20.100` echoed verbatim by `8.8.8.8`. **DNS 0x20** (draft-vixie-dnsext-dns0x20, 2008, never an RFC) exploits that: the resolver randomises QNAME case as extra anti-poisoning entropy & rejects replies whose case does not match. Google Public DNS announced global rollout **2023-07-25**, covering "almost all UDP queries (over 90% based on recent measurements)", w/ auto-detection of non-preserving nameservers, TCP retry & an exception list (announcement fetched, not inferred). Support elsewhere: **Unbound** (`use-caps-for-id`), **Knot** & **F5** do it, **BIND does not**. **PowerDNS Recursor does not generate it** either, contrary to what is often repeated: its docs only describe *preserving* a client's mixed case on the outgoing query, w/ `lowercase-outgoing` (default `no`) to switch that off, and the 2016 feature request for real randomisation is the only thing the docs cite. **This happens on the resolver->authoritative leg, unobservable from a client**, so our observations only prove case preservation on the legs we can see. Narrow but real relevance: if the tool queries authoritatives directly, do not assume case-normalised responses & compare QNAMEs case-insensitively.

### Wildcards & negative caching

A `*.example.com` wildcard synthesises answers for any non-existent name w/ no closer match, so **NXDOMAIN becomes impossible under that label** and "does this host exist?" stops being answerable. Observed on magic-DNS services: `1.2.3.4.nip.io -> 1.2.3.4`, `1.2.3.4.sslip.io -> 1.2.3.4`, while `zz9q-random.nip.io` returned NODATA w/ an SOA whose MNAME is the queried name itself. In a signed zone the giveaway is structural: the **RRSIG `labels` field is smaller than the owner name's label count**, proving synthesis. Toolbox's `json_response` does expose `labels` per RRSIG (verified), but only for whatever its stuck QTYPE=ANY returns, so it is a demo not a dependency. Cheaper and under our control: Google's & Cloudflare's DoH JSON hand back the RRSIG as a presentation string (`nsec 13 3 1800 ...`) whose third token *is* the labels count, so the check is a `strings.Fields` away on either.

**Negative caching** (RFC 2308 §5) has its own TTL, and it is not SOA MINIMUM alone: *"its TTL is taken from the minimum of the SOA.MINIMUM field and SOA's TTL."* Firsthand at the authoritative for `nic.cz`, SOA RR TTL 1800 & MINIMUM 7200 -> negative SOA served w/ TTL **1800**. RFC 2308 §5 recommends 1-3 h as a default, warns values exceeding one day "have been found to be problematic", and §7.1/7.2 cap SERVFAIL and dead-server caching at **five minutes** each.

The catch, measured across three resolvers & four zones, is that **the recursive clamps below that number and nothing tells the user**. Negative TTL at the authoritative vs what the public resolvers handed back: `nic.cz` 1800 -> 1800 / 1800 / 1800; `iana.org` & `icann.org` 3600 -> **1800** / 3600 / 3600; `verisign.com` 86400 -> **1800** / 86400 / 3072 (`8.8.8.8` / `1.1.1.1` / `9.9.9.9`). `8.8.8.8` pinned every negative answer to 1800 s regardless of zone, off by 48x on `verisign.com`; `1.1.1.1` honoured 86400 and counted down (1800 -> 1788 over 12 s). So printing only "cached N s, min of SOA TTL & MINIMUM" states the *zone operator's* intent, not what the user's resolver does. Show **both** & flag the disagreement. That is the arithmetic behind "I fixed the record but it still says not found", and no consumer tool shows either half.

## What the popular tools actually do about it

Table-stakes nearly everywhere: per-type lookups, TTL display, RCODE display, multi-resolver comparison. Differences live in the concepts above.

| Tool | Handles well | Blind spot |
|---|---|---|
| **Google Admin Toolbox dig** | Section-by-section dump (QUESTION/ANSWER/AUTHORITY/ADDITIONAL) + `json_response` w/ **parsed RRSIG subfields incl. `labels`** (verified), the wildcard tell decoded for free | Its `lookup` endpoint sent **QTYPE=ANY** regardless of param (below), which also caps what RRSIGs you can reach; no CORS header, unusable from a browser |
| **dnsviz.net** | Authoritative on DNSSEC chain-of-trust, NSEC/NSEC3 proofs, delegation graph. Engine is open source (GPL-2.0) | DNSSEC-only, not a general record browser |
| **zonemaster.net** | The delegation/glue checker: parent-vs-child NS, glue consistency, zone-level tests. Open source, run by The Swedish Internet Foundation + AFNIC. Direct prior art for feature #6 below | Zone-health report, not a record browser (HTTP 302 to a JS app; not probed further) |
| **nslookup.io** | Clean per-type pages, explains NXDOMAIN vs NODATA in prose | Single vantage point |
| **whatsmydns / dnschecker** | Global propagation matrices: the TTL-countdown question answered geographically | Both **403'd our curl** (bot protection); concept handling unverified firsthand |
| **mxtoolbox** | Email-record semantics (SPF/DKIM/DMARC chains), lookup limits | Weak on delegation/glue & EDNS |
| **`dig` itself** | Everything, if you know the flags | `+trace` **failed on this machine** (system `dig 9.10.6` returned a 28-byte reply from `8.8.8.8` and stopped): do not shell out to it |

Endpoints & limits, checked 2026-09-16:

| Endpoint | Auth | CORS | Notes |
|---|---|---|---|
| `https://dns.google/resolve?name=&type=&cd=&do=&ct=&edns_client_subnet=&random_padding=` | none documented | `access-control-allow-origin: *` | JSON. `type` defaults to 1 (A), accepts numeric (`257` -> CAA, verified) or names. **Structured `extended_dns_errors: [{info_code, extra_text}]`** plus a human `Comment` that also names the authoritative it used. Returns `Authority[]` incl. the **NSEC bitmap under `do=1`** (`"... RRSIG NSEC TYPE128"`), so compact denial is detectable over JSON. Keeps trailing dots, lowercases RRSIG type mnemonics. `cache-control: max-age` tracks TTL exactly (`max-age=34` w/ `"TTL":34`). No rate limit or quota documented, which is not the same as none. |
| `https://cloudflare-dns.com/dns-query?name=&type=&do=&cd=` | none | `access-control-allow-origin: *` | **Requires `accept: application/dns-json`**; omitting it returned HTTP **400** firsthand. Returns `Authority[]` too, incl. the NSEC bitmap under `do=1`. EDE arrives only as a `Comment` **string array** (`"EDE(9): DNSKEY Missing no SEP matching the DS found for dnssec-failed.org."`), must be regex'd not read. **Strips trailing dots** & uppercases RRSIG type mnemonics, unlike Google. No limits documented. |
| `https://dns.google/dns-query` (RFC 8484 wireformat) | none | n/a | `accept: application/dns-message`, base64url `dns=` param. HTTP 200, 61 bytes, for a hand-built `example.com A` query. |
| `https://dns.adguard-dns.com/resolve`, `https://dns.nextdns.io/dns-query` | none | **no ACAO header** | Both 200 w/ Google-shaped JSON; NextDNS even exposes the OPT pseudosection (`udp: 1232`) in `Additional`. Both are **filtering** resolvers, so answers are policy-modified: useful as a "is this blocked?" vantage point, wrong as a ground-truth resolver. Quad9's documented `:5053` JSON endpoint **timed out** from this host. |
| `https://toolbox.googleapps.com/apps/dig/lookup?domain=` | none | **no ACAO header** | Undocumented. Returns `{error_html, response, json_response}`. **Twelve** type-param spellings tried (`rr_type`, `type`, `rrtype`, `rr`, `qtype`, `typ`, `record_type`, `t`, `qt`, `rtype`, `recordType`, `dnsType`, incl. numeric `15`) and every one was ignored, QUESTION came back `ANY`. Server-side only, and unreliable. |

## Options for us, w/ trade-offs

Stack: single Go binary, Echo v5, htmx, no Node, optional Mongo, Hetzner box behind Cloudflare + nginx.

| Option | What it buys | Cost/complexity | Risk |
|---|---|---|---|
| **A. Go stdlib `net.Resolver`** | Zero deps, works today | Trivial | Dead end. No RCODE, TTL, flags, arbitrary QTYPE or AUTHORITY section. Cannot express ~80% of this document. |
| **B. `github.com/miekg/dns` raw queries from our box** | Everything: TTLs, flags, TC, EDNS0, ECS, EDE, NSEC bitmaps, SvcParams, per-resolver targeting, our own `+trace` | One dep (BSD-3-Clause, v1.1.73 Aug 2026); hand-roll retry / TCP fallback / timeouts | Outbound UDP/53 from Hetzner. A public form querying arbitrary nameservers is an **abuse amplifier**: needs rate limiting & a resolver allowlist |
| **C. DoH JSON passthrough (Google + Cloudflare), server-side** | No outbound :53 at all; both endpoints keyless & CORS-open; Google gives structured EDE free. **Stronger than it looks**: both return `Authority[]` and both expose the NSEC bitmap under `do=1`, so NXDOMAIN/NODATA/compact-denial *and* SvcParam rendering all work over JSON | Lowest: `net/http` + `encoding/json` | No delegation walk (no `+norec`, so no parent-side glue), no EDNS knobs beyond their params, no transport/TC visibility; two vendor dialects to normalise (trailing dots, RRSIG mnemonic case, `TYPE128` vs `NXNAME`, structured vs prose EDE) |
| **D. DoH JSON from the browser via htmx/Alpine** | Zero server load, user's own vantage point | Needs JS beyond htmx's comfort zone | Violates "htmx only when plain HTML can't"; loses server-side caching & Mongo history; CORS is a revocable vendor favour |
| **E. B for the hard parts + C as fallback** | Delegation walk, glue diff & EDE where they matter; degrades when :53 is blocked | Highest: two code paths, one normalised domain struct | Divergent results confuse users unless vantage point is labelled on screen |
| **F. Mongo-backed lookup history & diff** | "What changed since last time", the actual user question; reuses the `tools/iptools/history.go` pattern verbatim | Low, pattern exists in repo | Stored hostnames mildly sensitive; TTL-index it like the IP tool does |

Feature inventory, ranked by value-per-line-of-Go (assumes option B or C): **1.** fan-out "all common types" in one view, replacing the ANY button users will hunt for. **2.** NXDOMAIN / NODATA / referral disambiguation incl. RFC 9824 compact denial, matching both the `TYPE128` and `NXNAME` spellings. **3.** EDE decode (code + name + extra text) on every response, not only failures. **4.** `+cd` retry on SERVFAIL separating "DNSSEC broken" from "server down", as a one-line verdict. **5.** authoritative vs cached TTL side by side, countdown explicit. **6.** parent-vs-child NS + glue diff (the delegation walk): highest effort, highest differentiation. **7.** negative-TTL: the zone's intent `min(SOA TTL, MINIMUM)` **and** the TTL this resolver actually returned, side by side, flagged when they diverge. **8.** ECS panel w/ scope readout, the two reflector names, per-resolver policy note incl. the akahelp caveat. **9.** TC / transport badge: UDP size, whether TCP fallback happened, bufsize advertised **on this response**, plus NSID (RFC 5001) when the server sends one, since it's the one-line explanation for "the buffer size changed between two of my queries" against anycast resolvers. **10.** SvcParam rendering for HTTPS/SVCB (alpn, ECH, hints), since the fan-out returns them and hex is useless. **11.** IDN U-label ⇄ A-label toggle w/ mixed-script warning. **12.** apex flattening / ALIAS annotation + dangling-CNAME NODATA warning. **13.** wildcard detection via RRSIG `labels` < owner label count. **14.** CNAME chain visualiser, per-hop TTL, governing minimum highlighted. **15.** reverse lookup that builds `in-addr.arpa` / `ip6.arpa` correctly from a pasted address, incl. v6 nibbles. **16.** CAA apex-climb w/ the answering label named. **17.** trailing-dot normalisation notice: one line, prevents a support-ticket class.

## Hard constraints & failure modes

- **Outbound :53 from Hetzner.** Option B emits DNS queries to arbitrary destinations on user input. Rate-limit per source IP, cap queries per request, allowlist resolvers for the "pick a resolver" feature. Same Hetzner-abuse concern that shelved the live port scanner; DNS is far milder but not zero.
- **Cloudflare in front of us.** If we offer "multiple vantage points", the vantage point is one Hetzner box, not Cloudflare's network. Label honestly, do not imply propagation coverage we lack.
- **`dig +trace` is not an implementation strategy.** It failed here (28-byte reply, stopped). Shelling out to a system binary whose IDN support, flag set & trace behaviour vary per OS is a bug farm. The manual walk (`+norec` at each cut) worked every time and is ~40 lines w/ `miekg/dns`.
- **Vendor JSON dialects diverge.** Google keeps trailing dots, lowercases RRSIG mnemonics & gives structured EDE; Cloudflare strips dots, uppercases them, spells NXNAME where Google spells TYPE128, buries EDE in a prose `Comment` array, and 400s without the `accept` header. Normalise into one domain struct at the boundary, per CLAUDE.md rule #1.
- **CORS is a favour.** Google & Cloudflare send `access-control-allow-origin: *` today (2026-09-16); AdGuard & NextDNS send none, so the browser-side option is already narrower than it looks. Neither of the two documents a rate limit or stability promise. A browser-side design breaks the day either changes.
- **"No results" is four different things.** Shipping without the NXDOMAIN / NODATA / referral / compact-denial distinction means shipping a tool that is wrong on Cloudflare-hosted domains, i.e. most of them.
- **Validate user-supplied ECS.** `8.8.8.8` REFUSED our query carrying `203.0.113.0/24`, a documentation prefix. Reject bogons before forwarding.
- **Don't build a resolver.** We are a client. Caching is the resolver's job; our Mongo layer is history, not cache. Conflating them puts driver logic where domain logic belongs (rule #5).

## Verified firsthand vs inferred

**Verified firsthand** (`dig` / `curl` output quoted above, re-run 2026-09-16): TTL countdown vs full authoritative TTL; root & `.com` referral structure incl. 27 glue RRs; in-bailiwick (`google.com`, 8 glue RRs) vs sibling (`corpberry.com`, 12) glue; ANY behaviour across five targets incl. the `HINFO "RFC8482"` sentinel, Cloudflare's NOTIMP & Google's 35-answer dump; TC=1 at `bufsize=512` against the root and the TCP retry returning 4 RRs at 1139 bytes; advertised bufsizes **512 / 1232 / 512-then-1232 / 4096** (none at RFC 9715's 1400); NSID strings identifying the answering instance on all three public resolvers (`waw03` / `res710.qbre1` / `gpdns-fra`); ECS scopes /24, /23, /0; both ECS reflector names & their per-resolver output incl. `1.1.1.1` answering w/ an `ecs` value; REFUSED on a documentation-prefix ECS; NXDOMAIN+SOA vs NODATA+SOA; the RFC 9824 `NSEC ... TYPE128` record on two Cloudflare zones, and its `NXNAME` spelling in Cloudflare's JSON; SERVFAIL on `dnssec-failed.org` across three resolvers plus the `+cd` NOERROR retry; raw EDE option 15 bytes carrying INFO-CODE 9 and 21; case preservation on both visible hops; `dig 9.10.6` emitting raw UTF-8 for an IDN & failing where the A-label succeeded; Google DoH 400 on raw UTF-8; wildcard synthesis on `nip.io` / `sslip.io`; the **negative-TTL clamp table** (authoritative vs `8.8.8.8` / `1.1.1.1` / `9.9.9.9` on four zones, incl. `8.8.8.8` pinning 86400 -> 1800 and `1.1.1.1` counting 1800 -> 1788 over 12 s); `nic.cz` SOA TTL 1800 / MINIMUM 7200; `www.bing.com` 3-hop CNAME chain on two days; apex A-only answer & CNAME NODATA on Cloudflare-hosted `example.com`; HTTPS/SVCB as unknown-type hex in `dig` vs parsed SvcParams in Google's JSON, and `dig +short HTTPS` returning A records; v4 & v6 PTR; CAA present at apex, NODATA at `www`; all six API endpoints' status codes, CORS headers, auth requirements & response shapes; twelve rejected Toolbox type-param spellings; `dig +trace` failing identically on re-run; `whatsmydns.net` & `dnschecker.org` returning 403 to curl.

**Read from primary sources, not measured** (RFC texts & vendor docs fetched this pass, quoted where load-bearing): RFC 8482 §4's three permitted behaviours & §4.2's HINFO sentinel wording; RFC 7871's 24-bit / 56-bit privacy guidance; RFC 2308 §5's `min(SOA.MINIMUM, SOA TTL)` sentence, its 1-3 h recommendation and §7.1/7.2's five-minute caps; RFC 9715 Appendix A's 1280-48 derivation **and** its §3.1/§3.2 R3/R5 recommendation of 1400 bytes, which supersedes 1232 as the spec's live position; RFC 9824 §3.5 (EDE 30) & App. B's deployer list (Cloudflare, NS1, Route 53, Knot online signing, Oracle via NSEC3); IANA's Extended DNS Error Codes registry, 0-35 assigned; Cloudflare's 1.1.1.1 FAQ naming `whoami.ds.akahelp.net` as the sole ECS exception, which our probe **matches**; Cloudflare's CNAME-flattening page stating a dangling target returns NODATA; Google Public DNS's 0x20 announcement (2023-07-25, ">90%", auto-detect / TCP retry / exception list); PowerDNS Recursor's `lowercase-outgoing` docs; `miekg/dns`'s BSD-3-Clause LICENSE & v1.1.73 tag.

**Still inferred or unverified:** 0x20 on the resolver->authoritative leg is structurally unobservable from a client, so the rollout figures above are Google's own claim about its own network, and the Unbound / Knot / F5-yes, BIND-no matrix is secondhand (SIDN). Route 53 / DNSimple `ALIAS` being *equivalent* to Cloudflare flattening is vendor marketing language, not a probe. DNAME was not observed: no live example was found in a short hunt, so its synthesised-CNAME behaviour here is spec-read only. `whatsmydns.net` & `dnschecker.org` concept handling remains unverified (403 to curl, and per the brief the browser pane was off-limits). The Toolbox `lookup` endpoint's real type parameter presumably exists, since its web UI does per-type lookups; twelve spellings failed, so it is documented as unreliable, not broken. Neither Google nor Cloudflare publishes a rate limit for its JSON endpoint, and "undocumented" is not "absent". Every per-resolver observation here is vendor policy on one anycast instance on one date and can change without notice.

## Sources

- [RFC 1034: Domain Names, Concepts and Facilities (CNAME restrictions, wildcards, glue)](https://www.rfc-editor.org/rfc/rfc1034.txt)
- [RFC 2308: Negative Caching of DNS Queries (NXDOMAIN vs NODATA, negative-TTL rule)](https://www.rfc-editor.org/rfc/rfc2308.txt)
- [RFC 4592: The Role of Wildcards in the Domain Name System](https://www.rfc-editor.org/rfc/rfc4592.txt)
- [RFC 6891: Extension Mechanisms for DNS, EDNS(0)](https://www.rfc-editor.org/rfc/rfc6891.txt) · [RFC 7766: DNS Transport over TCP](https://www.rfc-editor.org/rfc/rfc7766.txt)
- [RFC 7871: Client Subnet in DNS Queries](https://www.rfc-editor.org/rfc/rfc7871.txt)
- [RFC 8482: Minimal-Sized Responses to DNS Queries with QTYPE=ANY](https://www.rfc-editor.org/rfc/rfc8482.txt)
- [RFC 8484: DNS Queries over HTTPS, wireformat](https://www.rfc-editor.org/rfc/rfc8484.txt)
- [RFC 8914: Extended DNS Errors](https://www.rfc-editor.org/rfc/rfc8914.txt) · [IANA: Extended DNS Error Codes registry, 0-35 assigned](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
- [RFC 9460: SVCB and HTTPS resource records](https://www.rfc-editor.org/rfc/rfc9460.txt) · [RFC 9462: Discovery of Designated Resolvers](https://www.rfc-editor.org/rfc/rfc9462.txt) · [RFC 2317: Classless IN-ADDR.ARPA delegation](https://www.rfc-editor.org/rfc/rfc2317.txt)
- [RFC 9715: IP Fragmentation Avoidance in DNS over UDP (Jan 2025; §3.1/§3.2 recommend 1400 bytes, superseding the 1232 figure derived in Appendix A)](https://datatracker.ietf.org/doc/html/rfc9715)
- [RFC 5001: DNS Name Server Identifier (NSID) Option](https://www.rfc-editor.org/rfc/rfc5001.html)
- [RFC 9824: Compact Denial of Existence in DNSSEC, NXNAME / TYPE 128](https://datatracker.ietf.org/doc/rfc9824/) · [Bortzmeyer's notes on RFC 9824](https://www.bortzmeyer.org/9824.html)
- [DNS Flag Day 2020: recommended 1232-byte EDNS buffer](https://dns-violations.github.io/dnsflagday/2020/) · [ISC explainer](https://www.isc.org/blogs/dns-flag-day-2020-2/)
- [Google Public DNS: global case randomisation (0x20) announcement](https://groups.google.com/g/public-dns-discuss/c/KxIDPOydA5M)
- [SIDN: Google enables case randomisation on its public resolvers](https://www.sidn.nl/en/news-and-blogs/google-enables-case-randomisation-security-on-all-its-public-dns-resolvers)
- [Google Public DNS: DoH JSON API reference](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Cloudflare: DoH JSON API reference](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Cloudflare 1.1.1.1 FAQ: ECS policy](https://developers.cloudflare.com/1.1.1.1/faq/) · [Cloudflare: CNAME Flattening](https://developers.cloudflare.com/dns/cname-flattening/)
- [PowerDNS Recursor settings: `lowercase-outgoing`, the only 0x20 mention in its docs](https://doc.powerdns.com/recursor/settings.html)
- [`github.com/miekg/dns` LICENSE, BSD-3-Clause](https://raw.githubusercontent.com/miekg/dns/master/LICENSE) · [latest release via proxy.golang.org](https://proxy.golang.org/github.com/miekg/dns/@latest)
- [Google Admin Toolbox dig](https://toolbox.googleapps.com/apps/dig/) · [DNSViz](https://dnsviz.net/) · [Zonemaster](https://zonemaster.net/) · [nslookup.io](https://www.nslookup.io/) · [nip.io](https://nip.io/) · [sslip.io](https://sslip.io/)
