# Internet.nl

Standards-**compliance grader**, not a lookup tool. You give it a domain, it returns a 0-100% score across five categories & 38 subtests (both web & mail land on 38, confirmed by hand-count of `checks/categories.py`), each w/ verdict, technical-detail table & a long explanation citing the RFC or NCSC-NL guideline behind it. Run by the **Dutch Internet Standards Platform** (ECP admin home; NLnet Labs built the foundation; SIDN, RIPE NCC, SURF, NCSC-NL, ISOC, Dutch Ministry of Economic Affairs among the 15 listed partners). Matters to a DNS-tool builder for three reasons: it grades **DANE/TLSA** and **IPv6 reachability of the nameservers themselves** (DNSViz does chain-of-trust only, intoDNS does delegation hygiene only), its **scoring model** is the cleanest published way to turn a pile of pass/fail DNS checks into one honest number, and the whole thing is **Apache-2.0 open source** so every mechanic is readable.

- **URL:** https://internet.nl · **Category:** free standards-compliance scorecard (web / mail / connection) · **Registration:** none for single-domain tests; **batch API + dashboard by request only** · **Pricing:** free, publicly funded · **API:** batch-only JSON REST v2, HTTP Basic auth
- **Firsthand check (2026-09-16):** `curl` root -> **200**, `server: nginx`, app version **v1.11.3** in footer, `x-clacks-overhead: GNU Terry Pratchett`. Ran a **full website test end to end** on `internet.nl` itself: `POST /site/ url=internet.nl` -> 302 `/site/internet.nl/` -> polled `/site/probes/internet.nl/` (returned `[{"name":"ipv6","done":true,"success":true},…]` for ipv6/dnssec/tls/appsecpriv/rpki) -> `/site/internet.nl/results` -> 302 to permalink `/site/internet.nl/4302030/`, **100%**, stamped `2026-09-16 09:05 UTC`, retest countdown **199 s**. Also read two live 100% reports (web + mail) in full, hit `/api/batch/v2/requests` (**401**, `www-authenticate: Basic realm="Please enter your batch username and password"`), `dig`'d the qname-min zone from 4 resolvers, re-counted every `Category`/`Subtest` class in `checks/categories.py` by hand (grep+sed on the raw file, not a summariser), and read `checks/resolver.py`, `interface/views/connection.py`, `interface/batch/openapi.yaml` & `.env.dist` from the repo. **Not** verified firsthand: the connection test (needs a browser + a JS-driven multi-host flow), the batch API responses (no account), the dashboard UI (`dashboard.internet.nl` returns "doesn't work properly without JavaScript").

## What it is

A **compliance test, explicitly not a security test** ("a 100% score does not mean that an online service is fully secure"). The norm is pinned to three things: the Netherlands Standardisation Forum's mandatory-open-standards list, **NCSC-NL's TLS guidelines** (live reports cite *version 2025-05*), and IETF RFCs. Three main tests: **website**, **email**, **connection**. Web & mail scores are permalinked & public, and 100% lands you in the **Hall of Fame** (4,553 domains at double-100% i.e. "champions" per `/halloffame/`, and separately 39,778 at web-only 100% per `/halloffame/web/`, both checked 2026-09-16; the count moves as the twice-monthly recheck runs, so treat as a ballpark). Tone throughout is civil-service neutral: no upsell, no scare copy, a "how to improve" line pointing you at your hoster.

## Registration, access & pricing

Free, no account, no key for the three interactive tests. Publicly funded (SIDN Fund paid for the 2023 containerisation). Batch API & dashboard accounts are **granted on request** to organisations, bound by a short terms-of-use doc (v20250118, read 2026-09-16):

| Limit | Value |
|---|---|
| Batch requests | **max 2 per week** |
| Domains per request | **max 5,000** |
| Accounts per organisation | **max 3** |
| Idle-account deletion | after **12 months** unused |
| Single-domain-per-request use | **forbidden** (use the web UI) |
| Third-party public/commercial front-end on the API | **forbidden** |

Attribution requested when you republish results. Code Apache-2.0; `/translations` CC BY 4.0; **name & logo explicitly excluded** from both licences.

## Features — complete inventory

Counts below are from `checks/categories.py` on `main`, read 2026-09-16. Live v1.11.3 renders these grouped under sub-headings (e.g. "Name servers of domain" / "Web server").

**Website test — 5 categories, 38 subtests**

| Category | Subtests |
|---|---|
| **IPv6** (5) | IPv6 addresses for name servers (≥2 required, per SIDN .nl rules) · **IPv6 reachability of name servers** · IPv6 addresses for web server · IPv6 reachability of web server · **Same website on IPv6 & IPv4** (ports, headers, HTTP status class, HTML content diff ≤10% after nonce-stripping) |
| **DNSSEC** (2) | DNSSEC existence (SOA signed; follows CNAME) · DNSSEC validity (`secure` / `bogus`) |
| **HTTPS/TLS** (22) | HTTPS available · HTTPS redirect (order-aware) · HTTP compression (BREACH) · HSTS (≥1 yr) · TLS version · cipher suites · **cipher suite order** (w/ violation tuple) · key-exchange params (curves, RFC 7919 FFDHE groups, **X25519MLKEM768 & friends rated Good**) · key-exchange hash function · TLS compression · secure renegotiation · client-initiated renegotiation (>10 = insufficient) · 0-RTT · Extended Master Secret · OCSP stapling · cert trust chain · cert public key · cert signature · cert hostname match · **CAA for domain** · **DANE existence** · **DANE validity** |
| **Security options** (5) | X-Frame-Options · X-Content-Type-Options · Content-Security-Policy · Referrer-Policy · **security.txt** |
| **RPKI** (4) | ROA existence + route-announcement validity, **separately for the name servers and for the web server** |

**Email test — 5 categories, 38 subtests**

| Category | Subtests |
|---|---|
| **IPv6** (4) | NS AAAA · NS IPv6 reachability · MX AAAA · MX IPv6 reachability |
| **DNSSEC** (4) | domain existence + validity · **MX domain existence + validity** (signed separately) |
| **Mail auth** (5) | DMARC existence · **DMARC policy** (p=quarantine/reject, `t=y` downgrades a level, validates `rua`/`ruf` incl. **external-destination authorisation**, permits RFC 9091 `np`) · DKIM existence (see below) · SPF existence · **SPF policy** (`~all`/`-all`, follows include/redirect, enforces the **10-DNS-lookup cap**, refuses to expand macros & excludes them from the count) |
| **STARTTLS & DANE** (19) | STARTTLS available (**Null-MX / no-MX aware**; max 10 MX tested; no A/AAAA fallback) · the full TLS battery as above · CAA for mail server · **DANE existence** · **DANE validity** · **DANE rollover scheme** (≥2 TLSA records) |
| **RPKI** (6) | ROA + validity for the domain's NS, the **MX domain's NS**, and the mail servers |

**Connection test — 2 categories, 6 report items** (from `interface/views/connection.py`): resolver reachable over IPv6 · AAAA resolvable · IPv6 connection to an IPv6-only host (shows IP, reverse, AS owner) · **IPv6 privacy** (SLAAC-without-privacy-extensions) · IPv4 connection (informational) · **DNSSEC validation by your resolver**.

**Around the tests:** permalinked, shareable, timestamped report URLs · **retest cooldown** (~200 s countdown, then a "Rerun the test" link) · overall % + per-category icon summary that expands to per-subtest verdict + technical table + explanation + requirement level · Hall of Fame (web / mail / **hosters**, incl. automated twice-monthly recheck & a documented delisting policy: 3 consecutive sub-100% scans ≈ 6 weeks, 2-month grace when new subtests start counting, 3-month cool-off before reapplying) · **embeddable 100% badges** (`/static/embed-badge-websitetest.svg`, self-host requested) · **zero-JS embeddable widget** (plain `<form action="https://internet.nl/site/" method="POST">` w/ one `url` field) · EN/NL w/ per-language hosts · IPv6-only host `ipv6.internet.nl` (**AAAA-only, no A**, confirmed by `dig`; my IPv4-only egress could not reach it) · how-to wiki at `toolbox.internet.nl` -> `github.com/internetstandards/toolbox-wiki` (CC BY 4.0) · Matomo, self-hosted.

**Batch API v2** (`https://batch.internet.nl/api/batch/v2/…`, HTTP Basic, semver w/ major in the path):

| Endpoint | Method | Notes |
|---|---|---|
| `/requests` | POST | body `{type: web\|mail, domains: […], name}`; domains used **as-is**, no www/bare expansion |
| `/requests` | GET | list, `?limit=` (default 10, `0` = unlimited) |
| `/requests/{request_id}` | GET | status: `registering` / `running` / `generating` / `done` / `cancelled` / `error` |
| `/requests/{request_id}` | PATCH | `{status: "cancelled"}` |
| `/requests/{request_id}/results` | GET | compliance view: per-domain status, scoring, report, results |
| `/requests/{request_id}/results_technical` | GET | technical view: per-address `reachable` + `routing{origin, route, rov_state}`, `dnssec.status` (`secure`/`insecure`/`bogus`/`unknown_ds_algo`/`error`), TLS detail (`ciphers_bad`, `ciphers_phase_out`, `cipher_order`, `cipher_order_violation`, `kex_params_*`, `extended_master_secret_status`, `client_reneg`, `kex_hash_func`), `dane_status`, `dane_records`, `dane_rollover`, MX `server_reachable` / `starttls_enabled` / `server_testable` |
| `/metadata/report` | GET | machine-readable hierarchy + labels + docs, "can be used to create reports equivalent to the main application" |

**Dashboard** (`dashboard.internet.nl`, separate repo): named domain lists (thousands each), spreadsheet upload/download (XLSX/ODS/CSV), scheduled & repeating scans, scan monitor w/ cancel, report tables + bar charts + **timelines**, **report-to-report diff** showing per-domain improvement/decline, compare up to 5 reports, spreadsheet export, published/shared reports (public or password), email notification on new report w/ major changes, per-field visibility settings, 2FA.

## Record types & query options supported

RR types it actually resolves (`checks/resolver.py`): **A, AAAA, NS, SOA, MX, TXT** (SPF/DMARC/DKIM), **TLSA, CAA, PTR**, plus DNSKEY/DS implicitly through a validating resolver. Zone-level: `dns_climb_tree` walks to the parent label; DKIM is probed as **`_domainkey.<domain>` expecting NOERROR** because the selector is unknowable from outside (a nameserver that wrongly answers NXDOMAIN for an empty non-terminal fails the check).

User-facing query knobs: **none**. No resolver picker, no "query the authoritative NS", no RR-type selector, no trace/delegation walk, no TCP toggle, no ECS, no raw/`dig`-style output, **no TTL display anywhere**. Internally it does use EDNS0 w/ **DO** always on and a **CD (checking-disabled)** resolver by default, w/ a second non-CD resolver used when a subtest needs a trustworthy AD bit (`guarantee_accurate_secure`, working around a cache-poisoning-of-your-own-cache footgun, repo issue #1869). The nameserver-reachability probe is a direct `make_query(qname, NS, use_edns=True, flags=CD)` over **UDP w/ TCP fallback straight at the target IP**.

## How it works

Entirely **server-side** for web & mail: Django + Celery + RabbitMQ + Redis + PostgreSQL, TLS via **nassl** (OpenSSL bindings), DNS via a **local validating Unbound** reached through a single pinned address (`RESOLVER_INTERNAL_VALIDATING`). Five probes run concurrently per test; the browser polls `/site/probes/<domain>/` every **3,000 ms**, up to **64** attempts (~192 s, matching the advertised "between 5 and 200 seconds"). Recursive-only: it resolves through its own validating resolver rather than querying each authoritative NS, which is why it grades *what a real client sees* and not *whether your NS set is self-consistent*. Results are cached for `settings.CACHE_TTL` (`get_retest_time()` in `interface/views/shared.py`; default `INTERNETNL_CACHE_TTL=200` seconds per `.env.dist`, matching the observed 199 s countdown), hence the retest cooldown & the report-id permalinks. The same `CACHE_TTL` also bounds how long a connection-test result stays in Redis (`cache.set(cache_id, results, settings.CACHE_TTL)`). Per-category aggregation over multiple IPs takes the **worst** score; for performance, TLS runs only against the **first available IPv6 & IPv4 address**, and at most **10 MX**.

**RPKI** is source-agnostic w/ two pluggable backends: **Team Cymru IP-to-ASN over DNS** to enumerate covering DFZ routes, and a **Routinator** RPKI relying-party instance over HTTP for validity (`ROUTINATOR_URL`; `https://rpki-validator.ripe.net/api/v1/validity` named as a public test instance). Responses are **not cached**. Status mapping: valid ROA everywhere -> success; not-found -> notice; any covered-but-invalid route -> fail (RFC 6811 terms).

**The connection test is the architecturally interesting one.** It cannot be done with a resolver library, so they built out-of-band callbacks: each test gets a UUID, the browser is pointed at **per-test unique subdomains** delegated to a **custom authoritative nameserver** that writes every querying resolver's IP into Redis under `ns_<host>.`; the Django app then reads those keys back to decide whether your resolver spoke IPv6. DNSSEC validation is tested by serving a **deliberately bogus-signed** hostname and checking whether you ever fetched it. Resolver IPs are mapped to ASNs via **RIPE RIS whois**, w/ the AS description pulled from a **`AS<n>.asn.cymru.com` TXT** record. IPv6 "privacy" is graded by checking whether your source address yields a **MAC vendor** (i.e. EUI-64 SLAAC without privacy extensions).

## Output & UX

Progressive: a live "the items below are being tested" page w/ five spinners, polled, then an automatic hop to the permalink. The report is **one long accordion**, `<details>`-style, w/ show-all / hide-all: score badge -> five category rows w/ icon + one-line verdict -> each expands to subtests, and each subtest to `Verdict` / `Technical details` (real table: NS name, IPv6 addr, IPv4 addr; or web-server IP, cipher, security level; or the literal TLSA triple `3 0 1 b6c8ef…`) / `Test explanation` / `Requirement level`. Explanations are genuinely long & cite the exact NCSC-NL paragraph, and several carry a **"Deployment recommendation"** block (the HSTS one walks you through staged `max-age` increases). Five statuses w/ distinct icons: Passed / Failed / Recommendation / Information / Error, plus **Not testable** ("already failed the parent subtest"). Print stylesheet shipped. **No JSON, no CSV, no export** on the free single-domain path: `Accept: application/json` on a report URL returns `text/html` (checked firsthand), and there are **no CORS headers at all** (checked firsthand), so a browser-side tool cannot call it.

## Monetization, limits & abuse controls

No monetization. Controls are: 200 s per-domain retest cooldown (`INTERNETNL_CACHE_TTL` default, confirmed in `.env.dist`); server-side rate-limiting is implicit in the cooldown + caching; batch access gated behind a human request + a 2-per-week / 5,000-domain fair-use rule; the terms explicitly ban reselling it behind a third-party front-end and ban single-domain batch requests. Privacy hygiene is a deliberate feature, not an afterthought: the connection test **anonymises before storing**, masking IPv4 to **/16** and IPv6 to **/32** and reducing reverse names to their **last 3 labels** w/ the rest replaced by `[…]`. Matomo is self-hosted. Vulnerability disclosure policy + PGP-signed `.well-known/security.txt` (expires 2027-04-10).

## Ideas worth stealing

- **The scoring model, verbatim.** Categories weigh **equally** regardless of subtest count (2 categories -> 50% each, not 130/140). Only subtests whose *worst possible status is FAIL* qualify for the score; everything else renders but scores nothing. Aggregated categories take the **worst** per-IP score. And the graduation path: **ship every new check as RECOMMENDED/OPTIONAL first, promote it to REQUIRED later**, so your score is stable across releases. That is one small Go struct: `Subtest{Name, Level, Points, MaxPoints, WorstStatus}` + `Category{Name, Subtests}`, and `total = mean(category scores)`.
- **Six statuses, not two.** Passed / Failed / Recommendation / Information / Error / **Not testable**. The last one is the good idea: when a parent check fails, mark children *not testable* instead of failing them, so one broken DNSSEC delegation doesn't paint eight rows red.
- **Reachability, not just presence.** Every "does it have an AAAA" check is paired w/ "**does that AAAA answer**". For an NS that's a direct `NS` query w/ EDNS+CD at the IP over UDP-then-TCP; timeout = unreachable; partial credit if some addresses answer. Cheap in Go (`miekg/dns` `Exchange` w/ a per-IP `Client`), and it is the single thing most delegation checkers skip.
- **Show the raw record next to the verdict.** The TLSA row prints `3 1 1 214fd79…`, the DMARC row prints the whole `v=DMARC1; p=quarantine; rua=…` string. Verdict for skimmers, raw string for the person who has to fix it.
- **Zero-JS embeddable widget.** A copy-pasteable `<form method="POST">` + a few lines of CSS, no script tag, no iframe. Perfect fit for a no-npm Go site, and it is free inbound traffic.
- **Free, key-less enrichment sources they use — all verified working, 2026-09-16.** `dig +short TXT 8.8.8.8.origin.asn.cymru.com` -> `"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"`; `dig +short TXT AS15169.asn.cymru.com` -> `"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"`; `GET https://rpki-validator.ripe.net/api/v1/validity/AS15169/8.8.8.0/24` -> JSON `{state: "valid", VRPs:{matched,unmatched_as,unmatched_length}}` **w/ `access-control-allow-origin: *`**. That is prefix + ASN + AS name + RPKI validity, no key, one of them CORS-open. Directly bolt-on-able to the existing iptools card.
- **Anonymise-on-write.** IPv4 -> /16, IPv6 -> /32, reverse name -> last 3 labels + `[…]`. Nine lines of Go, and it makes a Mongo lookup-history collection defensible.
- **Poll shape.** `GET /<tool>/probes/<target>/` returning `[{name, done, success}]`, every 3 s, capped at 64 tries. That is an htmx `hx-trigger="every 3s"` swap w/ an `HX-Refresh`/redirect when all are done, no WebSocket.
- **Cooldown as the rate limiter.** A visible "seconds until retest" countdown on the result page is friendlier & simpler than a 429, and it doubles as cache-hit messaging.
- **Permalink + timestamp + rerun link.** Report at `/site/<domain>/<id>/`, stamped in UTC, w/ a rerun link that creates a *new* id. Makes results citable & diffable, and it is already how the iptools Mongo history could be surfaced.
- **Explanation blocks that name the source.** Each check cites the exact guideline/RFC paragraph & often a "Deployment recommendation". Costs nothing but prose & is why this thing gets cited in policy documents.

## Gaps & what it does not do

Not a DNS lookup tool at all: **no arbitrary RR-type queries, no resolver selection, no authoritative-NS querying, no delegation trace, no TTL shown anywhere, no raw output, no propagation/consistency check across the NS set, no zone-transfer or serial-consistency checks** (intoDNS's territory), **no DNSSEC chain visualisation** (DNSViz's), no reverse/PTR lookup as a user feature, no passive DNS, no history/timeline for free users, no blocklist/reputation data, no monitoring or alerting without a dashboard account. No JSON & no CORS on the free path. DKIM is existence-only (no selector, no key evaluation). Web DANE is scored **Optional/Recommended only**, so a 100% web score says nothing about DANE. TLS is measured against only the first IPv6 + first IPv4 address & at most 10 MX. Norms are .nl-inflected (the ≥2-nameservers rule cites SIDN's registration requirements). Explicitly "not a monitoring tool" per the terms of use.

## Verified firsthand vs inferred

- **Verified:** HTTP 200 + headers + v1.11.3; a complete website test run from POST through polling to permalink, incl. the probes JSON payload; two live 100% reports read in full (website & mail) w/ their subtest names, requirement levels, verdicts & technical tables; batch API **401 + Basic-auth realm** (re-confirmed 2026-09-16); no CORS headers; `Accept: application/json` returns HTML; Hall of Fame counts (4,553 double-100%, 39,778 web-only) re-checked live 2026-09-16; `ipv6.internet.nl` AAAA-only; `internet.nl` DNSSEC-signed (alg 13, AD bit set via 1.1.1.1), NS = `ns1/ns2.sidn.nl` + `ns1/ns2.sidnlabs.nl`, `_443._tcp.internet.nl` CNAME-chained to `le-intermediate._dane.internet.nl` w/ a `2 1 1` TLSA; the qname-min zone (re-dig'd via 8.8.8.8 & 1.1.1.1, still returns HOORAY); Team Cymru & RIPE RPKI endpoints; the 38/38 web/mail subtest counts, hand-recounted class-by-class from the raw `checks/categories.py` (not a summariser — a first pass with an LLM-summarised fetch misread `MailTls` as 18 instead of 19, which is why this was re-done by direct grep/sed); the batch fair-use table (2/week, 5,000 domains, 3 accounts, 12-month idle deletion, single-domain & third-party-frontend bans) word-for-word against `terms-of-use.md`; the batch API's 7 endpoints & `POST /requests` body shape against `openapi.yaml`; Apache-2.0 + CC-BY-4.0 dual licensing against the repo's own `README.md` §License and `LICENSE-Apache-2.0.txt`/`LICENSE-CC-BY-4.0.txt` files; the 200 s retest cooldown as `INTERNETNL_CACHE_TTL=200` in `.env.dist`; RPKI's Team-Cymru-for-routes / Routinator-for-validity split, incl. the `rpki-validator.ripe.net` example, against `documentation/rpki.md`; the connection test's 6 report items and its `anonymize_IP` (/16 v4, /32 v6) & `anonymize_reverse_name` (last 3 labels) functions, read (not executed) from `interface/views/connection.py`; the CD/non-CD dual-resolver mechanism & issue-1869 reference in `checks/resolver.py`; all source quoted from `main`.
- **Inferred / read-only:** the connection test's live *behaviour* (structure read from `interface/views/connection.py`, **not executed** — it needs a browser and I did not drive one); batch API response *bodies* (schema read from `openapi.yaml`, no account to see a real response); dashboard features (from its README, not the live SPA, which needs JS); "widely used... in EU procurement" remains unconfirmed beyond the four named re-users on `/faqs/measurements/`.
- **Correction to the brief:** **qname minimisation is not a graded subtest.** Internet.nl *hosts* the test zone, and it works: `dig +short TXT a.b.qnamemin-test.internet.nl` returned `"HOORAY - QNAME minimisation is enabled on your resolver :)!"` via 8.8.8.8, 1.1.1.1, 9.9.9.9 and my system resolver (`qnamemin-test.internet.nl` is delegated to `ns.qnamemin-test.internet.nl`). But the integration issue, *"Integrate QNAME minimisation test in connection-test"*, is **still open and parked in the "icebox" milestone since 2016**, and no qname check appears in `categories.py` or the connection-test view. Known caveat w/ the technique: an upstream non-qmin forwarder can cache & replay the HOORAY answer, producing a false positive.
- **Unverified claim from the brief:** "widely used as the neutral scorecard in EU procurement". What I can confirm is the *measurements* page listing the **European Commission's EU Internet Standards Deployment Monitoring Website**, the Netherlands Standardisation Forum's compliance measurement, Statistics Netherlands (CBS), and Internet Society Portugal as re-users. Procurement specifically: not confirmed.

## Open source / reusable

`github.com/internetstandards/Internet.nl` — **Apache-2.0**, Python/Django, "Internet standards compliance test suite". Name & logo excluded from the licence. Worth reading, in order of payoff for this project: `checks/categories.py` (the subtest/category taxonomy & requirement levels), `documentation/scoring.md` (the scoring rules, 35 lines, the most transferable thing in the repo), `checks/resolver.py` (CD vs non-CD resolver pair, `dns_check_ns_connectivity`, `dns_climb_tree`), `interface/views/connection.py` (callback-based resolver probing + `anonymize_IP` / `anonymize_reverse_name` + Team Cymru AS lookup), `documentation/rpki.md`, `interface/batch/openapi.yaml`. Companion repos: `internetstandards/Internet.nl-dashboard`, `internetstandards/Internet.nl-API-docs`, `internetstandards/toolbox-wiki` (CC BY 4.0 how-tos, incl. a DANE-for-SMTP guide). Upstream building blocks they lean on & you could too: **Unbound/libunbound**, **nassl**, **Routinator**.

## Sources

- [Internet.nl](https://internet.nl) — live service; website / email / connection tests
- [Internet.nl — About](https://internet.nl/about/) — Dutch Internet Standards Platform, partner list, funding
- [Internet.nl — Explanation of test report](https://internet.nl/faqs/report/) — REQUIRED/RECOMMENDED/OPTIONAL levels, status icons, percentage calculation
- [Internet.nl — Batch API and web-based dashboard](https://internet.nl/faqs/batch-and-dashboard/) — batch/dashboard entry point
- [Internet.nl API & Dashboard terms of use (v20250118)](https://github.com/internetstandards/Internet.nl-API-docs/blob/main/terms-of-use.md) — fair-use limits
- [internetstandards/Internet.nl (Apache-2.0)](https://github.com/internetstandards/Internet.nl) — source, scope, building blocks, licence
- [`documentation/scoring.md`](https://github.com/internetstandards/Internet.nl/blob/main/documentation/scoring.md) — category weighting & qualifying-subtest rules
- [`documentation/rpki.md`](https://github.com/internetstandards/Internet.nl/blob/main/documentation/rpki.md) — Team Cymru + Routinator backends, RFC 6811 status mapping
- [`checks/categories.py`](https://github.com/internetstandards/Internet.nl/blob/main/checks/categories.py) — full category/subtest taxonomy
- [`checks/resolver.py`](https://github.com/internetstandards/Internet.nl/blob/main/checks/resolver.py) — CD/non-CD resolvers, `dns_check_ns_connectivity`
- [`interface/views/connection.py`](https://github.com/internetstandards/Internet.nl/blob/main/interface/views/connection.py) — connection-test callbacks, anonymisation, ASN lookup
- [`interface/batch/openapi.yaml`](https://github.com/internetstandards/Internet.nl/blob/main/interface/batch/openapi.yaml) — batch API v2 endpoints & schemas
- [internetstandards/Internet.nl-dashboard](https://github.com/internetstandards/Internet.nl-dashboard) — dashboard feature list
- [Issue #139 — Integrate QNAME minimisation test in connection-test](https://github.com/NLnetLabs/Internet.nl/issues/139) — still open, "icebox" milestone
- [RFC 6811 — BGP Prefix Origin Validation](https://datatracker.ietf.org/doc/html/rfc6811#section-2) — valid / invalid / not-found definitions
- [Team Cymru IP-to-ASN mapping](https://team-cymru.com/community-services/ip-asn-mapping/) — key-less DNS ASN lookup used by the RPKI & connection tests
- [Routinator (NLnet Labs)](https://www.nlnetlabs.nl/projects/rpki/routinator/) — RPKI relying party behind the ROA validity checks
- [`.env.dist`](https://github.com/internetstandards/Internet.nl/blob/main/.env.dist) — `INTERNETNL_CACHE_TTL=200` default, confirms the retest-cooldown constant
- [`interface/views/shared.py`](https://github.com/internetstandards/Internet.nl/blob/main/interface/views/shared.py) — `get_retest_time()` computed from `settings.CACHE_TTL`
- [`README.md`](https://github.com/internetstandards/Internet.nl/blob/main/README.md) — §License: Apache-2.0 for the codebase, CC BY 4.0 for `/translations`
- [Internet.nl Hall of Fame](https://internet.nl/halloffame/) — live champions (double-100%) count
