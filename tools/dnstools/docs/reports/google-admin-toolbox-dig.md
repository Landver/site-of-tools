# Google Admin Toolbox Dig & dns.google

Two *separate* Google DNS front-ends that people routinely conflate. **toolbox.googleapps.com/apps/dig** = Workspace-admin troubleshooting tool, server-side resolver, `dig`-style raw + parsed output. **dns.google** = the Google Public DNS (8.8.8.8) web surface, a 63-line JS form over a **free, keyless, CORS-open JSON DoH API** at `dns.google/resolve`. For a small Go+htmx DNS tool the second is the more important artifact: `/resolve` is a production-grade upstream you can call from a Go handler *or* straight from the browser, and the `/query` page is a working reference for how thin a UI over it can be.

- **URL:** https://toolbox.googleapps.com/apps/dig/ · https://dns.google/ · https://dns.google/resolve · **Category:** free public resolver + two free web lookup UIs · **Registration:** none, no account, no API key, no quota signup (checked 2026-09-16) · **Pricing:** $0, no paid tier exists · **API:** yes, `GET /resolve` (JSON) + `GET|POST /dns-query` (RFC 8484 wire) + an undocumented `GET` on Toolbox Dig's own `lookup`.
- **Firsthand check:** ~90 `curl` calls + `dig @8.8.8.8` from macOS, re-run 2026-09-16. Confirmed live: JSON schema incl. undocumented `Authority`/`extended_dns_errors`, `access-control-allow-origin: *`, `cache-control: private, max-age=300`, `do`/`cd`/`ct`/`edns_client_subnet`/`random_padding` behaviour, 400 error bodies, RFC 8484 base64url GET, `alt-svc: h3`, per-endpoint HTTP-method behaviour, DoT socket on `dns.google:853`. Pulled and read `/static/.../query.js` + `constants.js` (unminified) and `apps/dig/js/dig_prod.js` (minified, re-read this pass). Reproduced Toolbox Dig's backend call both ways: `POST .../apps/dig/lookup` w/ CSRF token **and** a bare `GET .../apps/dig/lookup?domain=&typ=` w/ no token at all, both returning the same JSON. Also captured the sibling **Check MX** report page. Not verified: rendered pixels (no browser was used, all UI claims come from HTML/JS read as text, and I say so inline).

## What it is

**Admin Toolbox Dig** is one of **11** tools under Google Admin Toolbox (nav captured verbatim: Browserinfo, Check MX, Dig, HAR Analyzer, Log Analyzer, Log Analyzer 2, Messageheader, Useragent, Additional Tools, Encode/Decode, Screen Recorder), pitched as "a web-based equivalent of the Unix dig command" for Workspace admins debugging mail/DNS. Django-style backend (`csrfmiddlewaretoken`, `403 Forbidden` on a tokenless **POST**), output text is dnspython `Message.to_text()` format.

**dns.google** is Google Public DNS's own site: a one-field landing page (`/`, a `GET` form straight into `/query`), a query page (`/query`), a cache-flush page (`/cache`), and the DoH endpoints. The resolver behind it is the anycast `8.8.8.8` / `8.8.4.4` / `2001:4860:4860::8888` / `::8844` service, plus **DoT on `dns.google:853`** (TCP 853 opened w/ a valid `CN=dns.google` cert in my test; TLS 1.2/1.3, forward-secret AEAD suites only per docs) and DNS64 on `2001:4860:4860::64` and `::6464` (docs-only, this host has no IPv6 egress so the DNS64 query timed out).

## Registration, access & pricing

Free, anonymous, no key, no Terms click-through. FAQ: client IP "only logged temporarily (erased within a day or two)", ISP + city/metro kept longer, never joined to a Google account. No blocking or filtering "except for certain domains in rare cases". NXDOMAIN is returned honestly, no ad hijacking. Cache flush is the only gated action, and it is gated by **reCAPTCHA** (sitekey `6LdkpLIZAAAAAN3z1J1rvLUEsNX9d-4QvrvXWhC3` in the page HTML), not by domain ownership.

## Features — complete inventory

### A. `dns.google/resolve` — JSON DoH API (the reusable asset)

| Feature | Detail (observed unless noted) |
|---|---|
| Single endpoint | `GET https://dns.google/resolve?name=&type=` |
| Keyless + CORS | `access-control-allow-origin: *` returned when an `Origin` header is present. Simple GET, no preflight needed. Browser-callable from any origin. |
| HTTP caching | `cache-control: private, max-age=300`, `vary: Accept-Encoding`, `x-content-type-options: nosniff`, HSTS preload, `alt-svc: h3=":443"` |
| Methods | Docs say "All API calls are HTTP GET requests", and the DoH page promises HEAD → 400, other verbs → 501. That **only holds on `/dns-query`** (verified: HEAD 400, PUT/DELETE/PATCH 501). On `/resolve` every verb I tried, `POST` `HEAD` `PUT` `DELETE` `PATCH`, returned **200** w/ a normal JSON answer. Treat the method leniency as undocumented, not contractual. |
| Rcode + flags | `Status` (int rcode), `TC`, `RD`, `RA`, `AD` (DNSSEC-validated), `CD` |
| Sections | `Question[]`, `Answer[]`, **`Authority[]`** and `Additional[]` — the latter two are *undocumented* on the JSON reference page but returned live (SOA in `Authority` on NXDOMAIN/NODATA) |
| Record shape | `{name, type (int), TTL, data}` — `data` is presentation-format rdata, incl. RRSIG blobs and SVCB/HTTPS param strings |
| `Comment` | Free-text diagnostics. Two flavours seen: **`"Response from 172.64.32.162."`** (which authoritative NS actually answered — a genuinely rare and useful leak) and DNSSEC failure text w/ **links to dnsviz.net and Verisign's DNSSEC debugger** |
| **`extended_dns_errors[]`** | Returned live: `[{"info_code":9,"extra_text":"No DNSKEY matches DS RRs of dnssec-failed.org"}]` — RFC 8914 EDE surfaced as JSON. The **field name** appears in none of the API pages (0 hits for `extended_dns_errors` across the JSON, DoH, security and troubleshooting pages), but Google *does* document the EDE **codes** themselves at length on the Domain Troubleshooting page (33 mentions of EDE, incl. 9 / 22 / 23) |
| `edns_client_subnet` echo | Response echoes the scope actually used, e.g. `"8.8.8.0/24"` or `"0.0.0.0/0"` |
| Errors | HTTP 400 + Google's HTML error page w/ a precise reason string: `Invalid query type: ‘NOTATYPE’.`, `Query must have a non-empty ‘name’ parameter.`, `Invalid query name: ‘..’`. Note the **typographic quotes** (U+2018/U+2019), not ASCII, if you ever regex them. Not JSON — a JSON client must special-case a `text/html` 400. Docs add **429 + `Retry-After`** under rate limiting; never observed. |

### B. `/resolve` query parameters

| Param | Values | Effect |
|---|---|---|
| `name` | 1–253 chars, labels 1–63 bytes, punycode required, RFC 4343 backslash escapes accepted | required |
| `type` | int `1..65535` or canonical string, case-insensitive; default `1` | verified: `65`, `99`, `65535` all 200; `0` and `65536` → 400. `ANY`/`255` is accepted but useless on modern authoritatives: `example.com/ANY` came back as the RFC 8482 minimal answer, a single `HINFO "RFC8482"` |
| `cd` | `1`/`true`/`0`/`false` | checking disabled. Verified: `dnssec-failed.org` → `Status:2` + EDE; `&cd=1` → `Status:0` + the A record |
| `do` | `1`/`true` | DNSSEC OK. Verified: `cloudflare.com&do=1` returns the RRSIG (type 46) alongside the A records |
| `ct` | `application/dns-message` \| `application/x-javascript` | content negotiation on the *same* endpoint. Verified: `ct=application/dns-message` returned 72 bytes of wire format |
| `edns_client_subnet` | `1.2.3.4/24`, `2001:700:300::/48`, or `0.0.0.0/0` to opt out | verified both directions |
| `random_padding` | ignored | pad all requests to constant length so on-path observers can't size-fingerprint the query |

### C. `dns.google/dns-query` — RFC 8484 wire, and DoT

`GET ?dns=<base64url DNS message>` and `POST` w/ `Content-Type: application/dns-message`. Verified: GET w/ a base64url query returned 65 bytes `application/dns-message` + `access-control-allow-origin: *` + the same `private, max-age=300`. Max DNS message 512 bytes per docs (not reproduced). This endpoint *does* enforce the documented method rules (HEAD 400, PUT/DELETE/PATCH 501).

**DoT** is the third transport: `dns.google:853`, TLS 1.2/1.3. I opened the socket and got a valid `CN=dns.google` certificate; my LibreSSL `openssl` did not negotiate the `dot` ALPN, so ALPN behaviour is unconfirmed. Docs describe the encrypted service as running "over HTTPS and QUIC", so the `alt-svc: h3=":443"` header I saw is consistent w/ documented HTTP/3 support, but the local `curl` 8.7.1 has no `--http3`, so **no h3 request was ever made**.

### D. `dns.google/query` — the web UI

Form fields: **DNS Name** · **RR Type** (free-text `<input list>` backed by a 34-entry `<datalist>`) · **EDNS Client Subnet** · switch *Disable DNSSEC validation* · switch *Show DNSSEC detail*. Mapping verified by reading the emitted permalink: `show_dnssec=true` → `do=true`, `disable_dnssec=true` → `cd=true`, `ecs=` → `edns_client_subnet=`, default `rr_type=A`.

- **IP literal auto-detect -> PTR.** Verified both directions: `?name=1.2.3.4` is rewritten server-side to `4.3.2.1.in-addr.arpa`/`PTR`, and `?name=2001:4860:4860::8888` to the full 32-nibble `8.8.8.8.0.0…0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa`. The heading, the form field's `value=` **and** the API permalink all carry the rewritten name, so the page never hides what it actually asked.
- **Self-describing heading.** One `<h2>` states name/type + both DNSSEC toggle states in words, so a screenshot is self-documenting.
- **API permalink under every result:** *"You may also resolve directly at: https://dns.google/resolve?name=…&type=A"*, rendered as a real link.
- **Shareable state in the URL:** `/query` is a plain `GET` form, so every result is a bookmarkable URL.

### E. `dns.google/cache` — cache flush

`POST /cache` w/ `name` + `rr_type` (28-entry datalist, a subset of the query page's 34 — drops six: `ALL`, **`CAA`**, `CERT`, `KEY`, `SIG`, `WKS`), gated by reCAPTCHA. No ownership proof needed. FAQ caveat: ECS-enabled records **cannot** be flushed.

### F. Admin Toolbox Dig

- **17 one-click RR-type buttons**, no dropdown: `A AAAA ANY CAA CNAME DNSKEY DS HTTPS MX NS PTR SOA SRV SVCB TLSA TSIG TXT`. Single domain text field. No resolver picker, no DNSSEC toggle, no ECS field.
- **Dual view**: a parsed table (`#response-table`) plus a **Raw View** toggle (`#raw_switch`, hidden until a response lands) revealing the literal dnspython dump. Reproduced for `example.com/MX`: `id 45579\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\n;QUESTION\nexample.com. IN MX\n;ANSWER\nexample.com. 156 IN MX 0 .\n;AUTHORITY\n;ADDITIONAL`. Before display the JS wraps the `;ANSWER`-to-`;AUTHORITY` span in `%%…%%` markers, presumably for highlighting.
- **Hash permalink**: `Va()` sets `window.location.hash = "<TYPE>/<domain>"`, and `Wa()` reads it back on load. So `https://toolbox.googleapps.com/apps/dig/#MX/example.com` is a shareable, restorable query. Zero server state.
- **Field decoration in the parsed table** (re-read from `dig_prod.js` this pass, still never seen rendered): `ttl`/`original_ttl` run through a `d/h/m/s` humanizer (`"1 hour 5 minutes"`); RRSIG `inception`/`expiration` regexed from `YYYYMMDDHHMMSS` into `HH:MM:SS MM/DD/YYYY` then `new Date(...)` — which parses as **local** time while DNS timestamps are UTC, so the displayed offset is probably wrong (inference from the source, not observed); `digest_type` mapped via `{0:Reserved,1:SHA-1,2:SHA-256,3:GOST,4:SHA-384}` w/ an `Unassigned` fallback above 4; DNSKEY `flags` labelled KSK/ZSK; SOA handled by **appending** a `|`-delimited 7-field copy to the raw rdata (`mname,rname,serial` verbatim + **four** humanized timers: refresh, retry, expire, minimum) for the template to split, not by replacing it; multi-string TXT joined and re-quoted; every key uppercased w/ `_`→space; DNSKEY `algorithm` arrives already decoded server-side as `ECDSAP256SHA256`.
- **Cancellable requests + a blunt empty state**: `AbortController` on the in-flight `fetch("lookup")`, a `LOOKING_UP` placeholder and timeout-driven error codes (`err2`…`errB - server side error`); if `json_response.ANSWER` is empty the table is cleared and the error region gets a literal `<b>Record not found!</b>`, even on a NOERROR/NODATA where the raw view plainly shows a SOA. Source-read only.
- **Undocumented keyless JSON API.** A bare `GET https://toolbox.googleapps.com/apps/dig/lookup?domain=example.com&typ=MX` returns the same `{error_html, response, json_response}` payload, **200, no CSRF token, no cookie, no referer**. It is the only other free keyless DNS JSON endpoint found here, but: no `access-control-allow-origin` (so not browser-callable cross-origin, unlike `/resolve`), `cache-control: private`, it sets a `wt_sessionid` cookie, and an **unknown `typ` silently falls back to `ANY`** rather than erroring (`typ=NOTATYPE` came back as an RFC 8482 HINFO answer). Undocumented and unsupported: fine to study, a bad idea to depend on.

### G. Check MX (sibling tool, same toolbox, directly relevant to a DNS audit feature)

`GET /apps/checkmx/check?domain=<d>` returns a fully server-rendered, shareable report, no token needed (a tokenless **POST** to the same path is the thing that 403s; omitting `domain` 302s back to the form). Optional **DKIM selector** input. Re-captured firsthand for `iana.org` on 2026-09-16: **15 checks** in three severity tiers (2 `error`, 4 `warning`, 9 `done`), each failing check carrying a "Help center article" link and the offending record inline:

`SPF must allow Google servers…` (shows `Decision: SPF fail - not authorized` + `Record: v=spf1 redirect=icann.org`) · `Domain must have at least one mail server` · `DKIM is not set up` · `DMARC is not set up` · `MTA-STS DNS Record` (RFC 8461, `_mta-sts.<d>` TXT) · `No Google mail exchangers found. Relayhost configuration?` · `Domain should have at least 2 NS servers` · `Naked domain must be an A record (not CNAME)` · **`Every name server must reply with exactly the same …`** × 7 (TXT DKIM, TXT DMARC, TXT MTA-STS, CNAME, NS, MX, TXT).

That family of seven is the distinctive mechanic: the label says Check MX queries **each authoritative NS individually** and diffs the answers, catching split-brain zones that any single-resolver lookup silently hides. The labels and per-check verdicts are what I captured; the internal query pattern is Google's description, not something I watched happen. `?domain=google.com` is refused w/ *"This domain is not allowed. This domain is configured just fine. No need to check it."* — a hard-coded carve-out, i.e. an abuse control, not a check result.

## Record types & query options supported

| | dns.google `/query` (34) | `/cache` (28) | Toolbox Dig (17) |
|---|---|---|---|
| list | A AAAA ALL CAA CDNSKEY CDS CERT CNAME DNAME DNSKEY DS HINFO HTTPS INTEGRITY IPSECKEY KEY MX NAPTR NS NSEC NSEC3 NSEC3PARAM PTR RP RRSIG SIG SOA SPF SRV SSHFP SVCB TLSA TXT WKS | same minus ALL, CAA, CERT, KEY, SIG, WKS | A AAAA ANY CAA CNAME DNSKEY DS HTTPS MX NS PTR SOA SRV SVCB TLSA TSIG TXT |

`INTEGRITY` in the datalist is the non-IANA experimental type; the datalist is advisory only, the field is free text and `/resolve` accepts **any** numeric type 1–65535.

**Knobs present:** DNSSEC `do` + `cd`, ECS (set or opt out), JSON vs wire content negotiation, query padding, raw-vs-parsed view (Toolbox), TTL displayed always. **Knobs absent everywhere:** no resolver picker (you always get Google's recursive view), no "query the authoritative NS directly", no `+trace` delegation walk, no TCP-vs-UDP choice, no per-query EDNS buffer size, no `+short`.

## How it works

Two different architectures, and the contrast is the lesson.

**dns.google/query is client-side.** The server returns a static shell whose `<pre id="results">` is empty; an inline CSP-nonce'd script calls `resolve(url)` from `query.js` w/ the absolute public URL (`resolve('https://dns.google/resolve?name=…')`), and `resolve()` does `fetch(url, {credentials:'omit'}).then(r=>r.json())` against the *same public* API you can call yourself. Confirmed by fetching the page HTML and the unminified JS. The whole of `query.js` is **63 lines / 1,868 bytes**: a 33-line recursive `stringifyResponse()` that pretty-prints the JSON and **injects decoded values as JS comments**: `"Status": 0 /* NOERROR */` and `"type": 1 /* A */`, using `rcodeToString` / `rrTypeToString` from a 2,149-byte `constants.js` (61 `case` labels across the two switches). Output goes to `innerText`, never `innerHTML`, so untrusted rdata can't inject markup. That is the entire UI. No templating of records, no table.

**Toolbox Dig is server-side.** `dig_prod.js` builds a `FormData` from `#dig-form` (domain, typ, CSRF) and `fetch("lookup", {method:"POST"})`. The backend resolves and returns `{"error_html":…, "response": <dig text>, "json_response": {id, opcode, rcode, flags, is_update, QUESTION:[{type}], ANSWER:[{type, answer:[…parsed rdata…]}]}}`. Reproduced end-to-end w/ curl. Note the asymmetry: **`json_response` carries only QUESTION + ANSWER**, so on an NXDOMAIN the SOA is visible in Raw View but absent from the table, and `QUESTION` drops the queried name entirely.

Resolution itself: Google Public DNS is anycast, validates DNSSEC on all signed zones unless `CD` is set (SERVFAIL on failure), caches NSEC per RFC 8198 (docs-only), and forwards **24 bits of IPv4 / 56 bits of IPv6** as ECS by default so authoritatives can geo-target. Probing `dig @8.8.8.8 -t TXT o-o.myaddr.l.google.com` returns two TXT strings: the `edns0-client-subnet` /24 it forwarded for me, and the Google egress IP that reached the authoritative. `version.bind`/`hostname.bind` CH TXT return nothing. EDNS UDP buffer advertised **in its replies to my `dig`: 512**; separately, the docs say its **outbound** queries cap the buffer at **1400** since DNS Flag Day 2020, and tell you to emulate that w/ `dig +bufsize=1400` when testing your own authoritatives.

## Output & UX

`dns.google/query`: server-rendered form + heading, then one async `fetch` that dumps annotated JSON into a `<pre>`. No table, no color, no per-record chrome, no export button (you copy the `<pre>` or follow the `/resolve` permalink). Empty/NXDOMAIN states are just the JSON; `fetch` failures print the raw `error` object into the same `<pre>`. Static assets are content-hash-pathed for infinite cacheability. Toolbox Dig: MDL cards, RR-type button row, a parsed table w/ decorated fields, a Raw View switch, an error region fed from the backend's `error_html`, and a spinner/timeout state machine, w/ result state in `location.hash` so back/forward works. Check MX is the opposite again, fully server-rendered w/ severity icons and help links, and its `?domain=` URL is directly shareable.

## Monetization, limits & abuse controls

No money anywhere. Limits (checked 2026-09-16):

- **Per-client-IP QPS.** The ISP doc's threshold for unrestricted use is **"less than 1500 QPS"** per IPv4 address or IPv6 /64 (verified wording; above that you reduce rates or request an increase, and CG-NAT ISPs are called out as likely to get throttled). The security doc adds per-client query **and** bandwidth caps plus a "per-client-IP maximum average amplification factor", explicitly says the thresholds are configurable from historical traffic and publishes **no numbers**. The DoH doc lists **HTTP 429** w/ `Retry-After`. Empirically, back-to-back `/resolve` GETs from one residential IP: 40 × 200 on the first pass, 20 × 200 on re-check. No throttling, no 429, i.e. the caps were never approached, not proven absent.
- **Abuse defenses:** overprovisioning, response-validity and nameserver-credibility checks, ~15 bits of port randomization (~32k ports), 64-bit DNS cookies (RFC 7873), 0x20 case randomization (nameservers handling >70% of outbound traffic), nonce labels (<3% of outgoing requests), and never more than one outstanding request per query name.
- **Cache flush:** reCAPTCHA-gated, ECS-backed records exempt (docs suggest TTLs ≤15 min instead).
- **Toolbox:** CSRF token required on **POST** (bare POST to both `dig/lookup` and `checkmx/check` → 403; I did not attempt to work around it), but the `GET` forms of both are open, so the token is not really an access control. Plus the hard-coded domain carve-out on Check MX.
- **HTTP caching:** `private, max-age=300` on `/resolve`, so an intermediary won't share your answers.

## Ideas worth stealing

- **Make the result page a thin client over your own JSON, and print the API URL under the result.** Google's UI is literally `fetch('/resolve?…')` + pretty-print. That is exactly the CLAUDE.md rule #2 shape: one domain call, HTML for browsers, JSON for everyone, and a visible `https://dns.corpberry.com/resolve?name=…&type=MX` link under the answer that teaches the API for free. Cheapest possible API documentation.
- **Annotate integers inline instead of hiding them.** `"Status": 0 /* NOERROR */`, `"type": 1 /* A */`. In Go this is a 40-line rcode/rrtype map, and it makes the raw JSON view readable without a second table. Go's `golang.org/x/net/dns/dnsmessage` already has the type constants.
- **`location.hash` (or a plain GET path) as the only state store.** `#MX/example.com` restores the form and the query w/ zero server session. For htmx, `/lookup/MX/example.com` as a real route w/ `hx-push-url` gets the same shareability plus server rendering.
- **IP literal auto-detect -> reverse PTR, and say so in the heading.** Typing `8.8.8.8` into a "DNS name" box and getting `8.8.8.8.in-addr.arpa/PTR` back, with the heading spelling out the rewrite, removes the single most common "how do I do a reverse lookup" question. Trivial in Go: `netip.ParseAddr` then build `in-addr.arpa`/`ip6.arpa`.
- **Dual raw/parsed view behind one switch.** Keep the honest `dig`-format text (`;QUESTION / ;ANSWER / ;AUTHORITY / ;ADDITIONAL`) *and* a decorated table from the same response. Power users copy the raw block into a bug report; everyone else reads the table. One htmx swap, no re-query.
- **Decorate rdata instead of printing it.** Humanize TTL to `1 hour 5 minutes`; split SOA's 7 fields into labelled rows w/ refresh/retry/expire/minimum humanized; decode DNSKEY flags to KSK/ZSK (**getting the polarity right**, see below); map DS `digest_type` and DNSSEC algorithm numbers to names; parse RRSIG `inception`/`expiration` **as UTC** and flag expiry. This is where a hobby tool beats `dig` and it is all pure-Go table lookups in the domain package.
- **Surface RFC 8914 Extended DNS Errors, and link out on failure.** `extended_dns_errors[{info_code, extra_text}]` turns a bare SERVFAIL into "No DNSKEY matches DS RRs of …". Almost no consumer DNS tool shows this. Free via `/resolve`; if you resolve yourself, `miekg/dns` exposes `dns.EDNS0_EDE`. Pair it w/ Google's own trick of shipping dnsviz.net and Verisign-debugger deep links in the failure `Comment`.
- **Expose "which authoritative answered".** `/resolve`'s `Comment: "Response from 2400:cb00:2049:1::a29f:21."` is a differentiator almost nobody surfaces. If you resolve in-process you know this for free.
- **Per-NS consistency diff (Check MX's best idea).** Query every NS in the delegation separately and diff the MX/NS/TXT/CNAME answers. Catches split-brain and mid-migration zones that a single resolver hides, and it is a natural pure-Go domain function returning `map[nsName][]record` + a diff struct. Google's own Domain Troubleshooting page prescribes exactly this by hand ("repeating the same queries at all authoritative servers"), along w/ `+bufsize=1400` size/timeout checks and a cross-resolver comparison against Cloudflare/Quad9/OpenDNS. That page doubles as a free spec for an automated audit feature, and it carries the EDE code catalogue to render alongside `info_code`.
- **Severity-tiered audit list that shows the passes too.** Check MX renders `error` / `warning` / `done` rows in one list w/ a help link per failure. Showing the green rows is what makes it feel like an audit rather than an error dump.
- **Content-hashed static asset paths** (`/static/78114068/query.js`), trivial w/ `go:embed` + a build-time hash.

## Gaps & what it does not do

No propagation check across public resolvers. No delegation trace / `+trace`. No choosing the resolver or querying an authoritative NS directly (Toolbox Dig has no NS field at all). No DNSSEC **chain** visualization, just the raw RRSIG/DS records. No WHOIS/RDAP, no registrar or expiry data. No TTL-vs-time or history. No monitoring, alerting or diffing over time. No bulk/batch lookups. No export (CSV/JSON download button, permalinks aside). No rate-limit headers to program against. Toolbox Dig drops AUTHORITY/ADDITIONAL from its parsed view. `/resolve` returns **HTML** on a 400, which every JSON client has to special-case. And nothing here is a health audit except Check MX, which is scoped to mail and hard-refuses some domains.

## Verified firsthand vs inferred

**Verified by curl/dig/openssl (all re-run 2026-09-16):** every `/resolve` param and response field listed above incl. `Authority` and `extended_dns_errors`; `access-control-allow-origin: *`; `cache-control: private, max-age=300`; `alt-svc: h3=":443"`; the method split (GET/POST/HEAD/PUT/DELETE/PATCH → 200 on `/resolve`, HEAD → 400 and PUT/DELETE/PATCH → 501 on `/dns-query`); numeric type bounds 1–65535; the `ANY` → RFC 8482 HINFO answer; the 400 error strings incl. their curly quotes; RFC 8484 base64url GET; `/query` parameter mapping and both IPv4 and IPv6 →PTR rewrites (from the emitted permalink, form value and heading); the 34- and 28-entry RR-type datalists character for character; `/cache` form + reCAPTCHA sitekey; Toolbox Dig's 17 type buttons, its `lookup` contract over **both POST-w/-CSRF and bare GET**, and real JSON for MX / bad-type / NODATA; Check MX's 15 checks in 2/4/9 tiers and the `google.com` refusal; 40/40 then 20/20 HTTP 200 under small bursts; `o-o.myaddr.l.google.com` ECS echo; TCP 853 open w/ a `CN=dns.google` cert.

**Read from source, not seen rendered:** every claim about the *visual* table — TTL humanization, the SOA field append, RRSIG date parsing, the `digest_type` map, KSK/ZSK labels, "Record not found!", the `%%` raw-view markers, the `AbortController` + timeout states — comes from reading minified `dig_prod.js` and unminified `query.js`/`constants.js`. No browser was used, so the DOM these functions produce was never seen.

**Likely bugs, flagged as inference, not confirmed on screen:** (1) `dig_prod.js` contains `f[h]==="256" ? "("+f[h]+") KSK" : "("+f[h]+") ZSK"`. Per RFC 4034 §2.1.1 that is inverted: flags `256` is a ZSK and `257` (Zone Key + SEP) is the KSK; a live `cloudflare.com/DNSKEY` pull returns both values, so the table should mislabel both. (2) RRSIG times are reformatted to `HH:MM:SS MM/DD/YYYY` and handed to `new Date()`, which V8 reads as local time though the wire value is UTC.

**Docs-only, not reproduced:** the 1500 QPS threshold, the amplification-factor and bandwidth caps, 429/`Retry-After`, log retention ("erased within a day or two"), RFC 8198 NSEC caching, the 1400-byte outbound buffer, the 512-byte DoH message ceiling, the DNS64 addresses (no IPv6 egress here, the query timed out), the DoT TLS-version/cipher policy, and Check MX's internal per-NS query pattern beyond the labels captured. **HTTP/3**: documented in prose ("over HTTPS and QUIC") and advertised via `alt-svc`, but the local `curl` has no `--http3`, so no h3 request was made. **`extended_dns_errors`**: the field name appears in none of the API pages, though the EDE codes it carries are documented on the troubleshooting page. Treat the field as stable-in-practice but uncontracted. Serving-location counts were still not found in any page read; the ISP page covers peering (via peering.google.com) but publishes no location list.

## Open source / reusable

Nothing here is open source, but three files are readable verbatim and small enough to reimplement in an afternoon:

- `https://dns.google/static/a9f8d71f/constants.js` (2,149 bytes, 84 lines, 61 `case` labels) — complete `rcodeToString` + `rrTypeToString` switch tables. Straight port to a Go `map[uint16]string`.
- `https://dns.google/static/78114068/query.js` (1,868 bytes, 63 lines) — the annotated-JSON pretty-printer, no dependencies.
- `https://toolbox.googleapps.com/apps/dig/js/dig_prod.js` (17,281 bytes) — minified but readable; the rdata-decoration logic (TTL, SOA, RRSIG, DNSKEY, digest types) is the interesting part.

For actually resolving in Go, the real reusable pieces are elsewhere: `github.com/miekg/dns` (full client, EDNS0, EDE, DNSSEC) or stdlib-adjacent `golang.org/x/net/dns/dnsmessage` for wire parsing. `/resolve` is a legitimate zero-dependency upstream if you want no UDP egress from the container, which matters given the same Hetzner-egress caution that shelved the iptools port scanner.

## Sources

- [Google Public DNS — DoH JSON API reference (parameters, response fields, name/type limits)](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google Public DNS — DNS-over-HTTPS overview (endpoints, methods, 429, 512-byte limit)](https://developers.google.com/speed/public-dns/docs/doh)
- [Get Started (8.8.8.8, 8.8.4.4, IPv6)](https://developers.google.com/speed/public-dns/docs/using) · [Secure transports (DoT on dns.google:853, TLS/QUIC)](https://developers.google.com/speed/public-dns/docs/secure-transports) · [DNS64 (::64 and ::6464)](https://developers.google.com/speed/public-dns/docs/dns64)
- [Google Public DNS — Domain Troubleshooting (EDE code catalogue, per-NS consistency checks, +bufsize=1400, cross-resolver comparison)](https://developers.google.com/speed/public-dns/docs/troubleshooting/domains)
- [Google Public DNS — Security (rate limiting, amplification factor, RFC 8198, entropy defenses)](https://developers.google.com/speed/public-dns/docs/security)
- [Google Public DNS — for ISPs (the "less than 1500 QPS" per-IP threshold)](https://developers.google.com/speed/public-dns/docs/isp)
- [Google Public DNS — FAQ (ECS 24/56 bits, DNSSEC CD behaviour, logging, NXDOMAIN, flush caveats)](https://developers.google.com/speed/public-dns/faq)
- [dns.google/query — live query UI (form fields, datalist, permalink)](https://dns.google/query?name=example.com&rr_type=A) · [dns.google/cache — flush form + reCAPTCHA gate](https://dns.google/cache)
- [Google Admin Toolbox Dig](https://toolbox.googleapps.com/apps/dig/) · [Toolbox home — full 11-tool list](https://toolbox.googleapps.com/apps/main/)
- [Check MX — server-rendered report URL](https://toolbox.googleapps.com/apps/checkmx/check?domain=iana.org) · [Toolbox Dig's undocumented JSON endpoint — bare GET, no CSRF token](https://toolbox.googleapps.com/apps/dig/lookup?domain=example.com&typ=MX)
- [RFC 8484 — DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484) · [RFC 8914 — Extended DNS Errors](https://www.rfc-editor.org/rfc/rfc8914) · [RFC 7871 — EDNS Client Subnet](https://www.rfc-editor.org/rfc/rfc7871) · [RFC 8461 — MTA-STS](https://www.rfc-editor.org/rfc/rfc8461) · [RFC 8482 — minimal ANY responses](https://www.rfc-editor.org/rfc/rfc8482) · [RFC 7873 — DNS Cookies](https://www.rfc-editor.org/rfc/rfc7873)
- [RFC 4034 §2.1.1 — DNSKEY Zone Key and SEP flag bits (KSK vs ZSK, basis for the mislabel finding)](https://www.rfc-editor.org/rfc/rfc4034#section-2.1.1)
