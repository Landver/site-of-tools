# Public resolver cache-purge tools (Cloudflare · Google · OpenDNS)

Three free, no-account web tools run by the operators of the three biggest public recursive resolvers. They do the thing a lookup tool structurally *cannot*: **evict a name from the resolver's own cache**, pushed across an anycast fleet in seconds. Every propagation checker answers "is it stale?"; these answer "make it not stale." That's the action an admin takes ~30 seconds after a propagation check comes back red, and it's the natural outbound link from any DNS tool we build. OpenDNS's is the odd one out: it's primarily an **inspect** tool (what does each of our 54 datacenters hold right now?) with refresh bolted on.

| | Cloudflare **Purge Cache** | Google **Flush Cache** | OpenDNS **CacheCheck** |
|---|---|---|---|
| **URL** | `one.one.one.one/purge-cache/` (also `1.1.1.1/purge-cache/`) | `dns.google/cache` | `cachecheck.opendns.com` |
| **Category** | purge only | purge only | inspect + purge |
| **Registration** | none | none | none (session cookie set) |
| **Pricing** | free | free | free |
| **API** | **yes, unauthenticated** — `POST /api/v1/purge` | no (reCAPTCHA-gated form) | undocumented `GET /api.php` |
| **Ownership proof** | none | none ("You do not need to prove ownership of the domain to flush it") | none |
| **RR types** | 18 (select) | 28 (datalist) | **A only** |

- **Firsthand check (2026-09-15, egress DE, 1.1.1.1 PoP `txl01`, OpenDNS `r2004.ams`; fact-check pass 2026-09-16 re-ran the same probes plus new ones):** all three pages HTTP 200 to plain curl on both dates. Purged `example.com`/A and `corpberry.com`/A via CF's JSON API and watched the TTL at `@1.1.1.1` reset 287 -> 300 at roughly **t+12s** (session 1). Re-verified CF's full error set, CORS-less response and exact type list live; re-fetched Google's 28-type list and reCAPTCHA sitekey live; called OpenDNS `api.php` for `fra` (read, refresh, invalid-location and NXDOMAIN cases) and confirmed it needs no cookie or CSRF token on either the read or refresh path. Read both tools' minified/unminified JS, re-downloading OpenDNS's `cachecheck-new.js` from CloudFront and confirming its 13,622-byte size and full status enum. **Did not** exercise Google's flush: it is hard-gated by reCAPTCHA and bypassing that is off-limits, so an unsigned `POST /cache` was sent (twice, across both sessions) purely to record the failure string ("reCAPTCHA failure!"); Google's own FAQ and its 2016 `public-dns-announce` post cover flush semantics and scope. Google's `Comment` field was confirmed live against the JSON `resolve` endpoint (not a purge) using `corpberry.com`/A, a plain public lookup, alongside repeat `iana.org`/A queries for the partial-TTL/no-Comment contrast case.

## What they are

All three are operator-run "fix my stale record" buttons, published because the alternative is a support ticket. Cloudflare's is a 5.7 KB static page plus a **2,196-byte** JS bundle whose entire payload is one `fetch`. Google's is a form on `dns.google` next to its DoH UI. OpenDNS's is a 2010-era jQuery page (the CSS carries a `/* cachecheck 4/22/10 */` comment) that Cisco has kept alive through the Umbrella acquisition while letting the docs behind it rot: `support.opendns.com` article 227987067 now 301s to a bare community-forum landing page.

**Not the same thing as CDN purge.** Searching "Cloudflare purge cache" lands almost entirely on zone/CDN cache purge (`/zones/{id}/purge_cache`, plan-tiered, token-authenticated). Resolver purge is a different product with a different endpoint and no auth at all. Worth a sentence of disambiguation in our own copy.

## Registration, access & pricing

Free, anonymous, no key, no quota published, checked **2026-09-16**. Cloudflare needs nothing at all. Google needs a solved reCAPTCHA per flush (sitekey `6LdkpLIZAAAAAN3z1J1rvLUEsNX9d-4QvrvXWhC3`, bound to the submit button via `data-callback="onSubmit"`). OpenDNS issues a fresh `OPENDNS_ACCOUNT` cookie on **every** response, including bare `api.php` calls, plus a `csrf_token` hidden field and an `X-CSRF-Token` header on its page's own XHRs — but **my curl sent neither a cookie nor a token and `api.php` accepted it anyway**, on both the read (`l=&d=`) and the refresh (`l=&d=&r=true`) calls. The cookie/CSRF pair is issued but enforced on neither path.

## Features — complete inventory

**Cloudflare Purge Cache**
- Single form: `domain` (required, free text) + `type` (select, defaults A).
- 18 RR types: `A AAAA CAA CNAME DNSKEY DS HTTPS LOC MX NAPTR NS PTR SPF SRV SVCB SSHFP TLSA TXT`.
- **Public JSON API**, no auth: `POST https://one.one.one.one/api/v1/purge?domain=<name>&type=<RRTYPE>`. `type` is optional. Params in the **query string**, not the body; no `Content-Type` needed.
- Fleet-wide, asynchronous. Response: `{"msg":"purge request queued. Please wait a few seconds and verify the request was successful"}`.
- Complete observed error set (each a ready-to-display string): `parameter "domain" is required` · `unsupported RRType` · `refreshed domain must be below a top level domain` (blocks `com`) · `wildcard purge is not supported` (they explicitly anticipated `*.example.com`).
- One name + one type per call. `type=ANY` and `type=A,AAAA` both rejected as `unsupported RRType`.
- `GET` and `OPTIONS` on the endpoint both return **403** from the WAF; only `POST` works.
- Sibling diagnostics at `one.one.one.one/help/`: connected-to-1.1.1.1 check, DoH / DoT / WARP detection, AS name + number, **Cloudflare data center**, per-address reachability for `1.1.1.1`, `1.0.0.1` and both IPv6 addresses, and a **copy-this-URL** button whose stated purpose is pasting into a forum post.
- No history, no batch, no monitoring, no verification step, no result page. The purge form and the help page do not link to each other.

**Google Flush Cache**
- Form `POST /cache` with `name`, `rr_type`, `g-recaptcha-response`. Result renders inline on the same page.
- **28 RR types** offered in the `<datalist>`, the widest of the three, including DNSSEC machinery and oddities: `A AAAA CDNSKEY CDS CNAME DNAME DNSKEY DS HINFO HTTPS INTEGRITY IPSECKEY MX NAPTR NS NSEC NSEC3 NSEC3PARAM PTR RP RRSIG SOA SPF SRV SSHFP SVCB TLSA TXT`. It's a `<datalist>` on a text input, so unlisted types are typeable.
- Documented semantics worth copying into help text (verified against Google's own FAQ wording, corrected from an earlier draft): flushing **any record type for a domain you've registered or sub-delegated with NS records also flushes delegation information** about that domain's nameservers, not just an NS-type flush specifically — do this *before* flushing subdomains like `www` after a registrar/host change, so they don't get refreshed from the stale old nameservers; the *only* way to clear all subdomains or all types is to **flush each type of each name individually**; for a stale CNAME chain, flush CNAME **starting at the last CNAME and working back** to the queried name, then flush the queried name's own type.
- **Domains using EDNS Client Subnet (ECS) for geolocation cannot be flushed at all** — Google's FAQ states this outright and tells ECS users to keep those records' TTLs at 15 minutes or less instead, since there's no flush escape hatch. Worth a prominent warning in our copy: this tool silently can't help a chunk of CDN-fronted domains. Separately, Google generally caps how long it serves a record past its authoritative TTL at **"six hours even if the actual TTL is longer"** — so the ceiling on "wait it out" is 6h, not unbounded.
- Companion **inspect** UI at `dns.google/query`: DNS Name, RR Type, an **EDNS Client Subnet** input, "Disable DNSSEC validation" and "Show DNSSEC detail" toggles, and a printed deep link to the raw JSON equivalent.
- Raw JSON resolver `dns.google/resolve?name=&type=` with `cd=1` (CD bit), `do=1` (returns RRSIG records), `edns_client_subnet=0.0.0.0/0` (opt out of ECS, echoed back in the response), and a `Comment: "Response from <auth IP>"` field naming the authoritative server.
- No API for the flush itself, no history, no batch, no monitoring.

**OpenDNS CacheCheck** — the only one that *shows* you the cache
- Enter a domain -> fan out to **54 named datacenters** across 6 regions, each rendered as its own cell in a geographic grid: South America (Rio, São Paulo), North America (Ashburn, Atlanta, Boston, Chicago, Denver, Dallas, Allen ×5, LA, Querétaro, Miami, Minneapolis, Reston, NYC, Palo Alto, Seattle, Vancouver, Toronto, Richardson), Europe (Amsterdam, Paris, Copenhagen, Dublin, Frankfurt, London, Madrid, Manchester, Milan, Marseille, Bucharest, Prague, Stockholm, Warsaw, Düsseldorf), Australia (Melbourne, Sydney), Asia (Chennai, Dubai, Hong Kong, Jeddah, Mumbai, Tokyo ×2, Osaka, Seoul, Singapore, Tel Aviv), Africa (Cape Town, Johannesburg).
- **"Refresh the cache"** button appears only *after* a check, and refreshes **every location** (one request each).
- Undocumented JSON API, one request per location: `GET /api.php?l=<loc>&d=<domain>` to check, `&r=true` to refresh. Location codes are the grid cell ids (`ash`, `chi`, `fra`, `lon`, `nrt`, `sin`, `syd`, `jnb`, `lab-dal1`…).
- Observed responses: `{"status":"SUCCESS","auth":true,"location":"fra","results":["104.20.23.154","172.66.147.243"]}`; refresh adds `"refresh":true` **and returns the post-refresh answer synchronously**; `{"status":"NXDOMAIN","auth":true,"location":"fra"}`; `{"status":"ERROR","auth":true,"error":"Invalid location code"}`.
- Full status vocabulary from the JS: `SUCCESS SERVFAIL NO_A_RECORD NXDOMAIN PHISH NO_RESPONSE LIMIT_EXCEEDED ACCESS_DENIED ERROR`. Each non-success status carries a written explanation in a tooltip ("SERVFAIL :: The domain's nameserver had an internal error…").
- **PHISH** is a status in its own right: OpenDNS filters phishing domains, so "your domain doesn't resolve" and "we block your domain" are different answers with different copy and a contact form attached.
- Rollup verdict computed client-side across all 54: all-identical -> "All locations returned the same (valid) answer"; mixed -> "Locations returned different answers" plus a bulleted explanation that geo-steering, not staleness, is a likely cause.
- Post-refresh branching copy: "If the refreshed results look good, you're done!" vs a 3-item troubleshooting list.
- Contact form pre-filled with domain + overall status, subject `Cache: <STATUS>: <domain>`.
- **A records only.** No type selector; `NO_A_RECORD` is a first-class status. Punycode conversion of IDNs happens client-side via a bundled `punycode.js`.

## Record types & query options supported

Cloudflare 18 types, Google 28, OpenDNS 1. **None** of the three lets you choose which resolver node to hit, trace delegation, force TCP, set EDNS/ECS on the purge, toggle the DNSSEC OK bit, or view raw wire output as part of the purge itself. Those knobs exist only on Google's separate `dns.google/query` and `dns.google/resolve` surfaces (ECS, CD, DO). No tool shows you the TTL it is about to evict, and no tool shows you the record it evicted. That absence is the single biggest product gap here.

## How it works

Server-side in every case; the browser just posts a form. **Cloudflare** is fire-and-forget: the API returns "queued" immediately and instructs you to verify yourself. Cloudflare's own engineering blog says its resolver platform ("BigPineapple") nodes relay cache lookups to peer nodes **in the same datacenter** by consistent hashing, and that configs/code are pushed **worldwide** via Quicksilver in seconds — the blog documents Quicksilver for config/code distribution, not explicitly for propagating a given purge's cache-eviction state, so treat "purge propagates globally via Quicksilver" as our inference, not Cloudflare's claim. What I actually measured: a TTL reset visible at PoP `txl01` about 12s after the POST, one PoP, one sample. **Google** runs a two-tier cache: "a small per-machine cache contains the most popular names" in front of a second pool that **partitions the cache by name**, so all queries for one name land on one machine. Google's own 2016 announcement of the flush tool states it clears "the domain/type out of the cache of **all resolvers that are currently up and running**" — i.e. documented as fleet-wide, not single-node, which contradicts a third-party blog's uncorroborated "single node only" claim; I still couldn't observe this directly since the flush itself is reCAPTCHA-gated. Separately, Google's JSON resolver documents a genuine cache-miss marker: `dns.google/resolve` returns a `"Comment": "Response from <auth IP>"` field specifically on **uncached** answers. Firsthand: querying `corpberry.com`/A returned TTL 300 (the zone's full configured TTL — a miss) **with** the Comment field present; repeated `iana.org`/A queries returning partial TTLs (255, 757) carried **no** Comment field. So the earlier draft's doubt about this was wrong — it is both documented and firsthand-confirmed as a cache-miss marker. **OpenDNS** is explicitly per-datacenter, which is why the UI is a 54-cell grid and why its own refresh loop fires 54 separate requests: there is no single cache to purge.

**Firsthand finding that reframes the whole category.** One resolver IP is not one cache. Polling `iana.org`/A (authoritative TTL 3600) six times over 25s on 2026-09-15:

| t | `dig @1.1.1.1` | Cloudflare DoH | Google DoH |
|---|---|---|---|
| 0s | 3152 | 1274 | 337 |
| +5s | 3146 | 3147 | 820 |
| +10s | 3140 | 1262 | 814 |
| +15s | **1255** | 3135 | 487 |
| +20s | 1249 | 3129 | 802 |
| +25s | 3122 | 3123 | **1777** |

Consecutive queries to the same address land on backends holding entries of wildly different age. Google's spread is the widest, matching its name-partitioned design. Practical consequence: **a single lookup cannot tell you "the" cache state of a public resolver**, and a purge that looks unconfirmed may just be a different backend answering. Also worth noting: `dig` over UDP/53 showed smooth TTL decay, while the DoH JSON endpoints returned undecremented TTLs for some names, so TTL-as-cache-age is only reliable over the wire path.

## Output & UX

Cloudflare: one line of text swapped into `#info-message`, button label flips to "Sending…" then back. No result page, no URL state, nothing to share or export. Google: the whole page re-renders server-side with the outcome inline. OpenDNS is by far the richest: async grid where all 54 cells show a spinner and fill in independently as each XHR lands, a "Waiting for all servers to respond…" banner that is replaced by the computed rollup verdict once `completed == results.length`, per-status tooltips, and conditional troubleshooting prose that differs before vs after a refresh. **No tool has a shareable result URL, an export, or a history.** Empty/error states are strings, not structured data (Cloudflare's), except OpenDNS which has a real status enum.

## Monetization, limits & abuse controls

None of the three is monetized; they are retention/support-deflection features. Abuse control is the whole differentiator: Cloudflare **has none visible** (no key, no CAPTCHA, no documented rate limit, WAF blocks only wrong methods); Google uses **reCAPTCHA per submission**, explicitly "to restrict automated abuse"; OpenDNS uses **IP-based throttling** with a dedicated `LIMIT_EXCEEDED` status and the message "Your IP address has been temporarily blocked due to excessive use of the CacheCheck tool", which also hides both submit buttons. If we call Cloudflare's API from our server, every user shares our egress IP, so we should self-throttle before Cloudflare decides to.

**CORS, measured.** Cloudflare's `/api/v1/purge` returns **no** `Access-Control-Allow-Origin` and 403s the `OPTIONS` preflight. A browser `fetch(url, {method:'POST'})` with no custom headers is a simple request, so it is sent and the purge executes, but the response is unreadable. OpenDNS's `api.php` also returns no ACAO. **Both need a server-side call if you want to show the result** — which suits a Go handler fine.

## Ideas worth stealing

- **The "Now purge it" step.** After our propagation/lookup view, a button per resolver. For Cloudflare it's a real `http.Post` from the handler to `https://one.one.one.one/api/v1/purge?domain=&type=`, parse `{"msg":...}`, return an htmx fragment. Neither CF's nor Google's form accepts query-string prefill (I checked: the inputs are static), so Google gets a plain link plus a **copy-to-clipboard of the exact name and RR type** to paste past the CAPTCHA.
- **Verify the purge — nobody does this.** Cloudflare literally tells the user "wait a few seconds and verify the request was successful" and then provides no verification. Record the TTL before, POST the purge, poll the same resolver every 2s for ~30s, and swap in "TTL jumped 287 -> 300 at t+12s, purge confirmed" the moment it resets. An `hx-trigger="every 2s"` polling fragment retired by an `HX-Reswap`/204. This is the highest-value feature in the whole report and it is roughly 40 lines of Go.
- **Cache-age gauge.** `age = authoritative_TTL - observed_TTL`, drawn as a bar with the remaining seconds. Turns an opaque number into "this answer is 4m13s old, 0m47s left."
- **Fragmentation probe.** Query the same resolver 5× and show the spread of TTLs (the table above). Cheap, genuinely novel, and it explains away the "I purged and nothing happened" support question before the user asks it.
- **Per-type purge matrix.** Cloudflare needs one call per type and rejects `ANY`. Render checkboxes for the types we actually found records for, fire them concurrently with `errgroup`, show a row per type. Turns their limitation into our feature.
- **Ship their error strings.** CF's four `msg` values are already user-ready; map them to our own copy and add the one they omit ("Cloudflare only, your ISP's resolver is unaffected").
- **OpenDNS's rollup line.** "All locations returned the same answer" vs "Locations returned different answers" is the single most useful sentence any of these tools emits. Compute the same over our own multi-resolver fan-out.
- **Distinguish geo-steering from staleness.** Observed live: `corpberry.com`/A is `104.21.25.133` via 1.1.1.1 but `188.114.96.3` via OpenDNS `fra`, both current. OpenDNS says this in prose; we can say it *conditionally*, only when the differing answers all share an ASN/org (our IP tool already resolves ASN, so this is free).
- **Honest "cannot be purged" list.** Quad9, your ISP's resolver, the OS stub, the browser. Pair with the `ipconfig /flushdns` / `resolvectl flush-caches` / `dscacheutil -flushcache` commands and a copy button.
- **Log purges to Mongo** alongside the existing lookup history: "you purged `corpberry.com` A 4 minutes ago" prevents the impatient double-purge.
- **Copyable diagnostic URL**, lifted from `one.one.one.one/help/`: a shareable link to a result so a user can paste it into a ticket. None of the three purge tools has one.

## Gaps & what it does not do

- **No Quad9.** Documented, verbatim: "Quad9 does not currently offer a public, cache flush tool" and "does not honor cache flush requests submitted to our support team", citing "technical and security limitations", recommending lowering TTLs ahead of a change instead. So our UI must show a resolver-by-resolver capability matrix, not a single "purge" button.
- **Google can't flush ECS-steered domains, full stop.** Its own FAQ: "Domains using EDNS Client Subnet (ECS) for geolocation cannot be flushed" — the only mitigation offered is keeping ECS record TTLs at 15 minutes or less so you never need to. A chunk of CDN/geo-DNS domains are simply unreachable by this tool, and that deserves its own line in our capability matrix, not a footnote.
- **No ISP resolvers, ever.** The long tail that actually serves end users is unreachable by any of this.
- **No verification, no history, no sharing, no export, no batch, no monitoring** in any of the three.
- Cloudflare shows neither the evicted record nor which PoPs were hit. Google gives no API and no machine-readable result. OpenDNS is **A-only**, so an MX or TXT problem is invisible to it, and its refresh is the slowest ("can take up to 20 seconds").
- No tool distinguishes a purged **negative** answer (cached NXDOMAIN, RFC 2308) from a purged positive one, which is exactly the case where people panic.
- OpenDNS's **SmartCache** deliberately serves expired records when authorities are unreachable, so a "stale" CacheCheck answer can be correct behaviour rather than a cache bug. Nothing in the UI says so.
- Ownership is never verified anywhere, so all three are trivially usable to force a third party's name to be re-resolved. Nobody seems to treat that as a problem, but our copy should not advertise it as a feature.

## Verified firsthand vs inferred

**Verified** (curl/dig, 2026-09-15/16, both against the live sites during this pass): all three pages return 200; CF's full API contract, method restrictions, missing CORS headers and all five response strings (`domain` required, `unsupported RRType`, TLD block, wildcard block, and the "queued" success message) reproduced live; CF purge visibly resetting a TTL at ~t+12s on PoP `txl01` (one sample); CF's 18-type list (byte-for-byte) and Google's 28-type list (byte-for-byte) read from the served HTML, re-fetched and re-counted; CF's JS bundle re-confirmed at exactly 2,196 bytes, page at 5,774 bytes; Google's reCAPTCHA gate, sitekey and its "reCAPTCHA failure!" response on an unsigned POST; Google's NS/delegation and CNAME-chain flush semantics quoted verbatim from its FAQ (and the earlier draft's paraphrase of the NS rule corrected — it's *any* record type on a delegated domain, not NS specifically); Google's ECS flush exclusion and ~6h max-serve-TTL, both read directly from the FAQ; Google's `Comment: "Response from <auth IP>"` field confirmed live as a cache-miss-only marker (present on a full-TTL/uncached `corpberry.com` answer, absent on partial-TTL/cached `iana.org` answers) and matches Google's own JSON API docs ("uncached responses are attributed to the authoritative name server"); OpenDNS's `api.php` shape and exact response bodies (`SUCCESS`/`auth`/`location`/`results`, `r=true` refresh returning fresh data synchronously with `"refresh":true`, `Invalid location code`, `NXDOMAIN`), all reproduced live; OpenDNS sets a fresh `OPENDNS_ACCOUNT` cookie on every response yet enforces neither that cookie nor the CSRF token on the request side, on the read path **and** the refresh path; absent CORS headers on both CF's and OpenDNS's endpoints; the 54-location grid (exact count, and the "Allen ×5" duplication) and the 9-value status enum, both read from the served HTML/JS and cross-checked against the 13,622-byte `cachecheck-new.js` on CloudFront (size also reproduced exactly); the multi-cache TTL spread table (original session, not re-run).

**Not verified / secondhand:** Google's flush behaviour end to end is still not independently observable — it's reCAPTCHA-gated by design and I did not attempt to defeat it, so what Google's flush *does* still rests on Google's own FAQ and its own 2016 `public-dns-announce` post, not on a purge I triggered myself. That said, the "single node only" doubt in the earlier draft is resolved in Google's favor: their own announcement states a flush clears the domain/type "out of the cache of all resolvers that are currently up and running" (fleet-wide), which is a primary source, not the uncorroborated third-party blog. Cloudflare's internal propagation mechanism: the blog documents intra-datacenter peer relay (BigPineapple, consistent hashing) and worldwide Quicksilver config/code push as separate facts — that Quicksilver is *what carries a purge's effect* worldwide is this report's inference, not something Cloudflare states. Cloudflare's actual rate limits on the resolver-purge endpoint: not published, and I deliberately did not probe for them (published Cloudflare API rate-limit numbers found via search are for the authenticated zone/CDN purge product, a different endpoint entirely — see disambiguation note above). OpenDNS min/max TTL clamping and NXDOMAIN caching duration: the Cisco caching note covers RFC 2181 trust levels, SmartCache and FIFO queue eviction but states no numeric figures at all.

## Open source / reusable

No repos. The implementations are readable and small enough to be their own documentation: Cloudflare's `purgeCache-<hash>.js` is 2,196 bytes and its operative line is `fetch(encodeURI("/api/v1/purge?"+params),{method:"POST"})`; OpenDNS's `cachecheck-new.js` (13,622 bytes, unminified, on CloudFront) contains the whole fan-out, status enum and verdict logic in plain jQuery and is the best available spec for their API. Neither carries a licence, so read for behaviour, don't copy code. On our side, `github.com/miekg/dns` gives the TTL reads and per-resolver querying the verify loop needs; everything else is `net/http` and `errgroup`.

## Sources

- [Cloudflare 1.1.1.1 Purge Cache tool](https://one.one.one.one/purge-cache/)
- [Cloudflare 1.1.1.1 FAQ (confirms the Purge Cache tool)](https://developers.cloudflare.com/1.1.1.1/faq/)
- [Cloudflare blog: how Rust and Wasm power 1.1.1.1 (BigPineapple, peer-node cache relay, Quicksilver)](https://blog.cloudflare.com/big-pineapple-intro/)
- [Google Public DNS Flush Cache tool](https://dns.google/cache)
- [Google Public DNS FAQ (flush semantics, no ownership proof, reCAPTCHA, ECS exclusion, ~6h TTL cap)](https://developers.google.com/speed/public-dns/faq)
- [Google Public DNS performance docs (two-tier, name-partitioned cache)](https://developers.google.com/speed/public-dns/docs/performance)
- [Google Public DNS JSON API (documents the `Comment` field on uncached/attributed responses)](https://developers.google.com/speed/public-dns/docs/doh/json)
- [Google public-dns-announce, 2016 — Flush Cache tool launch ("all resolvers that are currently up and running")](https://groups.google.com/g/public-dns-announce/c/O_goLLYq9HE)
- [OpenDNS CacheCheck](https://cachecheck.opendns.com/)
- [Cisco: how OpenDNS/Umbrella resolvers cache resource records (SmartCache, trust levels, queue eviction)](https://www.cisco.com/c/en/us/support/docs/security/umbrella/225049-how-the-resolvers-cache-resource.html)
- [Quad9 documentation FAQ (no cache flush tool, does not honor flush requests)](https://docs.quad9.net/FAQs/)
- [RFC 2308 — negative caching of DNS queries](https://datatracker.ietf.org/doc/html/rfc2308)
- [RFC 8767 — serving stale data to improve DNS resiliency](https://datatracker.ietf.org/doc/html/rfc8767)
- [Simon Willison, 6 Dec 2021 — note on 1.1.1.1/purge-cache](https://simonwillison.net/2021/Dec/6/purge-cache/)
