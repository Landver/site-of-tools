# whatsmydns.net

The category-defining **DNS propagation checker**: one query fanned out to **22** recursive resolvers around the world, answers rendered as a country-flagged list plus a world map, green tick on any non-empty answer, or on an exact match when you fill the optional expected-value box. Launched **7 June 2008** as a public beta, still run by a single operator (contact address + a PayPal donate button made out to `dan@mondodev.net`, no company page), ad-funded, **no accounts and no paid tier**. Matters to us because it is the reference implementation of the one DNS feature a small tool can actually own: *"is my change live yet, and where isn't it?"* The Checker is one hand-written JS module (bundled w/ axios + D3 into a 40 KB minified `app.js`) over a JSON backend; the Lookup half is a **plain server-rendered GET form w/ no JS at all**. The stack it settled on (Tailwind, no framework, per-row async fill) is one keystroke away from Go + htmx.

- **URL:** https://www.whatsmydns.net/ · **Category:** global propagation checker + DNS/domain/IP utility suite · **Registration:** none, no login exists · **Pricing:** free, ad-supported (Fuse header bidding, **5 slots**; Primis video; FOU Analytics; GA4), PayPal donations · **API:** undocumented internal JSON endpoints (`/api/servers`, `/api/details`, `/api/domain`), self-described as beta
- **Firsthand check (re-run 2026-09-16):** the live site **403s every non-browser client**, browser UA or not. `curl -sSI https://www.whatsmydns.net/` → `HTTP/2 403`, `cf-mitigated: challenge`, `server: cloudflare`, a Turnstile CSP + `accept-ch`/`critical-ch` client-hint demand; identical 403 on `/robots.txt`, `/sitemap.xml`, `/dns-lookup`, `/dns-tools.html`, `/api/servers`, `/api/domain?q=…`, apex and `www` alike. A CORS probe (`-H "Origin: https://example.com"`) also returns 403, so **no `access-control-*` headers are observable**. WebFetch on the homepage returned 403 too. Note the challenge is path-blind: `/login` and `/pricing` 403 exactly like `/`, so **live probing cannot prove or disprove that a path exists**. The absence claims below rest on their own rendered sitemap-footer and the Wayback index, not on these status codes. The companion [firsthand-ui-observations.md](firsthand-ui-observations.md) records the same block from a real Electron browser. Everything below about page content therefore comes from **Internet Archive replays of whatsmydns.net's own bytes** (homepage snapshot `20260915130048`; `js/app.js` snapshot `20260908212908`, reached by following the redirect from the homepage's versioned `?id=e44e1d09…` URL; `/api/servers` snapshot `20260729081124`; `/api/details` + `/api/domain` archived JSON, brotli-decoded), not from driving the live UI. Their own DNS I *did* query live: `dig NS whatsmydns.net` → `gina.ns.cloudflare.com` / `tom.ns.cloudflare.com`, Google Workspace MX, `v=spf1 include:_spf.google.com include:amazonses.com ~all`, A behind Cloudflare, **no DS record** (the DNS propagation checker does not sign its own zone).

## What it is

Two distinct tools sharing a chrome, plus a pile of small utilities:

1. **DNS Checker** (`/`) — the propagation grid. One record type, one name, **22 resolvers**, one answer cell each. Optimized for non-technical users; the site copy says as much ("using these tools can be complicated and difficult to understand for non-technical people which is why the whatsmydns.net DNS checker was created").
2. **DNS Lookup** (`/dns-lookup`, launched 18 Aug 2020) — **one** resolver, full packet detail: flags, TTLs, authority and additional sections. The technical counterpart.

Positioning is deliberate and stated on both pages: the Lookup page links down to the Checker ("Looking for easier to understand results?"), the Checker never pretends to be `dig`.

## Registration, access & pricing

No account system exists. The site's own footer is a full sitemap (DNS Tools · DNS Guides · DNS Lookup presets · Articles & Blog · DNS Servers · Browser Extension · Social Media · Contact · Legal) and carries **no account, pricing, plan or monitoring entry** on any page I pulled (homepage 2026-09-15, `/dns-tools.html` 2026-08-01, `/dns-lookup` 2026-08-23, `/blog`, `/dns/*`). The prior pass also found no `/login`, `/signup`, `/pricing`, `/account` or `/monitoring` in the Wayback index; I could not re-run that query (the CDX API was returning "Temporarily Offline" and 429 throughout 2026-09-16), so treat the sitemap-footer evidence as primary. Third-party directory listings agree the product is free-only. **The "paid monitoring" premise does not hold: whatsmydns.net sells nothing.** Monetization is ads + donations (see below). Contact is `contact@whatsmydns.net`; the API note gives `api@whatsmydns.net`; the donate button is a personal PayPal link (`dan@mondodev.net`), which is the clearest evidence of the one-person operation.

## Features — complete inventory

### Propagation checking (the core)

| Feature | Detail |
|---|---|
| Global fan-out | 22 resolver locations, 17 countries (2026-07 snapshot), one row each |
| Record types | **A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA** (10, tab strip) |
| **Expected Value field** | Second input (`#c`, placeholder `1.2.3.4`). Supply the value you *expect*; each row gets a green tick only if it matches |
| Per-row detail panel | Click a row or map marker → full dig-style transcript for that resolver |
| World map | D3.js + TopoJSON custom map (replaced jVectorMap + jQuery, Sep 2020), markers per resolver, hover-linked to the list; a list ↔ map toggle fires a `"Map View"` GA event |
| Country flags | Flag sprite per row (added 2013) |
| Shareable result URL | `#<TYPE>/<name>[/<expected>]` fragment, written on every search and replayed on load |
| Input normalization | Strips `http(s)://`, lowercases, truncates at first `/`, and **strips everything before `@`** so pasting an email address gives you its domain |
| Sticky search bar | Search + record-type control follows you down long result pages (2020) |
| Cancel-on-new-search | A new query aborts all in-flight lookups (shared axios `CancelToken`) |
| Colour-blind-safe status markers | Reworked Sep 2009 after red/green complaints. In today's bundle each of tick / cross / pending is its own SVG path or shape, so state survives without colour |

### Single-resolver DNS Lookup

| Feature | Detail |
|---|---|
| **No JavaScript** | The whole tool is `<form id="f" method="GET" action="/dns-lookup">` w/ `name="query"` + `<select name="server">`; record type is chosen by *navigating* to a preset URL. Server renders the result page. Nothing here needs JS |
| Resolver picker | `<select name="server">` w/ values `google · cloudflare · opendns · quad9 · yandex · global` |
| Record types | **ALL, A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, ANY** as a 12-item strip of `<a>` tags. `ALL` (`/dns-lookup`, the default, also the hidden `type` input's value) and `ANY` (`/dns-lookup/any-records`) are separate options |
| Output | Full response: `id`, `opcode`, `rcode`, `flags`, `;QUESTION`, `;ANSWER`, `;AUTHORITY`, `;ADDITIONAL`, TTLs intact (per the 18 Aug 2020 launch post; I never saw a rendered result page) |
| SEO presets | `/dns-lookup/{a,aaaa,caa,cname,mx,ns,ptr,soa,srv,txt,any}-records`, each the same tool preset to that type with its own title/description (verified: `/dns-lookup/mx-records` → `<title>MX Lookup - Check MX records for any domain</title>`) |
| Cross-link | Body copy: "Looking for easier to understand results? Use the Global DNS Checker tool to check DNS propagation." |

### Reverse DNS

`/reverse-dns-lookup` — PTR for an IP *plus* the related forward lookups *plus* **forward-confirmed reverse DNS (FCrDNS) validation**. `/reverse-dns-generator` converts an IP to its `.in-addr.arpa` / `.ip6.arpa` name.

### Domain tools (all one backend call)

`/domain-age` · `/domain-expiration` · `/domain-last-update` · `/domain-availability` · `/domain-name-owner` · `/domain-name-registrar` · `/dnssec-check` · `/whois` — eight URLs over one shared page. All eight are framings of a single `/api/domain?q=` response, whose `data` object is literally `{domain, registered, created, updated, expires, owner, registrar, dnssec, whois[]}`: one field per landing page, `whois[]` the raw record. Plus `/idn-punycode-converter`.

### IP & URL utilities

`/ipv6-expand` · `/ipv6-shorten` · `/ipv4-to-ipv6` · `/ipv6-to-ipv4` · `/whats-my-ip-address.html` · `/url-unshortener` · `/redirect-checker` (shows every hop).

### Content, distribution & long tail

Guides (`/dns-tools.html`, `/flush-dns.html`, `/dns-security` incl. `/dns-security/dns-attacks/dns-pharming`, `/hosts-file.html`) · **DNS server database** `/dns/{global,usa,uk,australia,france,new-zealand}` with **135** per-provider pages, counted off the 2026 index snapshots: UK 65, USA 29, AU 21, NZ 9, FR 5, "global" 6 (`/dns/usa/comcast.html`, `/dns/uk/zen-internet.html`, …). Started 2009, still linked from every page's footer · `/articles` + `/blog` (dev changelog, 3 pages, first post 7 Jun 2008) · **Chrome extension** "DNS Lookup" (`/dns-lookup/chrome` → Web Store id `ekbgejcpgolcbfcaeapipnaoemoomcgf`): reads the current tab's domain, shows its records, has an options page for default launch behaviour and claims per-record-type propagation. Store listing fetched live 2026-09-16: **~6,000 users, 3 ratings**, i.e. a footnote, not a channel · **`/opensearch.xml`**, declared via `<link rel="search">` on every page, so the browser address bar can query it directly · Twitter-intent + Facebook-sharer buttons, both of which hardcode `whatsmydns.net/` rather than your result URL.

### Not present

No DNSSEC chain validation or visualization, no zone-health/RFC audit, no SPF/DKIM/DMARC/BIMI parsing, no blocklist or reputation checks, no passive DNS or subdomain enumeration, no delegation trace, no monitoring/alerting, no history, no export, no documented public API.

## Record types & query options supported

Checker: **A AAAA CNAME MX NS PTR SOA SRV TXT CAA** (counted off the homepage tab strip). Lookup adds **ANY** and **ALL**. No HTTPS/SVCB, no DS/DNSKEY/RRSIG, no TLSA/SSHFP/NAPTR/LOC/URI — thin next to DigWebInterface's 49-item selector (45 genuine RR types, see [digwebinterface.md](digwebinterface.md)) or even DNSChecker's 12. SRV must be entered `_service._protocol.name` and comes back as `priority weight port target`, a convention the operator documented when SRV shipped on 5 Apr 2015. The base set (A AAAA CNAME MX NS PTR TXT) dates to 26 Jun 2008; SOA and CAA arrived later, CAA on 13 Jun 2017.

Knobs are deliberately near-zero. Checker: record type + name + expected value, nothing else. Lookup: record type + one named resolver. **No** authoritative-vs-recursive toggle, no custom resolver, no `+trace`, no TCP, no EDNS/ECS, no DNSSEC (`+dnssec`) flag, no raw-output mode in the Checker. TTLs are shown only inside the per-row detail panel, as raw seconds in the RR lines, never as a human duration. Compare NsLookup.io's "Revalidate in 5m."

## How it works

Fully **server-side resolution, client-side orchestration**, for the Checker only (the Lookup is a plain GET form, above). Read out of their shipped `js/app.js`:

1. On load, `GET /api/servers` → `[{id, latitude, longitude, location, provider, country}, …]`, 22 objects. The HTML ships 22 empty rows (`data-id="0"`…`"21"`, `data-provider="Loading..."`, `data-location` set to the country only); the JSON fills them **positionally**, `querySelectorAll("div[data-id]")[n]` against roster index `n`. **The grid size is baked into the HTML; the resolver roster is data**, and a roster that stopped being exactly 22 long would silently mis-fill. Note the `id` in the HTML is the row index while the opaque `id` from the JSON (`"dajkegaj"`, `"ypjmlglb"`, …) is kept as `sid` and is what the query carries.
2. On search, it **fans out one request per resolver, all at once**, no throttling: `GET /api/details?server=<sid>&type=<TYPE>&query=<name>`, each carrying a shared `CancelToken` so the next search kills the previous fan-out. An outstanding counter re-enables the Search button when it hits zero.
3. Each response is a decoded DNS message, not a string:
   `{"data":[{"query","type","id","opcode","rcode","flags":{"qr","rd","ra"},"questions":[…],"answers":["0.sd. 600 IN CNAME asvd72jy.cdn.blogcdn.net.", …],"authority":[],"additional":[],"response":["43.129.182.55","8.218.14.99"]}]}`
   `answers[]` is the raw RR set (TTLs intact, full CNAME chain); `response[]` is the flattened final values. The row prints `response[]` joined by `<br>`; the detail panel prints the whole thing dig-style.
4. The tick test is one line: `!!t.length && (!expected || expected.toLowerCase() === t.join("|").toLowerCase())`. **Non-empty answer with no expected value = tick.** With an expected value, the match is against the *joined set*, so a two-A-record domain needs `1.2.3.4|5.6.7.8` typed in to go green.

An older endpoint, `GET /api/check?server=<numeric id>&type=&query=&_token=<CSRF>`, returned a bare **HTML fragment** (`104.19.244.91<br />104.19.245.91`) rather than JSON. It appears in the archive through March 2025 and is absent from the current bundle, whose only two endpoints are `/api/servers` and `/api/details`. The `_token` parameter name is the Laravel convention, so Laravel is a reasonable read, not a confirmed one.

**Which resolvers.** Not the usual public-DNS roll call. The 2026-07 roster (22 entries, 17 countries) is mostly **ISP recursives**: OpenDNS (Holtsville NY) · Speakeasy (Dallas TX, Atlanta GA) · Comodo (Dothan AL) · Verizon (Providence RI) · Fibernetics (CA) · Total Play (MX) · Claro (BR) · ServiHosting (ES) · Completel SAS (FR) · DNS.Watch (DE) · Liquid (ZA) · Teknet Yazlim (TR) · Uni of Tech & Design (RU) · CMPak (PK) · Skylink Fibernet (IN) · 3BB Broadband (TH) · Tefincom (SG) · CNNIC (CN) · KT (KR) · Telstra + Pacific (AU). Comparing the 2023-01 and 2026-07 snapshots, **most entries changed** (Seattle/Speakeasy → Dallas, Peshawar/PTCL → Rawalpindi/CMPak, Delhi/OMNET → Coimbatore, …).

That these are **third-party recursives rather than machines whatsmydns operates** is no longer just an inference from the names: the 2008 launch post describes checking "a range of randomly selected name servers located in different locations around the world"; the 9 Nov 2010 post says outright that the new German and Turkish servers "have been kindly provided by the **Offensive IP Database**"; and the privacy policy states whatsmydns "may forward any search queries on to third-party services in order to return results to the user". The operator has never published a current sourcing statement, so the 2026 roster's provenance is extrapolated from those three. It explains why the roster is 22 and not 200: each entry is a scarce, perishable asset, churned as it disappears. It is also the honest answer to the question users are actually asking, since a Cloudflare 1.1.1.1 cache tells you nothing about what Telstra subscribers see.

## Output & UX

Async, per-row fill: every row starts at `-` and resolves independently, so the page is useful before the slowest resolver returns. Results render as country-flagged rows (location + provider + answer + tick) with a synchronized D3 world map above; hovering a row highlights its marker. Clicking either opens the detail panel with the dig transcript, empty-state text `Waiting for search request...`. The search button swaps a search icon for a spinner and disables itself for the duration. That per-row dig transcript is not original to the Checker: it was folded in from the Lookup tool on **19 Sep 2020**, three weeks after the Lookup shipped, which is the clearest statement of the "one domain service, two front ends" idea below.

Sharing is the standout. The fragment carries the whole query: `https://www.whatsmydns.net/#MX/example.com`, or with an assertion, `#A/example.com/1.2.3.4`. Shipped **10 March 2010** in response to a single user email, explicitly framed for "people helping you out on a community forum or similar." That is the mechanic behind the service's ubiquity in support threads: the link *is* the question. No export, no JSON download, no PDF, no history. (The social buttons are the opposite lesson: both share the bare site root.)

Below the fold sits a long explainer (what DNS is, what propagation is, why it "often takes up to 48-72 hours and sometimes longer", how to speed it up by lowering TTL in advance, the four server roles, a step-by-step resolution walkthrough, and a per-record-type glossary) — SEO surface and genuine support-deflection in one. It also does the thing most competitors skip: it concedes the term is wrong ("While technically DNS does not propagate, this is the term that people have become familiar with") and then keeps using it. Correct *and* findable.

## Monetization, limits & abuse controls

Ads and donations only. The homepage carries **five** Fuse header-bidding slots (`data-fuse="220704216{09,12,15,18,21}"`, `/js/fuse.js`, `fusetag.que.push(…)`), `/js/primis.js` (Primis video player), GA4 `G-5C5QQD2W2F`, a FOU Analytics noscript pixel (`api.fouanalytics.com/api/noscript-…gif`, ad-fraud measurement), Cloudflare Insights, and a CCPA preference portal link in the privacy policy. Footer: "Support Me … please consider donating to help pay hosting costs."

The abuse control is **Cloudflare Managed Challenge on the entire origin, API included** — verified firsthand, 403 + `cf-mitigated: challenge` on every path I tried, on both hostnames, with and without a browser UA. No published rate limits, because there is no supported programmatic path. The only stated API stance is a `meta.note` embedded in `/api/domain` responses: *"Please contact api@whatsmydns.net for commercial or high volume use. API is in beta and may change at any time."*

Privacy posture is worth knowing before copying anything: the policy (last updated 20 Aug 2020) says they collect visitor IPs and that search queries "may be their personal website or contain other personally-identifying information," that whatsmydns "may forward any search queries on to third-party services in order to return results to the user," and that they make "reasonable efforts" to strip PII from a query before transmitting it (which is what the `@`-stripping normalization actually implements). On top of that, every search fires both a GA event and a synthetic pageview at `/search/<TYPE>/<query>`, straight out of `app.js` — i.e. **every domain anyone checks lands in their analytics**.

## Ideas worth stealing

- **The Expected Value field.** The single best idea here and nearly free to build: a second input where the user states what the answer *should* be, turning a wall of strings into a pass/fail column. Their comparison is one case-insensitive string equality against `answers.join("|")`, which is brittle for multi-value RRsets. Ours should compare **sets**: normalize each value, sort, and tick when the expected values are a subset (or exact match, user's choice). Renders as one extra column, costs one Go helper.
- **The assertion belongs in the URL.** `#A/example.com/1.2.3.4` means the shared link carries the *claim*, not just the query. For a Go+htmx tool the path form is better and crawlable: `GET /check/A/example.com?expect=1.2.3.4`, plain `<form method="get">`, no JS router.
- **One `hx-get` per resolver row, all firing on load.** Their fan-out maps exactly onto `<tr hx-get="/api/resolver/{id}?type=A&name=…" hx-trigger="load" hx-swap="outerHTML">`. The server renders each row's fragment; the browser does the concurrency. This is the htmx-shaped feature in the whole DNS category, and their legacy `/api/check` returning `1.2.3.4<br />5.6.7.8` is literally an HTML fragment endpoint. No WebSocket, no SSE, no Alpine.
- **Ship the grid skeleton in the HTML, fill the roster from data.** 22 placeholder rows with `Loading...`, hydrated by a separate `/api/servers` call. In Go: render the skeleton from a `[]Resolver` slice in one template pass, then let each row fetch itself. Instant first paint, no layout shift. Steal the shape, not their bug: they match roster to row *by array index*, so a hardcoded 22-row skeleton and a data-driven roster are one edit away from silently disagreeing. Render the skeleton from the same slice.
- **Two tools, one chrome, opposite audiences.** Checker = many resolvers, one value, ticks. Lookup = one resolver, one query, whole packet. Explicitly cross-link them with the reason ("Looking for easier to understand results?"). We would ship both off one domain service and two templates. They also proved the layering works by moving the Lookup's transcript into the Checker's row detail three weeks after launch.
- **The half that needs no JS should have none.** Their Lookup is a `<form method="GET">` plus a strip of `<a>` tags, one per record type, pointing at `/dns-lookup/<type>-records`. That is CLAUDE.md rule #4 obeyed by accident: plain HTML where plain HTML suffices, JS only for the Checker's fan-out. Copy the shape exactly.
- **Colour-blind-safe status markers from day one.** They changed theirs in Sep 2009 after user complaints. A green tick / red cross column is the single most colour-dependent thing in this category; make the marker differ in glyph and shape, not just hue, and it costs nothing at build time.
- **Return the decoded message, not a string.** Their `/api/details` shape (`opcode`, `rcode`, `flags{qr,rd,ra}`, `questions`, `answers`, `authority`, `additional`, plus a flattened `response`) is a good target struct for our domain package: one Go type serves the HTML row (flattened), the detail panel (full), and the JSON response, which is exactly the CLAUDE.md §4 layering.
- **Free the input.** Strip scheme, strip path after the first `/`, strip everything before `@`. Pasting `https://example.com/pricing?x=1` or `sales@example.com` both just work. Twenty lines, disproportionate goodwill.
- **`ALL` and `ANY` as distinct choices.** `ALL` = run each supported QTYPE concurrently; `ANY` = send QTYPE 255 and show whatever comes back (usually an RFC 8482 `HINFO` refusal, which is itself worth teaching).
- **One backend call, eight landing pages.** Their whois response powers Age / Expiration / Last Update / Availability / Owner / Registrar / DNSSEC / Whois as separate URLs. Cheap surface area if the site ever wants organic traffic; same trick as `/dns-lookup/mx-records`.
- **Ship `/opensearch.xml`.** ~15 lines of XML, lets the browser omnibox query the tool directly. Nobody else in this category bothers.
- **FCrDNS as a labelled verdict**, not two raw lookups. We already resolve org/ASN in [`iptools`](../../../../tools/iptools/docs/README.md), so PTR → forward → "forward-confirmed: yes/no" is additive.

## Gaps & what it does not do

Ten record types and no HTTPS/SVCB in 2026 is the biggest hole. No DNSSEC validation (and its own zone is unsigned), no zone-health audit, no delegation trace, no authoritative-server querying, no custom resolver, no TCP/EDNS/ECS controls, no export, no history, no monitoring, no supported API. Four more absences are provable straight off the `/api/details` payload rather than off a result page I never saw: it carries **no latency, no timestamp, no answering-server identity, and no humanized TTL**: the only durations in it are raw seconds inside the RR strings. It answers exactly one question well and declines the rest. The tick logic is also quietly wrong for multi-value RRsets: order and set-membership both matter when they should not.

## Verified firsthand vs inferred

**Verified firsthand (live, 2026-09-16):** the 403 + `cf-mitigated: challenge` on `/`, `/robots.txt`, `/sitemap.xml`, `/dns-lookup`, `/dns-tools.html`, `/api/servers`, `/api/domain?q=…`, on apex and `www`, with and without a Chrome UA; absence of observable CORS headers; whatsmydns.net's own NS/MX/TXT/A and missing DS via `dig`; the Chrome Web Store listing's ~6,000 users and 3 ratings.
**Verified from their own served bytes, via Internet Archive replay (not live):** homepage markup, nav, footer sitemap, 10-item record-type strip, `#q`/`#c` inputs, 22 `data-id` rows w/ `Loading...`, the five `data-fuse` slots, the FOU pixel and the GA4 tag; `js/app.js` fan-out, shared `CancelToken`, outstanding counter, `Na` tick test, `Oa` detail renderer, hash routing and `@`/scheme/path input normalization, and the two GA calls per search; `/api/servers` roster (2023-01 and 2026-07, 22 entries / 17 countries); `/api/details` and `/api/domain` response shapes incl. the `api@whatsmydns.net` beta note; the `/dns-lookup` GET form, its `server` select and its 12-item type strip; `/dns-lookup/mx-records` and `/any-records` titles; the 135 per-provider `/dns/*` pages; the full tool inventory on `/dns-tools.html`; the Chrome extension page's own claims; privacy policy text and its 20 Aug 2020 date; dev-blog dates and wording (2008 launch + record types, 2009 colour-blind markers + server database, 2010 link sharing + Offensive IP Database, 2012 rewrite, 2013 flags, 2015 SRV + capacity, 2017 CAA, Aug–Sep 2020 Tailwind rewrite / Lookup tool / D3 map / detail-panel merge).
**Inferred, not observed:** that the ad tags currently render as ads (script sources and slot ids only); that Laravel is the backend (the legacy `/api/check` `_token` param name is the only evidence); that the 2026 resolver roster is sourced the way the 2008/2010 posts describe; exact live rate limits, which are unpublished.
**Still unresolved:** what `server=global` does in the Lookup picker. It is one `<option>` among five named public resolvers, which fits either "fan out" or "pick one", and it is *not* the same thing as the `/dns/global` page (that lists Cloudflare, Comodo, Google, OpenDNS, Quad9, Verisign). Do not build on either reading. I also could not re-run the Wayback CDX path sweep (API down all day), and the Chrome extension was never installed or run.
**Not observed at all:** any rendered result page, from either tool, because the Cloudflare challenge never cleared for any client I have. Every statement about result rendering is from their markup, their JS, their API responses and their own blog posts.

## Open source / reusable

Nothing. No public repo, no license, no published API contract, no data dump. The resolver roster in `/api/servers` is the one genuinely scarce asset and is not licensed for reuse. Everything transferable here is a **design pattern**, not code. For a Go implementation the reusable pieces are `miekg/dns` for the queries plus a resolver table you maintain yourself; the ideas above are what to build on top.

## Sources

- [whatsmydns.net homepage — record types, grid, copy](https://www.whatsmydns.net/) (live 403 to non-browsers; read via [archived snapshot 2026-09-15](https://web.archive.org/web/20260915130048/https://www.whatsmydns.net/))
- [`js/app.js` — fan-out, tick test, hash routing, detail renderer](https://web.archive.org/web/20260908212908id_/https://www.whatsmydns.net/js/app.js)
- [`/api/servers` — resolver roster JSON, 2026-07](https://web.archive.org/web/20260729081124id_/https://www.whatsmydns.net/api/servers)
- [`/api/details` — decoded DNS message response shape](https://web.archive.org/web/20230920235942/https://www.whatsmydns.net/api/details?server=dajkegaj&type=A&query=0.sd)
- [`/api/domain` — whois JSON + the "contact api@whatsmydns.net … API is in beta" note](https://web.archive.org/web/20250621115549/https://www.whatsmydns.net/api/domain?q=1-pizza.com)
- [`/dns-tools.html` — complete tool inventory](https://web.archive.org/web/20260801131630/https://www.whatsmydns.net/dns-tools.html)
- [`/dns-lookup` — the plain `<form method="GET">`, the `server` select, the 12-item ALL/ANY type strip, the Checker cross-link](https://web.archive.org/web/20260823182553/https://www.whatsmydns.net/dns-lookup)
- [`/dns-lookup/mx-records` — an SEO preset page, title and description verified](https://web.archive.org/web/2026/https://www.whatsmydns.net/dns-lookup/mx-records)
- [Dev blog — Advanced Link Sharing, 10 Mar 2010 (hash permalinks)](https://web.archive.org/web/20240520023901/https://www.whatsmydns.net/blog/advanced-link-sharing.html)
- [Dev blog p1 — DNS Lookup Tool, 18 Aug 2020; Lookup data merged into the Checker, 19 Sep 2020; D3.js/TopoJSON map, 10 Sep 2020; Tailwind rewrite, 4 Aug 2020; SRV 2015; CAA 2017](https://web.archive.org/web/20260715143240/https://www.whatsmydns.net/blog)
- [Dev blog p2 — "kindly provided by the Offensive IP Database", 9 Nov 2010; 2012 rewrite; UK server database, 2009](https://web.archive.org/web/2026/https://www.whatsmydns.net/blog?page=2)
- [Dev blog p3 — launch 7 Jun 2008 ("randomly selected name servers"); record types 26 Jun 2008; colour-blind status markers 5 Sep 2009](https://web.archive.org/web/2026/https://www.whatsmydns.net/blog?page=3)
- [Privacy policy — IP + query collection, third-party forwarding, PII-stripping claim, ad cookies, CCPA, last updated 20 Aug 2020](https://web.archive.org/web/20260715143225/https://www.whatsmydns.net/privacy-policy.html)
- [`/reverse-dns-lookup` — FCrDNS validation](https://web.archive.org/web/20260727093559/https://www.whatsmydns.net/reverse-dns-lookup)
- [`/dns-lookup/chrome` — extension walkthrough + Web Store link](https://web.archive.org/web/2026/https://www.whatsmydns.net/dns-lookup/chrome)
- [Chrome Web Store — "DNS Lookup", user count + ratings (fetched live 2026-09-16)](https://chromewebstore.google.com/detail/dns-lookup/ekbgejcpgolcbfcaeapipnaoemoomcgf)
- [`/dns/usa`, `/dns/uk`, `/dns/global` — per-provider page counts](https://web.archive.org/web/2026/https://www.whatsmydns.net/dns)
- [SourceForge directory listing — corroborates free-only pricing](https://sourceforge.net/software/product/whatsmydns.net/)
- [RFC 8482 — refusing ANY queries (why ANY mostly returns HINFO)](https://www.rfc-editor.org/rfc/rfc8482.html)
- [Companion: firsthand browser observations across the DNS tool set](firsthand-ui-observations.md)
- [Sibling report: DigWebInterface's record-type selector, counted against the IANA registry](digwebinterface.md)
