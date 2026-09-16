# DNSChecker.org

The mass-market **global DNS propagation checker**: enter a name, pick a record type, watch 28 resolvers spread over 21 countries answer one row at a time on a world map. Domain owned by **Softrix Technologies** per its own privacy policy; Softrix's portfolio page carries a Faisalabad, Pakistan address. Free, ad-funded, no account. Around the propagation widget they have bolted an ~88-tool grab-bag (DNS, IP, email-auth, SEO, plus QR codes and a Morse translator). Relevant to us twice over: it is the reference UX for "did my DNS change land yet", and it is the cautionary tale of what a tools site looks like when nobody says no.

- **URL:** https://dnschecker.org/ · **Category:** free ad-supported DNS propagation + general web-tools portal · **Registration:** none, no login surface on any page read · **Pricing:** $0, display ads · **API:** no public/documented API. Internal AJAX endpoints only, CSRF-gated.
- **Firsthand check:** `curl` on the live site **403s w/ `cf-mitigated: challenge`** (Cloudflare managed challenge), re-confirmed 2026-09-16 on `/` and on `/ajax_files/api/...`. Only `/robots.txt` serves live (200). I did **not** spoof a crawler UA to get past it. Page content came from **Wayback raw snapshots** (`web.archive.org/web/<ts>id_/`), dated inline, **including their un-minified front-end JS** (`main.js`, `index.js`, `draw_chart.js`, `all-dns-records-of-domain.js`), which is where most of the mechanism below is read from source rather than guessed. Independently probed w/ `dig`: 28 resolvers from their default list, TTL/AD-flag comparisons, CD-bit mechanic. Also probed `cfwho.com/api/v1/` (their third-party ASN backend) live.

## What it is

Three products stacked on one domain: the **propagation checker** (`/`), a fan-out of one query to many geographically dispersed **open recursive resolvers**, rendered as table + map; **DNS lookup** (`/all-dns-records-of-domain.php`), a single-resolver all-record-types dump w/ TTLs, a resolver picker that includes **the domain's own authoritative NS**, and Markdown/text export; and **everything else**, ~88 tools on their own index, roughly half DNS/IP/email-auth/network and the rest long-tail SEO filler.

## Registration, access & pricing

No account, no API key, no paid tier found (checked 2026-09-16 across homepage, all-tools, DNS lookup, health checker, privacy policy: no login, register, pricing or upgrade link anywhere). Funding is display ads: `a.pub.network/dnschecker-org/pubfig.min.js` plus `google_ads` blocks, and the privacy policy names **Freestar** as the ad partner. The "Ads keep servers running. Donate instead?" PayPal block still exists in the homepage source but is **both HTML-commented out and `display:none`**, so donations are not currently solicited. A `PayPro Global` TXT record sits on the apex (re-confirmed live 2026-09-16), which normally means a checkout processor is or was configured; no product it would sell is visible. An Android app exists (`/mobile-app`, linked via `/out/dnschecker_gplay`) and a Chrome extension (`gegfpbhjnhegdnjdkghhnneaocdbbhjp`); both free, both listings behind a Google consent wall I did not accept.

Beware two traps. "DNS Checker API" products on RapidAPI/Zyla/api.market are **third-party resellers**, unaffiliated w/ dnschecker.org. And a web search for DNSChecker pricing returns a confident "$29/mo Pro plan, free tier capped at 1 domain": that figure belongs to other products in the result set, not to dnschecker.org, and no first-party page supports it.

## Features, complete inventory

Grouped by aspect. Path = the actual page. Tool list enumerated from the archived `/all-tools.php` (snapshot 2026-08-25), which links **88 distinct tool paths**.

**Propagation (the core)**

| Feature | Detail |
|---|---|
| Multi-resolver propagation check | `/`, 28 resolvers, 21 countries; site's own copy claims "100+ global DNS servers" |
| Region-scoped propagation | `/continent/{africa,antarctica,asia,europe,northamerica,australia,southamerica}/` (7), `/country/{cc}/` (28 countries) |
| IP-family-scoped propagation | `/ip/6/` runs the same check against **IPv6 resolvers**; homepage sets `dns_key="ip"; dns_value="4"` |
| **Expected Value matcher** | Free-text expected answer + radio **`exact_match` / `contains` / `reg_match`** (exact is default). Tick/cross computed against this |
| **CD Flag checkbox** | Labelled "CD Flag", tooltip "Ask DNS Server NOT to perform DNSSEC validation before replying", **`checked` by default** |
| **Auto-refresh** | Checkbox + seconds field, **clamped to 20-60s**, persisted in a `refresh_dns_results_every` cookie |
| Resolved / Unresolved counters | Two button-styled tallies, **only un-hidden when an Expected Value is set**. Counters, not filters |
| **Add a custom DNS server** | Modal takes DNS name, IP, provider, map lat, map long, validated via `/check_custom_dns_ip.php`; checkbox submits it to the public list. Custom rows persist in **localStorage**, per browser |
| World map | **d3 v7 (`geoMercator`/`geoPath`) + topojson**, rendered only when `screen_size == 'lg'`. Clicking a marker replaces the map w/ a detail panel showing that resolver's **raw `<pre>` result** |
| Permalink | Result state written to the URL **hash** as `#TYPE/name[/expected]`; reloading pre-fills the form and offers a "Load" button |

**Record lookup**

`/all-dns-records-of-domain.php` (ALL + 12 types as radios, 6 resolver choices, **TTL column on every record type**, Expand All, Jump-to-record nav, **Download/Copy in Markdown and in plain text**, per-IP ASN annotation, WHOIS and blacklist annotations) · `/cname-lookup.php` · `/ns-lookup.php` · `/mx-lookup.php` · `/dnskey-lookup.php` · `/ds-lookup.php` · `/domain-ip-lookup.php` · `/reverse-dns.php` · `/ip-to-hostname.php`

**Health audit & validation**

`/domain-health-checker.php` — the big one. Result blocks observed in markup: **DNS · SPF · NS · DMARC · MX/SMTP · MX Blacklist**, rolled up as **Errors / Warnings / Passed** counters, under headings Complete Report, Blacklist Test Results, Mail Test Results, DNS Test Results, Problems (Warnings). Warns "It may take up to 5 minutes". · `/dns-record-validation.php` — lighter DNS-standards linter.

**Email authentication**

`/spf-record-validation.php` · `/dmarc-record-validation.php` · `/dmarc-record-generator.php` · `/dkim-record-checker.php` · `/bimi-record-lookup-generator.php` · `/smtp-test-tool.php` · `/email-header-analyzer.php` · `/email-verifier` (emits a **PDF report**)

**Reputation / blocklists**

`/ip-blacklist-checker.php` — IP + email blacklist check across multiple DNSBLs; also embedded in the health checker and inline in DNS-lookup A-record rows.

**IP & network**

`/whats-my-ip-address.php` · `/what-is-my-isp.php` · `/ip-location.php` · `/ip-whois-lookup.php` · `/ipv6-whois-lookup.php` · `/asn-whois-lookup.php` · `/ping-ipv4.php` · `/ping-ipv6.php` · `/online-traceroute.php` · `/port-scanner.php` · `/mac-lookup.php` · `/internet-speed-test` · `/user-agent-info.php`

**IP math** (all client-side calculators, no lookup)

`/netmask-cidr.php` · `/ipv4-to-ipv6.php` · `/ipv6-to-ipv4.php` · `/ipv6-compress.php` · `/ipv6-expand.php` · `/ipv6-cidr-to-range.php` · `/ipv6-range-to-cidr.php` · `/ipv6-address-generator.php` · `/ipv6-compatibility-checker.php` · `/ip-to-decimal.php` · `/mac-address-generator.php`

**Web / server**

`/server-headers-check.php` · `/ssl-certificate-examination.php` · `/website-server-software.php` · `/website-broken-link-checker.php` · `/website-link-analyzer.php` · `/search-domain-name-checker.php` · `/idn-punycode-converter.php`

**Reference content** (no input, pure SEO surface, but genuinely useful)

`/public-dns` — public resolvers indexed by **158 country pages** (counted in the 2026-08-01 snapshot) · `/dns` — ISP resolver lists for Global, US, UK, Australia (e.g. `/dns/United-States-of-America`) · `/flush-dns.php` — per-OS cache-flush instructions · `/blog`

**Filler** (for completeness, all off-topic): SEO (SERP preview, robots.txt / htaccess / URL-rewrite generators, Open Graph checker, PageRank); crypto & text (MD5, ROT13, password generator/strength/encryption, binary + Morse + Runic translators, lorem ipsum, word counter, small-text, invisible character, notepad, JSON viewer, URL opener); QR (generator, scanner, WiFi QR scanner); colortone converters (RGB/HEX/CMYK/HSV); BIN checker, credit-card validator, RAID calculator, time-card calculator, reverse image search, social-media name checker, image-to-text, Minecraft colour codes. A per-tool star-rating feedback widget (`tool_id`) sits on the tool pages.

## Record types & query options supported

| Knob | Supported? |
|---|---|
| RR types, propagation | A, AAAA, CNAME, MX, NS, PTR, SRV, SOA, TXT, CAA, DS, DNSKEY (12) |
| RR types, DNS lookup | same 12 + **ALL** (13 radios) |
| Choose resolver | DNS lookup page: `dns=` ∈ `google`, `cloudflare`, `opendns`, `quad9`, `yandex`, **`dnsauth`** ("Authoritative DNS", the domain's own NS) |
| Choose many resolvers | propagation page only, via the curated list + custom-added servers |
| **CD (Checking Disabled) bit** | **Yes**, a default-on checkbox, sent as `cd_flag=1`. Their own tooltip says it asks the resolver not to validate DNSSEC |
| DNSSEC validation display | **No.** DS/DNSKEY records are *shown*, chain-of-trust is never *validated*; no AD-flag display; CD is on by default, so validation is actively suppressed |
| Delegation trace / `+trace` | **No** |
| TTL display | **Split.** DNS lookup page shows a **TTL column** for every record type. Propagation table does **not** |
| Query time / latency | **No**, on either page |
| TCP, EDNS buffer size, ECS (client subnet) | **No** |
| Raw answer | Propagation: a raw `<pre>` blob per resolver, reachable only by clicking that resolver's map marker. DNS lookup: **Download/Copy in Markdown or plain text**. **No JSON export** on either |
| Shareable result URL | **Both.** DNS lookup `?query=&rtype=&dns=` via `pushState`; propagation `#TYPE/name[/expected]` via the hash |

## How it works

**Server-side fan-out, one HTTP request per resolver.** The homepage embeds the resolver set inline as `var dns_json_array = [{"id":1,"ip":"208.67.222.220","provider":"OpenDNS","location":"San Francisco CA, United States","latitude":38,"longitude":-122,"country":"US"}, ...]` and mirrors it into `<tr data-id data-latitude data-longitude data-location data-provider>` rows. `index.js` then iterates those rows and calls, per resolver:

```
GET https://dnschecker.org/ajax_files/api/{server_id}/{RRTYPE}/{name}?dns_key=ip&dns_value=4&v={VER}&cd_flag={0|1}
```

Read straight from their source: `` let apiURL = `${ajax_url}/api/${server_id}/${_t.value}/${_q.value}` ``, with `params: { dns_key, dns_value, v: VER, cd_flag }`. `{server_id}` is the DB id from that array, not a loop index. On the 2026-01-06 homepage the 28 ids run 1, 4, 9, 18, 24, 38, 67, 71, 77, 78, 81, 88, 101, 122, 136, 213, 214, 234, 256, 273, 312, 337, 383, 427, 442, 455, 459, 460. Id 460 in a 28-row sample suggests a resolver table with a few hundred rows; the exact size is not observable.

Requests are **CSRF-protected**: `_sendFetch` in `main.js` fetches `/ajax_files/gen_csrf.php`, caches `{csrf, ttl}` and attaches the token as a **`csrftoken` request header** on every subsequent call, refreshing it before expiry. That same endpoint doubles as their "what's my IP" source, returning `{csrf, ttl, ip, version, web_notification_key, browser}`. Requests go out with `credentials: 'include'`, `cache: 'no-store'` and a random `upd` cache-buster. The response is `{errors: [], result: {status, ips, ips_with_link, location, latitude, longitude, provider, version, _result}}`; `status == 'active'` draws a tick, anything else a cross.

The **expected-value comparison happens in the browser**, not server-side: `exact_match` is `ipsDataArray.includes(value)` (membership in the split answer list, so RRset ordering does not matter), `contains` is `.some(v => v.includes(value))`, `reg_match` is `.some(v => v.match(value))` wrapped in try/catch. A failed match rewrites `status` to `'closed'`, which is what flips the row to a cross.

The actual DNS query is issued **from their servers to the remote open resolver**, not from the visitor's browser (a browser cannot send UDP/53, and the endpoint takes a server id rather than an IP). That part is inference from the endpoint shape plus browser limits, not observation. Recursive throughout, except the DNS-lookup page's `dnsauth` mode, which targets the zone's own authoritative NS.

The DNS lookup page is a separate mechanism: `POST /ajax_files/all_dns_records_of_domain.php` with a Turnstile token, returning `result.records` keyed by RR type, each record carrying `ttl`. It then enriches every returned IP by calling the third-party **`https://cfwho.com/api/v1/{ip}`**, which I probed live: 200, no key, `access-control-allow-origin: *`, returns `{asn, netname, network, country, contacts.abuse, version}`.

`cd_flag` is the DNSSEC CD bit, now settled by their own tooltip text rather than by the parameter name. The mechanic, verified locally:

```
dig A dnssec-failed.org @8.8.8.8        -> status: SERVFAIL, ANSWER: 0
dig +cd A dnssec-failed.org @8.8.8.8    -> status: NOERROR,  ANSWER: 1, flags: ... cd
```

That is how you keep a propagation table from going all-red on a zone w/ a broken signature. Note they ship it **on by default**, which is a deliberate "never show the user a SERVFAIL" choice.

Infrastructure: apex and MX are entirely **Cloudflare** (A 104.26.7.89 / 104.26.6.89 / 172.67.73.216, NS `eric|gail.ns.cloudflare.com`, MX `*.mx.cloudflare.net`), and the edge runs a managed challenge aggressive enough to 403 plain curl.

## Output & UX

Three columns, each row starting filled w/ `-`: **name** (country flag SVG, "San Francisco CA, United States", provider + resolver IP w/ an info icon carrying `data-clipboardtext` and a `copied_text` confirmation, so **click-to-copy**), **result** (the answer values), **status** (`icon-dot-circle` pending, then `icon-checked-filled` in green or `icon-cross-mark` in red).

Rendering is **progressive**: 28 independent `fetch` calls land independently, so rows fill as they arrive rather than blocking on the slowest. Above the table sit the Resolved / Unresolved tallies, hidden until an Expected Value is typed. The map plots each row from its `data-latitude`/`data-longitude` and is the one place a **raw per-resolver result** surfaces, behind a marker click. The site also ships a dark mode.

Error states are weak: a dead resolver and a genuinely absent record both render as a cross, and the `.catch` branch renders a cross too. Standing caveat on the page: "Complete DNS Resolution may take up to 48 hours." The Android app is advertised as adding **lookup history** and **favourites**, which the web UI lacks; that claim is from DNSChecker's own `/mobile-app` copy (2024-12-03 snapshot), not from the store listing.

## Monetization, limits & abuse controls

Display ads via Freestar. No published rate limit, no quota, no key. Abuse controls live at the edge and in the session layer, not in a documented policy: a **Cloudflare managed challenge** in front of everything except `/robots.txt` (the real rate limiter); **CSRF token + `csrftoken` header** on the AJAX endpoints, which stops trivially scripting them; and **Cloudflare Turnstile**, loaded explicitly (`challenges.cloudflare.com/turnstile/v0/api.js?render=explicit`) on the DNS lookup page and referenced in the health checker's CSS. The captcha layer is a pluggable google-vs-cloudflare switch in `main.js`; the **homepage** snapshot has it off (`CaptchaEnable = !!0`), so it is enabled per tool, not site-wide. `robots.txt` (fetched live 2026-09-16) disallows only `/out/`, `/ot/`, `/go.php?url=*`, `/cdn-cgi/`, the affiliate redirectors. Tool pages are deliberately fully crawlable; the whole business is organic search.

## Ideas worth stealing

- **Expected-value matcher w/ exact / contains / regex.** The single best idea on the site, and cheap in Go. The user pastes the value they *just set* at their registrar, and each resolver row becomes a real pass/fail instead of a wall of strings to diff by eye. Copy their membership semantics, not a whole-string compare: match against the *set* of returned values so round-robin ordering never reads as failure. `strings.EqualFold`, `strings.Contains`, `regexp.MatchString`, three radio buttons, done.
- **Per-resolver row streams in independently.** Their mechanic is one HTTP request per resolver. The htmx-native version is better: render N rows server-side w/ `hx-trigger="load"` + `hx-get="/dns/row?resolver=8.8.8.8&type=A&name=..."`, each swapping itself. Zero client JS, no fan-out state, one slow resolver cannot stall the page, and it degrades to a plain table w/o JS. Rule #2 in CLAUDE.md is already satisfied since each row handler can also answer JSON.
- **Auto-refresh w/ an interval box, clamped.** Propagation is a waiting game. `hx-trigger="every 30s"` on the results container, driven by a user-set seconds field. Steal the clamp too: they floor at 20s and ceiling at 60s, which is the right instinct for a fan-out you are paying for. Pair w/ a "stop when all match expected" condition.
- **`dnsauth` as a first-class resolver choice.** Offering "ask the zone's own authoritative NS" next to Google/Cloudflare/Quad9 is the one option that answers "is my change live at the source, or just not cached yet". Trivial in Go: `NS` lookup, then re-query the target directly against one of the returned nameservers. Distinguishes "not propagated" from "not published", the actual question the user has.
- **Two copy affordances.** Click-to-copy on the resolver IP behind an info icon keeps the row clean and the IP one click away. And their lookup page has four export buttons (download/copy, Markdown/plain text) and no JSON: we can ship all three since rule #2 already forces a JSON representation, but copy-as-Markdown is the one people actually use, for pasting into a ticket.
- **TTL as a first-class column, on *both* views.** They show TTL on the lookup page but not on the propagation table, which is exactly backwards: TTL is the propagation story. Firsthand, `cloudflare.com` A came back w/ TTL 300 from 8.8.8.8, 150 from 1.1.1.1 and 277 from 9.9.9.9 in the same second. A low remaining TTL means that resolver's cache is about to re-fetch. Add query time next to it: `miekg/dns` hands you both.
- **CD-bit escape hatch.** Offer an "ignore DNSSEC validation failures" checkbox that sets the CD bit, so a broken-DNSSEC zone shows records instead of a table of SERVFAILs. Unlike them, default it **off** and surface the AD flag, so a validating answer is visible as such.
- **Resolved / Unresolved rollup above the table**, made clickable as filters, which is the one-line improvement they left on the floor.
- **Custom resolver add.** Let the user paste a resolver IP and add a row. Free for a self-hosted tool (no lat/long DB, just label it "custom"), and it covers "check against my corporate resolver" that no fixed list can. They persist theirs in localStorage, the right call for a stateless tool.
- **Reuse the existing Mongo lookup-history repo.** Their Android app has history + favourites, their web app has neither. `tools/iptools/history.go` already establishes the pattern, and a DNS feature gets it nearly free.
- **`cfwho.com/api/v1/{ip}` for ASN**, if we ever want ASN without shipping a BIN: keyless, CORS `*`, returns ASN + netname + abuse contact. We already have IP2Location ASN data, so this is a fallback, not a dependency.

## Gaps & what it does not do

- **No query time anywhere, no TTL on the propagation table, no raw answer without a map-marker click.** The things that tell you *why* two resolvers disagree are present-but-buried at best.
- **No DNSSEC validation, and CD on by default.** It shows DS and DNSKEY records; it never checks the chain or surfaces the AD flag, and it ships the checkbox that *suppresses* validation pre-ticked. I got `flags: ... ad` from 8.8.8.8, 9.9.9.9 and 80.80.80.80 on `cloudflare.com` w/ two lines of `dig`; a validation verdict is not hard, they just do not do it.
- **No delegation trace**, no "which nameserver is lying" view, no SOA serial comparison across a zone's NS set. For diagnosing a stale secondary this is the tool you actually want and nobody here ships it.
- **A cross means three different things.** Record absent, resolver dead, or resolver refused. My `dig` sweep of their 28-resolver default list (2026-09-16, `+time=4 +tries=1`, counting only rows that returned an address) got answers from **21 and nothing from 7** (204.12.225.227, 207.177.68.4, 94.232.184.146, 31.192.98.158, 187.6.84.178, 114.114.115.115, 114.130.5.6). A quarter of the default list did not answer from my vantage point. Any of those rows would read as "not propagated". A curated open-resolver list decays and needs health-checking; theirs shows no evidence of it.
- **Multi-record RRsets are a trap for the naive implementation, though not for theirs.** `example.com` has two A records (104.20.23.154 and 172.66.147.243, Cloudflare-hosted) and resolvers hand back different orderings run to run. DNSChecker dodges this by testing set membership; a "do all rows show the same string" check would flag healthy round-robin and GeoDNS as unpropagated. Compare *sets*, and say so in the UI.
- **No API**, no JSON export, and Cloudflare-challenged end to end, so unscriptable and unmonitorable. The permalinks exist but only restore form state, they do not re-run the check.
- **Enormous unfocused surface.** 88 tools on their own index, most unrelated. Worth naming as an anti-pattern: SEO long-tail farming, not a coherent product.

## Verified firsthand vs inferred

**Verified firsthand:** live 403 + `cf-mitigated: challenge` on `/` and `/ajax_files/api/...` (2026-09-16); `/robots.txt` 200 w/ its exact contents; the apex A/NS/MX/TXT records incl. the `PayPro Global` TXT; the 28-entry `dns_json_array`, its id list, schema and 21 distinct countries; the 7 continent and 28 country URLs and `/ip/6/`; `dns_key="ip"`/`dns_value="4"` as page globals; the API URL template and its `{dns_key, dns_value, v, cd_flag}` params, read from `index.js`; the `csrftoken` header + `gen_csrf.php` flow and its response shape, read from `main.js`; the three `comp_opt` radios and their client-side comparison semantics; the CD Flag checkbox, its default-checked state and its tooltip wording; the 20-60s auto-refresh clamp and its cookie; the custom-DNS modal fields, `/check_custom_dns_ip.php` and localStorage persistence; the hash permalink on `/` and the `pushState` `?query=&rtype=&dns=` permalink on the lookup page; the tick/cross/pending icon classes; the 3-column row markup w/ `data-clipboardtext` click-to-copy; the map being **d3 v7 + topojson** and its marker-click raw-result panel; the 12 propagation record types; the lookup page's 13 record radios, 6 resolver options and **TTL column**; its Markdown/text download+copy buttons and its `POST /ajax_files/all_dns_records_of_domain.php` endpoint; the Turnstile script tag on that page and `CaptchaEnable = !!0` on the homepage; the health-checker result-block ids and headings; the 88-entry all-tools link list; 158 country pages under `/public-dns`; the "owned by Softrix Technologies" line in the privacy policy and Freestar as ad partner; the donate block being commented out; `cfwho.com/api/v1/8.8.8.8` returning 200 w/ `access-control-allow-origin: *`; the 21/28 resolver reachability result; the TTL 300/150/277 split; AD flags on three resolvers; CD-bit SERVFAIL-vs-NOERROR behaviour.

**Inferred, not observed:** that the backend issues the DNS queries rather than the browser (forced by browser UDP limits plus an endpoint keyed on a server id, but not observed); the size of the resolver table behind the 28 shown (id 460 appears in the sample, nothing more); that the `PayPro Global` TXT implies a checkout processor is or was configured.

**Could not verify at all:** the live rendered result page, since every fetch is challenged, so everything above is pre-load markup plus their own JS rather than a running page. `data.result._result`, the raw blob shown on marker click, is never observed, only the `<pre>` wrapper. CORS on the AJAX endpoints could not be assessed: an `Origin`-bearing GET and an OPTIONS preflight both returned the Cloudflare challenge w/ no `access-control-*` headers, though their page CSP is `connect-src 'self'`. The Chrome extension and Android app listings sit behind a Google consent wall (302 to `consent.google.com`) I did not accept; app features come from DNSChecker's own `/mobile-app` page (2024-12-03 snapshot). No paid tier was found, which is weaker than confirming none exists. The Faisalabad address is Softrix's, from their own site, not DNSChecker's privacy policy. Pages the previous pass cited but which are linked from none of the pages I read, so unconfirmed: `/mx-record-validation.php`, `/dns-servers.php`, `/best-vpn-services.php`, `/browser-extension-privacy-policy.php`, `/dns-articles/`.

## Open source / reusable

Nothing. Closed PHP, no repo, no licence, no API. Reusable pieces are all conceptual, plus two data sets worth lifting by hand once if we want them: the `/public-dns` per-country resolver lists (158 countries) and the `/dns/{country}/{isp}` ISP resolver lists. For a Go implementation the real dependencies are `github.com/miekg/dns` (full control over CD/DO bits, EDNS, TCP, TTL, per-query timing, which `net.Resolver` will not give you) and a hand-curated, health-checked resolver list of our own.

## Sources

- [DNSChecker.org homepage, propagation checker](https://dnschecker.org/) (Wayback raw snapshot `20260106120849`; live fetch 403s). Its three un-minified scripts, same snapshot, carry most of the mechanism: [`index.js`](https://dnschecker.org/themes/v2/js/index.js) (API template, cd_flag, match modes, refresh clamp), [`main.js`](https://dnschecker.org/themes/v2/js/main.js) (`_sendFetch`, `gen_csrf.php`, `csrftoken` header, captcha switch), [`draw_chart.js`](https://dnschecker.org/themes/v2/js/draw_chart.js) (d3 `geoMercator`/`geoPath` + `topojson.feature`, marker-click panel)
- [DNS Lookup tool page](https://dnschecker.org/all-dns-records-of-domain.php) (Wayback `20260903075426`) and its [`all-dns-records-of-domain.js`](https://dnschecker.org/themes/v2/js/all-dns-records-of-domain.js) (TTL columns, Markdown/text export, `pushState` permalink, cfwho ASN calls)
- [DNSChecker all-tools index](https://dnschecker.org/all-tools.php) (Wayback `20260825174023`; 88 tool paths)
- [Domain DNS Health Checker](https://dnschecker.org/domain-health-checker.php) (Wayback `20260716045726`)
- [Public DNS servers by country](https://dnschecker.org/public-dns) (Wayback `20260801131627`; 158 country links)
- [DNSChecker privacy policy, names Softrix Technologies as owner and Freestar as ad partner](https://dnschecker.org/privacy.php) (Wayback `20260703155224`)
- [Softrix Technologies portfolio page for DNSChecker, source of the Faisalabad address](https://softrixtech.com/portfolio/dnschecker/)
- [DNSChecker Android app feature list](https://dnschecker.org/mobile-app) (Wayback `20241203183305`)
- [DNSChecker robots.txt](https://dnschecker.org/robots.txt) (fetched live 2026-09-16, HTTP 200)
- [cfwho.com ASN API, probed live 2026-09-16](https://cfwho.com/api/v1/8.8.8.8)
- [RFC 4035 §3.2.2, the CD bit (§3.2.1 DO, §3.2.3 AD)](https://www.rfc-editor.org/rfc/rfc4035#section-3.2.2)
- [RFC 1035, DNS implementation and specification, TTL semantics](https://www.rfc-editor.org/rfc/rfc1035) · [Cloudflare Turnstile client-side rendering](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/) · [d3-geo](https://d3js.org/d3-geo)
- [miekg/dns, the Go DNS library that exposes CD/DO/EDNS/TTL](https://github.com/miekg/dns)
