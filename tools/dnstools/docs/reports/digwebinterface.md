# DigWebInterface

`dig(1)` exposed as an HTML form. One hobbyist, **Martin Holk Rasmussen**, has run it since 2006 on a single OVH VPS, funded by ads + PayPal donations. It is the opposite product to NsLookup.io: **zero interpretation, total control**. It does not decode your SOA or name your DNS provider. It hands you the raw BIND text and gives you 12 checkboxes, 5 nameserver modes and 49 selectable query types to shape it. Relevant to us because it is the closest existing thing to "a Go binary shelling out DNS queries and rendering the answer", and because its two best mechanics (annotate-the-raw-text, and every-control-in-the-querystring) are cheap to copy and worth more than the tool's dated looks suggest.

- **URL:** https://www.digwebinterface.com/ · **Category:** raw-dig web frontend, power-user diagnostics · **Registration:** none, no account exists · **Pricing:** free, donation-funded · **API:** none (see *Monetization* for what actually evidences that)
- **Firsthand check:** ~30 live queries by `curl` across **2026-09-15/16**, incl. A/TXT/NS/SOA/MX/HTTPS/Reverse, `+trace`, `+norec`, all 10 bundled resolvers at once with compare, NIC and authoritative modes, colorize, save-to-file, sort-with-stats, and the path-style URL rewrite. Parsed the homepage HTML + inline JS for the full control set. Also `dig`/`whois` against their own infra and the IANA type registry for the record list. Only things not exercised: the CAPTCHA gate (never tripped it), AXFR (declined, house rule), and `/noads.php`/`/nobanner.php` (both `Disallow`ed in robots.txt).

## What it is

A CGI-ish wrapper around real `dig`. The banner in every response reads `DiG 9.16.23-RH`, i.e. a **RHEL-packaged BIND 9.16.23** binary, and the `WHEN:` line prints **CEST** (a Central European operator) even though the host is in Canada. Form submits `GET` to `/`, server shells out once per (hostname x nameserver) pair, HTML-escapes the output, runs an annotation pass over it and returns one fully rendered page. No JS framework, no AJAX, no database, `<font>` tags and `<table border="1">` throughout.

Domain created **2006-03-03** (whois, re-verified 2026-09-16), so ~20 years live. `sitemap.xml` lists **exactly one URL**, the homepage: there is no second tool, no docs page, no about page. The only UI-level "NEWS" item currently on the page: *"All records type are now supported. This means you can now query HTTPS, SVCB, CDNSKEY and many more."*

## Registration, access & pricing

Nothing to register. No tiers, no key, no paid plan, no account page. Funding is a PayPal donate button (`hosted_button_id=YM4LHEK5QURXL`) plus Publift/Fuse ad slots. Two self-service opt-outs live at `/noads.php` (ads off for two weeks) and `/nobanner.php` (hides the donate button), both cookie-based and both fronted by a JS `confirm('This will set a cookie on your computer')`. Charmingly honest, and a monetization posture worth noting: **the user can switch the ads off and the tool still works.**

## Features, complete inventory

### Query construction

| Feature | Param | Observed behaviour |
|---|---|---|
| Multi-hostname batch | `hostnames` (textarea) | Newline **or whitespace** separated. Fed `not a hostname!!` and it split into 3 queries (`not`, `a`, `hostname!!`). Result = matrix of hostname x nameserver, one labelled block each. |
| Record type | `type` | One flat 62-option `<select>` in two visual tiers: 11 common (A AAAA ANY AXFR CNAME MX NS PTR SOA TXT + `Reverse`), blank separator, then all 49. Blank = "Unspecified" = dig's default. No `<optgroup>`. |
| Reverse lookup | `type=Reverse` | Emits `dig +nocmd -x <ip> …` (the `+nocmd` is emitted twice, a string-concat tell), builds `in-addr.arpa` for you. Verified on `8.8.8.8` -> `dns.google.` |
| Absolute-name forcing | implicit | Always appends the root dot (`corpberry.com.`), so server-side search domains can never widen your query. |
| IDN + URL/email cleanup | `Fix` button | Client-side only, `puny.js`. Regex-extracts the host out of a URL or the domain out of an email, then runs `punycode.ToASCII()` **only on lines containing non-ASCII** (guard: `/^[\x20-\x7e]+$/`). Never touches the network. |

### Resolver / vantage selection

| Mode | Param | Notes |
|---|---|---|
| Named public resolver | `ns=resolver&useresolver=<ip>` | 10 bundled, with country tags: Cloudflare `1.1.1.1`, AdGuard (CY) `94.140.14.14`, AT&T (US) `165.87.13.129`, Comodo (US) `8.26.56.26`, Google `8.8.8.8`, HiNet (TW) `168.95.1.1`, OpenDNS `208.67.222.222`, Quad9 `9.9.9.9`, Verisign (US) `64.6.64.6`, Yandex (RU) `77.88.8.8`. |
| All of them | `ns=all` | Fires all 10 sequentially in one page load. |
| Authoritative | `ns=auth` | Resolves the zone's own NS set and queries **each** of them. Verified: hit `dion.` and `lisa.ns.cloudflare.com` for `corpberry.com`. |
| NIC / registry | `ns=nic` | Queries the **TLD** servers, i.e. the parent side of the delegation. Verified: answered by `h.gtld-servers.net.`, returning NS in AUTHORITY + glue A/AAAA in ADDITIONAL. This is intoDNS's parent-vs-child check with none of the test catalogue. |
| Arbitrary list | `ns=self&nameservers=<newline list>` | Free-text textarea, IPs or names. |
| Cap the fan-out | `onlyfirst=on` | Use only the first NS. Meaningful for `auth`/`nic` where the list can be 13 servers. |

### Output control (checkboxes, with the dig flags they actually produced)

| Label | Param | Flags observed on the `Show command` line |
|---|---|---|
| (default, Stats off) | | `+noadditional +noquestion +nocomments +nocmd +nostats` |
| Stats | `stats` | `+additional` (unsuppresses dig's header, flags, OPT pseudosection, query time, SERVER, WHEN, MSG SIZE) |
| Show command | `showcommand` | No dig flag. Prints the literal command in italics above the `<pre>`. |
| Colorize output | `colorize` | No dig flag. Wraps fields in `<font color>`: owner blue, TTL red, class green, type purple, RDATA navy. |
| Request NS ID | `nsid` | `+nsid`. Returned `NSID: … ("gpdns-yul")` from Google, i.e. RFC 5001 server identity. |
| Trace | `trace` | `+trace`. Full root -> TLD -> authoritative walk, every line annotated. |
| Sort alphabetically | `sort` | No dig flag. **Post-sorts the output text line by line.** See the wart below. |
| Short | `short` | `+short` on top of the suppression block. Values only. |
| No recursive | `norecursive` | `+norec`. Against `1.1.1.1` this correctly produced `SERVFAIL` + an **EDE 0** extended error, inherited free from dig 9.16. |
| Compare output | `compare` | No dig flag. Appends the comparison table. |
| Save to file | `save` | Writes `output/<md5>.txt`, links it as "Results can be downloaded here". |
| DNSSEC | `dnssec` | `+dnssec`. `+multiline` was also present on that run, as it is for `type=SOA`. |

### Comparison, export, sharing, navigation

- **Compare table.** With 2+ nameservers, a `Comparing output` table renders below the blocks: first resolver is `Base for comparison`, every other is `SAME` (green) or `DIFFERENT` (red), each row anchor-linked to its own result. Live on `corpberry.com` (2026-09-16, `ns=all`): base Cloudflare, `SAME` from AdGuard/Google/OpenDNS/Quad9/Verisign, `DIFFERENT` from AT&T/Comodo/HiNet/Yandex, the latter group returning a two-address RRset. Four lines of output, and it caught a real split answer. The membership of the two groups is **not stable** between runs, and the answers themselves rotate, so treat any specific IP here as a sample and not a fact about the zone.
- **Per-block copy button.** Each result carries a hidden `<textarea id="outputN">` holding the un-annotated text; the copy icon selects it and runs `document.execCommand("copy")`. Clipboard gets clean dig output, never the markup.
- **Download file.** Plain text, `Started: <ISO8601 Z>` header, then `hostname@nameserver (Friendly Name):` blocks holding un-annotated dig text. MD5-named under `/output/`, which robots.txt `Disallow`s. The file is world-readable to anyone with the hash and no expiry is advertised, so **anything you dig is retrievable by URL**; worth remembering before copying the mechanic.
- **Named anchors.** `<a name="corpberry.com-8.8.8.8">` per block, so `#host-nameserver` deep-links into one result inside a 10-block page.
- **Everything in the URL.** Every control round-trips through the query string, and the result page re-renders the form pre-filled with your inputs and checkboxes.
- **Settings-only permalink.** Documented tip: set your options, leave hostnames blank, submit, bookmark. The bookmark is now your preferred configuration.
- **Path-style shortcut.** `/<hostname>/<type>/<nameserver>` **301s** to the canonical query string. Verified: `/corpberry.com/MX/8.8.8.8` -> `?hostnames=corpberry.com&type=MX&ns=self&nameservers=8.8.8.8`; omitted segments fall back to `type=` and `ns=resolver&useresolver=1.1.1.1`. 1, 2 or 3 segments rewrite; 4+ is a 404. The rule is unconditional, so every unknown path on the site becomes a DNS query rather than a 404.
- **OpenSearch descriptor** at `/search.xml`, template `http://digwebinterface.com/{searchTerms}` (note: `http`, not `https`). Adds the tool to the browser's address bar as a search engine, which is what the path-style route exists to serve.
- **Accesskeys on most controls** (`H`ostnames, `T`ype, `C`olorize, Trac`e`, `D`NSSEC, …), `Q` or `Ctrl+Enter` to dig, `0` to reset, `X` to fix. Two controls ship `accesskey=""`, the `Request NS ID` checkbox and the `Resolver` radio, so the coverage is not total.

## Record types & query options supported

Counted programmatically off the live `<select>` on 2026-09-15 and again 2026-09-16: **49 distinct selectable query types**, plus `Reverse` plus "Unspecified". (A hand count off the rendered page in the companion `firsthand-ui-observations.md` came to 44; the machine count ran twice and is the one to trust.)

`A AAAA AFSDB ANY APL AXFR CAA CDNSKEY CDS CERT CNAME CSYNC DHCID DLV DNAME DNSKEY DS EUI48 EUI64 HINFO HIP HTTPS IPSECKEY KEY KX LOC MX NAPTR NS NSEC NSEC3 NSEC3PARAM OPENPGPKEY PTR RP RRSIG SIG SMIMEA SOA SRV SSHFP SVCB TA TKEY TLSA TSIG TXT URI ZONEMD`

**"49 record types" is the site's framing, not IANA's**, and the difference matters if we copy the list. Checked against the IANA DNS-parameters registry on 2026-09-16: `ANY` is not in the RR TYPE registry at all (it is QTYPE 255, query-only); `AXFR` (252) is a QTYPE, "transfer of an entire zone"; `TKEY` (249) and `TSIG` (250) are meta-RRs that exist only inside a transaction and never as zone data. That leaves **45 genuine RR types**, of which `DLV` (32769) is flagged **OBSOLETE** by RFC 8749 and `TA` (32768) is a non-RFC private registration from the pre-signed-root era. `IXFR` is absent from the selector even though `AXFR` is present. A list we ship should drop the 4 meta types and the 2 dead ones unless we have a reason not to.

Knobs present: choose resolver, choose authoritative NS, choose registry/parent NS, specify arbitrary NS, trace delegation, DNSSEC `DO` bit, `RD=0`, NSID, short vs full, raw TTL in seconds with humanized tooltip.

Knobs **absent**: no TCP toggle (`+tcp`), no EDNS buffer size or **EDNS Client Subnet**, no IPv4/IPv6 transport selector, no `+cdflag`, no port override, no timeout/retry control, no DoH/DoT. For a tool that markets itself on dig fidelity, ECS is the conspicuous hole: it is the one flag that would turn the single vantage point into a real geographic propagation check.

## How it works

**Entirely server-side and synchronous.** Grep of a 10-resolver result page: zero `XMLHttpRequest`, `fetch(`, `$.ajax` or `EventSource`. All 10 blocks are present in the initial HTML. One blocking request, TTFB ~0.7s single-resolver, ~1.1s total for the 2-NS authoritative run.

The vantage point is a **single OVH Canada VPS**: `digwebinterface.com` -> `144.217.88.214` (also IPv6 `2607:5300:205:200::7c0d`), PTR `vps-4d0ceac0.vps.ovh.ca`, whois `OrgName: OVH Hosting, Inc.`, country CA. Apache, HTTP/1.1, no CDN. Confirmed by NSID: DigWebInterface's query to `8.8.8.8` was answered by `gpdns-yul` (Montreal), while the same `dig +nsid` from this machine got `gpdns-fra` (Frankfurt).

That matters more than it looks. **You are always asking from Montreal.** The anycast resolvers (Cloudflare, Google, Quad9, OpenDNS) will therefore all answer from their eastern-North-America PoPs, so "all resolvers" does not mean "all over the world". This is a **resolver-diversity** tool, not a propagation-map tool, and it is quietly honest about that by never using the word "propagation".

What it is *not* is a clean proxy for geography. It is tempting to predict that the disagreeing resolvers will be the non-NA ones, but the observed split does not line up: on 2026-09-16 AdGuard (CY) agreed with the Cloudflare base while AT&T (US) and Comodo (US) disagreed. Disagreement here tracks each operator's own cache state and upstream, not the user's location. Any geographic reading of a compare table is the reader's inference and the tool does not support it.

Authoritative and NIC modes are the only recursion-aware logic: the backend resolves the NS set (child for `auth`, TLD for `nic`) before fanning out. Everything else is a straight pass-through. No caching layer of its own, no result store beyond the `/output/*.txt` files.

## Output & UX

Monospace `<pre>` of real dig text, one block per (hostname x nameserver), each headed `hostname@nameserver (Friendly Name):` with a copy icon, and optionally the exact command in italics. It looks like a 2006 web page because it is one.

The part that is not raw is the **annotation pass**, and it runs whether or not you tick Colorize:

```html
<a href="javascript:addhost('corpberry.com.')">corpberry.com.</a>	<span class="help" title="4m 42s">282</span>	IN
  <a href="https://rfc-editor.org/info/rfc1035/"><span class="help" title="Address record. Click to go to the RFC.">A</span></a>	<a href="javascript:addhost('172.64.80.1')">172.64.80.1</a>
```

Five separate ideas in one line of output (markup copied verbatim from a live response, 2026-09-16):

1. **TTL stays an integer, gains a tooltip.** `282` with `title="4m 42s"`, `172800` with `title="2d"`. Every other tool in this category either prints seconds (raw) or replaces them with prose (NsLookup.io's "Revalidate in 5m"). This gets both, non-destructively, at the cost of one `<span title>`.
2. **Record type links to its RFC**, per type and current: `A` -> rfc1035, `HTTPS` -> **rfc9460**, with a tooltip spelling the name out ("HTTPS Binding", "Start of [a zone of] authority record").
3. **Owner names and RDATA are clickable and feed back into the form.** `addhost()` appends to the hostnames box, `addns()` appends to the "Specify myself" box and flips the radio. So a `+trace` result turns the whole delegation chain into a click-to-re-query surface: click `h.root-servers.net.` in the trace and it becomes your next nameserver.
4. **SOA and DNSSEC get `+multiline`**, so dig's own field comments carry through: `10000 ; refresh (2 hours 46 minutes 40 seconds)`, `604800 ; expire (1 week)`. Free SOA decoding, zero code. Every one of those timers also picks up its own tooltip (`604800` -> `title="1w"`).
5. **SOA-specific annotation the rest of the page does not do.** The RNAME is rewritten into a real `mailto:` link with the DNS-to-email conversion applied and the queried zone pre-filled as the subject: `dns.cloudflare.com.` renders as `href="mailto:dns@cloudflare.com?subject=corpberry.com"`. Genuinely useful, and the single most "interpreted" thing on an otherwise uninterpreted page. The serial gets a tooltip too, but see the wart below.

Error and empty states: **none of its own.** Whatever dig says is what you see, `NXDOMAIN`, `SERVFAIL`, `WARNING: recursion requested but not available`, EDE codes and all. There is no "no records found" row, no input validation message, no spinner. Garbage in gets dug and the DNS error is the answer.

## Monetization, limits & abuse controls

- **Stated fair-use policy**, verbatim from the page: *"This tool is not intended for automated lookups. Any other usage is in general welcome and free. To prevent abuse a CAPTCHA needs to be solved for every 100 lookups in a 24 hour period. Failing to solve it may result in a temporary ban."* So: **100 lookups / 24h / client, then reCAPTCHA**, wording re-read verbatim 2026-09-16. `recaptcha/api.js` is loaded on every page. I stayed well under across both sessions and never saw the gate, so the threshold, the ban and the gate's presentation are all the site's word, not observed behaviour.
- **No API and no documented machine interface**, consistent with the policy. Be careful how this is evidenced: `/api`, `/api.php`, `/json` and `/dig.php` do all `301`, but *not* because the paths are reserved. The path-style rewrite swallows any single segment and treats it as a hostname, so `/api` redirects to `?hostnames=api&type=&ns=resolver&useresolver=1.1.1.1`, exactly as `/help` and `/faq` do. The real evidence is the one-URL sitemap, the absence of any documentation, and the lack of any CORS header (verified: `curl -sI -H "Origin: https://example.com"` returns only `Date`, `Server: Apache`, `Content-Type`), which also rules out browser-side reuse.
- `checkSize()` flips the form to `POST` when hostnames + nameservers exceed **1500 characters**, trading the shareable URL for a bigger batch. A commented-out `alert()` in the source shows the author considered warning users about the loss.
- Revenue: Publift/Fuse ad slots (`cdn.fuseplatform.net`), PayPal donations (`hosted_button_id=YM4LHEK5QURXL`), and a Google Analytics tag still carrying a `UA-` property ID, `UA-315272-5`, loaded via `gtag.js` with no GA4 `G-` ID anywhere on the page. Universal Analytics stopped processing hits in 2024, so that tag is almost certainly collecting nothing: a fair marker of how actively the page is maintained. Both the ads and the donate button are user-disableable.

## Ideas worth stealing

- **Annotate raw text instead of replacing it.** This is the whole lesson. Render the canonical wire form, then wrap each field in a span: TTL keeps its integer and gains `title="4m 42s"`, the RR type keeps its mnemonic and gains an RFC link. In Go this is a `miekg/dns` RR rendered field-by-field into a template, not a regex over text, so we get it more cheaply and more safely than they do. Beginner-legible and expert-verifiable from the same output, which is the fight every tool in this category is having.
- **Click a name in the answer to make it the next query.** `addhost()`/`addns()` cost two lines of JS and turn a `+trace` into an explorable object. With htmx this is a link with `hx-get` to the same handler and an `hx-target` on the result pane, no JS at all.
- **Parent vs child as a nameserver *mode*, not a test suite.** `ns=nic` asks the TLD, `ns=auth` asks the zone. Two resolution paths, and the user compares by eye. intoDNS builds 20 checks to say the same thing. If we want delegation insight cheaply, ship these two modes first and the health checks never.
- **Compare as a diff table over answers you already have.** Base + `SAME`/`DIFFERENT` per resolver, each row anchored to its block. Trivially implementable as: normalize the RRset (sort + strip TTL), hash it, group. Ours should hash the *parsed RRset*, not the text, which fixes their order-sensitivity for free.
- **`Show command`.** Printing the exact `dig …` line teaches the CLI, makes the result reproducible outside the tool, and is the single highest trust-per-byte element on the page. We can print the equivalent `dig` invocation for whatever we ran, even though we will not shell out to dig.
- **Path URL that 301s to the canonical query string.** `/example.com/MX/8.8.8.8` -> `?hostnames=…`. Pretty entry points, one canonical form to render and cache. Echo v5 routing makes this a two-line redirect handler, and it composes with rule #2: the same path with `Accept: application/json` is the JSON API they never built.
- **Three near-free extras.** An OpenSearch descriptor (~10 lines of XML plus one `<link rel="search">`) puts the tool in the browser address bar. A hidden textarea behind the copy button means copy yields clean text while the page shows annotated markup, today `navigator.clipboard.writeText()` off a `data-raw` attribute. And a settings-only permalink, submitting with an empty target to bookmark your options, is a degenerate case of "the query is the URL" that costs nothing to allow.
- **Tooltips as the entire help system.** Every checkbox has a `title` explaining the flag; every record type explains itself and links to the RFC. No help page, no modal, no docs site to maintain.
- **The ad opt-out.** If this ever carries ads, copy the mechanic: a link that turns them off for two weeks, with an honest confirm. Fits the house copy rules better than any ad-blocker nag.

## Gaps & what it does not do

- **No interpretation whatsoever.** No provider attribution, no zone health checks, no SPF/DKIM/DMARC parsing, no blocklist or reputation lookup, no WHOIS, no propagation map, no monitoring or change alerts, no history, no passive DNS, no DNSSEC *chain validation* (it will fetch DNSKEY/RRSIG/DS, and then you validate them yourself). Also a **single vantage point (Montreal)**: any claim about what users elsewhere see is your inference, not the tool's.
- **`sort` is a naive line sort over the whole output.** Verified 2026-09-16: with `stats=on` it alphabetizes dig's own header too, so a run comes back with `;; ANSWER SECTION:` above `;; Got answer:`, `;; MSG SIZE` above `;; OPT PSEUDOSECTION:`, and `;; flags:` stranded near the bottom. The result is unreadable rather than merely reordered. It is only safe with the stats block suppressed, where it does the useful job of normalizing RRset order before a compare. A parsed implementation has no such trap.
- **Naive linkification of RDATA.** An `HTTPS` record's SvcParams came back wrapped in `addhost('1 . alpn="h3,h2" ipv4hint=…')`, i.e. clicking it would paste the whole parameter string into the hostnames box. Text-level annotation cannot know what a field means; a typed one can.
- **The SOA serial tooltip is confidently wrong.** It decodes the serial as a Unix timestamp unconditionally: `corpberry.com`'s Cloudflare-issued serial `2415019265` is annotated `title="12-Jul-2046 16:41:05"`, a date 20 years in the future. Serials are opaque `uint32` counters (RFC 1035 §3.3.13); only the `YYYYMMDDnn` convention is date-shaped, and this is not it. A good illustration of the cost of guessing: the one place the tool interprets a number is the one place it misleads. If we decode serials, detect the `YYYYMMDDnn` shape first and otherwise say nothing.
- **No input validation or normalization feedback.** `not a hostname!!` silently became three queries.
- **No API, no CORS, no JSON, no rate-limit headers.** Automation is explicitly out of scope.
- **No TCP, ECS, transport or timeout controls** despite being the "full dig" tool.
- **Accessibility and mobile.** `<font>` tags, fixed-width tables, tooltip-only help, a 19-row textarea. It has a viewport meta and nothing else.

## Verified firsthand vs inferred

**Verified by `curl`/`dig`/`whois`, first on 2026-09-15 and re-run independently on 2026-09-16:** every form control and its parameter name (parsed from the live HTML); the 12 checkboxes, 5 `ns` radios and 10 resolvers with their exact labels and IPs; the 49-type list (counted programmatically twice); each checkbox's dig flags, read off the `Show command` line, incl. the default `+noadditional +noquestion +nocomments +nocmd +nostats` and `stats` -> `+additional`; the annotation markup incl. TTL tooltips, RFC links (`A` -> rfc1035, `HTTPS` -> rfc9460), the SOA `mailto:` rewrite, the SOA serial tooltip, and `addhost`/`addns`; the colorize `<font>` palette; the compare table and its SAME/DIFFERENT verdicts; `auth` (dion/lisa.ns.cloudflare.com) vs `nic` (13 gtld-servers) answering servers; `+trace`'s root walk with clickable delegation; `+norec` producing SERVFAIL + `EDE: 0 (Other)`; whitespace-splitting of `not a hostname!!` into 3 queries; the saved `/output/<md5>.txt` format and its retrievability; the path-style 301s for 1/2/3 segments and the 404 at 4; `/search.xml`; `/sitemap.xml` (one URL); `robots.txt`; absence of CORS headers; absence of XHR/fetch/EventSource in a 10-resolver result page; `DiG 9.16.23-RH`; the CEST `WHEN:` line; `gpdns-yul` (site) vs `gpdns-fra` (this machine) NSID; OVH CA hosting and PTR; domain creation 2006-03-03. `fix()`, `checkSize()`, `addhost()`, `addns()` and `doCopy()` were read in full from the inline source.

**Verified against third-party registries:** the meta-vs-RR-type breakdown and the DLV/TA status, from the IANA DNS-parameters registry (2026-09-16). The absence of a LICENSE file in the reimplementation repo, by probing `LICENSE`/`LICENSE.md`/`LICENSE.txt`/`license` on both `master` and `main` (all 404 while `api/query.php` returns 200 from the same branch, so it is not a default-branch artifact).

**Quoted from the site, not tested:** the 100-lookups/24h CAPTCHA threshold and the temporary-ban consequence. The wording was re-read verbatim off the live page on 2026-09-16 and `recaptcha/api.js` is loaded on every page, so the policy text and the script are confirmed; the enforcement is not.

**Not exercised:** the CAPTCHA gate itself, AXFR (declined against third-party nameservers), `/noads.php` and `/nobanner.php` (robots-disallowed; the "disable them for two weeks" wording and the `confirm()` handler are confirmed in the homepage markup, the resulting cookie behaviour is not), and the POST fallback above 1500 chars (the `checkSize()` source is confirmed verbatim, the threshold was never crossed).

**Could not be re-checked:** the first-Wayback-snapshot date, previously given as 2006-04-06. archive.org returned "Temporarily Offline" on 2026-09-16, so the claim has been dropped rather than repeated; the whois creation date carries the "since 2006" point on its own.

**Inferred, not observed:** that the backend shells out to the `dig` binary rather than using a DNS library. The evidence is circumstantial but consistent: the verbatim `DiG 9.16.23-RH` banner, the CEST `WHEN:` line, the exact flag echo, and the duplicated `+nocmd` in the `Reverse` command line, which is what argv-by-string-concatenation looks like. Also inferred: that the operator is in a Central European timezone (from `WHEN:`); the site itself states no nationality. `sort` implying `+multiline` is *not* claimed and was re-tested: `+multiline` appears with `type=SOA` and with `dnssec=on`, and did not appear with `sort=on&type=HTTPS`.

## Open source / reusable

DigWebInterface itself is **closed**: no repo, no license, no published source. Nothing to vendor.

There is a third-party reimplementation, **[`Lars-/opensource-digwebinterface`](https://github.com/Lars-/opensource-digwebinterface)** (PHP 8.3, zero Composer dependencies, 10 stars, 6 forks, not a fork itself, re-checked 2026-09-16). **Treat it as unlicensed.** The README carries a hardcoded shields.io MIT badge and a "License" section pointing at `[LICENSE](LICENSE)`, but that link is dead: no license file exists under any common filename on either `master` or `main`. A badge is not a grant, so **do not vendor or copy from it** without asking the author to add the file.

Worth a skim for two things only. `api/query.php` shows the AJAX-per-resolver shape DigWebInterface deliberately does not use: a POST JSON endpoint taking `{hostname, type, nameserver, options, resolver_name}`, and, unlike the original, it sets `Access-Control-Allow-Origin: *`. And the README's security section is a useful checklist of exactly the hazards a shell-out design creates (`escapeshellarg`, per-session rate limiting, XSS on echoed output). **We avoid all of them by not shelling out**: `github.com/miekg/dns` gives typed RRs, no subprocess, no quoting bug, and makes the annotation pass a template rather than a regex.

## Sources

- [DigWebInterface homepage, form markup, tips, fair-usage policy and About](https://www.digwebinterface.com/)
- Site artifacts fetched directly: [robots.txt](https://www.digwebinterface.com/robots.txt) (disallows /output/, /noads.php, /nobanner.php), [search.xml](https://www.digwebinterface.com/search.xml) (OpenSearch, per the [OpenSearch 1.1 spec](https://github.com/dewitt/opensearch)), [sitemap.xml](https://www.digwebinterface.com/sitemap.xml) (exactly one URL)
- [IANA DNS parameters, RR TYPE registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4), source for the meta-type split, plus [RFC 8749](https://www.rfc-editor.org/info/rfc8749) (DLV to Historic) and [RFC 1982](https://www.rfc-editor.org/info/rfc1982) (serial arithmetic, why a serial is not a timestamp)
- [BIND 9.16 `dig` manual, flags observed in the Show command line (+trace, +nsid, +norec, +short, +multiline, +dnssec)](https://bind9.readthedocs.io/en/v9.16.23/manpages.html)
- RFCs the tool links record types to, or whose behaviour it surfaces: [1035](https://www.rfc-editor.org/info/rfc1035) (A/NS/SOA), [9460](https://www.rfc-editor.org/info/rfc9460) (SVCB/HTTPS), [5001](https://www.rfc-editor.org/info/rfc5001) (NSID, behind "Request NS ID"), [8914](https://www.rfc-editor.org/info/rfc8914) (Extended DNS Errors, seen in the +norec SERVFAIL)
- [`Lars-/opensource-digwebinterface`, third-party PHP reimplementation](https://github.com/Lars-/opensource-digwebinterface)
- [`github.com/miekg/dns`, the Go DNS library that replaces shelling out to dig](https://github.com/miekg/dns)
- [Companion file: firsthand UI observations for the DNS-tool set](./firsthand-ui-observations.md)
