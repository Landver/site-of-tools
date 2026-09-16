# MXToolbox

The default free DNS/email diagnostic on the internet since 2004, run by MxToolbox Inc (Austin TX). Superficially a pile of lookup pages; the real product is **SuperTool**, a single command bar (`mx:`, `spf:`, `blacklist:` …) fronting one lookup engine, and the real differentiator is that **every lookup returns named pass/warn/fail checks, not just records**. For anyone building a DNS lookup tool this is the reference for "what does a DNS answer *mean*", and the single richest source of check ideas. Its public JSON API is also unusually easy to study: it returns the same objects the website renders.

- **URL:** https://mxtoolbox.com · **Category:** DNS + email-deliverability diagnostics & monitoring SaaS · **Registration:** anonymous SuperTool free, free account for 1 monitored domain, paid for Delivery Center · **Pricing:** $0 / $129 / $399 per mo (re-read off the vendor product page 2026-09-16; no checkout exercised, `/pricing` 404s) · **API:** REST, `https://api.mxtoolbox.com/api/v1/`, UUID key in `Authorization` header
- **Firsthand check:** curled the REST API unauthenticated (works, but **only** for the literal argument `example.com`; every other argument -> `401` w/ body `"You are not authorized to access the API..."`). Then pulled an anonymous **`TempAuthorization`** visitor key from `/api/v1/user` and used it to run **arbitrary** arguments, which is what makes the `:all` form, the DKIM selector form and ~20 undocumented commands observable without an account. Parsed full JSON for `mx`/`a`/`soa`/`ptr`/`dns`/`ns`/`spf`/`cname`/`srv`/`dnskey`/`ds`/`whois`/`blacklist`. Found undocumented `format=0|1|2`, decoded a base64 `DnsAnswer` to a **55-byte raw DNS wire packet** (`id=0x7be9 flags=0x8400`: QR=1 AA=1 RCODE=0, QD=1 AN=1, QTYPE=15, TTL=300). Enumerated the `/problem` catalogue (193 checks) and `/NetworkTools.aspx` (38 lookup tools) **from raw HTML** by anchor grep. Confirmed `Access-Control-Allow-Origin: *` on site & API w/ an `Origin:` header. Cross-checked their answers against my own `dig`: exact match. Did **not** log in; everything behind a login below is from vendor docs/pages & marked as such.

## What it is

One engine, many front doors. `mxtoolbox.com/SuperTool.aspx` takes `command:argument` and dispatches to the same backend the `/dnscheck.aspx`, `/blacklists.aspx`, `/spf.aspx` … landing pages hit. On top of the lookups sit three products: **Domain Health** (bundled report), **monitoring/alerts** (re-run a lookup on a schedule, alert on change), and **Delivery Center** (deliverability suite w/ inbox placement, DMARC aggregate-report parsing, feedback loops). Economics worth naming: free tools are an SEO & funnel machine (each named check has its own indexed, server-rendered `/problem/<cmd>/<check>` explainer page). Lookups = lead magnet; monitoring & deliverability = product.

## Registration, access & pricing

| Tier | Price (vendor page, 2026-09-16) | What you get |
|---|---|---|
| Anonymous | $0, no account | SuperTool lookups w/ ads; server-issued `TempAuthKey` per visitor |
| Free account | $0 | "Blacklist Monitoring: Weekly", "Domain(s): 1" (verbatim from the product page) |
| Delivery Center | **$129/mo** | 5 domains, 500,000 msg volume, inbox placement, complaint reporting, adaptive blacklist monitoring, inbound+outbound mailflow monitoring, impersonation protection |
| Delivery Center Plus | **$399/mo** | above + advanced threat tools + **SPF flattening**, 5 domains, 5,000,000 msg volume |
| Managed / MSP / Bulk | quote | separate `/c/products/deliverymanaged`, `/msp`, `/bulk` pages, no price listed |

Price strings were read out of the raw HTML of `/c/mxtoolboxproducts`, not only through a renderer. Still vendor copy: `/pricing` 404s and no checkout was exercised. The widely-repeated "free tier covers the top 30 blacklists" line appears only in third-party reviews, **not** on any vendor page I could fetch, so treat it as hearsay.

API quotas are account-scoped, visible only logged-in (`GET /api/v1/Usage` -> `DnsRequests/DnsMax`, `NetworkRequests/NetworkMax`; resets daily 00:00 UTC). API reference states a free tier of **64 DNS requests/day, 0 network requests/day**; unverifiable without an account (`/Usage` -> 400 both unauthenticated and w/ a visitor key). Vendor KB: 403 = rate limited, add exponential backoff. The design decision to note is **two quota currencies**: DNS lookups (cheap, pure queries) vs Network lookups (expensive, outbound TCP/ICMP: `blacklist`, `http`, `https`, `ping`, `smtp`, `tcp`, `trace`). Free = DNS only.

## Features, complete inventory

### The named-check catalogue (the core asset)

Every lookup returns check results partitioned into `Failed` / `Warnings` / `Passed` / `Timeouts` / `Errors`, each w/ a stable numeric `ID`, `Name`, `Info` & a `Url` to an explainer page. Counts below are **parsed from the raw HTML** of `/problem` (the page is server-rendered; 193 unique `/problem/<group>/<slug>` anchors), not transcribed from a renderer:

| Group | # | Examples |
|---|---|---|
| **DNS** | 21 | Record Published · Bad Glue Detected · At Least Two Servers · All Servers Responding · All Servers Authoritative · Local Parent Mismatch · Primary Server Listed At Parent · Servers on Different Subnets · Servers Have Public IPs · **Open Recursive Name Server** · **Open Zone Transfer** / **Server Allows Zone Transfer** · SOA Serial Numbers Match · SOA Serial Number Format · SOA Refresh/Retry/Expire/NXDOMAIN Value · Lookup Timeout · All NS Timed Out · No Valid NameServers Responded |
| **SPF** | 16 | Record Published · Syntax Check · Multiple Records · Record Deprecated · **Included Lookups** (the 10-lookup limit) · **Void Lookups** · Recursive Loop · Duplicate Include · Type PTR Check · Contains characters after ALL · MX Resource Records · Record Null Value · Modifier · Redirect Evaluation · Alignment · Authentication |
| **DKIM** | 12 | Record Published · Syntax Check · Public Key Check · Signature Verified · Body Hash Verified · Signature Alignment · Identifier Match · Duplicate Tags · Expiration · Domain DNS Check · Signature Missing · Signature Syntax Check |
| **DMARC** | 5 | Record Published · Syntax Check · Multiple Records · Policy Not Enabled · **External Validation** (RUA/RUF third-party authorization) |
| **BIMI** | 11 | Record Published · Syntax Check · Image Format · Logo Validation · Certificate Authority / Issuer / Expiration / Logo / **Trust Chain** · + 2 DMARC prerequisites |
| **MTA-STS** | 8 | Record Published · Syntax Check · Multiple Records · **HTTPS Policy Fetch** · **HTTPS Policy Certificate** · Policy Syntax Check · **MX Host Validation** · SMTP TLS |
| **TLSRPT** | 3 | Record Found · Invalid Syntax · Multiple Records |
| **SMTP** | 10 | Connect · Banner Check · **Open Relay** · TLS · Reverse DNS Resolution · **Reverse DNS Mismatch** · DNS Resolution · Connection Time · Transaction Time · Server Disconnected |
| **HTTP / HTTPS / TCP** | 9 | Connect · Delay Check · Dns · Filter · **Certificate Check** · **Certificate Expiration** |
| **CNAME / WHOIS / DOMAIN** | 5 | CNAME multiple records · CNAME used incorrectly · **Domain Expiration Check** · Domain DNS Failure · Monitors Change |
| **IP blacklists** | 64 named | Spamhaus ZEN · SPAMCOP · BARRACUDA · Abusix (3 lists) · UCEPROTECT L1/L2/L3 · Sender Score · MAILSPIKE BL/Z · PSBL · LASHBACK · BLOCKLIST.DE · CYMRU BOGONS (+IPv6) · DAN TOR / TOREXIT · ivmSIP / ivmSIP24 · s5h.net (+IPv6) · Hostkarma · TRUNCATE · 0SPAM · Backscatterer · DroneBL · Interserver · SPFBL · ZapBL · … (**no SORBS**: decommissioned by Proofpoint June 2024, and MXToolbox has dropped it from the IP catalogue; only the two legacy SORBS RHSBL entries survive) |
| **Domain/URI blacklists** | 8 | Spamhaus DBL · SURBL multi · ivmURI · SEM FRESH/URI/URIRED · SORBS RHSBL BADCONF/NOMAIL |
| **LLMs.txt** | 8 | File Exists And Reachable · Content Type · H1 Name Present · Summary Blockquote · File Lists Present · Linked URLs Reachable · Markdown Variants · Optional Section |
| **robots.txt AI policy** | 13 | per-agent checks for **ClaudeBot, anthropic-ai, GPTBot, ChatGPT-User, CCBot, cohere-ai, Google-Extended, PerplexityBot** + Wildcard Rule Present · Sitemap Directive · LLM Bots Addressed · File Exists · Content Type |

Three numbers, all different, all real: marketing says "over 100 blacklists"; the `/problem` catalogue enumerates **64** IP-level + 8 domain-level; an anonymous live `blacklist:8.8.8.8` actually returned **60** results (all `Passed`). Likely only lists w/ a written explainer get a `/problem` page, and the anonymous tier queries a subset. Treat 60 as the observed floor and 64 as the documented one.

### Tools & views (enumerated from `/NetworkTools.aspx` raw HTML: 38 lookup tools)

Lookups: **MX · A (`DnsLookup.aspx`) · AAAA (`IPv6.aspx`) · CNAME · TXT · SOA · PTR (`ReverseLookup.aspx`) · SRV · DNSKEY · DS · RRSIG · NSEC · NSEC3PARAM · CERT · LOC · IPSECKEY · ASN · ARIN · WHOIS · SPF · DKIM · DMARC · BIMI · MTA-STS · TLSRPT · DNS (server audit, `DNSCheck.aspx`) · Blacklist · Blocklist · SMTP Diagnostics (`diagnostic.aspx`) · TCP · HTTP · HTTPS · Ping · Traceroute · LLMs.txt · Robots.txt LLM Policy · Email Health · What Is My IP**. No **CAA**, no **SVCB/HTTPS**, no **NAPTR** anywhere on the page (0 string hits) or in the API (`caa`, `svcb` -> 400).

Reports & analyzers: **Domain Health Report** · **Email Health Report** · **Header Analyzer** (paste raw headers -> hop-by-hop delay table + auth results) · **DMARC Report Analyzer** (upload/parse aggregate XML) · **Email Deliverability** (mail `ping@tools.mxtoolbox.com`, get a report link back by email) · **Email Extraction Tool** (`EmailExtraction.aspx`, pulls addresses out of pasted text) · **Google/Yahoo sender compliance** · **Microsoft compliance** · **Outbound email sources**.

Convenience: **Bulk Lookup** · **Subnet Calculator** (monitor a whole subnet) · **DNS Propagation** (own page `/dnspropagation.aspx`, or the `:all` argument suffix) · **SPF Generator** · **DMARC Generator** · **Password Generator**.

Monitoring: scheduled re-run of any lookup w/ change alerting, tagged monitors, Mailflow end-to-end send/receive monitoring, adaptive blacklist monitoring, domain-impersonation watch. (Vendor docs; not verified, requires account.)

### API surface

| Method | Path | Notes |
|---|---|---|
| GET | `/api/v1/Lookup/{Command}/{arg}` | also `/Lookup/{Command}/?argument=` and the `?command=&argument=&format=` querystring form |
| GET | `/api/v1/Lookup?command=dkim&argument={domain}:{selector}` | DKIM selector syntax, **observed**; a literal `:` in the path segment 302s, the querystring form works |
| GET | `/api/v1/Lookup?command={cmd}&argument={domain}:all` | multi-nameserver "propagation" form, **observed** |
| GET | `/api/v1/Monitor` | `?command=`, `?name=`, `?tag=` filters (vendor docs). 401 unauthenticated; a visitor `TempAuthKey` does **not** unlock it, so it is account-key-only |
| GET | `/api/v1/Monitor/{MonitorUID}` | single monitor; CRUD documented, never exercised (no monitor was created) |
| GET | `/api/v1/Monitor/{MonitorUID}/Tag` | tag CRUD, vendor docs only |
| GET | `/api/v1/Usage` | quota counters; 400 both unauthenticated and w/ a visitor key, observed |
| GET | `/api/v1/user` | **undocumented**; anonymous, returns `MemberType: Anonymous` + `MxVisitorUid` + `TempAuthKey` + `NumDomainHealthMonitors` |

Auth: `Authorization: <uuid>` (no `Bearer`). Documented commands (22): `a, aaaa, arin, asn, bimi, dkim, dmarc, dns, mta-sts, mx, ptr, soa, spf, tlsrpt, txt` (DNS quota) + `blacklist, http, https, ping, smtp, tcp, trace` (network quota). **Observed: the docs lag badly, the API does not.** All of `ns`, `cname`, `srv`, `dnskey`, `ds`, `rrsig`, `nsec`, `nsec3param`, `cert`, `loc`, `ipseckey`, `whois`, `llmstxt`, `robotsai`, `blocklist` return 200 w/ a proper `Command` echo. Two are aliases: `ns` echoes `Command: dns`, `blocklist` echoes `Command: blacklist`. `arin` requires an IP (`400 Invalid Input … arin requires an IP Address`). Optional `port` param for TCP.

**Undocumented `format` param, observed:** `format=0` full results JSON · `format=1` engine internals (below) · `format=2` `{HTML_Value: "<div …>"}`, a **server-rendered HTML fragment** of the result table, ready to swap into a page.

## Record types & query options supported

RR types: A, AAAA, CNAME, MX, TXT, SOA, NS (`ns:`, an alias for `dns:`), PTR, SRV, CERT, LOC, IPSECKEY, and the DNSSEC set **DNSKEY, DS, RRSIG, NSEC, NSEC3PARAM**. `ResourceRecordType` in the JSON carries the correct IANA numeric type whenever an answer exists, observed: A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, TXT=16, SRV=33, DS=43, DNSKEY=48. It falls back to `0` on an empty answer, so it reports the answer's type, not the query's. Still enough to confirm a real typed query rather than string scraping. **No CAA and no SVCB/HTTPS**: both 400 at the API and absent from the tool page.

Knobs are thin, and this is the notable weakness. **No** user-chosen resolver, **no** "query this specific nameserver", **no** ECS/EDNS client-subnet control, **no** TCP-vs-UDP toggle, **no** `+dnssec` AD-flag view, **no** raw `dig`-style output. What exists:

- `:all` argument suffix (`mx:example.com:all`) = their "DNS propagation". **Verified firsthand w/ a visitor key, and it is not what the name suggests.** It is not a geographic vantage-point fan-out. It queries **every authoritative nameserver of the zone itself** and returns `MultiInformation[]` of `{NameServer, Answers[], MD5, IsSoa, IsSoaMatch, SortOrder, Errors}`: one entry per NS, w/ a base64 MD5 of that server's answer set so mismatches pop out. On `a:wikipedia.org:all` it returned exactly the 3 NS my own `dig +short NS wikipedia.org` returns, all three MD5s identical. Vendor copy agrees: "check the propagation of DNS records **across your servers**". Cost: 2.2 s for a 2-NS zone vs 20 ms for the plain lookup.
- `domain:selector` for DKIM, **verified**: `dkim/google._domainkey.example.com` comes back normalized to `CommandArgument: "example.com:google"`, so the two spellings are the same query. `ip:port` for TCP.
- TTL is humanized ("24 hrs", "5 min"); raw seconds appear only in the transcript.
- Resolver choice is implicit: they always walk **root -> TLD -> authoritative** and report which authoritative NS answered (`ReportingNameServer`).

## How it works

**Server-side resolution, client-side rendering, but only for results.** The SuperTool result page (`/SuperTool.aspx?action=mx:example.com&run=toolpage`, 85 KB) does **not** contain the answer in its HTML (`grep` for the returned nameservers `elliott`/`hera`: 0 hits; JSRender template markers present), and `/domain/example.com/` (112 KB) is the same empty shell. The page ships JSRender 1.0.14 from cdnjs plus `/bundles/mxClassic*.js`, calls `GET api/v1/Lookup?command=…&argument=…&format=0`, and renders client-side. Domain Health does the same, one XHR per panel, which is why the report paints progressively. Worth separating from this: the *catalogue* pages (`/problem`, `/NetworkTools.aspx`) are plain server-rendered ASP.NET w/ real anchors, so the SEO surface is crawlable even though the results are not.

**Anonymous access mechanic (read out of `mxShared.js`, then confirmed):** on load the page calls `/api/v1/user`. For a logged-out visitor it returns `TempAuthKey`; the JS stashes it on `window` and every lookup XHR does `xhr.setRequestHeader('TempAuthorization', window.TempAuthKey)`. I fetched a key & ran `dns:corpberry.com`, `a:wikipedia.org:all`, `blacklist:8.8.8.8`, `cname:www.github.com` and ~20 undocumented commands w/ it: all 200, full results. So the visitor key is a real, unauthenticated capability over the whole lookup surface, and the "public" `api.mxtoolbox.com` path w/o any key allows exactly one demo argument (`example.com`). It does **not** extend to account features: `/Monitor` stays 401 and `/Usage` stays 400 w/ the key attached.

**Resolution is authoritative, not recursive-cache.** The `Transcript` field is a hop-by-hop delegation trace they build themselves:

```
1 m.gtld-servers.net 192.55.83.30 NON-AUTH 7 ms Received 2 Referrals, rcode=NO_ERROR   example.com. 172800 IN NS hera.ns.cloudflare.com, …
2 elliott.ns.cloudflare.com 108.162.195.228 AUTH 2 ms Received 1 Answers, rcode=NO_ERROR   example.com. 300 IN MX 0 .,
- LookupServer [mx:example.com] 15ms
```

Per hop: server name, IP, AUTH/NON-AUTH, RTT, referral/answer count, `rcode`, and the records. That is a `dig +trace` they own end to end, which is how they can assert "All Servers Authoritative", "Local Parent Mismatch" (parent NS set vs NS set from the child) and "Bad Glue". For `:all` and for `mx:`, the transcript also shows the engine **chaining extra lookups** behind one command (an `mx:` run trails `dmarc:` and `bimi:` probes), which is where the supplemental warnings on an MX result come from.

**Caching & change detection.** `format=1` leaks the engine's per-lookup state: `DnsAnswer`, `DnsAnswerPrevious`, `DnsChanged`, `DNSRecordFirstLookup`, `DNSRecordChanged`, `HasAlertBeenSent`, `IsKeeper`, `HasDbAccess`, `SubActionsState`, `RaisedSubactions`, `AllSubActionTested`, `IgnoredSubactions`, `LookupActionResultUID`. I base64-decoded `DnsAnswer` and got a **55-byte raw DNS wire response**: `id=0x7be9 flags=0x8400` (QR=1, **AA=1**, RCODE=NOERROR), QD=1 AN=1, QTYPE=15, TTL=0x12c=300, RDATA `pref 0 . `. Storing the wire packet next to `DnsAnswerPrevious` + `DnsChanged` is observed; that monitoring alerts off a **byte-diff** of the two is the obvious reading but is **inferred**, since the alerting pipeline sits behind a login. `RaisedSubactions`, `AllSubActionTested` and `IgnoredSubactions` each decode to exactly **64 bytes** (512 bits); `SubActionsState` is an object wrapping three more of the same (`_priorSubActions`, `_currentSubActionState`, `IgnoredSubActions`) plus `IsFirstTimeEverRun`. 512 bits lines up cleanly w/ the check IDs I observed (299-511), so **bitmaps over the check-ID space** is a strong inference from size + ID range, not documentation. `IsExcludedByUser` on each check is the per-user mute. Infrastructure, observed from headers: Microsoft IIS 10 / ASP.NET behind CloudFront (`via: … cloudfront.net`, `x-amz-cf-pop`), `x-role: WebServer` vs `x-role: LookupServer` (lookups are a separate tier), `x-stage: prod`. `Cache-Control: no-cache` on lookups, `private` on the SuperTool shell. `/aboutus.aspx` renders a diagnostic block in the page: `ServerIdentifier: WebServer-i-095e27f47e1183eda`, `RevisionId`, `Build Time`, `Running Since`, so it is EC2 behind the CDN and they ship often (build stamp was ~9 h old when I read it).

## Output & UX

Result = one card per lookup, stacked, each headed `command:argument` and, if anything failed, `- N Tests Failed`. Inside:

1. **Records table** for the RR type. For `dns:` the columns are Type, Domain Name, IP Address, ASN (name + number), TTL, Status, Time (ms), **Auth**, **Parent**, **Local**: three separate agreement columns, each a colored dot (the JSON literally carries `"Status": "[GREEN]"`, `"Auth": "[GREEN]"`, `"Parent": "[GREEN]"`, `"Local": "[GREEN]"`). Failures are *localized to a nameserver*, not to the domain.
2. **Check list**, warnings/failures first w/ a "More Info" link, then the passes. The HTML rendering carries far more detail than the JSON `Info` string: JSON says `"SOA Serial Number Format is Invalid"`, the HTML says `elliott.ns.cloudflare.com reported Serial 2414908178 : Serial year was 2414 which is in the future.` and `Expire 604800 : Expire is recommended to be between 1209600 and 2419200`. Actual observed value + recommended range + which server reported it.
3. **Transcript** (collapsible) w/ the delegation trace.
4. **Related lookups.** The JSON ships a `RelatedLookups[]` array of `{Name, URL, Command, CommandArgument}`, so every result offers the obvious next hop (from `mx:` -> `a`, `dns`, `spf`, and the `:all` per-nameserver view). `URL` points at the API route, not the web page. Cheap, and it is what turns one lookup into a session.
5. **Derived labels:** `DnsServiceProvider` ("Cloudflare"), `EmailServiceProvider`, `MxRep`, `DnsServiceProviderIdentifier`. They fingerprint the provider from the NS/MX set.

Shareable URLs: yes, `mxtoolbox.com/SuperTool.aspx?action=<cmd>%3a<arg>&run=toolpage` and the pretty `/domain/<domain>/` & `/emailhealth/<domain>/` forms (200 on my curl). Export is PDF/CSV for logged-in users (not verified). Empty/error states are structured, not prose: `Timeouts[]`, `Errors[]`, `IsError`, `IsEmptySubDomain`. Domain Health arranges four panels, **Blacklists · Mail Server · Web Server · DNS**, each a count + status, w/ a Problems rollup on top (panel names grepped out of the shell; the filled-in numbers arrive by XHR).

## Monetization, limits & abuse controls

Free lookups are top of funnel; ads inject into the result HTML (`ShowAd($('#divAd_0'), 0, 'dns')` sits inside the `format=2` fragment, so the ad slot ships *with* the result). Upsell is per-check contextual: each `/problem/…` explainer ends in a Delivery Center pitch, not a generic banner. Limits observed: `api.mxtoolbox.com` unauthenticated allows only `example.com` (everything else 401, not 429, so it is an authorization gate not a rate limiter). Web UI uses the per-visitor `TempAuthorization` key. `robots.txt` disallows `/api/v*`, `/pro/`, `/public/checkout/`, `/public/emailtemplates/`, `/public/tools/emailheaders.aspx`, `/public/unsubscribe.aspx`, blocks AhrefsBot from `/problem/`, `dotbot` (Dotcom-Monitor) from `/domain/` and `/emailhealth/`, and `meta-externalagent` from `/SuperTool.aspx`. Note who is *not* blocked: no rule for GPTBot, ClaudeBot or CCBot, which is a choice worth noticing on a site that ships a robots.txt AI-policy checker. Vendor KB: daily quotas reset 00:00 UTC, 403 on rate limit, exponential backoff advised. **`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`** on both the site and the API, verified with an `Origin:` header.

## Ideas worth stealing

- **Ship named checks, not just records.** This is the whole idea. A lookup that returns `{Failed, Warnings, Passed}` where each entry is `{ID, Name, Info}` is a different product from one that prints an RRset. In Go this is a `[]Check` returned from the domain package alongside the records; `platform.Respond` renders it as a list in HTML and as JSON arrays for API callers, zero duplication. Start with the ~8 highest-value DNS checks (≥2 NS, all NS respond, all authoritative, parent/child NS sets match, NS on different /24s, NS have public IPs, SOA serials match, SOA timer values in RFC 1912 range) and grow the list. Stable numeric IDs from day one, because they become permalinks.
- **Say the number and the recommended range.** Not "SOA Expire out of range" but `reported Expire 604800 : recommended 1209600 to 2419200`. Verified against my own `dig` (`example.com` SOA expire really is 604800, serial really is 2414908178, which is not YYYYMMDDnn), so the check is honest and the wording is the entire value-add. One line of template, and it is the difference between a toy and a tool.
- **Do your own delegation walk, then sell it twice.** Once as **three agreement columns** per nameserver, Auth / Parent / Local (does this NS answer authoritatively, is it in the parent's delegation, is it in the child zone's own NS RRset), which blames a specific server instead of the domain. Once as a **collapsed transcript**, per hop: server, IP, AUTH/NON-AUTH, RTT ms, answer/referral count, rcode. `miekg/dns` gives both for free if you resolve iteratively rather than asking a recursor, and the transcript is the receipt that makes the checks believable.
- **`RelatedLookups` on every result.** Ship 3-4 `{Name, Command, Argument}` next-hops in the same response. For an htmx tool this is literally four `hx-get` links under the result. Highest ratio of retention to effort on this whole list.
- **Hash each authoritative NS's answer set and compare hashes.** Their `:all` mode is one query per NS in the zone plus an MD5 of that server's answers, so "your nameservers disagree" is a one-line comparison instead of a set diff. Cheap (N queries, N hashes), it is the *correct* meaning of "is my change live" for a zone owner, and it composes with the delegation walk you are already doing. Do it under an honest name, "nameserver consistency", and leave the word propagation for an actual geographic fan-out.
- **Store the raw wire packet, diff bytes.** For a "watch this record" feature, persist the `[]byte` of the DNS response (Mongo `bson.Binary`) plus the previous one; change detection is `!bytes.Equal(cur, prev)`, not field-by-field comparison. MXToolbox demonstrably stores the packet and a `DnsAnswerPrevious`; whether their alerting diffs bytes is my reading, not something I saw. The pattern is right either way, and it matches the existing repository-below-domain shape & `EnsureTTLIndex`.
- **A `/problem/<cmd>/<check>` explainer page per check.** Each check's `Info` links to a small markdown page: what the field means, the RFC, the recommended range, how to fix. This repo already renders markdown w/ goldmark for the blog, so the checks and their docs can live in `tools/<tool>/docs/` and be served under a route. Doubles as the SEO surface, which is exactly why MXToolbox has one.
- **One command bar, `cmd:arg` syntax, two classes of lookup.** Single input, parse prefix, dispatch, sensible default when no prefix: avoids 20 separate pages & makes the URL trivially shareable (`?action=mx:example.com`). Humanize TTL in the table ("24 hrs") but keep raw seconds in the transcript. Split the commands into DNS (cheap) vs network (outbound TCP/ICMP: SMTP probe, port check, traceroute); even w/o billing, that is the right way to gate the expensive half behind explicit opt-in, and it echoes the port-scanner decision already taken in `iptools`. Note also their `format=2` `{HTML_Value}`: the htmx pattern arrived at independently, though content negotiation here does it cleaner (htmx request -> fragment, not JSON-wrapped HTML).
- **The robots.txt AI-policy check is a genuinely novel, cheap tool.** Fetch `/robots.txt`, check for rules addressing ClaudeBot, GPTBot, anthropic-ai, CCBot, ChatGPT-User, cohere-ai, Google-Extended, PerplexityBot, plus wildcard & sitemap directives. Pure HTTP + string matching, no DNS, ~100 lines, and nobody else on this comparison list has it.

## Gaps & what it does not do

- **No resolver choice, no raw output.** Cannot say "resolve via 1.1.1.1 vs 8.8.8.8 vs my ISP", cannot target a specific authoritative NS, cannot set EDNS client-subnet. No `dig`-format answer section, no wire hexdump, no copyable zone-file lines either, despite the engine holding the wire packet (I had to reach `format=1` to see it). For a tool positioned on DNS rather than email, this is the obvious opening.
- **DNSSEC is record-lookup only.** `DNSKEY`/`DS`/`RRSIG`/`NSEC`/`NSEC3PARAM` are lookups (`ds:example.com` really does return key tag 2371, algorithm 13, digest type 2); there is no **chain-of-trust validation** verdict, no AD-flag report, and no DNSSEC group in the `/problem` catalogue at all, confirmed against the 193 enumerated slugs. Large, cleanly-scoped gap.
- **The API docs lag, not the API.** The reference lists 22 commands; at least 15 more work unannounced (`ns`, `cname`, `srv`, `dnskey`, `ds`, `rrsig`, `nsec`, `nsec3param`, `cert`, `loc`, `ipseckey`, `whois`, `llmstxt`, `robotsai`, `blocklist`), as do `format`, `:all` and `domain:selector`. So the API is effectively at parity w/ the web UI and only the documentation is a gap. Still no documented API for Domain Health as a unit.
- **"Propagation" is not propagation.** `:all` compares the zone's own authoritative nameservers, not resolvers in different places. There is no geographic vantage-point network here at all, which is exactly the hole whatsmydns/DNSChecker fill. Anyone reading MXToolbox's feature list as "they already do propagation" would be wrong.
- **Heavy, ad-laden, JS-required.** ~112KB of HTML for a Domain Health shell containing no answer, plus HubSpot, ad slots, multiple bundles. A fast, no-JS, no-ads result page is a real differentiator here, not a consolation prize.
- **Email-shaped.** Every road leads to deliverability. Nothing for CAA, SVCB/HTTPS, NAPTR, DoH/DoT endpoints, or zone-wide delegation diffing, all confirmed absent from both the tool page and the API.

## Verified firsthand vs inferred

**Verified by curl/dig/raw-HTML parsing:** the API is reachable unauthenticated for `example.com` only (401 otherwise, w/ the exact quoted body), and a `/api/v1/user` visitor key lifts that limit for lookups but not for `/Monitor` (401) or `/Usage` (400); full JSON shape incl. `Failed/Warnings/Passed/Timeouts/Errors`, `Information`, `MultiInformation`, `Transcript`, `RelatedLookups`, `DnsServiceProvider`, `MxRep`, `ResourceRecordType`; the 15 undocumented commands and the two aliases (`ns`->`dns`, `blocklist`->`blacklist`); `caa`/`svcb` -> 400; `format=0/1/2` behavior; `DnsAnswer` is a base64 raw DNS wire packet (decoded & header-parsed, 55 B, AA=1) and the three subaction fields are 64 B each; the DKIM `domain:selector` normalization; the `:all` mechanism, incl. the per-NS `MD5`/`IsSoaMatch` fields, cross-checked against `dig +short NS wikipedia.org`; a live `blacklist:8.8.8.8` returning 60 lists; the **193-entry `/problem` catalogue and the 38-tool `/NetworkTools.aspx` list, both anchor-grepped out of raw HTML** (contrary to an earlier pass, neither page is client-rendered); pricing strings in the raw HTML of `/c/mxtoolboxproducts`; SuperTool & Domain Health result pages contain no answer server-side and render via JSRender 1.0.14; `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` on site and API; IIS 10 / ASP.NET / CloudFront w/ `x-role: WebServer|LookupServer` and the EC2 instance id on `/aboutus.aspx`; Austin TX address; `robots.txt` contents; page status codes incl. `/pricing` -> 404; sitemap contents. Their answers for `example.com`, `wikipedia.org` and `corpberry.com` match my local `dig` exactly (NS, MX `0 .`, TXT, SOA), and the two SOA warnings they raise are independently correct against RFC 1912.

**Read from vendor pages/docs, not observed:** the $129 / $399 / $0 tiers and their feature bullets (product page only, no checkout exercised), the free-API "64 DNS requests/day, 0 network/day", Monitor and Monitor/Tag endpoint semantics (no monitor was ever created), the 00:00 UTC quota reset and the 403-means-rate-limit advice.

**Inferred, flagged as such in the text:** that monitoring alerts off a byte-diff of `DnsAnswer` vs `DnsAnswerPrevious` (the fields are real, the pipeline consuming them is not observable); that the three 64-byte fields are bitmaps over the check-ID space (512 bits vs observed IDs 299-511 is suggestive, not documented).

**Not verified at all:** anything behind a login. Logged-in result page layout, PDF/CSV export, monitoring alert channels & cadence, Delivery Center UI, DMARC Report Analyzer output, Header Analyzer output.

## Open source / reusable

Nothing of MXToolbox's product is open source. Their GitHub org `MxToolbox` has exactly one public repo, `BalloonLaunch` (MIT, Python, high-altitude balloon tracking), unrelated to the tools. The backend is closed .NET and `robots.txt` disallows `/api/v*`. The reusable parts are conceptual (check catalogue, wire-packet diffing, transcript format) plus one practical hook: the anonymous demo endpoint `https://api.mxtoolbox.com/api/v1/lookup/{cmd}/example.com` is open, CORS-`*` and key-free, which makes it a usable fixture for comparing your own engine's output against theirs during development. It is not a data source for a shipped tool: one argument only, ToS unreviewed, and Go stdlib `net` + `github.com/miekg/dns` do the actual work better anyway.

## Sources

- [MXToolbox SuperTool](https://mxtoolbox.com/SuperTool.aspx)
- [MXToolbox RESTful API Reference](https://mxtoolbox.com/api/api-reference)
- [MXToolbox KB: API Methods](https://knowledgebase.mxtoolbox.com/home/api-methods)
- [MXToolbox KB: About API](https://knowledgebase.mxtoolbox.com/home/about-api)
- [MXToolbox Network Tools (full tool list)](https://mxtoolbox.com/NetworkTools.aspx)
- [MXToolbox Problem catalogue (every named check)](https://mxtoolbox.com/problem)
- [MXToolbox Products & pricing](https://mxtoolbox.com/c/mxtoolboxproducts)
- [MXToolbox Blacklist Check](https://mxtoolbox.com/blacklists.aspx)
- [MXToolbox DNS Propagation tool ("across your servers")](https://mxtoolbox.com/dnspropagation.aspx)
- [MXToolbox About Us (Austin TX address, build/instance diagnostics)](https://mxtoolbox.com/aboutus.aspx)
- [MXToolbox sitemap.xml (41 canonical pages, incl. the product pages)](https://mxtoolbox.com/sitemap.xml)
- [MXToolbox Email Extraction Tool](https://mxtoolbox.com/EmailExtraction.aspx)
- [MxToolbox GitHub org (one unrelated MIT repo)](https://github.com/MxToolbox)
- [The Register: Proofpoint shut SORBS down, June 2024](https://www.theregister.com/2024/06/07/sorbs_closed/)
- [IANA DNS Parameters: RR TYPE registry (numeric codes checked against `ResourceRecordType`)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [MXToolbox `/problem/dns/dns-soa-expire-value` (RFC 1912 range)](https://mxtoolbox.com/problem/dns/dns-soa-expire-value)
- [MXToolbox robots.txt (crawl & API policy)](https://mxtoolbox.com/robots.txt)
- [RFC 1912: Common DNS Operational and Configuration Errors (SOA timer guidance)](https://www.rfc-editor.org/rfc/rfc1912)
- [RFC 7208: SPF (the 10 DNS-lookup and void-lookup limits)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 8461: MTA-STS (HTTPS policy fetch, MX host validation)](https://www.rfc-editor.org/rfc/rfc8461)
