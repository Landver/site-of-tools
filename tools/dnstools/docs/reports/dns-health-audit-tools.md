# DNS health audit tools (intoDNS · DNSInspect · DNS Spy · MXToolbox Domain Health)

Four tools that answer a different question than a lookup tool: not "what does this name resolve to" but **"is this zone correctly delegated & configured"**. All four query the **parent (TLD) servers first, then every authoritative NS individually**, compare the answers, and emit a pass/warn/fail report w/ remediation prose. Relevant to us because a DNS-lookup tool that only prints RRsets is table stakes; the audit layer is the part people bookmark, & the whole thing is achievable in Go w/ `miekg/dns` + a few hundred lines of rules. Two more entries matter for the build decision and are covered at the end: **Zonemaster** (the OSS one, *and* a free public API) and **nslookup.io DNS Health** (free JSON API, already occupies the niche this report originally called unmet).

| | URL | Category | Registration | Pricing | API |
|---|---|---|---|---|---|
| **intoDNS** | intodns.com | free one-shot zone+mail audit | none | free | none |
| **DNSInspect** | dnsinspect.com | free scored audit w/ report permalinks | none | free | none |
| **DNS Spy** | dnsspy.io | continuous monitoring + scored Security Center | account required | paid only, **figures unverified & conflicting** (see below) | Enterprise; also an MCP server |
| **MXToolbox Domain Health** | mxtoolbox.com/domain | free-tier-gated composite report over SuperTool | optional | 1 free health check/24h; API free tier 64 (or 68, docs disagree) DNS req/day | `mxtoolbox.com/api/v1/` & `api.mxtoolbox.com/api/v1/` |
| **Zonemaster** | zonemaster.net | free one-shot audit, **open source**, **public JSON-RPC API** | none | free | JSON-RPC 2.0, unauthenticated, CORS `*` |
| **nslookup.io DNS Health** | nslookup.io/dns-health | free scored audit | none | free | undocumented JSON endpoint, unauthenticated |

**Firsthand check (re-run 2026-09-16, Bash curl/dig unless noted).**
- **intoDNS:** fully readable. `GET https://intodns.com/<domain>` → 200; 19,308 B for `corpberry.com`, 24,900 B for `python.org`; the form posts `GET /check/?domain=X` which 302s to `/<domain>`. Parsed the full check table for both → **45 checks / 5 categories**, reproduced exactly on re-run. `~1.2 s` wall for a complete report. **No CORS headers.** No real `robots.txt`: the catch-all route swallows the path & renders "Work in progress! / Something wrong happend."
- **DNSInspect:** **still could not read live.** curl *and* WebFetch got **403 w/ `cf-mitigated: challenge`**. Search engines *do* index live report pages, so the check list below (from **raw Wayback captures** of `/aaas.org/1427235207` cap. 2024-10-17 & `/1slotguvenilir.com/10816604` cap. 2025-01-18) is corroborated in outline by 2026 search-index snippets of live `/<domain>` reports, which independently mention the TCP/25 connect, postmaster & abuse acceptance, PTR, recursive-query and identical-NS checks. Structure, scores & transcripts remain archive-sourced.
- **DNS Spy:** **still could not read live.** 403 challenge on `/`, `/features`, `/pricing`. Check table below is from raw Wayback captures (2026-05-28, 2026-03-09). Live marketing copy recovered only via search-index snippets, which disagree w/ the archive in places, flagged inline.
- **MXToolbox:** page 200 but JS-gated (served HTML carries *"Javascript is disabled. Javascript is required for this site."*; counters render zeroed). **Called its own endpoints:** `/api/v1/domain/python.org` (200, no auth, returns a job list), `/api/v1/lookup/dns/python.org` (**401**), `/api/v1/lookup/dns/example.com` & `/spf/example.com` (200; `example.com` is their documented open test target). Enumerated **192 check pages across 18 families** from `/problem/`. `access-control-allow-origin: *` on `/api/v1/`.
- **Zonemaster:** ran a **complete audit end to end** against the public instance (`POST https://zonemaster.net/api`, JSON-RPC 2.0, no key): `start_domain_test` → `test_progress` → `get_test_results`. `example.com` finished in ~30 s and returned **110 result rows** across 10 modules.
- **nslookup.io:** `GET https://www.nslookup.io/api/v1/dns-health/example.com` → **200 `application/json`**, no key, 4 KB, scored. No CORS header, so server-side only.

## What they are

**intoDNS** (intodns.com) is the 2008-era reference: free, no account, Django (per its own footer link), operated by Romanian host **Hosterion / IntoVPS**, author credited as "Elvsoft". Zero product surface: one input, one page, no API, no history. Still ranks because the output is legible & every finding cites an RFC.

**DNSInspect** (dnsinspect.com, © 2008-2023, footer `Version 1.1-1db8cd1 (2023-03-30)` as of the archived captures) is intoDNS plus a **score**: six 0-100 category bars, an overall letter grade, a site thumbnail, and a **permanent numbered report URL**. It is also the only one of the four that **opens real SMTP sessions** against your MX.

**DNS Spy** (dnsspy.io) started as Mattias Geniar's Laravel side project; his own blog announced a handover to **SecurityTrails** on 2020-09-16. Today's site is a different codebase w/ MSP positioning, and **I could not confirm who operates it now**. It abandoned the one-shot model: the audit ("Security Center") is a continuously re-run, weighted, letter-graded scoring engine w/ change alerting. Free public `/scan/<domain>` is the funnel.

**MXToolbox Domain Health** is not a tool, it is a **fan-out over SuperTool**: one composite page that runs 9 independent SuperTool lookups (observed count for `python.org`) against your domain & its MX hosts, then bins every result into Problems / Blacklist / Mail Server / Web Server / DNS. Commercial, patented (page footer reads *"Patents 10839353 B2 & 11461738 B2"*), monetized on monitoring.

## Registration, access & pricing

- **intoDNS / DNSInspect:** no account, no paywall, no rate-limit banner observed. Both fronted by Cloudflare; DNSInspect's is set to challenge non-browsers, intoDNS's is not.
- **DNS Spy:** **no free monitoring tier** (killed deliberately; their post cites a 3000:1 free-to-paid ratio). 7-day trial, no credit card. Plans start at 10 domains; **Enterprise = 100 domains + full API + 10,000 credits/mo** (their wording is *credits*, not calls). **Prices are unverified and sources conflict:** the 2026-05-28 archive showed **$9** Personal / **$49** Enterprise; a third-party directory listing shows **starting at €4.99/mo**. Treat both as stale. Free public `/scan/<domain>` is unauthenticated & its results are published/cached for other visitors (their wording).
- **MXToolbox:** observed on the live page 2026-09-16, *"Free Users are allowed only one (1) Domain Health Check every 24 hours."* API docs (read off `restapi.aspx`, not an authenticated call): `Authorization: {UUID}` header, **no** `Bearer` prefix; quota resets **12:00 am UTC**; `GET api/v1/Usage` returns `DnsRequests / DnsMax / NetworkRequests / NetworkMax`. **Their own page contradicts itself on the free quota:** the Quick Start prose says *"68 DNS API requests"*, the Rate Limits table says *"Free | 64 (daily) | 0"*. Network requests are **0** on free either way. Free accounts also get one (1) free monitor.

## Features: complete inventory

### intoDNS: 45 checks, 5 categories, 4 states (`pass` / `warn` / `error` / `info` GIFs), enumerated firsthand

| Category | Checks |
|---|---|
| **Parent** (5) | Domain NS records (names the exact gTLD server interrogated) · TLD Parent Check · Your nameservers are listed · DNS Parent sent Glue · Nameservers A records |
| **NS** (18) | NS records from your nameservers · Recursive Queries (open-resolver test) · Same Glue (parent glue vs child A) · Glue for NS records · Mismatched NS records · DNS servers responded · Name of nameservers are valid · Multiple Nameservers (RFC 2182 §5) · Nameservers are lame · Missing nameservers reported by parent · Missing nameservers reported by your nameservers · Domain CNAMEs · NSs CNAME check · Different subnets · IPs of nameservers are public · DNS servers allow TCP connection · Different autonomous systems · Stealth NS records sent |
| **SOA** (8) | SOA record dump · NSs have same SOA serial · SOA MNAME entry (is MNAME listed at parent) · SOA Serial · SOA REFRESH · SOA RETRY · SOA EXPIRE · SOA MINIMUM TTL (RFC 2308 negative-cache framing) |
| **MX** (11) | MX Records · Different MX records at nameservers · MX name validity · MX IPs are public · MX CNAME Check · MX A request returns CNAME · MX is not IP · Number of MX records · Mismatched MX A · Duplicate MX A records · Reverse MX A records (PTR) |
| **WWW** (3) | WWW A Record (follows CNAME chain) · IPs are public · WWW CNAME |

All four state icons confirmed by filename across two live reports (`pass.gif`, `warn.gif`, `error.gif`, `info.gif`; a domain w/o MX exercises warn + error). **Not present, verified by grep over two full reports:** SPF, DKIM, DMARC, DNSSEC, CAA, TXT, AAAA/IPv6, TLS, DS, RRSIG, all zero hits. intoDNS has not grown a check in ~a decade.

### DNSInspect: ~50 checks, 6 scored categories, 5 states (`OK` / `NOTICE` / `WARNING` / `ERROR` / **`Test ignored`** w/ reason)

Categories & their own 0-100 score: **Parent · NS · SOA · MX · Mail · Web**. Everything intoDNS has, plus:

- **NS:** Name Servers Have **AAAA** Records (at parent *and* at child) · **Name Servers Versions**: CHAOS `version.bind` TXT probe, reports leaked BIND strings as a WARNING · Name Servers Distributed on Multiple **/24s** & on Multiple **ASNs** (prints the ASN → NS grouping) · nameserver count evaluated against a recommended **2 to 7** range (from a 2026 search-index snippet of a live report, not the archive).
- **SOA:** **SOA Number Format** (validates `YYYYMMDDnn` convention) · **SOA Rname** (decodes `hostmaster.example.com.` → a mailto) · Refresh/Retry/Expire/Minimum each stated w/ an explicit **recommended range** (e.g. Refresh `[1200..43200]`, Expire `[604800..1209600]`, Minimum `[3600..86400]`).
- **MX:** **RBL Check** on MX IPs · **Check Google Apps Settings** (recognizes the provider & validates its documented MX set) · Reverse Entries for MX rendered as a **Server / IP / PTR / IPs-that-PTR-resolves-back-to** table (forward-confirmed reverse DNS, not just PTR presence).
- **Mail (the distinctive block):** **Connect to Mail Servers**: real TCP/25 connect, captures the `220` banner per host · **Mail Greeting**: compares the HELO/banner hostname to the MX hostname · **Accepts Postmaster Address** & **Accepts Abuse Address**: issue an actual `MAIL FROM:` / `RCPT TO:` transaction per MX and **print the full SMTP transcript** · **Check SPF record** · **Identical TXT records** & **Identical SPF records** across all NS (incl. the legacy `SPF` RR type 99, deprecated by RFC 7208 §3.1) · **Check DMARC record** (presence only).
- **Web:** Resolve Domain Name · Domain Name IPs are Public · Resolve WWW · WWW IPs are Public. **Furniture:** site **thumbnail** from `/thumbs/<hostname>` · **permalink** `/<domain>/<reportID>` freezing the run (the 2024 capture renders a 2017 report) · share string `DNS Report: aaas.org A [88/100] (3 warnings)` · print button · "Report completed in 5.35 seconds" · public **"Recent reports"** feed.
- **Not present (as of the captures):** DNSSEC, CAA, DKIM, BIMI, MTA-STS, TLS-RPT.

### DNS Spy, Security Center: 46 checks / 6 categories in the 2026-05 archive; live copy now says "40+"

Counts & names read verbatim from the archived check listing (2026-05-28). `[E]` = Enterprise-gated. The live page indexed in 2026 advertises "40+ automated security checks", so the table below may be one revision stale.

| Category | Checks (criticality) |
|---|---|
| **Connectivity** (5) | Nameserver Online Status (High) · IPv4 NS Availability (Med) · IPv6 NS Availability (Med) · Nameserver Subnet Distribution, >1 /24 (Med) · SOA Serial Sync (Med) |
| **Performance** (2) | IPv4 Response Time, fails >300 ms (Med) · IPv6 Response Time (Med) |
| **Resilience** (9) | Multiple Nameservers (High) · CAA Records (Med) · DNSSEC Enabled, DNSKEY present (Med) · **DNSSEC Validation**, full DNSKEY/DS/RRSIG chain of trust `[E]` (High) · IPv4 & IPv6 Provider Diversity (Med) · IPv4 & IPv6 Geographic Distribution (Low) · Nameserver Domain Diversity (Low) |
| **DNS Records** (16) | SPF Record (High) · DMARC Record (High) · DMARC Policy Strength, flags bare `p=none` (Med) · Multiple SPF Records (Med) · SPF Restrictiveness, flags `+all` (Med) · **Comprehensive Email Security**, SPF+DKIM+DMARC alignment `[E]` (High) · **Dangling CNAME Detection, subdomain-takeover risk** `[E]` (High) · MX Record Redundancy (Med) · MX TTL Adequacy ≥3600 (Med) · NS Record Consistency (Med) · NS TTL Adequacy ≥3600 (Med) · SOA Configuration (Med) · **RFC Compliance**, run via `named-checkzone` (Low) · Root A Record (Low) · IPv6 Root AAAA Record (Low) · WWW Record (Low) |
| **SSL/TLS** (6, all `[E]`) | Certificate Hostname Mismatch (High) · Weak Key Length, RSA<2048 / EC<256 (High) · Weak Signature Algorithm, SHA-1/MD5 (High) · Deprecated TLS Protocol, 1.0/1.1 (Med) · Certificate Chain Validation (Med) · Self-Signed Certificate (Med) |
| **Expiration** (8) | Domain Expired (High) · Domain Expiring 7d (High) / 30d (Med) / 90d (Low) · SSL Cert Expired `[E]` (High) · SSL Expiring 7d `[E]` (High) / 30d (Med) / 90d (Low) |

**Scoring mechanic (the distinctive part).** Score **weighted by criticality: High ×3, Medium ×2, Low ×1**, mapped to **A 90-100 · B 80-89 · C 70-79 · D 60-69 · F 0-59**. The exact multipliers & bands are archive-only; live copy confirms only "every check carries a severity weight" and an A-F grade. Score is computed at **three scope levels** (account / domain group / individual domain), which live copy also confirms. Every run is stored as a `SecurityCheckEvent`; **notifications fire only on state transitions** (pass→fail, fail→pass). Each failed check deep-links to a KB remediation article.

**Rest of the product** (archive + 2026 search snippets): DNS record monitoring across **60+ RR types** on every authoritative NS, w/ diff-level change history, auto-discovery & out-of-sync NS detection · **AXFR zone-transfer monitoring** where the zone permits it · **WHOIS + RDAP** change monitoring & a unified expiration calendar · SSL cert auto-discovery per IP endpoint, alerts at **90/30/7 days** · **Phishing Sentinel** (typosquat/homograph/IDN, 17+ techniques, threat score 0-100) · Domain Groups w/ per-group grades (MSP reporting) · daily zone backups exportable as BIND / PowerDNS / CSV · notifications to email / Slack / Discord / PagerDuty · per-provider integration pages (`/dns-providers/<provider>`) · an **affiliate program**. **New since the report's first draft:** a **DNS Spy MCP Server** exposing the platform to AI agents via **50+ tools**, Enterprise-only, metered against the 10,000 credits/mo. The earlier claim of "50+ REST endpoints + Swagger + bearer token" is **unread and probably a garbled restatement of the MCP tool count**; only the MCP figure is attested anywhere I could read. Free tools: CAA Record Validator, DNS Propagation Checker (**40+ global resolvers**), Domain Scanner, Public DNS Servers List, embeddable DNS-server widget.

### MXToolbox Domain Health: 192 documented check pages across 18 command families

Enumerated firsthand from `mxtoolbox.com/problem/` on 2026-09-16 (counts drift; an earlier pass read 193):

| Family | n | Family | n | Family | n |
|---|---|---|---|---|---|
| blacklist | 63 | dkim | 12 | http | 4 |
| dns | 21 | bimi | 11 | tcp / tlsrpt | 3 / 3 |
| spf | 16 | smtp | 10 | cname / domain / https | 2 / 2 / 2 |
| robotsai | 13 | rhsbl / llmstxt / mta-sts | 8 / 8 / 8 | dmarc | 5 · whois 1 |

- **dns (21):** DNS Record Published · All Servers Responding · All Servers Authoritative · All Name Servers Timed Out · No Valid Nameservers Responded · DNS Lookup Timeout · At Least Two Servers · Local Parent Mismatch · Primary Server Listed At Parent · Bad Glue Detected · Servers are on Different Subnets · Servers Have Public IP Addresses · Open Recursive Name Server · **Open Zone Transfer** · Server Allows Zone Transfer · SOA Serial Numbers Match · SOA Serial Number Format · SOA Refresh Value · SOA Retry Value · SOA Expire Value · SOA NXDOMAIN Value.
- **smtp (10):** SMTP Connect · Banner Check · Connection Time · Transaction Time · DNS Resolution · Reverse DNS Resolution · Reverse DNS Mismatch · **Open Relay** · TLS · Server Disconnected.
- **spf (16):** Record Published · Syntax Check · Multiple Records · Deprecated (RR type 99) · Record Null Value · Included Lookups (the 10-lookup limit) · **Void Lookups** · Recursive Loop · Duplicate Include · Redirect Evaluation · Modifier · MX Resource Records · Characters After ALL · Type PTR Check · Alignment · Authentication. (12 of these were returned as `Passed` on my live `example.com` call.)
- **dkim (12)**; **dmarc (5)**; **bimi (11)** incl. VMC cert & SVG logo validation; **mta-sts (8)**; **tlsrpt (3)**; **blacklist (63)** IP RBLs + **rhsbl (8)** domain lists; **whois (1)**. **robotsai (13)** & **llmstxt (8)** are 2025-era additions checking `robots.txt` handling of GPTBot / ClaudeBot / CCBot / PerplexityBot / Google-Extended and `llms.txt` well-formedness. Nobody else here has them.

**Observed response schema** (`/api/v1/lookup/dns/example.com`, unauthenticated test target, read 2026-09-16): `UID, ArgumentType, Command, IsTransitioned, CommandArgument, TimeRecorded, ReportingNameServer, TimeToComplete, RelatedIP, ResourceRecordType, IsEmptySubDomain, SPF_Subaction_Detail, Records, IsEndpoint, HasSubscriptions, AlertgroupSubscriptionId, Failed[], Warnings[], Passed[], Timeouts[], Errors[], IsError, Information[], MultiInformation[], Transcript[], MxRep, EmailServiceProvider, DnsServiceProvider, DnsServiceProviderIdentifier, CustomData, RelatedLookups[]`. Each check is `{ID, Name, Info, Url, PublicDescription, IsExcludedByUser}` where `Url` is its KB article. For `example.com`: 14 Passed, 2 Warnings, 0 Failed, `ReportingNameServer: hera.ns.cloudflare.com`, `TimeToComplete: 360` ms (varies run to run), `DnsServiceProvider: "Cloudflare"`.

Three payload shapes worth naming separately:
- **`Information[]` on a `dns` lookup = a per-nameserver matrix**: `Type, Domain Name, IP Address, TTL ("24 hrs"), Status [GREEN], Time (ms), Auth [GREEN], Parent [GREEN], Local [GREEN], Asn [{asname, asn}], IsIpV6`. One grid replaces a dozen prose checks: agreement is shown as three columns (authoritative / parent / local) rather than three separate findings.
- **`Transcript[]` = the iterative resolution log**: `TimeStamp, Depth, ServerName, ServerIP, Authoritative (AUTH|NON-AUTH), ElapsedTime, Result ("Received 2 Referrals , rcode=NO_ERROR"), Question, Answers`. Depth 1 is a gTLD server (`m.gtld-servers.net` on my run, the letter varies), depth 2 the authoritative NS. They resolve from the TLD down & show their work.
- **`Information[]` on an `spf` lookup = the tokenized record**: `{Prefix:"-", Type:"all", Value:"", PrefixDesc:"Fail", Description:"Always matches. It goes at the end of your record.", RecordNum:null}` per mechanism.

Beyond lookups the API also exposes **`GET api/v1/Monitor`** (paid; filter by command/name/tag), **`GET api/v1/Monitor/{uid}/Tag`**, and **`GET api/v1/Usage`**. Both `mxtoolbox.com/api/v1/` and `api.mxtoolbox.com/api/v1/` served my lookup 200.

## Record types & query options supported

| | RR types touched | Query knobs exposed to user |
|---|---|---|
| intoDNS | NS, SOA, A, MX, CNAME, PTR | **none**: no resolver picker, no RR selector, no output format |
| DNSInspect | + AAAA, TXT, SPF(99), DMARC TXT | **none** |
| DNS Spy | 60+ monitored; CAA, DNSKEY/DS/RRSIG, TXT/SPF/DKIM/DMARC | **none** in the audit; propagation tool picks from 40+ resolvers |
| MXToolbox | `a, aaaa, asn, bimi, dkim, dmarc, dns, mta-sts, mx, ptr, soa, spf, tlsrpt, txt` + network `blacklist, http, https, ping, smtp, tcp, trace` | argument **modifiers** on the SuperTool page: `domain:all` = propagation, `domain:selector` for DKIM, `?port=` for TCP. **The REST route rejects them:** `/api/v1/lookup/dns:all/example.com` 302s into `/Public/Errors/Generic.aspx`, so propagation is web-UI-only |
| Zonemaster | full delegation + DNSSEC chain | `profile` (only `default` on the public instance), IPv4/IPv6 toggles, optional explicit NS set |

The shared, deliberate design choice: **none lets you choose a recursive resolver or set EDNS/ECS/DO flags**. An audit tool queries the parent & each authoritative server directly by definition; resolver-picking is digwebinterface/Google-Admin-Toolbox territory. Only MXToolbox surfaces raw TTLs & a trace; intoDNS prints `TTL=…` inline in its info rows; DNSInspect prints `TTL=86400` per NS/MX record.

## How it works

All are **100% server-side**; nothing is done in the browser (MXToolbox's browser JS only orchestrates calls to its own API). All follow the same pipeline: resolve the parent zone → query a TLD server w/o recursion for the delegation & glue → query **each** authoritative NS individually & non-recursively → diff parent vs child vs each other → apply rules. Reproduced the primitives w/ `dig`: `+norecurse` against `a0.org.afilias-nst.info` returns `python.org`'s four Route 53 NS from the parent; per-NS `SOA` shows serial agreement; `+tcp` succeeds; CHAOS `version.bind` returns empty against Route 53 (they refuse it, which is itself the finding DNSInspect reports on).

- **intoDNS:** Django, Cloudflare in front (`cf-cache-status: DYNAMIC`, `vary: Cookie`), complete report in ~1.2 s wall. Two runs of the same domain returned byte-identical output; `DYNAMIC` argues for re-running per request rather than caching, but **I did not prove which**, and the URL is also the permalink either way.
- **DNSInspect:** caches each run under a numeric report ID & serves it indefinitely (a 2024 capture rendered a 2017 run). Self-reported in-page run times **1.31 s** and **5.35 s**; the spread is plausibly the live SMTP work, inferred, not stated by them.
- **DNS Spy:** continuous scan cycles per domain rather than on-demand; free `/scan/<domain>` advertises 1-2 minutes & publishes the result publicly. Check applicability is discovered per domain (records, certs & plan) rather than run blindly.
- **MXToolbox:** the interesting one. `GET /api/v1/domain/{domain}` is a **planner**: it returns *only a job list*, verified for `python.org` → `https`, `http`, `dns`, `blacklist`, `mx`, `dmarc` against the domain, `blacklist` & `smtp` against `mail.python.org`, plus `spf`. The browser then fires `GET /api/v1/lookup/{Command}/{Address}` per job and appends each result into its category pane as it lands. **Planner is unauthenticated; the lookups are not.**
- **Zonemaster:** the only one whose mechanism you can just read. Backend is a job queue: `start_domain_test` returns a 16-hex `test_id`, `test_progress` returns 0-100, `get_test_results` returns a flat array of `{module, testcase, ns, message, level}`. My `example.com` run: 110 rows, `Counter({INFO: 102, NOTICE: 6, WARNING: 2})`.

## Output & UX

- **intoDNS:** one flat 4-column table, `Category | Status | Test name | Information`, 46 rows incl. header, category label spans its block, GIF icon carries the state. No JS, no progressive rendering, no export. Every finding ends in plain-English remediation + an **RFC citation**; grep over a live report finds RFC1912 (×3), RFC2181 (×2), RFC2182, RFC2308. Empty state is blunt: *"Oh well, I did not detect any MX records…"*.
- **DNSInspect:** summary widget first: site thumbnail | six rows of `icon + horizontal bar + 0-100 score`, each anchor-linked to its section | a large **letter grade** block. Then the sections. Share/print/permalink in the meta row. Skipped checks state *why*: "Test ignored, name servers are located outside of current zone."
- **DNS Spy:** dashboard-shaped, not report-shaped: grade badge at account/group/domain, nav badge counting failed checks, per-check history timeline, KB deep-link per failure.
- **MXToolbox:** five counter cards (Problems / Blacklist / Mail Server / Web Server / DNS), each `Errors / Warning / Passed`, tabs per category, a **"Show All Tests"** toggle. Renders **progressively** as each fan-out lookup returns. Unusable w/o JS: the served HTML says so in as many words.

## Monetization, limits & abuse controls

intoDNS & DNSInspect monetize indirectly (hosting-company footer ads; DNSInspect not visibly at all) & defend w/ Cloudflare: DNSInspect's challenge is aggressive enough to lock out curl, WebFetch *and* the Wayback crawler, a real product cost, though search engines still get through. DNS Spy sells the *continuity*, not the checks: one-shot scan is free & public, the graded history + alerting + SSL/DNSSEC/dangling-CNAME checks are paid, and the free monitoring tier was deliberately killed. MXToolbox gates the same data three ways: **frequency** (1 Domain Health check / 24 h free), **depth** (propagation modifiers are web-UI-only, monitoring is paid), and **volume** (API 64/68 DNS req/day free, **0 network req**, meaning `smtp`/`blacklist`/`http` cost money from request one). Its `robots.txt` disallows `/api/v*`, `/problem/`, `/domain/` and `/SuperTool.aspx` while the API itself sends `access-control-allow-origin: *`.

## Ideas worth stealing

- **Planner endpoint + htmx fan-out.** MXToolbox's `/api/v1/domain/{d}` → job list → N independent lookups is *exactly* our layering. Domain service returns `[]CheckJob`; handler renders N `<div hx-get="/health/{d}/{check}" hx-trigger="load" hx-swap="outerHTML">` stubs into their category panes. Each check is its own handler → its own domain call → `platform.Respond`, so each speaks HTML fragment + JSON for free, slow checks never block fast ones, and the page paints in stages w/o a websocket. If fan-out latency ever outgrows one request, Zonemaster's three-call shape (`start` → `progress` → `results`) is the fallback and maps cleanly onto a Mongo job doc.
- **Weighted score, not a pass count.** DNS Spy's ×3/×2/×1 by criticality → 0-100 → `A≥90 / B≥80 / C≥70 / D≥60 / F`. One `Severity` enum + one `Weight()` method in the domain package; the grade is the shareable artifact. nslookup.io does the same thing w/ a per-category score plus an overall, which reads better.
- **The DNSInspect summary widget**, verbatim in structure: per-category bar + score + anchor jump, overall grade block beside it. It makes a 50-row report skimmable in one screen, and anchors mean the deep link lands on the failing section. Steal their share string too: `DNS Report: example.com A [88/100] (3 warnings)` writes the OG title & `<title>` for you.
- **Frozen report permalinks.** `/{domain}/{id}` storing the run, exactly the Mongo repository pattern already used for iptools lookup history: repo below the domain service, `platform.EnsureTTLIndex` for self-pruning, nil-safe so an empty `MONGODB_URI` just disables permalinks.
- **Five states, not three:** `pass / info / warn / fail / skipped`, and make `skipped` carry its reason ("name servers are outside this zone"), which stops a not-applicable check reading as a failure. Zonemaster's ladder is the mature version: CRITICAL / ERROR / WARNING / NOTICE / INFO / DEBUG, default reporting NOTICE and above. Pair each state w/ a **`KBSlug`**: MXToolbox returns a KB `Url` per check and DNS Spy links every failure to an article, and we already render markdown from `docs/`, so the tool ships its own remediation pages. Cheapest credibility in the category.
- **The nameserver matrix**, the highest information-per-pixel thing any of them renders: one table (NS name, IP, ASN + asname, TTL, response ms, Auth / Parent / Local agreement columns) replaces ~8 individual intoDNS checks & reuses iptools' existing ASN lookup. Under it, ship MXToolbox's **`Transcript[]`** collapsed as "show resolution trace": iterative resolve from a root/TLD server w/ recursion disabled, logging depth, server, AUTH/NON-AUTH, elapsed, rcode, answers, which is cheap in Go.
- **Tokenized SPF table** w/ a plain-English `Description` per mechanism & a `PrefixDesc` ("Fail" for `-`) beats printing the raw string; the 10-lookup / void-lookup counters are pure arithmetic over the parse tree.
- **Cite the RFC, and state the recommended range.** intoDNS's oldest habit; DNSInspect's numeric framing is the other half (`Refresh is 1800, recommended [1200..43200]`). Quote RFC 2182 §5 exactly, *"recommended that three servers be provided for most organisation level zones"*, rather than paraphrasing it into a hard minimum.
- **Skip the live SMTP probing.** DNSInspect's `RCPT TO: <postmaster@…>` transcript is the most impressive thing here and the worst fit for us: outbound :25 from a Hetzner box is usually blocked or reputation-poisoned, and unsolicited RCPT probing of third-party MX looks like address harvesting. Same call as the shelved port scanner. **Do** the DNS-only mail checks (MX sanity, PTR + forward-confirmed reverse, SPF/DMARC parse); leave the socket alone.
- **Cross-check against Zonemaster in tests.** Its public API is free, keyless and CORS-open, so our test suite can diff our findings against a reference implementation for a handful of fixture domains. Do this offline in tests, not per user request.

## Gaps & what it does not do

- **DNSSEC is barely covered in the four originally surveyed.** intoDNS & DNSInspect have **zero** DNSSEC checks; DNS Spy splits it (DNSKEY presence in all plans, chain-of-trust validation Enterprise-only). But **Zonemaster's DNSSEC module is 18 test cases and free**, and nslookup.io scores a 7-check DNSSEC category free, so "an honest DNSSEC verdict" is no longer a differentiator on its own. DNSViz remains the deep-dive.
- intoDNS & DNSInspect have **no CAA, DKIM, BIMI, MTA-STS or TLS-RPT** (& no AAAA at all in intoDNS), and neither has a JSON path, an API, or a reason to log in. Nobody in the set exposes **resolver choice, EDNS/ECS, DO bit, TCP toggle, or raw `dig` output** either: correct for the audit frame, but it means a health report is not a substitute for a lookup tool & shouldn't pretend to be.
- **No propagation view in the free audits.** Parent-vs-authoritative agreement is not the same as what 30 public resolvers currently cache; MXToolbox sells that as `:all`, DNS Spy gives a free 40+-resolver checker as a separate tool.
- **The "free curl-able zone audit" niche is NOT unmet.** This was the original draft's headline conclusion and it is wrong. **Zonemaster's public instance** already serves a full audit over unauthenticated JSON-RPC w/ `Access-Control-Allow-Origin: *`, and **nslookup.io** already returns a scored JSON health report from a keyless `GET`. What is still genuinely thin: a **single-request, synchronous, sub-second HTML-or-JSON** audit (Zonemaster needs three calls and ~30 s; nslookup.io's endpoint is undocumented and unpromised), and one whose remediation prose & RFC citations are its own rather than a KB paywall. Differentiate on latency, on content negotiation, and on the writing, not on existing at all.

## Verified firsthand vs inferred

**Verified firsthand (2026-09-16 unless noted):** every intoDNS check name, category & state-icon filename (parsed from two live reports, 45 checks reproduced exactly); intoDNS timings, sizes, status codes, absent CORS, `/check/?domain=` → `/{domain}` redirect, RFC-citation counts, the absence of SPF/DNSSEC/CAA/AAAA/TXT/TLS. MXToolbox's planner→fan-out architecture, the planner's unauthenticated 9-job list for `python.org`, the 401 on non-`example.com` lookups, the full response schema incl. `Information[]` NS matrix, `Transcript[]` & tokenized SPF, the 12 `Passed` SPF check names, `access-control-allow-origin: *`, the `robots.txt` disallow list, the 192-page/18-family problem catalogue, the "one (1) Domain Health Check every 24 hours" wording, the JS-required page shell, the patent numbers in the footer, the `dns:all` REST route 302ing to a generic error page. **Zonemaster's entire public API** (JSON-RPC, keyless, CORS `*`, engine v9.0.0, full `example.com` run: 110 rows, 10 modules, INFO/NOTICE/WARNING observed). **nslookup.io's** keyless JSON health endpoint (200, 7 categories, 32 checks returned, per-check `severity`, overall score 75, no CORS header). All `dig` reproductions of the audit primitives (parent-vs-child NS, SOA serial agreement across NS, TCP/53, CHAOS `version.bind` refusal, absence of legacy TYPE99).

**Read from docs, not from an authenticated call:** MXToolbox's auth header format, the 24-command list, the quota reset time and the `Usage`/`Monitor` endpoint shapes, all from `restapi.aspx`, which **contradicts itself on the free DNS quota (68 in prose, 64 in the table)**. Check names outside the `dns` and `spf` families were enumerated from `/problem/` URL slugs, not from live responses.

**Read from archived captures, not live** (both sites 403 curl & WebFetch w/ `cf-mitigated: challenge`, re-confirmed 2026-09-16): every DNSInspect check name, score widget, thumbnail, permalink & SMTP-transcript detail (Wayback raw captures 2024-10-17 & 2025-01-18; the check list is independently corroborated in outline by 2026 search-index snippets of live report pages, but the scores, transcripts and furniture are not). Every DNS Spy check name, criticality, weight multiplier & grade band (Wayback 2026-05-28 & 2026-03-09); live copy says "40+ checks" against the archive's 46, so the table may be a revision stale.

**Unverified or contradicted:** **DNS Spy prices.** The archive shows $9 / $49; a third-party directory shows €4.99/mo starting. Neither is confirmable and both may be stale; do not quote a DNS Spy price without re-checking. **DNS Spy's REST API surface**: `/docs/api` is a JS SPA and returned nothing even archived; the "50+ endpoints / Swagger / bearer token" line has no readable source and is more likely a restatement of the **50+ MCP tools** their blog does advertise. **DNS Spy's current operator**: Geniar's post (2020-09-16) announces a handover to SecurityTrails, today's site is a different codebase & positioning, and I could not establish who runs it. **intoDNS report caching**: two identical runs returned identical bytes; `cf-cache-status: DYNAMIC` argues for re-running, unproven either way. `dnsinspect.org` is a *different, newer* site from `dnsinspect.com` w/ no ownership link found, so nothing from it is used above. DNSInspect's exact live check list today remains unconfirmable while the challenge is up.

## Open source / reusable

- **[Zonemaster](https://github.com/zonemaster/zonemaster)** (AFNIC + IIS, **2-clause BSD**, license confirmed in the README) is the only serious open implementation of this category & the closest thing to a spec. Components: Zonemaster-**LDNS**, **Engine**, **CLI**, **Backend** (JSON-RPC 2.0 over HTTP POST), **GUI**. Nine documented test modules, **74 test case specifications** total: Address 3, Basic 3, Connectivity 4, Consistency 6, DNSSEC 18, Delegation 7, Nameserver 14, Syntax 8, Zone 11 (a live run also emits a `System` module). Severity ladder **confirmed**: CRITICAL / ERROR / WARNING / NOTICE / INFO / DEBUG / DEBUG2 / DEBUG3, default reporting NOTICE and above. It is Perl, so not a dependency for us, but the test-case docs are a ready-made checklist, the module taxonomy is a better category split than any commercial UI, and the **public instance is a free keyless API we can diff against in tests**.
- **None** of intoDNS, DNSInspect or DNS Spy publish source. MXToolbox is closed & patented.
- For Go the realistic stack is `github.com/miekg/dns` for non-recursive per-NS queries + CHAOS/EDNS control; `named-checkzone` exists as a shell-out precedent (DNS Spy's own RFC-compliance check uses it per their archived copy) but adds a BIND dependency we do not want in a distroless image.

## Sources

- [intoDNS live report for python.org (check table read firsthand; [home page](https://intodns.com/) carries the Django/Hosterion attribution)](https://intodns.com/python.org)
- [MXToolbox Domain Health page (free-tier limit, patent numbers, JS gate)](https://mxtoolbox.com/domain/)
- [MXToolbox problem knowledge base (192 pages / 18 families, enumerated)](https://mxtoolbox.com/problem/)
- [MXToolbox lookup API, open test target (DNS response schema + [SPF tokens](https://mxtoolbox.com/api/v1/lookup/spf/example.com), read firsthand)](https://mxtoolbox.com/api/v1/lookup/dns/example.com)
- [MXToolbox REST API documentation (auth header, commands, quotas, Monitor & Usage)](https://mxtoolbox.com/restapi.aspx)
- [DNS Spy Security Center feature page (checks, weights, grade bands, archived)](https://dnsspy.io/features/security-center)
- [DNS Spy pricing (unreadable live; figures unverified)](https://dnsspy.io/pricing)
- [DNS Spy blog: why the free tier was cancelled](https://dnsspy.io/blog/we-cancelled-free-tier/)
- [DNS Spy blog: MCP server, 50+ tools, Enterprise, 10,000 credits/mo](https://dnsspy.io/blog/dns-spy-mcp-server)
- [DNS Spy third-party directory listing (starting price €4.99/mo, AXFR monitoring)](https://sourceforge.net/software/product/DNS-Spy/)
- [Mattias Geniar: a new start for DNS Spy (handover to SecurityTrails, 2020-09-16)](https://ma.ttias.be/a-new-start-for-dns-spy/)
- [DNSInspect report permalink (structure, scores, SMTP transcript), read via Wayback](https://www.dnsinspect.com/aaas.org/1427235207)
- [Zonemaster project README (2-clause BSD, five components)](https://github.com/zonemaster/zonemaster)
- [Zonemaster public documentation (nine test modules, 74 test cases, JSON-RPC API, [severity levels](https://doc.zonemaster.net/latest/specifications/tests/SeverityLevelDefinitions.html))](https://doc.zonemaster.net/latest/)
- [Zonemaster public instance, JSON-RPC endpoint exercised firsthand](https://zonemaster.net/api)
- [nslookup.io [DNS Health](https://www.nslookup.io/dns-health/) & its keyless JSON endpoint, read firsthand](https://www.nslookup.io/api/v1/dns-health/example.com)
- [RFC 2182 §5: how many secondaries ("recommended that three servers be provided")](https://www.rfc-editor.org/rfc/rfc2182)
- [RFC 2308: negative caching of DNS queries (SOA MINIMUM semantics)](https://www.rfc-editor.org/rfc/rfc2308)
- [RFC 7208 §3.1: SPF RR type 99 deprecated in favour of TXT](https://www.rfc-editor.org/rfc/rfc7208)
