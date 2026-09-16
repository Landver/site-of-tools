# DNS lookup landscape & ideas to steal

> Raw record lookup is a commodity, free & keyless from Google/Cloudflare DoH JSON in one HTTP call
> (`google-admin-toolbox-dig`, `dns-apis-and-pricing`) — competing on *records* is pointless. Every
> report in this corpus agrees the value sits one layer up: judgment on top of records that already
> exist for free — RFC-cited verdicts, honest propagation semantics (cache-age & ECS-scope, not raw
> TTL), plain-English protocol failures (EDE, negative caching, wildcard synthesis) — and almost none
> of that layer is done well, done free, or done without a CAPTCHA wall anywhere in the 37 reports.

Synthesizes 37 research reports (see sibling `.md` files, `firsthand-ui-observations.md` records what
actually rendered when driven live 2026-09-15). Each non-obvious claim tagged w/ source slug. Where
reports disagree, or the corpus stayed thin, called out explicitly at the end.

## Comparison table

| Service | Category | Registration | Client/server | Headline capability | Monetization | Standout idea |
|---|---|---|---|---|---|---|
| MXToolbox (`mxtoolbox`) | DNS + email deliverability SaaS | Freemium, ad-supported free tier | Server-side, keyed REST API (64/day free) | One command-bar (`cmd:arg`) over ~36 lookups, every result = named pass/warn/fail checks | Freemium + ads + paid monitoring/API | Stable numeric check IDs w/ `/problem/<cmd>/<check>` explainer pages |
| NsLookup.io (`nslookup-io`) | Consumer DNS lookup + zone health + email/cert security | Free lookup, freemium monitoring | Server-side + free keyless REST API + MCP server | Best-designed consumer lookup: path permalinks, decoded records | Monitoring upsell (currently free) | Pre-deploy DNS Change Analyzer, severity-weighted risk score |
| DNSChecker.org (`dnschecker-org`) | Propagation checker + web-tools portal | Free, ad-supported, no account | Server-side, no public API | Fans query to ~28 curated resolvers across 21 countries + ~110-tool grab-bag | Ads | Expected Value matcher (Exact/Contains/RegExp) |
| whatsmydns (`whatsmydns`) | Global propagation checker + utility suite | Free, ad-funded, no accounts | Server-side, undocumented internal JSON | Canonical free checker: 22 ISP recursive resolvers, 17 countries | Ads | Shareable hash URL encodes query *and* expected value |
| ViewDNS.info (`viewdns-info`) | Multi-tool DNS/IP/domain intel portal + commercial API | Free web tools, metered paid API/credit pool | Server-side, same backend both sides | 26 free tools sit on 22 metered API endpoints | Free-tool-as-paid-API-funnel + bulk data | Redacted-JSON teaser sells the API off the HTML page |
| Google Admin Toolbox / dns.google (`google-admin-toolbox-dig`) | Free public resolver + vendor UI, keyless JSON DoH API | None, keyless | Both — `/resolve` is CORS-open, browser-callable | Two free Google DNS front-ends over a keyless CORS-open JSON DoH backend | None (Google infra) | Annotate raw integers inline: `"Status":0 /* NOERROR */` |
| DigWebInterface (`digwebinterface`) | Raw-dig web frontend / power-user diagnostics | Free, donation-funded, CAPTCHA after 100/24h | Server-side, no API | Raw `dig(1)` as HTML form: 49 types, 10 resolvers, 5 NS modes | Donations + ads (2-week opt-out) | Prints the exact `dig` command it ran |
| DNSlytics (`dnslytics`) | Passive DNS / domain & IP OSINT dataset (not live) | Freemium (Month/Year Pass) | Server-side dataset + a few free keyless endpoints | 330M+ domain passive-DNS corpus, reverse NS/MX/IP/PTR/SPF | Paid passes + premium reverse lookups | One query grammar powers every "reverse X" tool as a thin route |
| Robtex / HE / RIPEstat (`robtex-he-ripestat`) | 3 network-intelligence / passive-DNS / registry APIs | Free (Robtex freemium, HE ads, RIPEstat free keyless) | Both, RIPEstat fully CORS-open | "What else is connected to this name/IP/prefix," not "what's the A record" | Robtex paid tiers; RIPEstat is RIPE NCC-funded | RIPEstat's FCrDNS closure rendered as confirmed/not-confirmed |
| Zone-audit cluster: intoDNS/DNSInspect/DNS Spy/MXToolbox Health (`dns-health-audit-tools`) | Zone configuration checkers | Free (intoDNS/DNSInspect), freemium (DNS Spy/MXToolbox) | Server-side | Parent + every authoritative NS queried, pass/warn/fail w/ remediation | DNS Spy/MXToolbox paid tiers & monitoring | Planner-endpoint + htmx-shaped fan-out; weighted 0-100 score |
| Zonemaster (`zonemaster`) | Open-source zone/delegation validator | Free, no-auth, self-hostable | Both — JSON-RPC API + CLI + self-hosted engine | 73 RFC-cited test cases, 8-level severity, CORS-open JSON-RPC | None (IIS/AFNIC public good) | Numbered stable check catalogue + severity-per-tag profile |
| DNSViz / Verisign Debugger (`dnsviz-and-dnssec-debuggers`) | DNSSEC chain-of-trust analyzers | Free, no account | Server-rendered | DNSViz = annotated graph + dated archive; Verisign = live checklist | None (research/vendor goodwill) | Responses matrix: every RRset x every authoritative NS, Y/N |
| Email-auth cluster: dmarcian/EasyDMARC/LearnDMARC/Postmark/Mailhardener (`email-dns-checkers`) | Email DNS validators & builders | Freemium | Server-side, some free JSON | Parsed/judged SPF/DKIM/DMARC/BIMI/MTA-STS/TLS-RPT/DANE + builders | Freemium, Enterprise API gating, digests | Per-tag "defined vs effective value" split |
| DNSDumpster / HackerTarget (`dnsdumpster-hackertarget`) | Passive DNS recon / OSINT attack-surface discovery | Free keyless API family + paid membership | Server-side, keyless (quota per source IP) | htmx-built recon dashboard joining dataset subdomains to ASN/PTR/banner enrichment | Membership scanners, DD Plus/API | Per-row kebab menu firing drill-downs into a modal |
| SecurityTrails & passive-DNS vendors (`securitytrails-passive-dns`) | Passive/historical DNS intelligence (commercial DBs) | Paid (free-tier figures contradictory) | Server-side commercial APIs | Answers "what did this resolve to before now" | Paid API tiers, credits | Bidirectional single route matches name-or-IP against both key and value |
| CT/crt.sh/Cert Spotter/Chaos/subfinder/Amass (`subdomain-enumeration-and-ct`) | Passive subdomain enumeration / Certificate Transparency | Free keyless (crt.sh, Cert Spotter free), some keyed | Both, CORS-open JSON | CT logs = the working replacement for a zone transfer | Cert Spotter firehose paid, Chaos key-gated | `exclude=expired` as a segmented "currently valid vs ever issued" toggle |
| RDAP / WHOIS / who.is / DomainTools (`whois-rdap-tools`) | Registration-data lookup | Free (RDAP, IANA), freemium (who.is), paid (DomainTools) | Both, RDAP largely CORS-open | RDAP is the sanctioned WHOIS replacement, keyless JSON-over-HTTPS | DomainTools paid API/SDK, who.is login-gated extras | Cache the 5 IANA bootstrap files, resolve registry→registrar in 2 hops |
| DNS leak / resolver-identity cluster (`dnsleaktest-and-resolver-identity`) | DNS leak test / resolver identification | Free, no account | Both — server-run beacon zone + JS client | Identifies which recursive resolvers a visitor actually uses | None / VPN-adjacent | Own a wildcard subzone w/ a small authoritative logger |
| API/pricing landscape (`dns-apis-and-pricing`) | Survey (not a single service) | n/a | n/a | Raw lookup is free/keyless/high-quota; paid tiers sell the inverse index | n/a | Fire Google+Cloudflare DoH concurrently, badge disagreement |
| DNSBL/RBL/URIBL/DNSWL cluster (`rbl-and-domain-reputation`) | IP & domain reputation blocklists | Mostly free (public-resolver ACL'd), Spamhaus DQS key-gated | Server-side, DNS-as-database queries | DNS itself as a reputation key-value store | MXToolbox/Talos paid monitoring, DQS keys | Render-then-fill htmx rows, decode refusal/rate-limit sentinel codes |
| DNS protocol semantics (`dns-concepts-and-query-modes`) | Technique/concept report | n/a | n/a | Protocol semantics a tool must render correctly, mapped to UI + cost | n/a | RFC 9824 compact-denial detection via NSEC bitmap TYPE128 |
| Record-type reference (`record-types-reference`) | Technique/concept reference | n/a | n/a | Every DNS record type worth supporting, tiered by value | n/a | Decode the ECH `SvcParam`; nobody else in the corpus does |
| Public DoH/DoT/DoQ resolvers (`doh-dot-doq-and-public-resolvers`) | Technique/concept research | n/a (resolvers mostly keyless) | Both | 7 major public resolvers' encrypted-DNS APIs, CORS posture, measured disagreement | n/a | DDR SVCB record reveals a resolver's own DoH/DoT/DoQ endpoints |
| Go DNS libraries (`go-dns-implementation`) | Implementation research | n/a | n/a (our own build) | Assessment of Go DNS libs to build the tool on | n/a | `errgroup` fan-out + `singleflight` collapsing of duplicate lookups |
| Propagation methodology (`propagation-checking-methodology`) | Technique/concept | n/a | n/a | "Propagation" conflates 4 unrelated effects; 3 are detectable | n/a | Cache-age column (authTTL − reportedTTL) replaces raw TTL |
| Browser constraints (`browser-constraints-dns-2026`) | Platform-feasibility report | n/a | Defines the client/server split | Maps which DNS features can run in the visitor's browser vs must run server-side | n/a | DoH JSON GET is a CORS *simple* request — zero preflight cost |
| Monitoring & history features (`monitoring-and-history-features`) | Technique/concept survey | n/a | n/a | The paid tier of every DNS tool is scheduled re-checks + diff + alerts + history | n/a | Hash the canonicalized RRset as the change primitive (mirrors botcheck) |
| Globalping (`globalping`) | Distributed real-probe measurement network | Free, keyless, CORS-open; credits for volume | Both | jsDelivr's free API running real `dig` on 5,000+ volunteer probes | None (jsDelivr-backed) | Group probes by identical answer-set, not a "% propagated" number |
| CF/Google/OpenDNS cache-purge tools (`resolver-cache-purge-tools`) | Resolver cache management | Free, operator-run, no account | Server-side calls to their endpoints | 3 free tools evict a name+type from a public resolver's own cache | None | "Now purge it" step, then poll to prove it worked |
| dnstwist (`dnstwist`) | Typosquat / brand-impersonation discovery | Free, no account, Apache-2.0 OSS | Both — hosted + CLI | 16 permutation fuzzers + bulk resolution + live clone detection via fuzzy hash | None (OSS project) | Per-TLD homoglyph gating table (suppresses guaranteed-NXDOMAIN noise) |
| internet.nl (`internet-nl`) | Standards-compliance scorecard | Free, gov/ISOC-backed, open-source | Server-side, documented batch API | Scores a domain 0-100% across 38 subtests (DNSSEC/DANE/IPv6/mail/RPKI/TLS) | None (public good) | Scoring model: equal category weight, only REQUIRED subtests count |
| DNSPerf / PerfOps (`dnsperf-perfops`) | Comparative DNS benchmark + on-demand test API | Free keyless catalogue, credit-metered tests | Server-side, documented REST API | Benchmarks 37 authoritative providers/12 resolvers/13 roots from 413 nodes | Paid monitoring/alerts/reports | Async job+poll model maps directly onto an htmx self-repolling fragment |
| doggo (`doggo`) | Open-source CLI DNS client + hosted web front end | Free, GPL-3.0, no account | Both | `dig` replacement on miekg/dns: UDP/TCP/DoT/DoH/DoQ/DNSCrypt + trace + Globalping | None (OSS) | Transport-as-URL-scheme on the single resolver input field |
| check-host.net / ping.pe (`check-host-and-ping-pe`) | Multi-node reachability checkers w/ DNS side-feature | Free, keyless JSON API, no account | Server-side | check-host hands out 56 probes as keyless JSON; ping.pe deliberately keeps a smaller set | None observed | `/nodes/hosts` keyless, cacheable vantage-point feed |
| RIPE Atlas (`ripe-atlas-dns`) | Distributed active-measurement research infra | Free reads (keyless, CORS-open); credits for new measurements | Both | ~15k probes, DNS first-class; open archive of 37.5M DNS measurements w/ raw wire answers | None (RIPE NCC-funded) | Mine the open archive instead of owning probes |
| Abuse & rate-limit constraints (`abuse-ratelimits-and-ethics`) | Cross-cutting constraint report | n/a | n/a | Our real exposure is fan-out & attribution laundering, not amplification | n/a | Per-request query budget, not just a per-IP limiter |
| Firsthand UI pass (`firsthand-ui-observations`) | Live-driven companion report | n/a | n/a | 9 flagship tools driven live in-browser 2026-09-15, records what actually rendered | n/a | Cross-tool pattern: query-in-URL, TTL-as-time, name the answering server |

## Market segmentation

| Job | Who does it today | How well served |
|---|---|---|
| Sysadmin debugging a broken zone/delegation | intoDNS, DNSInspect, DNS Spy, MXToolbox Health, Zonemaster, DigWebInterface (`dns-health-audit-tools`, `zonemaster`, `digwebinterface`) | **Well served by volume**, but only Zonemaster and NsLookup.io's health API are fast/keyless/JSON (`dns-health-audit-tools` fact-check reversed its own "unmet niche" claim once it tested both live) — differentiate on latency & curl-ability, not existence |
| Dev checking propagation after a change | whatsmydns, dnschecker-org, nslookup-io, ViewDNS, dnsmap.io, Globalping (`whatsmydns`, `dnschecker-org`, `globalping`) | **Most crowded job in the corpus, worst-served on honesty**: `propagation-checking-methodology` shows the incumbents conflate cache age, anycast, GeoDNS steering & resolver filtering into one red/green cell and silently hide dead resolvers |
| DNS change risk review before a deploy | NsLookup.io only (`nslookup-io`) | **Genuinely underserved** — one tool in 37 reports does pre-deploy diff + deterministic rules + risk score; nobody else attempts it |
| Email admin fixing SPF/DKIM/DMARC/BIMI/MTA-STS | MXToolbox, dmarcian, EasyDMARC, LearnDMARC, Postmark, Mailhardener (`mxtoolbox`, `email-dns-checkers`) | Well served, but most parsed-verdict tooling sits behind freemium email-capture gates |
| Security researcher enumerating attack surface | DNSDumpster/HackerTarget, SecurityTrails, crt.sh/Cert Spotter, Robtex, DNSlytics, dnstwist (`dnsdumpster-hackertarget`, `securitytrails-passive-dns`, `subdomain-enumeration-and-ct`, `dnstwist`) | Well served for paid users; the free/keyless tier (crt.sh, Cert Spotter, HackerTarget's keyless routes) is real but scattered across 6+ separate front doors |
| DNSSEC deployer validating chain of trust | DNSViz, Verisign Debugger, Zonemaster's DNSSEC module, internet.nl (`dnsviz-and-dnssec-debuggers`, `zonemaster`, `internet-nl`) | Well served for depth, poorly served for speed — DNSViz's graph model is powerful but slow/visual, nobody ships a fast plain-text EDE-driven "why is DNSSEC failing" answer |
| Privacy user checking their resolver | dnsleaktest.com, bash.ws, ipleak.net, browserleaks/dns, 1.1.1.1/help (`dnsleaktest-and-resolver-identity`) | Served, but each tool only shows part of the picture (egress IP *or* transport *or* DNSSEC validation), never EDE + transport + validation in one honest card |
| Registrar/domain-lifecycle check (WHOIS/RDAP, expiry) | RDAP/rdap.org, who.is, ViewDNS, DomainTools (`whois-rdap-tools`) | Well served; RDAP's free keyless tier makes this cheap to bolt onto any tool |
| Power user wanting a scriptable dig replacement | DigWebInterface, Google Admin Toolbox Dig, doggo, raw DoH JSON (`digwebinterface`, `google-admin-toolbox-dig`, `doggo`) | Well served, mostly free; the gap is a **hosted** version with content-negotiated HTML+JSON on the same URL — most either have no JSON (DigWebInterface) or gate it (ViewDNS) |
| Reputation/blacklist check for deliverability | RBL/DNSBL cluster, MXToolbox blacklist (`rbl-and-domain-reputation`) | Well served in raw data; almost every free frontend gets the refusal/rate-limit sentinel codes wrong (treats any `127.*` as "listed") |
| Ongoing monitoring/alerting on a domain's DNS | DNS Spy, NsLookup.io, Uptime Kuma, CompleteDNS, nearly every paid tier (`monitoring-and-history-features`) | This *is* the monetization layer of the whole category — nobody gives it away free, which is exactly the gap our existing Mongo lookup-history pattern can fill for near-zero cost |
| Brand-protection / typosquat monitoring | dnstwist only (`dnstwist`) | Narrow but well served by the one tool that exists; open-source, embeddable outright |

## Ideas to steal

### UX
- **Query in the URL** (path, hash, or full query string) so every result is bookmarkable, shareable & crawlable with zero server session — universal winning pattern, confirmed live on 5 different tools (`nslookup-io`, `digwebinterface`, `google-admin-toolbox-dig`, `dnschecker-org`, `dnsviz-and-dnssec-debuggers`, `firsthand-ui-observations`).
- **Command-prefix single input box** (`mx:example.com`, `blacklist:1.2.3.4`) dispatching ~36 lookups from one field instead of N separate pages (`mxtoolbox`).
- **Settings-only permalink**: submit with a blank target to bookmark preferred resolver/option choices before ever querying a domain (`digwebinterface`).
- **Expected-value field** turns a wall of resolver strings into a real pass/fail column; put the assertion in the URL too so a shared link carries the claim (`whatsmydns`, `dnschecker-org`).
- **Async per-row fill** via `hx-trigger="load"` per resolver/check row instead of one blocking request — a slow row never stalls the page (`dnschecker-org`, `whatsmydns`, `dnsdumpster-hackertarget`, `dns-health-audit-tools`'s planner-endpoint pattern).
- **Transport as a URL scheme on the resolver field** (`udp://`, `tls://`, `https://`, `quic://`) so one text box covers six transports (`doggo`).
- **Lazy long-tail record-type dropdown**: render the common 7 eagerly, put the other ~40 types behind a searchable select that fires a second request only on demand (`nslookup-io`, `record-types-reference`).
- **Cross-tool chips under every result** ("dns lookup · mx lookup · dmarc lookup · propagation") — highest retention-per-effort mechanic observed (`mxtoolbox`).
- **Auto-detect an IP literal** pasted into the name box and silently rewrite it to a PTR query, stating so in the heading (`google-admin-toolbox-dig`, `doggo`).
- **Dated archive w/ Previous/Next navigation** over cached runs instead of always re-querying live — someone else's recent run answers instantly, and you can diff over time (`dnsviz-and-dnssec-debuggers`).

### Result presentation
- **TTL rendered as a human duration** ("Revalidate in 5m") with the raw integer kept in a tooltip or transcript, never just replaced — confirmed live on 4 separate tools (`nslookup-io`, `google-admin-toolbox-dig`, `mxtoolbox`, `digwebinterface`, `firsthand-ui-observations`).
- **Name the server that actually answered** — parent NS, authoritative NS, or anycast PoP via NSID — on every result, for falsifiability (`mxtoolbox`, intoDNS in `dns-health-audit-tools`, `globalping`, `ripe-atlas-dns`).
- **Absence is a row, not a blank section**: "No CNAME record found", "No mail servers found" (`nslookup-io`, `firsthand-ui-observations` pattern 4).
- **Provider attribution as a headline** ("Overall result: Cloudflare"), derived from the NS suffix via a small static table, printed *above* the raw data (`nslookup-io`, `mxtoolbox`).
- **Four-plus honest result states, never one red cell**: NXDOMAIN / REFUSED / SERVFAIL / timeout are four different problems that whatsmydns itself admits conflating (`propagation-checking-methodology`).
- **Cite the RFC section inline** next to every verdict, and state the recommended numeric range beside the observed value ("Expire 604800 : recommended 1209600–2419200") (`mxtoolbox`, `dns-health-audit-tools`, `zonemaster`).
- **Semantic TXT classification by prefix** (`google-site-verification=`, `v=spf1`, `MS=`, `atlassian-domain-verification=`) into a plain human label, pure string table (`nslookup-io`, `record-types-reference`).
- **Findings as `<details>/<summary>`**: severity dot + plain sentence + collapsed raw evidence, zero JS required (`dnsviz-and-dnssec-debuggers`).
- **Per-nameserver Auth/Parent/Local agreement as three explicit columns**, replacing ~8 separate prose checks (`mxtoolbox`, `dns-health-audit-tools`).
- **State the honest denominator**: "m of n resolvers answered" with the dead ones named, instead of silently dropping them from the grid (`propagation-checking-methodology`; `firsthand-ui-observations` independently caught 7 of 28 DNSChecker resolvers timing out).
- **Rollup counter line above a big table** ("3 listed · 1 whitelisted · 36 clean · 2 failed of 42") (`rbl-and-domain-reputation`).

### Features
- **Pre-deploy DNS change analyzer**: diff current vs proposed zone, deterministic rules, severity-weighted 0-100 risk score — the single most novel feature in the entire corpus, and only one tool has built it (`nslookup-io`).
- **Fire Google + Cloudflare DoH concurrently and badge disagreement** between them — a free multi-vantage check that spends no infrastructure of our own (`dns-apis-and-pricing`, `doh-dot-doq-and-public-resolvers`).
- **Surface RFC 8914 Extended DNS Errors** as the human "why it failed" line instead of a bare SERVFAIL — almost no consumer tool in the corpus does this (`google-admin-toolbox-dig`, `doh-dot-doq-and-public-resolvers`, `dns-concepts-and-query-modes`, `go-dns-implementation`).
- **Lead with the authoritative-only check**: query the zone's own NS set directly before any third-party resolver fan-out — the only honest "did my change go out" signal, and it costs zero third-party load (`viewdns-info`, `propagation-checking-methodology`).
- **Two-query SERVFAIL diagnostic**: retry with CD=1; NOERROR on retry proves a DNSSEC-validation failure rather than a dead server, one checkbox of UI (`dns-concepts-and-query-modes`).
- **Cache-age column** (authoritative TTL minus reported TTL), replacing the raw-TTL column that is incomparable across resolvers (`propagation-checking-methodology`).
- **CT-log (crt.sh) subdomain pipeline** as the recon feature: ~60 lines of Go, free, keyless, CORS-open, zero packets sent to the target itself (`subdomain-enumeration-and-ct`).
- **RDAP as the WHOIS replacement**: cache the 5 IANA bootstrap JSON files on boot, resolve registry then registrar in two hops (`whois-rdap-tools`).
- **Own a wildcard beacon subzone** with a small authoritative responder logging `(qname, source IP)` for a genuine "which resolver do you actually use" test (`dnsleaktest-and-resolver-identity`).
- **Mine RIPE Atlas's open archive** instead of owning probes: `GET /measurements/?type=dns&target=`, unpack the base64 `abuf` with miekg/dns for real multi-vantage answers, free and keyless (`ripe-atlas-dns`).
- **Globalping as a free real-probe propagation backend**: group probes by identical answer-set instead of a "% propagated" number, the structurally correct fix for GeoDNS (`globalping`).
- **DNSBL/reputation card**: reversed-IP-or-domain query across a handful of lists, decoding refusal codes (127.255.255.x, URIBL 127.0.0.1) explicitly rather than truthing any `127.*` as a hit (`rbl-and-domain-reputation`).
- **Fan out N common RR types concurrently** with `errgroup` instead of a dead `ANY` button, which RFC 8482 makes lie (`go-dns-implementation`, `record-types-reference`, `doggo`).

### Trust & honesty
- **Never guess on ambiguous evidence**: decode refusal/rate-limit sentinel codes explicitly instead of treating any `127.*` DNSBL answer as "listed" (`rbl-and-domain-reputation`).
- **Label rows by resolver operator, not by country flag**, unless real ECS or real multi-vantage probing backs the claim — one Hetzner box only reaches each anycast operator's nearest PoP (`propagation-checking-methodology`, `dnsperf-perfops`).
- **State plainly when "propagation" isn't geographic**: MXToolbox's own `:all` queries the zone's authoritative NS set, not distributed vantage points — say which kind a feature actually is (`mxtoolbox` fact-check).
- **Read the echoed ECS scope, not just the sent subnet**: scope 0 means the answer was NOT geo-tailored, which disproves most "ECS changed my result" claims (`dns-concepts-and-query-modes`, `browser-constraints-dns-2026`).
- **Show provenance and vintage together**: which server/dataset answered plus how fresh it is (`check-host-and-ping-pe`'s dated geo-DB snapshots, `dnslytics`' dated crawl-freshness changelog).
- **Never blend live and passive-DNS rows into one list**: distinguish "I resolved this just now" from "a dataset observed this once in 2019" (`securitytrails-passive-dns`).
- **Treat a health-check false alarm as a labeling problem, not a silence problem**: MXToolbox flags Cloudflare's own SOA Expire as "out of range" on live production zones — keep the check, call it a convention, not an error (`firsthand-ui-observations`, `dns-health-audit-tools`).
- **Cap fan-out per request and say "truncated" in the UI**, rather than trusting a per-IP rate limiter alone to catch one expensive click (`abuse-ratelimits-and-ethics`).
- **Never treat `ANY` as "everything"**: RFC 8482 minimal responses make it lie; label it explicitly and fan out named types instead (`dns-concepts-and-query-modes`, `record-types-reference`, `doggo`).

## What everyone does the same (table stakes)

- **Core 7 record types** (A, AAAA, CNAME, MX, NS, TXT, SOA) on every tool in the corpus, free, no account (`record-types-reference`, and nearly every service row above).
- **The query lives in the URL** in some form (path, hash, or query string) — every actively-maintained tool observed firsthand does this (`firsthand-ui-observations`).
- **Multi-resolver picker** (Google/Cloudflare/Quad9/OpenDNS at minimum) — present on `digwebinterface`, `doggo`, `google-admin-toolbox-dig`, `whatsmydns`, `dnschecker-org`.
- **Reverse/PTR lookup** with auto-built `in-addr.arpa`/`ip6.arpa` — near-universal across the whole corpus.
- **Free, no-account single lookup** — every one of the 30+ consumer-facing services surveyed gives this away; paywalls start at the *second* query type (bulk, API, monitoring, history).
- **Raw TTL shown somewhere as an integer** — even the tools that also humanize it keep the number (`google-admin-toolbox-dig`, `nslookup-io`).

## What almost nobody does (the gaps)

- **Cache-age column** (authTTL − reportedTTL) instead of an incomparable raw TTL (`propagation-checking-methodology`).
- **ECS scope readout** distinguishing "geo-steered" from "stale" — neither `nslookup-io` nor `dnschecker-org` show it despite both offering propagation grids.
- **RFC 8914 Extended DNS Errors surfaced as human text** on a consumer result page — only the raw DoH JSON APIs carry the field; no free consumer *tool* renders it (`google-admin-toolbox-dig`, `doh-dot-doq-and-public-resolvers`, `dns-concepts-and-query-modes`).
- **Pre-deploy DNS change risk review** — one tool in 37 reports (`nslookup-io`).
- **Content-negotiated HTML+JSON on the same free-lookup URL** — most gate JSON behind a paid, key-gated API (`viewdns-info`, `dns-apis-and-pricing`); DigWebInterface has no JSON path at all.
- **RFC 9824 compact-denial (NXNAME) detection** — not observed anywhere in the corpus (`dns-concepts-and-query-modes`).
- **Negative-cache TTL explained as "why a fixed record still says not found"** — only partial coverage, in NsLookup.io's SOA panel and MXToolbox's SOA dump (`propagation-checking-methodology`, `record-types-reference`).
- **Honest "m of n resolvers answered, named"** — whatsmydns and DNSChecker both silently hide dead resolvers from their grids (`propagation-checking-methodology`, `firsthand-ui-observations`).
- **Wildcard-synthesis structural detection** via the RRSIG `labels` field — nobody in the corpus does this (`dns-concepts-and-query-modes`, `record-types-reference`).
- **Two-query CD=1 SERVFAIL diagnostic** to disambiguate "DNSSEC bogus" from "server down" on a consumer page (`dns-concepts-and-query-modes`).

## Where reports disagree or the corpus stayed thin

- **SecurityTrails' free-tier quota** is genuinely unresolved: three mutually contradictory secondhand figures (50/mo, 2,000/mo, 10,000 credits/mo) and no reachable primary pricing page across the whole research pass (`securitytrails-passive-dns`).
- **DNS Spy pricing** conflicts between the vendor's own archived page ($9 Personal / $49 Enterprise) and a third-party directory ("starting at €4.99/mo"); neither could be confirmed live (`dns-health-audit-tools`).
- **whatsmydns.net's monitoring pricing** ($9/mo Starter, 3 free monitors) was downgraded to "do not build against these numbers" after finding zero independent corroboration and a suspicious match to an unrelated vendor's plan in the same search results (`monitoring-and-history-features`).
- **ViewDNS's API pricing** could not be read at all (403 to every fetch attempt across two research passes) and conflicting secondhand figures exist ($29–$549/mo tiers vs. a claimed "10,000 free credits" offer); the table cell was left blank rather than guessed (`viewdns-info`).
- **What "propagation" even means differs by vendor.** MXToolbox's `:all` queries the zone's own authoritative NS set (not geographic); NsLookup.io, whatsmydns, DNSChecker and Globalping genuinely query geographically distinct resolvers or real probes. The corpus's own first pass on MXToolbox got this backwards before a firsthand check caught it — a durable trap for anyone reading vendor copy at face value (`mxtoolbox`).
- **The "unmet niche" of a fast, free, JSON zone-health audit was itself wrong on first pass.** `dns-health-audit-tools` initially concluded nobody offered this; a firsthand check found both Zonemaster's JSON-RPC API and NsLookup.io's health endpoint already do, live. Treat any "nobody does X" claim below the fold in a single report with suspicion until cross-checked against the others.
- **ping.pe's real probe count** swung from a secondhand "~30 locations" to a firsthand-measured 166 in one run (`check-host-and-ping-pe`); a single measurement doesn't establish a stable published number, and the report says so.
- **Vendors don't agree with themselves.** MXToolbox's own docs self-contradict on the free DNS quota (Quick Start prose says 68/day, the rate-limit table says 64/day) (`dns-health-audit-tools`). Don't treat a single vendor page as ground truth without a second read.
- **The dns0.eu shutdown date** stayed genuinely unresolved even after correction — both cited sources describe the shutdown as "immediate" with no exact cutover date, so the report states what the sources say rather than a fabricated precision date (`doh-dot-doq-and-public-resolvers`, `browser-constraints-dns-2026`).
- **peterzen/goresolver's DNSSEC-failure behavior** could not be fully reproduced on a second pass — validated the 4 signed domains tested, but could not reliably reproduce the specific "refused bogus chain" result from the first pass, and a separate crash-on-unreachable-resolver defect was newly found instead (`go-dns-implementation`).
