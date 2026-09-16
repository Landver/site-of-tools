# DNS lookup tool — exhaustive feature inventory

Every DNS-related feature observed across the 36 research reports in `reports/`, grouped by aspect. Purpose: a menu to pick from, not a recommendation (see `00-landscape-and-ideas.md` / `02-build-fit.md` for that). "Who offers" cites report slugs (filename minus `.md`); a feature named by 3+ reports is table-stakes, named by 1-2 is a differentiator, and a feature nobody in the corpus ships is called out at the end as our own idea. Cost bands: **trivial** (<1 day, stdlib/one query), **moderate** (1-3 days, needs `miekg/dns` or a parser), **heavy** (a real subsystem: scheduler, own dataset, auth chain), **needs paid data** (no free path exists).

Slugs used below: `mxtoolbox` `nslookup-io` `dnschecker-org` `whatsmydns` `viewdns-info` `google-admin-toolbox-dig` `digwebinterface` `dnslytics` `robtex-he-ripestat` `dns-health-audit-tools` `zonemaster` `dnsviz-and-dnssec-debuggers` `email-dns-checkers` `dnsdumpster-hackertarget` `securitytrails-passive-dns` `subdomain-enumeration-and-ct` `whois-rdap-tools` `dnsleaktest-and-resolver-identity` `dns-apis-and-pricing` `rbl-and-domain-reputation` `dns-concepts-and-query-modes` `record-types-reference` `doh-dot-doq-and-public-resolvers` `browser-constraints-dns-2026` `go-dns-implementation` `propagation-checking-methodology` `abuse-ratelimits-and-ethics` `monitoring-and-history-features` `globalping` `resolver-cache-purge-tools` `dnstwist` `internet-nl` `dnsperf-perfops` `doggo` `check-host-and-ping-pe` `ripe-atlas-dns`

---

## 1. Record lookup & query control

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Core 7-type lookup (A/AAAA/CNAME/MX/NS/SOA/TXT) in one request | "what does this domain point to" | mxtoolbox, nslookup-io, dnschecker-org, whatsmydns, viewdns-info, digwebinterface, google-admin-toolbox-dig, record-types-reference, doggo | table-stakes | trivial | pure Go DNS query |
| Long-tail RR type selector (45-80 types) | full protocol coverage | digwebinterface (49), nslookup-io (52), record-types-reference (miekg/dns 80), dns-apis-and-pricing | differentiator past ~20 | moderate | pure Go DNS query |
| Eager-common / lazy-long-tail two-tier type UI | fast first paint, full coverage on demand | nslookup-io, record-types-reference (option D) | differentiator | trivial (htmx `hx-get` on select change) | pure Go DNS query |
| Free-text RR type input (name or numeric TYPE\<n\>) | query types the UI forgot | google-admin-toolbox-dig (`dns.google/query`), digwebinterface, record-types-reference | differentiator | trivial | pure Go DNS query |
| "Query all common types" fan-out (replaces dead ANY) | "just show me everything useful" | dns-concepts-and-query-modes, record-types-reference, doggo (`--any`), whois-rdap-tools-adjacent | differentiator, highest value-per-line per dns-concepts | moderate (errgroup fan-out) | pure Go DNS query |
| ANY (QTYPE 255) with RFC 8482 sentinel detection + explainer | "why did ANY return garbage/NOTIMP" | dns-concepts-and-query-modes, record-types-reference, dns-apis-and-pricing | differentiator | trivial | pure Go DNS query |
| Resolver picker (Google/Cloudflare/Quad9/OpenDNS/Yandex/etc.) | "what does *my* resolver see" | nslookup-io, dnschecker-org, whatsmydns, doggo (9 presets), dns-apis-and-pricing, doh-dot-doq-and-public-resolvers | table-stakes | trivial | pure Go DNS query or public JSON API |
| Custom/arbitrary nameserver target | "ask this specific server" | digwebinterface (ns=self), doggo, globalping, ripe-atlas-dns, zonemaster (undelegated testing) | differentiator | moderate (needs allowlist/rate-limit, abuse-ratelimits-and-ethics) | pure Go DNS query |
| Authoritative-only mode (query the zone's own NS, skip cache) | "is this actually live, not just cached" | digwebinterface, dnschecker-org (`dnsauth`), doggo (`-A`), mxtoolbox (`:all`) | differentiator | moderate | pure Go DNS query |
| Registry/NIC mode (query TLD servers for parent-side delegation+glue) | "what does the registry think my NS is" | digwebinterface | differentiator | moderate | pure Go DNS query |
| Reverse lookup (PTR) with auto-built in-addr.arpa/ip6.arpa | "what hostname is this IP" | mxtoolbox, nslookup-io, dnschecker-org, whatsmydns, viewdns-info, digwebinterface, doggo, record-types-reference | table-stakes | trivial | pure Go DNS query |
| IP-literal auto-detect → rewritten to PTR query | paste an IP into the name box, it just works | google-admin-toolbox-dig, whatsmydns | differentiator | trivial | pure Go DNS query |
| Batch/multi-hostname input (newline or whitespace separated) | check many names at once | digwebinterface, viewdns-info (bulk lookup) | differentiator | trivial | pure Go DNS query |
| Query multiple nameservers in one submit, side by side | compare answers across servers I choose | digwebinterface (ns=all, 10 bundled resolvers), doggo (cartesian names×types×classes×NS) | differentiator | moderate | pure Go DNS query |
| Compare-output table (SAME/DIFFERENT vs base resolver) | "which resolvers disagree" | digwebinterface | differentiator | moderate (hash RRset, not text) | pure Go DNS query |
| "Fix" input normalization: strip scheme/path/@, punycode IDN | paste a URL/email and it just works | whatsmydns, digwebinterface, record-types-reference | table-stakes | trivial | pure Go (`x/net/idna`) |
| Absolute-name forcing (trailing dot) with notice | "why does my tool disagree with dig" | digwebinterface, dns-concepts-and-query-modes | differentiator | trivial | pure Go |
| IDN U-label⇄A-label toggle + punycode display | see both unicode and ASCII forms | record-types-reference, dns-concepts-and-query-modes, whatsmydns, dnstwist | table-stakes among serious tools | trivial | pure Go (`x/net/idna`) |
| Mixed-script/homograph warning on IDN labels | "is this a lookalike domain" | dns-concepts-and-query-modes, dnstwist | differentiator | trivial | pure Go |
| Show TTL as raw seconds | baseline fact | mxtoolbox, nslookup-io, dnschecker-org, whatsmydns, record-types-reference | table-stakes | trivial | pure Go DNS query |
| Humanize TTL ("24 hrs", "5 min") alongside raw seconds | readability | mxtoolbox, digwebinterface (tooltip), dns-apis-and-pricing | differentiator | trivial | pure Go |
| TTL countdown display (authoritative TTL vs remaining/observed TTL) | "is my change live yet" — cheapest credibility signal per dns-concepts | dns-concepts-and-query-modes, propagation-checking-methodology, mxtoolbox (implicit) | differentiator, nobody in corpus does both sides well | trivial | pure Go DNS query |
| Cache-age column (authoritative TTL minus reported TTL) | replaces useless raw-TTL column | propagation-checking-methodology | differentiator, explicitly called "nobody surveyed does it" | trivial | pure Go DNS query (needs to know zone's real TTL) |
| Per-record RCODE / header flags display (AA/TC/RD/RA/AD/CD) | protocol-literate users, debugging | google-admin-toolbox-dig, doggo, ripe-atlas-dns, go-dns-implementation | differentiator | trivial | pure Go DNS query |
| Recursive vs authoritative answer distinction (aa/ra flags + TTL behavior) | "is this cached or fresh from the source" | dns-concepts-and-query-modes, mxtoolbox (Auth/Parent/Local columns) | differentiator | trivial | pure Go DNS query |
| Query timing / RTT per lookup or per hop | performance signal | mxtoolbox (transcript), digwebinterface, doggo, go-dns-implementation, dnsperf-perfops | differentiator | trivial | pure Go DNS query |
| Raw/dig-style output toggle | power users, bug reports, reproducibility | digwebinterface, dnschecker-org (export), dns-concepts-and-query-modes (gap in most tools) | differentiator | trivial (format existing struct as BIND text) | pure Go |
| "Show command" (print the equivalent dig invocation) | teaches the CLI, makes results reproducible | digwebinterface | differentiator, "highest trust-per-byte element" | trivial | pure Go |
| Zone-file / BIND-format copyable output | copy-paste into a zone file | dns-apis-and-pricing (gap), go-dns-implementation (`dns.NewRR` inverse) | differentiator | trivial | pure Go |
| Colorize / annotate raw output (field-by-field) | beginner-legible + expert-verifiable from one view | digwebinterface, google-admin-toolbox-dig (`/* NOERROR */` inline annotations) | differentiator | trivial | pure Go |
| Dual raw + parsed/decorated view, one switch | honest debugging view + friendly view from one query | google-admin-toolbox-dig, digwebinterface | differentiator | trivial | pure Go |
| Shareable permalink for a query (path or hash-based) | bookmark/share a result | nslookup-io (path+hash), whatsmydns (`#TYPE/name/expected`), digwebinterface (querystring+named anchors), mxtoolbox, dnsviz-and-dnssec-debuggers, globalping | table-stakes among serious tools | trivial | pure Go (route param) |
| Settings-only permalink (bookmark preferred options, blank target) | save my defaults | digwebinterface | differentiator | trivial | pure Go |
| GET-shaped form / URL fully encodes query state | crawlable, shareable, no session needed | nslookup-io, digwebinterface, google-admin-toolbox-dig, whatsmydns | table-stakes | trivial | pure Go (Echo route) |
| POST-redirect-GET to clean bookmarkable result URL | no query-string noise, still shareable | dnsviz-and-dnssec-debuggers (Verisign 303) | differentiator | trivial | pure Go |
| Expected-value / assertion field ("this should resolve to X") with match modes (exact/contains/regex) | turn a wall of answers into pass/fail | dnschecker-org, whatsmydns, propagation-checking-methodology | differentiator | trivial | pure Go |
| CIDR/subnet calculator | netmask/CIDR math | dnschecker-org, viewdns-info, mxtoolbox, dns-apis-and-pricing | table-stakes (already in iptools) | trivial | pure Go (net/netip) |
| CNAME chain resolution + full-chain rendering (not just final target) | "why is this going to the CDN", debug redirects | dns-apis-and-pricing, record-types-reference, dns-concepts-and-query-modes, doggo, whois-rdap-tools (who.is apex vs www) | differentiator, most tools show final target only | trivial | pure Go DNS query |
| Apex CNAME flattening / ALIAS annotation | "why can't I see my CNAME at the apex" | dns-concepts-and-query-modes, record-types-reference | differentiator | trivial | pure Go (match apex A against known CDN ASN table) |
| Dangling-CNAME / NODATA subdomain-takeover warning | security finding | dns-concepts-and-query-modes, dns-health-audit-tools | differentiator | moderate | pure Go |
| NODATA vs NXDOMAIN vs referral disambiguation (SOA vs NS in AUTHORITY) | "no results" means 3 different things | dns-concepts-and-query-modes, record-types-reference, propagation-checking-methodology, dns-apis-and-pricing | differentiator, "most common bug in this category" | trivial once resolving iteratively | pure Go DNS query |
| RFC 9824 compact-denial detection (NSEC bitmap TYPE128/NXNAME) | NXDOMAIN is being hidden on Cloudflare/NS1/Route53 zones | dns-concepts-and-query-modes, record-types-reference | differentiator, "almost no consumer tool has it" | moderate (parse NSEC bitmap) | pure Go DNS query, DO bit |
| CAA apex-tree-walk (does not climb automatically) | "no CAA policy" on a subdomain, correctly explained | dns-concepts-and-query-modes, record-types-reference | differentiator | trivial | pure Go DNS query |
| Attrleaf underscore-name auto-helper (builds `_service._proto`, `_dmarc`, `<sel>._domainkey`) | naive domain+type form returns NODATA and reads as broken | record-types-reference, dns-apis-and-pricing | differentiator | trivial | pure Go |
| SOA field-by-field decode with humanized durations + RNAME de-obfuscation | "what does 604800 mean", "who owns this zone" | record-types-reference, google-admin-toolbox-dig, mxtoolbox | differentiator | trivial | pure Go |
| SOA recommended-range framing (state observed value + RFC 1912 range) | not just pass/fail, but *why* | mxtoolbox, dns-health-audit-tools, zonemaster | differentiator | trivial | pure Go (constants table) |
| SRV `_service._proto` prefix helper | most tools make users type the underscore prefix by hand | record-types-reference, whatsmydns (gap) | differentiator | trivial | pure Go |
| CAA parameter decode (issue/issuewild/iodef/issuemail/cansignhttpexchanges) | cert-issuance policy readout | mxtoolbox, record-types-reference, internet-nl | differentiator | trivial | pure Go |
| HTTPS/SVCB AliasMode vs ServiceMode rendering | modern apex-aliasing record type | record-types-reference, dns-concepts-and-query-modes, doh-dot-doq-and-public-resolvers | differentiator, dividing line in 2026 | moderate | pure Go DNS query |
| SvcParam decode (alpn, port, ipv4hint/ipv6hint, dohpath, ech, tls-supported-groups, etc.) | make HTTPS/SVCB human-readable instead of hex | record-types-reference, doh-dot-doq-and-public-resolvers | differentiator, nobody on the shelf fully does it | moderate | pure Go (`encoding/binary`) |
| ECHConfigList byte-level decode (version, config_id, KEM, cipher suites, public_name) | "what SNI does this site's ECH actually send in the clear" | record-types-reference | differentiator, "literally nobody does it" | moderate (~70 lines) | pure Go |
| TLSA/DANE decode with usage/selector/mtype labelling | mail cert pinning | mxtoolbox, email-dns-checkers, record-types-reference, internet-nl | differentiator | trivial | pure Go |
| SSHFP algorithm + fingerprint-type name decode | verify SSH host key out-of-band | record-types-reference | differentiator | trivial | pure Go |
| NAPTR / DNAME / URI (clickable link) / OPENPGPKEY / SMIMEA / LOC (map render) / CERT / HINFO / RP / KX / AFSDB / IPSECKEY / APL / EUI48/64 / HIP / DHCID / TA / AMTRELAY / RESINFO long-tail decode | completeness for power users | record-types-reference (Tier 4), digwebinterface, robtex-he-ripestat | differentiator | moderate (per-type decoder each) | pure Go |
| CSYNC / ZONEMD / DSYNC parent-sync & zone-integrity records | zone operators verifying transfer/integrity | record-types-reference | differentiator, DSYNC not observed live anywhere | moderate | pure Go |
| Unknown-type-number rendering as `TYPE<n>` rather than dropped/renamed | future-proofing, RFC 3597 fallback | record-types-reference, dns-apis-and-pricing, google-admin-toolbox-dig (contrast: it fails this) | table-stakes for correctness | trivial | pure Go |
| Apex TXT vendor-prefix labelling (Atlassian/Apple/AWS SES/Adobe/Tailscale/MS=/Salesforce/etc.) | turn noise into named integrations | record-types-reference, dnsdumpster-hackertarget (analyticslookup) | differentiator, "pure data, no API" | trivial (static table) | pure Go |
| Semantic TXT classification by prefix (google-site-verification=, v=spf1, v=DMARC1, MS=, etc.) | same as above, general mechanism | nslookup-io, record-types-reference | differentiator | trivial | pure Go |
| Multi-string TXT joined and re-quoted correctly | upstreams format TXT differently (quoted vs unquoted) | google-admin-toolbox-dig, browser-constraints-dns-2026 (normalize across providers) | table-stakes for correctness | trivial | pure Go |
| RRset sorting before compare/diff | upstreams disagree on order | record-types-reference, digwebinterface (compare table), globalping | table-stakes for correctness | trivial | pure Go |
| DNS record splitter (chop >255-octet TXT into quoted 255-char chunks) | publish a long SPF/DKIM/BIMI record correctly | email-dns-checkers | differentiator, "most-used boring utility" | trivial | pure Go |
| Paste-a-record mode (validate a record before publishing, no DNS lookup) | pre-publish validation | email-dns-checkers | differentiator | trivial | pure Go |
| Root-hints / undelegated-zone testing (supply your own NS/DS before delegation exists) | pre-launch zone validation | zonemaster | differentiator | moderate | pure Go |
| DNS Change Analyzer: pre-deploy diff of proposed zone vs current, with severity-weighted risk score | "will this change break something before I ship it" | nslookup-io | differentiator, genuinely novel per corpus | heavy (rules engine) | pure Go (own logic) |
| Reverse-DNS generator (build in-addr.arpa/ip6.arpa from an IP, without querying) | prep a PTR delegation request | whatsmydns | differentiator | trivial | pure Go |
| Domain typo / permutation generator (15-16 fuzzers: omission, transposition, homoglyph, bitsquat, etc.) | see what a name looks like mistyped, feed into other checks | dnstwist | differentiator (own aspect, see §7) | moderate | pure Go (string algorithms) |

## 2. Propagation / multi-resolver

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Multi-resolver fan-out grid (same query, N resolvers) | "has my change propagated" | dnschecker-org (28), whatsmydns (22), viewdns-info (17), mxtoolbox (`:all`, NS-only), nslookup-io (32), propagation-checking-methodology, dns-apis-and-pricing | table-stakes for this category | moderate | pure Go DNS query (own resolver list) or public JSON API |
| Real distributed-probe fan-out (actual global vantage points, not one box) | true geographic propagation, not a curated resolver list | globalping (5,000+ probes), ripe-atlas-dns (~15k probes), check-host-and-ping-pe (56 / 166), dnsperf-perfops (413 nodes) | differentiator, "the only credible free source" per globalping | heavy (third-party API integration) | public JSON API (free, keyless) |
| Country flags / city labels per resolver row | orient the reader geographically | dnschecker-org, whatsmydns, propagation-checking-methodology | table-stakes | trivial | own dataset (resolver→geo table) |
| World map visualization of results | at-a-glance geographic spread | dnschecker-org (D3+TopoJSON), whatsmydns (D3), dnsperf-perfops | differentiator | moderate | client-side JS (vendor a small mapping lib) |
| Expected-value match column (exact/contains/regex) with green-tick pass/fail | turn strings into a verdict | dnschecker-org, whatsmydns, propagation-checking-methodology | table-stakes | trivial | pure Go |
| Resolved/Unresolved live tallies as clickable filters | "how many of N agree" | dnschecker-org, propagation-checking-methodology | differentiator | trivial | pure Go |
| Shareable permalink encoding query + expected value + resolver set | send a link to a colleague | whatsmydns (`#TYPE/name/expected`), dnschecker-org (`#type/name/expected`), viewdns-info | table-stakes | trivial | pure Go |
| Auto-refresh / re-poll interval control | watch until consistent | dnschecker-org, mxtoolbox (monitoring) | differentiator | trivial (htmx `hx-trigger="every Ns"`) | pure Go |
| Per-row async fill (each resolver streams in independently) | fast partial results instead of blocking on the slowest resolver | dnschecker-org, whatsmydns, globalping (`inProgressUpdates`), check-host-and-ping-pe | differentiator | moderate | htmx `hx-get` per row |
| Custom/add-your-own resolver | check against a corporate or ISP resolver | dnschecker-org (modal, opt-in to public list) | differentiator | trivial | pure Go |
| Region/country/continent-scoped propagation subset | narrower, faster check | dnschecker-org (`/continent/`, `/country/`), globalping (location filters), ripe-atlas-dns (probe selection) | differentiator | trivial-moderate | own dataset or public API |
| Per-record-type propagation (not just A) | check MX/TXT/NS propagation too | nslookup-io (all 52 types), whatsmydns (10 types) | table-stakes among serious tools | trivial | pure Go |
| ECS-based single-resolver geo-sweep (simulate many client subnets against one authoritative) | cheap alternative to real distributed probes | dns-apis-and-pricing, browser-constraints-dns-2026, propagation-checking-methodology | differentiator, "affordable architecture we could copy" | trivial | public JSON API (Google DoH `edns_client_subnet`) |
| ECS scope-prefix readout (not just source) | disprove false "ECS changed my result" claims — scope 0 means not geo-specific | dns-concepts-and-query-modes, propagation-checking-methodology, browser-constraints-dns-2026 | differentiator, "nearly no consumer tool shows this" | trivial | public JSON API |
| Authoritative-only "nameserver consistency" check (query each of the zone's own NS, hash+diff answers) | the *correct*, honest meaning of "is my change live" — zero third-party resolver load | mxtoolbox (`:all`), propagation-checking-methodology, viewdns-info | differentiator, explicitly recommended as the lead check | moderate | pure Go DNS query |
| SOA-serial agreement check across all authoritative NS | "did all my nameservers pick up the change" | mxtoolbox, viewdns-info, dns-health-audit-tools, zonemaster, propagation-checking-methodology | differentiator | trivial | pure Go DNS query |
| Per-answer-set MD5/hash comparison across nameservers | one-line "your nameservers disagree" instead of a manual set diff | mxtoolbox (`:all`) | differentiator | trivial | pure Go |
| "m of n resolvers answered" with dead ones named | honesty about list rot | propagation-checking-methodology | differentiator, "incumbents silently hide list rot" | trivial | pure Go |
| Error-state disambiguation in propagation grid (NXDOMAIN/REFUSED/SERVFAIL/timeout as 4 distinct cells, not one red) | most tools conflate these | propagation-checking-methodology (whatsmydns admits this itself) | differentiator | trivial | pure Go |
| Filtering-resolver classification (0.0.0.0 sinkhole vs block-page IP vs NXDOMAIN, labelled not red) | distinguish "blocked by your resolver" from "broken" | propagation-checking-methodology, doh-dot-doq-and-public-resolvers, dns-concepts-and-query-modes (EDE 15-18) | differentiator | trivial | pure Go |
| "Consistent in ≤N seconds" header (max remaining TTL across responders) | the actual answer users want | propagation-checking-methodology | differentiator | trivial | pure Go |
| Negative-TTL surfacing (SOA MINIMUM) in propagation context | "a wrong NXDOMAIN will stick for N minutes" — most "not propagating" reports are a cached negative | propagation-checking-methodology, dns-concepts-and-query-modes | differentiator | trivial | pure Go |
| Cache-flush outlinks (Google/OpenDNS/Cloudflare purge pages) | give the user the next step instead of building it | propagation-checking-methodology, resolver-cache-purge-tools | table-stakes cheap addition | trivial | none (just links) |
| Actual cache-purge integration (POST to Cloudflare/Google/OpenDNS purge endpoints) | fix it, don't just diagnose it | resolver-cache-purge-tools | differentiator, "the verification step Cloudflare tells users to do but never provides" | moderate | public JSON API (unauthenticated purge endpoints) |
| Purge-then-poll verification (confirm TTL jumped post-purge) | prove the purge worked | resolver-cache-purge-tools | differentiator | moderate | pure Go DNS query + htmx polling |
| Per-type purge matrix (fire concurrently across found types) | batch purge | resolver-cache-purge-tools | differentiator | moderate | public JSON API |
| Resolver-fragmentation probe (query same resolver IP 5x, show TTL spread) | prove "one resolver IP" is many independent caches | resolver-cache-purge-tools | differentiator | trivial | pure Go |
| Propagation check history + diff vs previous run | "what changed since I last checked" | propagation-checking-methodology, monitoring-and-history-features | differentiator | moderate | own dataset (Mongo) |
| Which authoritative node answered (anycast PoP via NSID or Comment field) | explain cross-run variance | google-admin-toolbox-dig, propagation-checking-methodology, dns-concepts-and-query-modes, globalping, dnsperf-perfops | differentiator | trivial | pure Go DNS query (NSID) or public JSON API |
| Bulk/multiple record types checked per propagation run | efficiency | viewdns-info, globalping (reuse probe set across types) | differentiator | trivial | pure Go |
| CSV/JSON export of propagation results | take results elsewhere | propagation-checking-methodology (free via content negotiation), dnsdumpster-hackertarget (XLSX) | table-stakes given content negotiation | trivial | pure Go |
| RIPE Atlas one-off measurement for real hardware vantage points | genuine distributed probes when our own fan-out isn't enough | propagation-checking-methodology, ripe-atlas-dns | differentiator, heavier integration | heavy (credit economy, async polling) | public JSON API (credits required for on-demand) |
| Grouping probes by identical answer set (not "% propagated") | avoid false "only 17% propagated" reading of healthy GeoDNS | globalping | differentiator, corrects a naive metric | moderate | public JSON API |
| Eyeball-network vs datacenter-network probe toggle | only ISP-resolver probes reflect real end users | globalping | differentiator | trivial (filter param) | public JSON API |

## 3. Zone health audit

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Minimum-NS-count check (RFC 2182, ≥2) | basic redundancy | mxtoolbox, dns-health-audit-tools, zonemaster, viewdns-info, internet-nl | table-stakes | trivial | pure Go |
| All NS respond / all authoritative | delegation health | mxtoolbox, dns-health-audit-tools, zonemaster, viewdns-info | table-stakes | trivial | pure Go |
| Parent NS set vs child NS set match ("stealth NS" / mismatch detection) | invisible to any recursive-only tool | mxtoolbox, dns-health-audit-tools, zonemaster, viewdns-info, dns-concepts-and-query-modes | differentiator, needs `+norec` at TLD | moderate | pure Go DNS query (iterative) |
| Missing/stale glue detection, glue vs authoritative A diff | a top-tier real outage class | dns-health-audit-tools, mxtoolbox, viewdns-info, zonemaster, dnsviz-and-dnssec-debuggers, dns-concepts-and-query-modes | differentiator | moderate | pure Go DNS query (parent-side) |
| NS record is not a CNAME | RFC compliance | dns-health-audit-tools, zonemaster | table-stakes | trivial | pure Go |
| NS on different /24 subnets / different ASNs / different providers (diversity) | single-point-of-failure risk | mxtoolbox, dns-health-audit-tools, viewdns-info, robtex-he-ripestat (CONNECTIVITY03/04 idea) | differentiator | trivial (reuse iptools ASN lookup) | pure Go + existing ASN data |
| NS IPs are public (no RFC1918) | misconfiguration check | mxtoolbox, dns-health-audit-tools, viewdns-info | table-stakes | trivial | pure Go |
| Open recursion / open resolver test | security misconfig on the zone's own NS | mxtoolbox, dns-health-audit-tools, zonemaster | differentiator | trivial | pure Go DNS query |
| Open zone transfer (AXFR) test | security misconfig, legal-grey to run against third parties | mxtoolbox, dns-health-audit-tools, zonemaster, dnsdumpster-hackertarget, abuse-ratelimits-and-ethics (caution) | differentiator, ship as a finding on your own domain, not recon | trivial to implement, ethically gated | pure Go DNS query |
| TCP/53 reachability check | firewall/misconfig | mxtoolbox, dns-health-audit-tools, zonemaster | table-stakes | trivial | pure Go |
| version.bind CHAOS TXT disclosure check | info-leak finding | dns-health-audit-tools, zonemaster | differentiator | trivial | pure Go DNS query (CHAOS class) |
| Nameserver response-time threshold / per-NS latency rollup (min/max/avg/median/stddev) | performance finding | dns-health-audit-tools, zonemaster (`--nstimes`), dnsperf-perfops | differentiator | trivial | pure Go |
| SOA serial format (YYYYMMDDnn) + agreement across all NS | classic misconfiguration | mxtoolbox, dns-health-audit-tools, zonemaster, viewdns-info | table-stakes | trivial | pure Go |
| SOA MNAME listed at parent | delegation consistency | dns-health-audit-tools, viewdns-info, zonemaster | differentiator | moderate | pure Go DNS query (parent-side) |
| SOA REFRESH/RETRY/EXPIRE/MINIMUM range checks (RFC 1912) | tuning issues | mxtoolbox, dns-health-audit-tools, viewdns-info, zonemaster | differentiator | trivial (constants table) | pure Go |
| MX validity: not-a-CNAME, public IPs, PTR present, duplicate A records, count ≥1 | mail routing health | mxtoolbox, dns-health-audit-tools, email-dns-checkers, viewdns-info | table-stakes | trivial | pure Go |
| MX redundancy / single-point-of-failure count | mail resilience | mxtoolbox, dns-health-audit-tools | differentiator | trivial | pure Go |
| Forward-confirmed reverse DNS for MX (FCrDNS: IP→PTR→forward→match) | mail reputation signal | dns-health-audit-tools, robtex-he-ripestat (RIPEstat dns-chain), whatsmydns | differentiator | trivial (~20 lines) | pure Go DNS query |
| WWW/root A record presence + CNAME-chain-resolves check | basic reachability | dns-health-audit-tools | table-stakes | trivial | pure Go |
| RFC-compliance lint via zone-parsing (`named-checkzone`-equivalent) | catch syntax errors | dns-health-audit-tools | differentiator | moderate | pure Go (zone parser) |
| Website thumbnail / screenshot in zone report | visual confirmation the domain is live | dns-health-audit-tools (intoDNS) | cosmetic differentiator | moderate (headless browser) | client-side JS or own infra |
| HTTP/HTTPS connect check + TLS certificate check/expiration | is the web server up and cert valid | mxtoolbox, dns-health-audit-tools, internet-nl | table-stakes for a "domain health" feature | trivial | pure Go (net/http, crypto/tls) |
| SSL cert chain validation, weak-key, weak-sig-algo, self-signed, deprecated-TLS-version detection | full cert audit | dns-health-audit-tools, internet-nl | differentiator | moderate | pure Go (crypto/tls, crypto/x509) |
| SSL expiration tiered alerts (90/30/7 days) | proactive renewal warning | dns-health-audit-tools, monitoring-and-history-features | differentiator, needs scheduling | moderate | pure Go + scheduler |
| CAA record presence + validator (for domain and mail) | cert-issuance policy audit | mxtoolbox, dns-health-audit-tools, internet-nl | differentiator | trivial | pure Go |
| Per-nameserver agreement matrix (Auth / Parent / Local as 3 columns) | blame a specific server, not the whole domain | mxtoolbox, dns-health-audit-tools | differentiator, "replaces ~8 separate prose checks" | moderate | pure Go DNS query (iterative) |
| Collapsible delegation transcript (per-hop server/IP/AUTH/RTT/rcode/answers) | the receipt that makes checks believable | mxtoolbox, digwebinterface, dns-health-audit-tools, dnsviz-and-dnssec-debuggers, dns-concepts-and-query-modes | differentiator | moderate | pure Go DNS query (iterative, own `+trace`) |
| DNS/email service-provider fingerprinting from NS/MX set | "this domain uses Cloudflare / Google Workspace" | mxtoolbox, nslookup-io, dns-health-audit-tools | differentiator | trivial (static NS-suffix table) | own dataset (small static table) |
| Weighted 0-100 score / letter grade (A-F) across categories | executive-summary verdict | dns-health-audit-tools (DNSInspect/DNS Spy), internet-nl, nslookup-io (health audit) | differentiator | trivial (scoring formula) | pure Go |
| Per-category score bars with anchor links | navigate a long report | dns-health-audit-tools | differentiator | trivial | pure Go/CSS |
| Five-state result model (pass/info/warn/fail/skipped, with skipped reason) | not-applicable checks don't read as failures | dns-health-audit-tools, zonemaster (8-level severity), robtex-he-ripestat, internet-nl (6 statuses incl. "Not testable") | differentiator | trivial (enum) | pure Go |
| Numbered, stable, permalinked check-ID catalogue (e.g. ZONE02, DELEGATION01) | checks become citable, each gets an explainer page | zonemaster, mxtoolbox (`/problem/<cmd>/<check>`) | differentiator | trivial (ID scheme + docs) | pure Go + markdown docs |
| Per-check remediation/explainer page (RFC-cited, deep-linked from result) | teach, not just flag | mxtoolbox (193 pages), dns-health-audit-tools, zonemaster, dnsviz-and-dnssec-debuggers | differentiator | moderate (content authoring) | markdown (goldmark, already in repo) |
| "State observed value + recommended range" wording, not bare pass/fail | the actual value-add per mxtoolbox's own admission | mxtoolbox, dns-health-audit-tools | differentiator | trivial | pure Go (template) |
| Async job/planner endpoint + progressive per-check rendering | slow checks don't block fast ones | dns-health-audit-tools, zonemaster (JSON-RPC poll), globalping, dnsperf-perfops | differentiator | moderate | htmx `hx-get` fan-out |
| Frozen/permalinked report snapshot (point-in-time, timestamped) | citable, diffable history | dns-health-audit-tools, dnsviz-and-dnssec-debuggers, internet-nl, zonemaster | differentiator | moderate | own dataset (Mongo + TTL index) |
| Report-to-report diff / compare up to N reports | "what changed between scans" | internet-nl (dashboard), monitoring-and-history-features | differentiator, paid-tier feature elsewhere | moderate | own dataset |
| Public recent-reports feed / Hall of Fame | social proof, SEO surface | dns-health-audit-tools, internet-nl | differentiator | trivial | own dataset |
| Show-all-tests toggle (problems-only vs full pass list) | avoid burying passes | dns-health-audit-tools | trivial nicety | trivial | pure Go |
| Print stylesheet / print button | share a report on paper/PDF | dns-health-audit-tools | trivial nicety | trivial | CSS |
| Pre-filled social-share string encoding the verdict | distribution mechanic | dns-health-audit-tools | trivial nicety | trivial | pure Go |
| Domain groups / account-level aggregated grading (MSP multi-client view) | agency use case | dns-health-audit-tools (DNS Spy) | out of scope for a hobby tool | heavy | own dataset + auth |
| Cheap network-intelligence judgments over existing ASN data ("all your NS are in one AS13335") | turn facts iptools already has into a finding | zonemaster (idea), robtex-he-ripestat | differentiator | trivial | pure Go + existing iptools ASN data |
| Reverse zone (in-addr.arpa/ip6.arpa) health testing | audit a PTR delegation the same way as a forward zone | zonemaster | differentiator | moderate | pure Go |
| `--save`/`--restore`-style offline replay of a zone's DNS data (fixture capture) | deterministic tests, matches repo's black-box test convention | zonemaster (CLI feature, informs our testing not the product) | internal tooling idea | trivial | pure Go (JSON fixture) |
| Self-hosted Zonemaster proxy/integration instead of hand-rolled checks | reuse 73 RFC-argued, BSD-licensed checks wholesale | zonemaster, robtex-he-ripestat | differentiator, biggest shortcut in the corpus | moderate (embed their profile.json, call their public API) | public JSON API (self-hostable, GPL/BSD engine + free CORS-open instance) |

## 4. DNSSEC

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| DNSKEY/DS/RRSIG/NSEC/NSEC3/NSEC3PARAM raw lookup | "is this record published" | mxtoolbox, dnschecker-org, record-types-reference, go-dns-implementation | table-stakes lookup, not validation | trivial | pure Go DNS query (DO bit) |
| DNSSEC enabled/signed flag (DNSKEY presence only, no chain check) | quick yes/no | dnschecker-org, dns-health-audit-tools (partial) | table-stakes | trivial | pure Go DNS query |
| Full chain-of-trust validation (root→TLD→zone, DNSKEY/DS/RRSIG walked and verified) | "is this domain's DNSSEC actually valid, not just present" | dnsviz-and-dnssec-debuggers, zonemaster, go-dns-implementation (goresolver), dns-health-audit-tools (gap in 2 of 4) | differentiator, the deep feature | heavy | pure Go (`miekg/dns` RRSIG.Verify chain, or goresolver lib) |
| Three-way status vocabulary: secure / insecure / bogus (+ lame/incomplete for delegations) | richer than pass/fail | dnsviz-and-dnssec-debuggers | differentiator | trivial (enum) | pure Go |
| KSK/ZSK split display (flags decode) | which key does what | record-types-reference, google-admin-toolbox-dig, dns-health-audit-tools | differentiator | trivial | pure Go |
| RRSIG detail (algorithm name, keytag, signer, inception/expiry parsed to dates) | debug signature issues | google-admin-toolbox-dig, dnsviz-and-dnssec-debuggers, go-dns-implementation, record-types-reference | differentiator | trivial (constants table + time parse) | pure Go |
| RRSIG expiry countdown / expiring-soon alert | proactive warning, "nearly absent from commercial roundups" | monitoring-and-history-features, go-dns-implementation | differentiator | trivial | pure Go + scheduler for alerting |
| DS digest-type name decode (SHA-1/SHA-256/GOST/SHA-384) | readable instead of numeric | google-admin-toolbox-dig, record-types-reference | trivial nicety | trivial | pure Go (constants table) |
| DNSSEC algorithm numeric→name decode (ECDSAP256SHA256 etc.) | readable | google-admin-toolbox-dig, dnsviz-and-dnssec-debuggers (filter), zonemaster | trivial nicety | trivial | pure Go (constants table) |
| CD=1 (checking-disabled) retry on SERVFAIL, to isolate validation failure from server-down | one-checkbox diagnostic | dns-concepts-and-query-modes, record-types-reference, go-dns-implementation | differentiator, "genuinely diagnostic" | trivial (two queries) | pure Go DNS query |
| Extended DNS Error (RFC 8914) decode on DNSSEC failures ("no SEP matching the DS") | human-readable failure reason instead of bare SERVFAIL | dns-concepts-and-query-modes, doh-dot-doq-and-public-resolvers, go-dns-implementation, dns-apis-and-pricing | differentiator, "highest-value field in the landscape" | trivial | pure Go DNS query or public JSON API |
| Authentication-chain graph (Graphviz-style visual, node status colored) | see the whole chain at a glance | dnsviz-and-dnssec-debuggers | differentiator, heaviest visual feature in corpus | heavy (graph rendering) | pure Go + client-side graph lib |
| Responses-view inconsistency matrix (per-RRset × per-authoritative-server Y/N) | catch split-brain DNSSEC between NS | dnsviz-and-dnssec-debuggers | differentiator | moderate | pure Go (query each NS) |
| Parent-vs-child delegation diff table (NS name / in parent? / in child? / glue / authoritative addr) | glue-vs-NS mismatch explains itself | dnsviz-and-dnssec-debuggers, dns-health-audit-tools | differentiator | moderate | pure Go DNS query (parent-side) |
| Findings table: severity dot + plain-English claim + collapsed raw evidence (`<details>`) | approachable + verifiable from one page | dnsviz-and-dnssec-debuggers | differentiator | trivial (HTML pattern, zero JS) | pure Go |
| Cite RFC section inline next to every warning | credibility, doubles as docs | dnsviz-and-dnssec-debuggers, mxtoolbox, dns-health-audit-tools, zonemaster | differentiator (cheap, high value) | trivial | markdown authoring |
| Custom/out-of-band trust anchor input (paste a DS or DNSKEY) | test before the parent publishes | dnsviz-and-dnssec-debuggers | differentiator | moderate | pure Go |
| Pre-delegation / explicit-DS testing | test DS before it's live at the parent | dnsviz-and-dnssec-debuggers, zonemaster | differentiator | moderate | pure Go |
| Date-picker historical-analysis archive ("what did DNSSEC look like on this date") | audit trail | dnsviz-and-dnssec-debuggers | heavy differentiator | heavy (storage + retention policy) | own dataset |
| Cross-link to a competing DNSSEC debugger ("want a second opinion?") | honesty, doesn't cost us anything | dnsviz-and-dnssec-debuggers | trivial nicety | trivial | none |
| Graph/result export (PNG/JPG/SVG/DOT/JS) | share/embed a DNSSEC chain diagram | dnsviz-and-dnssec-debuggers | differentiator | moderate | client-side graph lib |
| DS-without-matching-DNSKEY / DNSKEY-not-validated-by-any-DS detection | pinpoint exactly where the chain breaks | dnsviz-and-dnssec-debuggers | differentiator | moderate | pure Go |
| CDS/CDNSKEY existence + validation (child-to-parent automation records) | modern DS-rollover automation | zonemaster, record-types-reference | differentiator | trivial | pure Go DNS query |
| Custom trust anchors (de-select root KSK, add your own) | testing/lab use | dnsviz-and-dnssec-debuggers | niche differentiator | moderate | pure Go |
| NSEC/NSEC3 denial-of-existence proof rendering | verify "this name doesn't exist" cryptographically | dnsviz-and-dnssec-debuggers, zonemaster | differentiator | moderate | pure Go |
| DNSSEC via RDAP `secureDNS` field (delegationSigned + DS keyTag/algorithm, zero DNS queries) | free DNSSEC chip from registry data | whois-rdap-tools | differentiator, "zero DNS queries" | trivial | public JSON API (RDAP) |
| IPv6 reachability of DNSSEC-relevant nameservers (dual-stack chain testing) | full internet.nl-style rigor | internet-nl | differentiator | moderate | pure Go |
| DANE rollover scheme validation (≥2 TLSA records for mail) | mail cert-pinning resilience | internet-nl, email-dns-checkers | differentiator | trivial | pure Go |

## 5. Email DNS (SPF / DKIM / DMARC / BIMI / MTA-STS / TLS-RPT)

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| SPF record lookup + parse | is SPF published | mxtoolbox, dnschecker-org, email-dns-checkers, internet-nl, record-types-reference | table-stakes | trivial | pure Go DNS query |
| SPF recursive include-lookup counting vs the 10-lookup limit (direct vs nested split) | the classic silent-failure mode | mxtoolbox, email-dns-checkers, nslookup-io, record-types-reference | differentiator | moderate (recursive parse) | pure Go |
| SPF void-lookup counting (NXDOMAIN/empty, 2-lookup sub-budget) | separate RFC 7208 §4.6.4 limit | mxtoolbox, email-dns-checkers | differentiator | trivial | pure Go |
| SPF multiple-record / duplicate-include / recursive-loop / redirect-eval / deprecated-type-99 detection | common misconfigurations | mxtoolbox, dns-health-audit-tools, email-dns-checkers | differentiator | moderate | pure Go |
| SPF tokenized table with plain-English mechanism description | teach, not just validate | mxtoolbox, email-dns-checkers | differentiator | trivial | pure Go (mechanism→sentence map) |
| SPF CIDR expansion inline (ip4/ip6 mechanism → range + count) | "how many addresses does this authorize" | email-dns-checkers, record-types-reference (adjacent) | differentiator | trivial (net/netip + math/big) | pure Go |
| SPF total authorized-address count (IPv4+IPv6) | same as above, summed | email-dns-checkers | differentiator | trivial | pure Go |
| SPF validation of a pasted (unpublished) record | pre-publish check | email-dns-checkers | differentiator | trivial | pure Go |
| DKIM lookup by selector | is DKIM published for this selector | mxtoolbox, dnschecker-org, email-dns-checkers, record-types-reference | table-stakes given a selector | trivial | pure Go DNS query |
| DKIM selector discovery via wordlist guess (no way to enumerate from DNS) | find selectors without being told one | record-types-reference | differentiator, must be labelled a guess | trivial (static wordlist) | pure Go |
| DKIM CNAME-delegation chain display (e.g. Microsoft's selector→onmicrosoft.com) | catch the "NXDOMAIN with a CNAME right there" trap | record-types-reference | differentiator, real bug found in the wild | trivial | pure Go |
| DKIM validation of a pasted key (pre-publish) | test before publishing | email-dns-checkers | differentiator | trivial | pure Go |
| DKIM signature verification (body hash, alignment, identifier match, expiration) | full DKIM-Signature header validation | mxtoolbox, dns-health-audit-tools | differentiator, needs a sample signed message | moderate | pure Go |
| DMARC record lookup + tag-by-tag parse (p/sp/pct/rua/ruf/fo) | policy readout | mxtoolbox, dnschecker-org, email-dns-checkers, internet-nl, record-types-reference | table-stakes | trivial | pure Go DNS query |
| DMARC policy-strength check (flags bare `p=none`) | "you published DMARC but it does nothing" | mxtoolbox, dns-health-audit-tools, email-dns-checkers | differentiator | trivial | pure Go |
| DMARC external RUA/RUF authorization validation | third-party report-destination check per RFC | mxtoolbox, email-dns-checkers | differentiator | moderate | pure Go DNS query (authorization record lookup) |
| DMARC "defined vs effective" tag split (e.g. unpublished `np` effectively `reject` via `sp`) | show inherited defaults, not just literal record | email-dns-checkers | differentiator | trivial | pure Go |
| DMARCbis (RFC 9989/9990/9991) awareness: Organizational Domain via DNS Tree Walk, `psd=` tag | currency with the May-2026 DMARC reissue | email-dns-checkers | differentiator, protocol-currency risk if skipped | moderate | pure Go |
| DMARC record wizard / generator | build a record, don't just check one | email-dns-checkers, dnschecker-org | differentiator | trivial | pure Go (form→string) |
| DMARC aggregate-report (XML) analyzer / human converter | parse the RUA reports mailboxes receive | mxtoolbox, email-dns-checkers | differentiator, heavier UX | moderate | pure Go (XML parse) |
| DMARC failure/forensic report viewer | parse RUF reports | email-dns-checkers | differentiator | moderate | pure Go |
| DMARC report GeoMaps / data-provider directory | "who sent XML this week", "where are failures coming from" | email-dns-checkers | differentiator, heavy | heavy | own dataset |
| BIMI record lookup + syntax check | brand-logo-in-inbox readiness | mxtoolbox, dnschecker-org, email-dns-checkers, internet-nl | differentiator | trivial | pure Go DNS query |
| BIMI SVG fetch + Tiny-PS profile check, rendered preview | validate the actual logo file | email-dns-checkers, record-types-reference | differentiator | moderate (fetch + parse SVG profile) | pure Go (HTTP fetch) |
| BIMI VMC X.509 parse + SHA-1 logotype digest match, trust-chain/issuer/expiry | full mark-certificate validation | mxtoolbox, email-dns-checkers | differentiator, heavy | moderate | pure Go (crypto/x509) |
| BIMI cross-check against DMARC policy (void without `p=quarantine|reject`) | cheapest way to catch a real misconfig | email-dns-checkers | differentiator, "checking one record against another beats dig" | trivial | pure Go |
| BIMI generator + SVG-to-Tiny-PS converter | build compliant assets | email-dns-checkers | differentiator | moderate | pure Go (SVG manipulation) |
| MTA-STS TXT pointer check + HTTPS policy fetch (`.well-known/mta-sts.txt`) | two-protocol check most tools miss the second half of | mxtoolbox, email-dns-checkers, record-types-reference, dns-health-audit-tools | differentiator | trivial | pure Go DNS query + HTTP fetch |
| MTA-STS policy cert validity/expiry, line-ending (CRLF) check, mx: cross-check against live MX | full policy-file audit | email-dns-checkers | differentiator | moderate | pure Go |
| MTA-STS generator + policy hosting | build and serve the policy file | email-dns-checkers | out of scope (hosting) for a lookup tool | heavy | own infra |
| TLS-RPT record check (`_smtp._tls`) | one-line parse | mxtoolbox, dnschecker-org, email-dns-checkers, record-types-reference | table-stakes given the others exist | trivial | pure Go DNS query |
| TLS-RPT generator + report aggregation | build/collect reports | email-dns-checkers | out of scope (needs a mail receiver) | heavy | own infra |
| Live email test via a generated one-time address (send a real message, animate the SMTP conversation) | end-to-end deliverability proof | email-dns-checkers, mxtoolbox | heavy differentiator | heavy (needs a mail server) | own infra (SMTP receiver) |
| Paste-your-headers mode (same visualization, no send) | analyze without sending | email-dns-checkers | differentiator | moderate | pure Go (header parse) |
| Email header analyzer (hop-by-hop delay table + auth results) | trace a real message's path | mxtoolbox, dnschecker-org, email-dns-checkers | differentiator | moderate | pure Go (RFC 5322 parse) |
| Email verification (valid/disposable-address test) | adjacent lead-gen tool | dnschecker-org, viewdns-info | out of scope-ish, orthogonal to DNS | moderate | pure Go + MX/SMTP probe |
| SMTP diagnostics: connect/banner/STARTTLS/open-relay/reverse-DNS-mismatch | outbound-port-25 dependent, may be blocked from Hetzner | mxtoolbox, dns-health-audit-tools | differentiator, blocked by egress policy per abuse-ratelimits-and-ethics | moderate, ethically/technically gated | pure Go (net.Dial :25) — likely blocked |
| 10-question interactive DMARC quiz | education/engagement | email-dns-checkers | novelty differentiator | moderate | pure Go/JS |
| Embeddable iframe widget (postMessage height resize) | distribution channel | email-dns-checkers | differentiator | moderate | client-side JS |
| Cross-protocol MX-domain DNSSEC grading (separate from the domain's own DNSSEC) | internet.nl-level rigor | internet-nl | differentiator | trivial | pure Go |
| STARTTLS-availability check with Null-MX / max-10-MX awareness | mail-transport security | internet-nl | differentiator | moderate (SMTP probe, may be egress-blocked) | pure Go |

## 6. Reverse & passive DNS

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Reverse IP lookup (co-hosted domains on one IP) | "what else lives here" | viewdns-info, dnslytics, dnsdumpster-hackertarget, whois-rdap-tools (via RDAP verisign nameservers), record-types-reference-adjacent | differentiator | needs paid data or own dataset | paid API or own dataset (no free comprehensive source) |
| Reverse NS lookup (domains delegating to a nameserver) | "who else uses this DNS provider" | dnslytics, dnsdumpster-hackertarget (findshareddns), robtex-he-ripestat, viewdns-info | differentiator | needs paid data or own dataset | paid API, or build over time from own lookup history |
| Reverse MX lookup (domains sharing a mail server) | shared-infrastructure pivot | dnslytics, robtex-he-ripestat, viewdns-info | differentiator | needs paid data | paid API |
| Reverse WHOIS (by registrant email/name/org) | who else does this registrant own | viewdns-info, securitytrails-passive-dns | needs paid data | heavy | paid API |
| Reverse Adsense / Analytics tag pivot (by pub-xxxx or AW-/GT-/UA- ID) | shared-ownership signal | dnslytics, dnsdumpster-hackertarget (free analyticslookup) | differentiator | trivial for the free HackerTarget path, else paid | public JSON API (HackerTarget, free) or paid (DNSlytics) |
| Reverse SPF lookup (domains authorizing an IP to send mail) | infra pivot | dnslytics | needs paid data | heavy | paid API |
| Historical DNS by record type (A/AAAA/MX/NS/SOA/TXT, first-seen/last-seen/count) | "what did this resolve to before" — the thing live resolution structurally cannot answer | securitytrails-passive-dns, dnslytics (Hosting History), robtex-he-ripestat, ripe-atlas-dns (mine the open archive) | differentiator, the headline passive-DNS value prop | needs paid data (comprehensive) or own dataset (grows slowly) | paid API for depth; own Mongo history for a thin free version |
| Own-lookup passive-DNS sensor (log every visitor lookup as (rrname, rrtype, rdata, first_seen, last_seen, count)) | become your own tiny pDNS source over months, zero vendor | securitytrails-passive-dns, monitoring-and-history-features | differentiator, "no vendor and no key" | trivial to start, valuable slowly | own dataset (Mongo, reuse iptools history pattern) |
| Co-occurrence counts per value (ip_count, host_count, ns_count) | "how many other domains share this NS/IP" | securitytrails-passive-dns | differentiator | needs paid data at scale, cheap over own history | own dataset (grows) or paid API |
| NS-set / MX-set hash (nshash/mxhash) for fast provider-migration detection | one timeline event instead of 4 record diffs | securitytrails-passive-dns (Silent Push), monitoring-and-history-features | differentiator | trivial (~15 lines) | pure Go |
| Bidirectional single-route lookup (one input, matches as query OR answer) | forward + reverse-IP + reverse-NS from one handler | securitytrails-passive-dns (mnemonic pattern) | differentiator | trivial (route design) | own dataset |
| "Truncated at N" / `limited: bool` envelope flag | honesty about result caps | securitytrails-passive-dns | trivial but valuable | trivial | pure Go |
| Aggregated vs unaggregated toggle (collapsed one-row-per-answer vs every observation window) | summary vs full detail | securitytrails-passive-dns (DNSDB) | differentiator | trivial (GROUP BY) | own dataset |
| COF (Common Output Format) field naming for interop | plug into existing passive-DNS tooling | securitytrails-passive-dns | niche differentiator | trivial | own dataset |
| humantime toggle (epoch vs RFC3339) | readability switch | securitytrails-passive-dns | trivial | trivial | pure Go |
| Count-before-fetch (`?count_only=1`) | instant "1,204 results" before the expensive render | securitytrails-passive-dns | differentiator | trivial | pure Go |
| DNS monitor / passive archive mined from RIPE Atlas's open measurement history | free, keyless historical vantage-point data | ripe-atlas-dns | differentiator | moderate | public JSON API (free, keyless reads) |
| IP-history / hosting-change timeline (A/AAAA/MX/NS/SPF changes over time, with owner+lastseen) | "when did this move hosts" | viewdns-info, dnslytics (Hosting History), monitoring-and-history-features | needs paid data or own dataset | heavy | paid API or own Mongo history |
| Whole-CIDR/subnet reverse-PTR sweep (walk a /24-or-smaller reverse zone live) | infrastructure-naming discovery, cheap when scoped | dnslytics (reverse-PTR by wildcard keyword), robtex-he-ripestat (HE per-prefix IP\|PTR\|A table) | differentiator | moderate (bounded concurrent PTR queries) | pure Go DNS query |

## 7. Subdomain discovery

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Certificate Transparency subdomain enumeration (crt.sh JSON) | "what subdomains has this domain issued certs for" — zero packets to the target | subdomain-enumeration-and-ct, dnsdumpster-hackertarget (adjacent), monitoring-and-history-features, dns-apis-and-pricing | differentiator, "the working replacement for zone transfer" | trivial (~60 lines) | public JSON API (crt.sh, free, keyless, CORS-open) |
| crt.sh search-type/match-mode variety (21 search types, exact/LIKE/FTS) | precise CT queries | subdomain-enumeration-and-ct | differentiator | trivial | public JSON API |
| exclude=expired toggle ("currently valid" vs "ever issued") | two genuinely different attack-surface answers | subdomain-enumeration-and-ct | differentiator, "headline control" | trivial | public JSON API |
| deduplicate=Y (collapse precert/cert pairs) | clean result count | subdomain-enumeration-and-ct | trivial | trivial | public JSON API |
| Per-FQDN rollup (first-seen/last-seen/cert-count/issuers), inverting CT's per-cert rows | the view everyone actually wants, nobody renders it | subdomain-enumeration-and-ct | differentiator, genuinely novel | trivial | public JSON API (post-process) |
| Wildcard-cert blind-spot detection + finding ("a wildcard covers this, CT can't show names issued under it") | honesty about CT's limits | subdomain-enumeration-and-ct | differentiator | trivial (probe a random label) | pure Go + public API |
| crt.sh Atom/RSS feed handoff for ongoing monitoring | zero-code "new cert" alerting | subdomain-enumeration-and-ct, monitoring-and-history-features | trivial | trivial | public JSON API (link out) |
| Cert Spotter issuance API (structured JSON, cursor pagination, revocation status) | alternative/complementary CT source | subdomain-enumeration-and-ct | differentiator | trivial | public JSON API (free tier) |
| Chaos public bug-bounty dataset (open subdomain index, no key) | free bulk subdomain data for known programs | subdomain-enumeration-and-ct | niche differentiator | trivial | public JSON API |
| Static CT log tiled API (checkpoint/tile fetch, CDN-cacheable) | scale to the whole CT ecosystem without a firehose | subdomain-enumeration-and-ct | heavy differentiator | heavy | public JSON API |
| Multi-source passive aggregation (subfinder-style, 50+ sources) | maximum subdomain coverage | subdomain-enumeration-and-ct (as a reference, not a build target) | out of scope (too many keyed sources) | heavy | needs multiple paid/free APIs |
| Amass-style horizontal correlation (cert org → sibling root domains) | find related domains via shared cert ownership | subdomain-enumeration-and-ct | differentiator, subtle mechanism | moderate | public JSON API (CT) + own logic |
| DNSDumpster-style passive-dataset subdomain table with per-row enrichment (PTR/ASN/netblock/open services) | never show a bare hostname | dnsdumpster-hackertarget | differentiator | moderate | own dataset or reuse iptools enrichment |
| Live re-resolution of dataset-derived subdomain rows (dataset ✓live / ✗dead / changed) | differentiator competitors structurally can't match | dnsdumpster-hackertarget | differentiator | trivial (concurrent net.Resolver calls) | pure Go DNS query |
| Zone-transfer (AXFR) attempt against every NS as a discovery method | legacy technique, mostly refused today | dnsdumpster-hackertarget, dns-apis-and-pricing, abuse-ratelimits-and-ethics (legal-grey) | table-stakes but low yield; ship as own-domain finding, not recon | trivial | pure Go DNS query |
| Progressive reveal (name list fast, then per-row resolve+status badge streamed in) | fast first paint on a slow enumeration | subdomain-enumeration-and-ct | differentiator | moderate | htmx per-row `hx-get` |
| dnstwist-style typosquat/permutation subdomain generation + bulk resolution | find lookalike domains, not real subdomains, but adjacent discovery | dnstwist | differentiator (own aspect below) | moderate | pure Go |
| CIDR-scoped subdomain/host discovery (crawl history, OSINT observation history) | needs paid data | securitytrails-passive-dns (Validin) | needs paid data | heavy | paid API |

## 8. WHOIS / RDAP

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| RDAP domain record lookup (registrar, dates, EPP status, nameservers) | modern structured WHOIS replacement | whois-rdap-tools, dnschecker-org, viewdns-info, google-admin-toolbox-dig (adjacent), monitoring-and-history-features | table-stakes for a "domain info" feature | trivial | public JSON API (RDAP, free, keyless, mostly CORS-open) |
| IANA bootstrap discovery + caching (which RDAP server serves which TLD) | required plumbing for any RDAP lookup | whois-rdap-tools | table-stakes (infra, not user-facing) | trivial | public JSON API (IANA), cached daily |
| Supplementary TLD map for bootstrap gaps (~40 popular TLDs missing from IANA's list) | fix the most embarrassing misses | whois-rdap-tools | differentiator | trivial (small static JSON) | own dataset (static file) |
| Two-hop thin-registry resolution (registry record → registrar record via IANA registrar ID) | full contact chain for thin gTLDs | whois-rdap-tools | differentiator | trivial (embed IANA registrar-ids CSV) | public JSON API + own static dataset |
| RDAP nameserver object lookup | resolve a nameserver hostname to its own record | whois-rdap-tools | differentiator | trivial | public JSON API |
| RDAP IP-network / ASN / entity(registrar) record lookup | who owns this IP/ASN | whois-rdap-tools, robtex-he-ripestat | table-stakes (overlaps existing iptools ASN feature) | trivial | public JSON API |
| RDAP reverse-DNS zone record at the RIR | registry-side PTR delegation info | whois-rdap-tools | niche differentiator | trivial | public JSON API |
| DNSSEC via RDAP `secureDNS` (delegationSigned, DS keyTag/algorithm/digest) | free DNSSEC flag, zero DNS queries | whois-rdap-tools | differentiator (also listed in §4) | trivial | public JSON API |
| EPP status codes decoded to plain language with icann.org/epp links | "transfer locked by registrar" instead of `clientTransferProhibited` | whois-rdap-tools | differentiator | trivial (static map) | own dataset (static table) |
| Lifecycle events (registration/expiration/transfer/deletion/last-RDAP-update) | domain-age and expiry facts | whois-rdap-tools, viewdns-info, whatsmydns | table-stakes | trivial | public JSON API |
| Abuse contact as nested entity (role=abuse, tel+email) | who to report to | whois-rdap-tools, viewdns-info (dedicated abuse-contact tool), robtex-he-ripestat (RIPEstat) | differentiator | trivial | public JSON API |
| RFC 9537 redacted-field disclosure array (what was hidden, why, how) | honesty about GDPR-redacted WHOIS instead of blank rows | whois-rdap-tools | differentiator, "nobody in the free tier does this well" | trivial | public JSON API |
| RFC 9083 structured error objects | machine-readable error handling | whois-rdap-tools | table-stakes for correctness | trivial | public JSON API |
| RDAP search (entities by name, nameservers by IP, domains by NS/name) | pivot queries | whois-rdap-tools (ARIN reverse_search confirmed live) | differentiator | trivial | public JSON API (varies by RIR) |
| RDAP reverse search (RFC 9536: "which networks does this org hold") | free org-wide network pivot | whois-rdap-tools | differentiator, confirmed live on ARIN | trivial | public JSON API |
| Sorting/paging (RFC 8977) and partial-response fieldSet (RFC 8982) | efficient large queries | whois-rdap-tools | niche differentiator | trivial | public JSON API |
| WHOIS port-43 fallback for non-RDAP TLDs | coverage for legacy registries | whois-rdap-tools | table-stakes fallback | moderate (raw TCP/43 client) | pure Go (net.Dial) |
| Dual-render RDAP JSON and WHOIS-style key:value text from one struct | content negotiation for free, matches repo rule #2 | whois-rdap-tools | differentiator | trivial | pure Go |
| Nameserver hostname→IP resolution joined into the registration panel | connect the WHOIS half to the DNS half at no cost | whois-rdap-tools | differentiator | trivial | pure Go DNS query |
| "Changed since you last looked" diff on RDAP response hash | reuse Mongo history pattern | whois-rdap-tools, monitoring-and-history-features | differentiator | trivial | own dataset (Mongo) |
| Domain-expiry / registrar-change / EPP-status-change monitoring with alerts | paid-tier feature everywhere else, cheap to approximate | monitoring-and-history-features, whois-rdap-tools, securitytrails-passive-dns | differentiator, heavy for full alerting | moderate (scheduler) + heavy for delivery channels | own dataset + scheduler |
| Registrant contact-change history (normalized WHOIS/RDAP over time) | needs paid data | securitytrails-passive-dns, dnslytics | needs paid data | heavy | paid API |
| Domain-availability check | "is this name free to register" | whatsmydns, dnschecker-org, viewdns-info, whois-rdap-tools | table-stakes | trivial | public JSON API (RDAP 404 = available, roughly) |
| Similar-domains / typo suggestions | adjacent discovery | who.is (whois-rdap-tools), dnstwist (own aspect) | differentiator | trivial-moderate | own logic |
| Hosting/network narrative (provider, AS, managed DNS, email configured, IPv6, CAA pinning) | plain-English summary of raw facts | whois-rdap-tools (who.is) | differentiator | moderate (synthesis logic) | pure Go + existing iptools data |
| "Neighbourhood" stat (sites sharing the hosting provider) | overlaps reverse-IP (§6) | whois-rdap-tools (who.is) | differentiator | needs paid data or own dataset | paid API |

## 9. Reputation / blocklists

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Multi-DNSBL IP reputation check (Spamhaus ZEN, SpamCop, Barracuda, UCEPROTECT, etc.) | "is this IP blocklisted" | mxtoolbox (100+), rbl-and-domain-reputation, dnschecker-org, robtex-he-ripestat (`/ip_reputation`, 110-111 lists) | table-stakes (already partially in iptools) | trivial per list, moderate for the set | pure Go DNS query (DNS-as-database) |
| Domain/URI blocklist check (Spamhaus DBL, SURBL, URIBL) | "is this domain/URL blocklisted" | mxtoolbox, rbl-and-domain-reputation, dnschecker-org | table-stakes | trivial | pure Go DNS query |
| Render-then-fill per-list async rows (one `hx-get` per zone) | 40-row matrix stays readable and non-blocking | rbl-and-domain-reputation | differentiator | trivial (htmx pattern) | pure Go DNS query |
| Per-list input-form routing (IP query vs rDNS/domain query, computed automatically) | avoid the "naive DNSBL bug" of querying the wrong form | rbl-and-domain-reputation | table-stakes for correctness | trivial | pure Go |
| Zone→return-code→description table with refusal/rate-limit states distinguished from "listed" | classic amateur bug: treating any 127.* as a hit | rbl-and-domain-reputation | table-stakes for correctness | trivial (constants table) | pure Go |
| Wider verdict vocabulary (whitelist hits ≠ red; timeout/SERVFAIL ≠ green) | DNSWL/URIBL-white hits are positive evidence | rbl-and-domain-reputation | differentiator | trivial | pure Go |
| Retired/wrong-zone sentinel handling (e.g. Spamhaus SWL "no longer in operation") | don't misreport a decommissioned list | rbl-and-domain-reputation | table-stakes for correctness | trivial | pure Go (special-case table) |
| Per-answer TTL + SOA serial as freshness signal on blocklist hits | reads as a measurement, not a scrape | rbl-and-domain-reputation | differentiator | trivial (needs `miekg/dns`, not `net.Resolver`) | pure Go DNS query |
| Rollup counter above the matrix ("3 listed · 1 whitelisted · 36 clean · 2 failed of 42") | makes a 40-row table readable | rbl-and-domain-reputation | differentiator | trivial | pure Go |
| Concurrent DNSBL fan-out with short per-query timeout | sub-second card even for 40 lists | rbl-and-domain-reputation | table-stakes for UX | trivial (errgroup) | pure Go |
| DQS/paid-key upgrade seam (key-as-DNS-label) | future-proof for premium Spamhaus zones | rbl-and-domain-reputation | out of scope initially, cheap to design for | trivial (config var) | pure Go |
| Domain-side + mail-infrastructure-side fusion (resolve MX→A, check both against ZEN) | one card for domain and mail reputation | rbl-and-domain-reputation | differentiator | trivial | pure Go |
| CVE/vuln lookup tied to a host (Shodan CVEDB pattern) | adjacent security context for a scanned IP | dns-apis-and-pricing (context), out-of-corpus Shodan reference | out of scope for DNS tool proper | needs paid data | paid/free API (Shodan InternetDB, already used in iptools) |
| Domain/URL reputation via Google Safe Browsing / Web Risk | phishing/malware verdict | rbl-and-domain-reputation | differentiator | trivial (Safe Browsing v4 is free, quota-limited) | public JSON API (free tier) |
| Cisco Talos-style reputation dossier (no public API) | not buildable without their data | rbl-and-domain-reputation | not viable | n/a | no free API |
| Phishing/lookalike domain scoring (0-100 threat score) | brand-protection angle | monitoring-and-history-features (typosquat monitoring), dnstwist | differentiator | moderate | own logic (dnstwist fuzzers + live-clone check) |

## 10. Resolver identity & leak testing

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Wildcard-zone DNS beacon (unique hostname per session, logged by our own authoritative NS) | "which resolver does your browser actually use" | dnsleaktest-and-resolver-identity | differentiator, "the whole feature is this one component" | heavy (own authoritative nameserver) | own dataset + custom DNS server (miekg/dns `dns.Server`) |
| Standard vs extended probe rounds (quick 6 vs thorough 36) | speed/thoroughness tradeoff, two named modes | dnsleaktest-and-resolver-identity | differentiator | trivial once the beacon exists | own infra |
| Adaptive probe cadence (burst then back off) | discover the whole resolver pool without hammering | dnsleaktest-and-resolver-identity | differentiator | trivial | own infra |
| Per-resolver hit-count distribution (not just a set) | richer than boolean "leaking: yes/no" | dnsleaktest-and-resolver-identity | differentiator | trivial | own infra |
| IPv4-only / IPv6-only split labels (reveal resolver's v6 egress regardless of client v6) | separate discriminator from record type | dnsleaktest-and-resolver-identity (browserleaks dns4/dns6) | differentiator, subtle mechanism (transport family, not record type) | moderate | own infra |
| Transport-conditional NXDOMAIN beacons (answer only under TCP/v6/ECS conditions) | DNS answer itself carries the verdict | dnsleaktest-and-resolver-identity | differentiator | moderate | own infra |
| Resolver capability card (transport, EDNS buffer/version, DO bit, ECS presence+width, qname-min) | "what kind of resolver is this" | dnsleaktest-and-resolver-identity, doh-dot-doq-and-public-resolvers | differentiator, "no other small tool shows this" | moderate | own infra + query analysis |
| Stateless shareable result via base64 JSON in URL fragment | no DB, no expiry, result never reaches server | dnsleaktest-and-resolver-identity | differentiator | trivial | client-side JS |
| DoH/DoT/WARP detection (transport-conditional query pattern) | "are you using encrypted DNS" | dnsleaktest-and-resolver-identity (1.1.1.1/help) | differentiator | moderate | own infra |
| `/cdn-cgi/trace`-style plain k=v connection-telemetry endpoint | human-readable, `cut -d=`-friendly | dnsleaktest-and-resolver-identity | differentiator (adopt the format for our own endpoints) | trivial | pure Go |
| Resolver-identity TXT reflectors (whoami.ds.akahelp.net, o-o.myaddr.l.google.com) | "what did the authoritative actually see" via third-party free names | dns-concepts-and-query-modes, browser-constraints-dns-2026, dnsleaktest-and-resolver-identity | differentiator, one-click check | trivial | public JSON/TXT reflector (third-party, free) |
| EDNS NSID request (RFC 5001) revealing which anycast PoP answered | explains "why do I get different results on different queries" | dns-concepts-and-query-modes, google-admin-toolbox-dig, globalping, dnsperf-perfops, ripe-atlas-dns | differentiator | trivial | pure Go DNS query (EDNS option) |
| CHAOS-class version.bind/hostname.bind query | which server software/anycast node answered | dns-health-audit-tools, ripe-atlas-dns | differentiator | trivial | pure Go DNS query |
| DNS-over-TLS certificate inspection (per-node cert reveals the actual box) | free extra data from the TLS handshake | doh-dot-doq-and-public-resolvers | differentiator | trivial | pure Go (crypto/tls) |
| DDR lookup (`_dns.resolver.arpa` SVCB) showing a resolver's own advertised DoH/DoT/DoQ endpoints | prove transport support without owning that client | doh-dot-doq-and-public-resolvers, record-types-reference | differentiator | trivial | pure Go DNS query |
| WebRTC leak detection (host/srflx candidates) | adjacent to DNS-leak testing, mostly redundant with server view | dnsleaktest-and-resolver-identity, browser-constraints-dns-2026 | niche, out of scope for a DNS tool proper | moderate | client-side JS |
| Anonymity-rating percentage + details page | composite score across leak signals | dnsleaktest-and-resolver-identity | differentiator | moderate (scoring logic) | own infra |
| DNS-before-TLS trigger (fetch no-cors to force resolution without needing a valid cert) | browser-side beacon needs no wildcard TLS cert | browser-constraints-dns-2026 | differentiator (implementation trick) | trivial | client-side JS |
| PerformanceResourceTiming domainLookupStart/End + Timing-Allow-Origin | honest "your resolver took Nms cold" on our own hostnames | browser-constraints-dns-2026 | differentiator | trivial | client-side JS |
| NEL (Network Error Logging) dns.* report types + Reporting API collector | passive resolver-failure telemetry | browser-constraints-dns-2026 | niche differentiator | moderate | client-side + own collector endpoint |
| Block-mechanism classifier (sinkhole/block-page-IP/synthetic-NXDOMAIN/EDE-17/passthrough) | which of 5 distinct blocking behaviors a resolver uses | doh-dot-doq-and-public-resolvers, dns-concepts-and-query-modes | differentiator | trivial (compare against known IP/EDE table) | own dataset (known block-page IPs) |
| Per-resolver latency race (compare response time across resolvers for the visitor) | which resolver is fastest for you | doh-dot-doq-and-public-resolvers, dnsperf-perfops | differentiator | trivial | client-side JS or pure Go |

## 11. Performance / benchmark

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Authoritative-provider / public-resolver leaderboard (ranked by latency/uptime/quality) | "who has the fastest DNS" | dnsperf-perfops | needs own continuous measurement to build fresh, else link out | needs paid data (or heavy own infra) | paid/own infra |
| Vendored keyless provider/resolver catalogue (names, logos, NS hostnames) | offline "who runs this domain's DNS" lookup by NS suffix-match | dnsperf-perfops | differentiator | trivial (build-time asset) | public JSON API (free, build-time only) |
| On-demand DNS speed benchmark (query from N nodes, apex A lookup) | ad-hoc "how fast does my domain resolve globally" | dnsperf-perfops, globalping, ripe-atlas-dns, check-host-and-ping-pe | differentiator | moderate | public JSON API |
| Async job + poll pattern for benchmark results | maps directly onto htmx self-repolling fragment | dnsperf-perfops, globalping, zonemaster | table-stakes implementation pattern for any async check | trivial | htmx |
| Colour-banded latency thresholds (<40ms plain, 40-59 amber, ≥60 red) | glanceable performance signal | dnsperf-perfops | trivial nicety | trivial | pure Go/CSS |
| Explicit sentinel values for timeout/error (-1/-2) vs null | four distinct "no answer" stories | dnsperf-perfops | table-stakes for correctness | trivial | pure Go |
| NSID-based "answered by gpdns-fra" PoP identification | explain latency variance | dnsperf-perfops, google-admin-toolbox-dig, globalping, ripe-atlas-dns | differentiator (also §10) | trivial | pure Go DNS query |
| Uptime vs quality as two separate numbers ("zone resolves" vs "every NS resolves") | catches the one-dead-nameserver case | dnsperf-perfops | differentiator | trivial | pure Go |
| Real-probe ping/traceroute/MTR/HTTP measurement (not DNS, but bundled by the same free APIs) | adjacent network diagnostics | globalping, ripe-atlas-dns, check-host-and-ping-pe, dnsdumpster-hackertarget (HT tools) | out of scope for a DNS-only tool, but cheap to bolt on via the same API client | trivial-moderate | public JSON API |
| DNS-vs-resolver comparison overlay (add a resolver curve on top of a provider curve) | "is my slowness the authoritative or my resolver" | dnsperf-perfops | differentiator | moderate | paid/own infra |

## 12. Monitoring, history & alerting

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Scheduled re-check of a stored record set | "watch this domain for me" | mxtoolbox, dns-health-audit-tools, monitoring-and-history-features, securitytrails-passive-dns, dnslytics, nslookup-io | differentiator, heavy at scale | moderate (scheduler) | own dataset + scheduler |
| RRset-level diff with before/after values | "what changed" | mxtoolbox (DnsAnswer/DnsAnswerPrevious), monitoring-and-history-features, nslookup-io | differentiator | trivial (hash canonicalized RRset) | own dataset |
| Per-record-type watch selection, with sane defaults (NS/MX/TXT/CAA/SOA required, A/AAAA opt-in) | avoid alert fatigue from GeoDNS churn | monitoring-and-history-features | differentiator | trivial | own dataset |
| NS-set change alerting (delegation-hijack detection) | high-severity security signal | monitoring-and-history-features, securitytrails-passive-dns (Silent Push nshash) | differentiator | trivial | own dataset |
| Cross-authoritative-NS answer consistency check as a monitor | catches split-brain over time | monitoring-and-history-features, mxtoolbox | differentiator | trivial | pure Go DNS query, scheduled |
| SOA-serial tracking over time | catch silent zone changes | monitoring-and-history-features, mxtoolbox | differentiator | trivial | own dataset |
| Resolution-failure / NXDOMAIN / SERVFAIL alerting | uptime-style DNS monitoring | monitoring-and-history-features, dns-health-audit-tools | differentiator | moderate (scheduler + alert channel) | own dataset + scheduler |
| DNS response-time / latency monitoring over time | performance regression detection | monitoring-and-history-features, dnsperf-perfops | differentiator | moderate | own dataset + scheduler |
| Three-class alert taxonomy (blocking failure / change notice / advisory lint) | most of the perceived product quality, costs nothing | monitoring-and-history-features (Oh Dear pattern) | differentiator | trivial (enum) | own logic |
| Passive lookup-history-as-monitoring (diff-on-repeat-lookup, no scheduler needed) | the "wow moment" for free — reuses existing iptools history pattern | monitoring-and-history-features | differentiator, cheapest version of monitoring | trivial | own dataset (Mongo, pattern exists in repo) |
| DNSSEC RRSIG-expiry countdown as a monitor | proactive cert-adjacent alerting, "nearly absent from commercial roundups" | monitoring-and-history-features, go-dns-implementation | differentiator | trivial | own dataset + scheduler |
| CAA / MX / TXT-verification-token change alerting | catch cert-issuance or mail-routing hijack | monitoring-and-history-features | differentiator | trivial | own dataset |
| Domain-expiry / registrar-change / EPP-status-change alerting | catch a lapsing domain before it's gone | monitoring-and-history-features, whois-rdap-tools | differentiator | moderate (needs RDAP polling) | own dataset + scheduler + public API |
| RBL/blacklist-listing change monitoring | catch a new blocklist hit | monitoring-and-history-features, rbl-and-domain-reputation | differentiator | moderate | own dataset + scheduler |
| TLS cert expiry / issuer-change monitoring | adjacent to DNS but commonly bundled | monitoring-and-history-features, dns-health-audit-tools | differentiator | moderate | own dataset + scheduler |
| CT new-certificate alerting | catch unexpected cert issuance | monitoring-and-history-features, subdomain-enumeration-and-ct (Atom feed hand-off) | differentiator | trivial via feed hand-off, moderate to build ourselves | public API (crt.sh Atom) or own polling |
| Typosquat / lookalike-domain brand monitoring (recurring dnstwist-style scan) | ongoing brand protection | monitoring-and-history-features, dnstwist | differentiator, heavy at scale | heavy (scheduler + clone-detection) | own logic + scheduler |
| Subdomain discovery + new-subdomain alerting | catch shadow IT / forgotten hosts | monitoring-and-history-features, subdomain-enumeration-and-ct | differentiator | moderate | own dataset + public API (CT) |
| Public status pages (shareable uptime/health page) | share monitoring results externally | monitoring-and-history-features (Uptime Kuma pattern) | out of scope initially, heavy | heavy | own infra |
| Notification channels: email/webhook/Slack/Discord/Teams/PagerDuty/SMS | how alerts reach a human | monitoring-and-history-features | heavy, needs real delivery infra | heavy | own infra (SMTP, webhook client) |
| Maintenance windows / snooze on alerts | avoid noisy alerts during planned changes | monitoring-and-history-features | differentiator | trivial once alerting exists | own dataset |
| Bulk domain import + bulk history (thousands of domains) | agency/MSP use case | monitoring-and-history-features, viewdns-info, mxtoolbox | out of scope for a hobby tool | heavy | own infra |
| API access to history | programmatic access to stored monitoring data | monitoring-and-history-features | table-stakes given content negotiation already exists | trivial | own dataset |
| Retention-depth / check-frequency as the paid axis (documenting our own free limits honestly) | set expectations | monitoring-and-history-features | trivial policy decision | trivial | none |
| "You purged this N minutes ago" double-purge prevention | UX nicety on top of cache-purge feature | resolver-cache-purge-tools | differentiator | trivial | own dataset (Mongo) |
| Check history + diff vs previous propagation run | same pattern applied to propagation checks specifically | propagation-checking-methodology | differentiator | trivial | own dataset |

## 13. API & export

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Content negotiation: same URL, HTML for browsers/htmx, JSON for everyone else | one feature serves both surfaces (repo's own golden rule) | mxtoolbox (`format=`), dnsdumpster-hackertarget, check-host-and-ping-pe, email-dns-checkers, dns-health-audit-tools | table-stakes (already a repo rule) | trivial | pure Go (`platform.Respond`) |
| HTML-fragment response mode (server-rendered swap target, not JSON-wrapped HTML) | direct htmx target | mxtoolbox (`format=2`), dnsdumpster-hackertarget, email-dns-checkers | table-stakes given htmx use | trivial | pure Go |
| Plain pipe-delimited/text output variant | scriptable via bare `curl` with no client library | dnsleaktest-and-resolver-identity (`?txt`), record-types-reference (raw view) | differentiator | trivial | pure Go |
| Free, keyless, CORS-open JSON API for record lookups | let a browser or script call us directly | nslookup-io, google-admin-toolbox-dig (dns.google/resolve), globalping, subdomain-enumeration-and-ct (crt.sh), whois-rdap-tools (RDAP) as prior art | table-stakes for a modern API-shaped tool | trivial once domain logic exists | pure Go |
| OpenAPI 3.1 spec published for the JSON API | discoverability, tooling generation | nslookup-io, globalping, dnsperf-perfops | differentiator | trivial (generate from routes) | pure Go |
| Rate-limit headers (x-ratelimit-limit/-remaining/-reset) | professional feel, warns before a ban | nslookup-io, dnsdumpster-hackertarget (x-api-quota/-count/-boost), globalping, cert-spotter (subdomain-enumeration-and-ct) | table-stakes for a public API | trivial (middleware) | pure Go (Echo middleware) |
| MCP server exposing the domain layer as tools | let AI agents query us directly | nslookup-io, viewdns-info, robtex-he-ripestat, dns-spy (dns-health-audit-tools), globalping, ripe-atlas-dns (community) | differentiator, growing trend | moderate (thin wrapper over existing REST API) | pure Go |
| CLI distribution wrapping the same API | power-user access, teaches the API | doggo, globalping, zonemaster, dnstwist | differentiator, out of scope unless demand appears | moderate | pure Go (separate binary) |
| Browser extension | convenience distribution | dnschecker-org, whatsmydns, dnslytics, dnsdumpster-hackertarget | out of scope for a solo project initially | heavy | separate codebase |
| Bookmarklet / OpenSearch descriptor (browser-omnibox search) | zero-friction distribution, ~10-15 lines | whatsmydns, digwebinterface | differentiator, very cheap | trivial | static XML file |
| Official Go client library / SDK | programmatic ergonomics for our own API | globalping, ripe-atlas-dns, dnstwist (Python lib) | out of scope initially | moderate | pure Go |
| Slack/Discord/GitHub-bot integrations | distribution via chat platforms | globalping | out of scope for a hobby tool | heavy | own infra + bot tokens |
| n8n / Zapier node | fits VIDA's own stack coincidentally, but orthogonal here | globalping | out of scope | heavy | own infra |
| CSV/XLSX export (summary sheet + detail sheet) | take results into a spreadsheet | dnsdumpster-hackertarget, dns-health-audit-tools (BIND/PowerDNS/CSV backup) | differentiator | trivial (CSV), moderate (XLSX) | pure Go (`encoding/csv`, or xlsx lib) |
| Zone-file export (BIND/PowerDNS format) | reusable outside our tool | dns-health-audit-tools (DNS Spy daily backups) | differentiator | trivial | pure Go |
| OG-image generator per result (social share card) | shared links preview as a real card | nslookup-io | differentiator, cosmetic | moderate (image/draw + font) | pure Go (`image/draw`) |
| Webhook delivery for monitoring events | integration point for external systems | monitoring-and-history-features | heavy, tied to monitoring feature | heavy | own infra |
| Usage/quota endpoint (`GET /limits`) | let API users see their own remaining budget | mxtoolbox (`/api/v1/Usage`), globalping (`/v1/limits`), dnsperf-perfops (`/remaining-credits`) | differentiator | trivial | pure Go |

## 14. Education / UX affordances

| Feature | Answers | Who offers | Type | Cost | Dependency |
|---|---|---|---|---|---|
| Named checks with stable IDs + explainer pages, not just raw records | "what does this record *mean*" — the single biggest UX idea in the corpus | mxtoolbox, dns-health-audit-tools, zonemaster, dnsviz-and-dnssec-debuggers | differentiator, load-bearing | moderate (content authoring, trivial code) | markdown (goldmark, already in repo) |
| Related-lookups / next-hop suggestions on every result | turns one lookup into a session | mxtoolbox (`RelatedLookups[]`), google-admin-toolbox-dig | differentiator, "highest ratio of retention to effort" | trivial (4 htmx links) | pure Go |
| Plain-language templated sentence per finding (interpolated with the actual data) | teaches while it validates | email-dns-checkers, learn-dmarc pattern | differentiator | trivial (template map) | pure Go |
| Final one-line verdict sentence, not buried in detail panels | respect the user's time | email-dns-checkers (LearnDMARC) | differentiator | trivial | pure Go |
| RFC citation inline next to every finding, linked | cheapest credibility upgrade available | mxtoolbox, dns-health-audit-tools, zonemaster, dnsviz-and-dnssec-debuggers | table-stakes among serious tools | trivial | markdown authoring |
| Tooltip-only help system (every control explains itself inline) | no separate docs page to maintain | digwebinterface | differentiator | trivial | HTML `title=`/CSS |
| Record type hyperlinked to its RFC | replaces a whole reference page | digwebinterface, record-types-reference | differentiator | trivial | static table |
| Learning-centre articles (per-record-type explainers, "what is a DNS leak" etc.) | SEO surface + genuine education | nslookup-io (49 articles), dnsleaktest-and-resolver-identity, whatsmydns | differentiator | heavy (content volume) | markdown authoring |
| FAQ page with schema.org FAQPage JSON-LD | cheap SEO surface | doggo | differentiator, very cheap | trivial | static HTML/JSON-LD |
| Per-record-type SEO landing pages | organic traffic, doubles as docs | nslookup-io (52), whatsmydns, mxtoolbox (`/problem/*`) | differentiator | moderate (templating, content) | pure Go (route + markdown) |
| Print stylesheet | share a report on paper | dns-health-audit-tools | trivial | trivial | CSS |
| Dark/light theme toggle | table-stakes modern UX | check-host-and-ping-pe, doggo (terminal), various | table-stakes (repo already themes via Tailwind) | trivial | CSS |
| Mobile-responsive column reorder instead of horizontal scroll | usability on small screens | dnsleaktest-and-resolver-identity (browserleaks) | table-stakes | trivial | CSS |
| Anonymize-before-share toggle (redact IP/hostname before sending a link) | privacy-respecting sharing | dnsleaktest-and-resolver-identity | differentiator | trivial | client-side JS |
| Honest "how we measure" methodology blurb | removes methodology questions cheaply | dnsperf-perfops | trivial, worth copying verbatim in spirit | trivial | static copy |
| Explicit "why nothing changed" / not-applicable states (never silently blank) | avoid "is this broken" support questions | zonemaster ("Not testable"), robtex-he-ripestat (`data_call_status`), dns-health-audit-tools (`skipped` reason) | table-stakes for correctness | trivial | pure Go (enum) |
| Comment thread on a result page (self-hosted, e.g. remark42) | community troubleshooting | dnsleaktest-and-resolver-identity | out of scope for a hobby tool | heavy | own infra |
| Self-hosted analytics instead of third-party | privacy posture consistent with the rest of the site | dnsleaktest-and-resolver-identity (Matomo), internet-nl | table-stakes if repo already self-hosts analytics | trivial | existing infra |
| "Save as image" client-side screenshot export (html2canvas) | paste a result into a ticket, higher perceived value than CSV | check-host-and-ping-pe | differentiator | trivial (vendor a small MIT lib under `shared/static/js/`) | client-side JS (no npm needed, vendored) |
| Live counter heading ("N servers detected, M tests, K errors") | sense of progress on an async page | check-host-and-ping-pe, globalping | differentiator | trivial | htmx OOB swap |
| Per-node/per-server provenance popover (hostname, IP, datacenter, ASN) | "why does this vantage point disagree" | check-host-and-ping-pe, mxtoolbox, dnsperf-perfops | differentiator | trivial (join against cached node metadata) | own dataset |
| Copy-to-clipboard on raw values (resolver IP, record data) | keeps the row clean, one click to copy | dnschecker-org, digwebinterface | trivial nicety | trivial | client-side JS |
| Command-echo line showing exactly what was run | reproducibility outside the tool | digwebinterface, ping.pe (check-host-and-ping-pe) | differentiator | trivial | pure Go |
| Explicit disclaimer / abuse contact / security.txt | cheap legal insurance | abuse-ratelimits-and-ethics | table-stakes for a public tool | trivial | static file |
| "Only scan/check hosts you're authorized to" notice on aggressive features | sets expectations, matches Shodan/Censys framing | abuse-ratelimits-and-ethics | table-stakes | trivial | static copy |
| Free-tier truncation banner inline at top of results (not hidden in a modal) | honesty about caps | dnsdumpster-hackertarget | trivial | trivial | pure Go |

---

## Features nobody in the corpus offers but would obviously be useful

*Our own extrapolation, not observed practice anywhere in the 36 reports.*

- **One page that fuses zone health + email health + DNSSEC + reputation into a single score, but keeps every sub-check's raw evidence one click away.** Every competitor picks a lane (MXToolbox = email, Zonemaster = delegation, DNSViz = DNSSEC, RBL tools = reputation). Nobody in the corpus renders all four families as one coherent report from one engine with one score. A single Go domain package returning `[]Check` per family, rendered under one letter grade, is architecturally free given the repo's layering rule and is the actual differentiator against a field of specialists.
- **"Why did my resolver and the authoritative disagree" explainer that automatically picks the right explanation** (cache lag vs GeoDNS/ECS steering vs censorship/filtering vs stale glue) instead of making the user read four separate panels and infer it themselves. The individual signals (ECS scope, NSID, EDE codes, block-page IP tables) all exist in the corpus; nobody composes them into one verdict sentence.
- **A "since your last visit" diff delivered with zero account and zero email**, purely via a signed token in the permalink URL (not cookies, not login) that lets a returning visitor re-open the same query and see a highlighted diff against their last run. The Mongo-history idea is everywhere in the corpus; making it work for an anonymous visitor via a URL token instead of an account is not.
- **A single "what changed and does it matter" severity classifier that understands DNS record semantics**, not just byte-diffing (e.g., an A record round-robin reshuffle is noise; an NS-set change is critical; a TTL-only change is informational). Every monitoring product in the corpus diffs RRsets; none of them appear to weight the diff by which fields changed.
- **Inline "try this on your own resolver" instructions generated per-finding** (the exact `dig`/`nslookup`/PowerShell command to reproduce a specific failing check locally), auto-filled with the user's actual query. Several tools print *a* dig command (digwebinterface); none tie a specific remediation-doc finding to the exact reproduction command for that finding.
- **A "confidence" label on every derived/inferred fact** (provider fingerprinting, ASN-diversity judgments, wildcard detection) distinguishing "observed directly" from "inferred from a heuristic," modeled on this very research corpus's own fact-check discipline. No competitor product in the corpus visibly distinguishes its own hard data from its own guesses to the end user.
- **A DNS-focused robots.txt/llms.txt-style AI-crawler-and-agent policy checker that also checks whether the domain's own DNS-based agent discovery records exist** (e.g., emerging `_agent`/`.well-known` DNS conventions), extending MXToolbox's robots.txt AI-policy idea (HTTP-only today) into the DNS layer itself as those conventions mature.
