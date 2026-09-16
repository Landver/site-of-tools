# DNS lookup — research index

Firsthand research into DNS lookup services, gathered so the owner can decide **what DNS
feature corpberry should build**. Nothing built yet, no decision made — no Go, no domain
package, no `tools/dnstools/` exists.

> **Where this lives:** originally gathered at `docs/tools/dnslookup/` before the
> tool existed. Now filed under `tools/dnstools/docs/` per CLAUDE.md's layout
> rule, alongside the tool it informed.

## How to read this

Three levels, read in order, each says what the level below it is *for*:

1. **[00-landscape-and-ideas.md](00-landscape-and-ideas.md)** — the map. What the whole
   competitive set agrees is commodity vs where the value actually sits, feature ideas worth
   stealing, ideas nobody ships.
2. **[01-feature-inventory.md](01-feature-inventory.md)** — the menu. Every DNS-related
   feature observed across the 37 reports, grouped by aspect, tagged table-stakes /
   differentiator / nobody-ships-this, w/ a trivial/moderate/heavy/needs-paid-data cost band
   per feature.
3. **[02-build-fit.md](02-build-fit.md)** — the filter. Which menu items this specific stack
   (Go, Echo v5, htmx, no Node, no paid APIs by default) can actually ship, w/ evidence, tiered
   into a proposal + the decisions only the owner can make.

Everything below 00/01/02 is primary source material those three synthesize from — open a
report directly only when you need the firsthand detail behind a specific claim.

## Report index

| File | What's in it |
|---|---|
| **Synthesis** ||
| [00-landscape-and-ideas.md](00-landscape-and-ideas.md) | Competitive map, where value sits vs commodity, feature ideas |
| [01-feature-inventory.md](01-feature-inventory.md) | Exhaustive feature menu across all 37 reports, cost-banded |
| [02-build-fit.md](02-build-fit.md) | Feasibility filter for this stack, tiered proposal, owner decisions |
| **General lookup services** ||
| [reports/nslookup-io.md](reports/nslookup-io.md) | NsLookup.io — best-designed consumer lookup, free keyless API, closest direct competitor |
| [reports/digwebinterface.md](reports/digwebinterface.md) | DigWebInterface — raw `dig` as an HTML form, zero interpretation |
| [reports/google-admin-toolbox-dig.md](reports/google-admin-toolbox-dig.md) | Google Admin Toolbox Dig + `dns.google` free keyless DoH JSON API |
| [reports/mxtoolbox.md](reports/mxtoolbox.md) | MXToolbox SuperTool — pass/warn/fail checks on top of records, richest check-idea source |
| [reports/dnschecker-org.md](reports/dnschecker-org.md) | DNSChecker.org — mass-market 28-resolver propagation map + 88-tool grab-bag, cautionary UX tale |
| [reports/whatsmydns.md](reports/whatsmydns.md) | whatsmydns.net — category-defining 22-resolver propagation checker, single operator since 2008 |
| [reports/viewdns-info.md](reports/viewdns-info.md) | ViewDNS.info — 26 free tools + 22 paid API products, one-domain-many-lookups IA reference |
| [reports/doggo.md](reports/doggo.md) | doggo (mr-karan) — Go CLI+web dig replacement on `miekg/dns`, closest prior-art architecture |
| [reports/check-host-and-ping-pe.md](reports/check-host-and-ping-pe.md) | check-host.net & ping.pe — hobbyist multi-vantage-point checkers, keyless JSON |
| [reports/globalping.md](reports/globalping.md) | Globalping (jsDelivr) — free keyless CORS-open real multi-vantage-point DNS/ping/traceroute |
| [reports/dnsperf-perfops.md](reports/dnsperf-perfops.md) | DNSPerf/PerfOps — benchmarks DNS providers/resolvers, CORS-open REST API, 413 nodes |
| [reports/ripe-atlas-dns.md](reports/ripe-atlas-dns.md) | RIPE Atlas — research-grade ~15k-probe network, open unauthenticated read API, 37.5M past measurements |
| [reports/resolver-cache-purge-tools.md](reports/resolver-cache-purge-tools.md) | Cloudflare/Google/OpenDNS cache-purge tools — the "make it not stale" action a propagation check leads to |
| **Zone health & DNSSEC** ||
| [reports/dns-health-audit-tools.md](reports/dns-health-audit-tools.md) | intoDNS/DNSInspect/DNS Spy/MXToolbox Domain Health + Zonemaster + nslookup.io Health — delegation/config audit |
| [reports/dnsviz-and-dnssec-debuggers.md](reports/dnsviz-and-dnssec-debuggers.md) | DNSViz + Verisign DNSSEC Debugger — chain-of-trust walk, opaque SERVFAIL -> plain sentence |
| [reports/internet-nl.md](reports/internet-nl.md) | Internet.nl — Dutch gov/NLnet standards grader, 38 subtests, DANE + nameserver IPv6, Apache-2.0 OSS |
| [reports/zonemaster.md](reports/zonemaster.md) | Zonemaster (AFNIC/.se-.nu) — 73-test-case zone delegation validator, richest public test catalogue |
| **Email DNS** ||
| [reports/email-dns-checkers.md](reports/email-dns-checkers.md) | dmarcian/EasyDMARC/LearnDMARC/Postmark/Mailhardener — SPF/DKIM/DMARC/BIMI/MTA-STS/DANE policy evaluation |
| **Recon & passive DNS** ||
| [reports/dnsdumpster-hackertarget.md](reports/dnsdumpster-hackertarget.md) | DNSDumpster + HackerTarget (same co.) — keyless CORS-open API, htmx front end reference |
| [reports/dnslytics.md](reports/dnslytics.md) | DNSlytics — 10+ yr passive-DNS archive, killed its live-query tools 2024-01-01 |
| [reports/dnstwist.md](reports/dnstwist.md) | dnstwist — lookalike-domain fuzzer, 16 portable fuzzers, fuzzy-hashes clones against the real site |
| [reports/robtex-he-ripestat.md](reports/robtex-he-ripestat.md) | Robtex, Hurricane Electric BGP toolkit, RIPEstat — "what else is connected to this name/IP" |
| [reports/securitytrails-passive-dns.md](reports/securitytrails-passive-dns.md) | SecurityTrails & passive/historical DNS — what a name resolved to before now |
| [reports/subdomain-enumeration-and-ct.md](reports/subdomain-enumeration-and-ct.md) | crt.sh/Cert Spotter/Chaos + subfinder/Amass — Certificate Transparency as free subdomain inventory |
| **Adjacent lookups (WHOIS/RDAP, reputation)** ||
| [reports/whois-rdap-tools.md](reports/whois-rdap-tools.md) | WHOIS -> RDAP — keyless JSON, `Access-Control-Allow-Origin: *` verified, registrar two-hop + GDPR gaps |
| [reports/rbl-and-domain-reputation.md](reports/rbl-and-domain-reputation.md) | RBL/DNSBL reputation — DNS-as-key-value-DB trick, licensing (not engineering) is the catch |
| **Resolver identity & encrypted DNS** ||
| [reports/dnsleaktest-and-resolver-identity.md](reports/dnsleaktest-and-resolver-identity.md) | dnsleaktest/bash.ws/ipleak/browserleaks/1.1.1.1-help — "which resolver is *this visitor* using", needs a delegated zone |
| [reports/doh-dot-doq-and-public-resolvers.md](reports/doh-dot-doq-and-public-resolvers.md) | DoH/DoT/DoQ transports + 8 public resolvers — CORS reachability, multi-resolver diff as unclaimed feature |
| **APIs & pricing** ||
| [reports/dns-apis-and-pricing.md](reports/dns-apis-and-pricing.md) | Commercial + free API supply survey — raw records are free/keyless, vendors sell the inverse index & history |
| **Technique / reference reports** ||
| [reports/dns-concepts-and-query-modes.md](reports/dns-concepts-and-query-modes.md) | Protocol semantics a naive lookup page gets silently wrong (query modes, flags, TTL, etc.) |
| [reports/record-types-reference.md](reports/record-types-reference.md) | Which RR types to query/decode/render; DoH JSON APIs decode different partial slices past ~20 types |
| [reports/browser-constraints-dns-2026.md](reports/browser-constraints-dns-2026.md) | What can execute client-side vs must run in the Go binary; resolver-ID needs a delegated zone |
| [reports/go-dns-implementation.md](reports/go-dns-implementation.md) | stdlib `net.Resolver` vs real candidates for a Go `dns` domain package; no tool code written |
| [reports/propagation-checking-methodology.md](reports/propagation-checking-methodology.md) | What "propagation" mechanically is (cache age, anycast, GeoDNS) behind the map UIs |
| [reports/monitoring-and-history-features.md](reports/monitoring-and-history-features.md) | Scheduled re-checks/diff/alert/archive tier — the one slice needing persistent state + a scheduler |
| [reports/abuse-ratelimits-and-ethics.md](reports/abuse-ratelimits-and-ethics.md) | Real abuse risks for a public DNS tool (fan-out, attribution laundering, upstream ToS), not amplification |
| [reports/firsthand-ui-observations.md](reports/firsthand-ui-observations.md) | Flagship tools driven live in a real browser 2026-09-15, discrepancies vs the docs/curl-based reports flagged |

## State of the research

- **37 reports** in `reports/` + 3 synthesis files (`00`/`01`/`02`) = 40 files, all covering DNS
  lookup / zone-health / recon / email-auth / resolver-identity services and the protocol
  mechanics under them.
- **Method:** web research (docs, source, GitHub, ToS/privacy pages) + firsthand `curl`/`dig`
  probing (status codes, CORS headers, JSON API shapes, keyless-vs-keyed checks). **No browser
  automation** was used for the per-service reports.
- **[reports/firsthand-ui-observations.md](reports/firsthand-ui-observations.md) is the one
  exception**: the only file produced by driving the flagship tools live in a real browser,
  recorded separately as a companion so a doc-based claim never gets silently presented as
  something we watched render.
- **Fact-check pass:** each of the 37 `reports/` files was written by one agent, then
  fact-checked by a second agent that re-verified claims against sources and edited the file
  in place.
- **`00-landscape-and-ideas.md`, `01-feature-inventory.md`, `02-build-fit.md` were written
  without that second-agent critic review** — they synthesize the (already fact-checked)
  reports but were not themselves re-verified line by line.
- **Not done:** the planned corpus-wide completeness-critic pass (checking the corpus as a
  whole for gaps, not just per-file accuracy) **was cut for token budget and never ran.** Treat
  coverage as good-faith, not exhaustive-verified.
- **Not covered yet:** no tool has been designed, no Go written, no decision made on
  `ip.corpberry.com` page vs own subdomain, no client interviews on which feature they'd
  actually use.
