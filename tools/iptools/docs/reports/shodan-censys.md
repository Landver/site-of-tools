# Shodan & Censys (internet-wide scanning services)
> Two dominant "search engines for internet-connected devices": server-side scanners continuously crawling public internet, selling searchable results, host dossiers, monitoring, APIs.

## Overview

Reference products in space. Neither client-side/on-demand scanner like we're building — they run massive **server-side, internet-wide scan infra** on schedule, cache everything, sell access to resulting database. Study them purely for **product / UX / monetization ideas**: how they present host's open ports, "services detected", banners, CVEs, & freemium gating.

- **Shodan** bills as "the world's first search engine for Internet-connected devices"; claims 3M+ users incl 89% of Fortune 100. Scans internet weekly (paid API closer to real time). [shodan.io](https://www.shodan.io/)
- **Censys** main competitor, marketed as "Shodan alternative for internet-wide scanning", heavier enterprise/threat-intel & attack-surface-management (ASM) tilt. [censys.com/resources/pricing](https://censys.com/resources/pricing/)

## Port scanning / network probing — how it works

**Architecture (both): server-side, continuous, cached — opposite of our design.**
- Operate own distributed scanner fleet sweeping entire IPv4 space (& known IPv6/hostnames) on recurring cadence, grabbing & storing service banners. User "search" queries cached database; does **not** trigger fresh probe of target (except paid "on-demand rescan" features). [shodan.io](https://www.shodan.io/), [censys.com/resources/pricing](https://censys.com/resources/pricing/)
- Freshness = paid axis: Shodan's free/InternetDB data updates **weekly**; paid Shodan API real-time. [internetdb.shodan.io](https://internetdb.shodan.io/)

**What a host record contains.** Per IP, Shodan returns open ports, service/protocol on each, banner text w/ software **product + version**, CPEs, hostnames, org/ISP/ASN, geolocation, descriptive **tags** (e.g. `vpn`, `cloud`, `self-signed`), optional **web screenshots**, known **CVEs/vulns**. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/)

**Result "states".** Being cache-of-what-was-found engines, effectively only report **open/observed** state — open port w/ captured banner. Don't surface live open/closed/filtered trichotomy like on-demand scanner (nmap, or our browser tool) must. Meaningful gap we can differentiate on.

**InternetDB (Shodan's free, no-auth endpoint) — most directly relevant piece for us.** `https://internetdb.shodan.io/<ip>` returns compact JSON for IP: `ports[]`, `cpes[]`, `hostnames[]`, `tags[]`, `vulns[]`. Free for non-commercial use, no account/API key, updates weekly (no banner text — lighter than full API). [internetdb.shodan.io](https://internetdb.shodan.io/) Clean model of exact "given IP, list ports + label services + flag known CVEs" shape our IP tool already lives near.

**Ports covered.** Shodan tracks large published set of ports/protocols (data-status site lists per-port protocol, service, banner count, risk level, top product, associated CVEs). Censys documents "41 protocols total" on Free/Starter; full protocol set searchable only on higher tiers. [data-status.shodan.io/ports](https://data-status.shodan.io/ports.html), [docs.censys.com data-access-tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)

## UX & result presentation

**Host detail page (Shodan).** Single IP page leads w/ summary header (IP, org/ISP, ASN, geolocation, hostnames, last-seen), then **list of open ports** where each expands to service banner (product, version, CPE) & any CVEs. Tags render as pills; web service may show screenshot thumbnail. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/)

**Search filters / facets.** Query language w/ `filter:value` syntax (`port:`, `country:`, `org:`, `product:`, `vuln:`, `tag:`, `has_screenshot:` …) plus **facets** summarizing result set (top ports, top products, top countries). Note which filters gated (see monetization). [shodan.io](https://www.shodan.io/), [stationx.net how-to-use-shodan](https://www.stationx.net/how-to-use-shodan/)

**Maps.** Geographic plot of results, up to ~1,000 at a time; zooming re-runs query for visible area. [stationx.net](https://www.stationx.net/how-to-use-shodan/)

**Images.** UI wrapper around `has_screenshot` filter — gallery of captured device/web screenshots. [stationx.net](https://www.stationx.net/how-to-use-shodan/)

**Monitor (Shodan) — alerts UX.** Register your IP ranges, get "real-time notifications when something unexpected shows up" (new open port, exposed database, data leak, phishing lookalike) within ~5 min of setup, via email, Slack, Microsoft Teams, Discord, Telegram, Gitter, PagerDuty, or custom **webhooks**. Markets "actionable insights, not cluttered dashboards filled with noise." [monitor.shodan.io](https://monitor.shodan.io/)

**Censys presentation.** Similar host/service dossier plus **Collections** (saved searches/segments), host & DNS **history** timelines, adversary **dashboards**, `CensEye`, certificate history on higher tiers. Notably exposes **API + MCP access** on every paid tier — official model-context-protocol endpoint for AI agents. [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com data-access-tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)

## Other tools & services offered

**Shodan:** Search engine · Monitor (network alerts) · Maps · Images · Trends (historical query analytics) · Developer **API** (REST + Streaming/firehose + Trends) · **Bulk Data** / enterprise firehose · **InternetDB** (free per-IP lookup) · **CVEDB** (open vuln DB API: CVE lookups, CPE-keyed search, KEV filtering, EPSS ordering, date-range queries) · Chrome/Firefox browser plugins · CLI · Snippets. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/), [developer.shodan.io/api](https://developer.shodan.io/api)

**Censys:** Search (host / web property / certificate) · Collections · Enrichment API · deep app scan / live re-scan · web screenshots · Adversary Investigation module (threat data, CensEye, adversary dashboards) · Critical Infrastructure Monitoring add-on · API + MCP access on all paid tiers. [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com](https://docs.censys.com/docs/data-access-tiers-entitlements)

## Business / monetization model

**Shodan — credits + subscription + one lifetime hook.** [account.shodan.io/billing](https://account.shodan.io/billing)
- **Free:** $0 — 100 query credits/mo, 100 scan credits/mo, 16 monitored IPs, most filters but **no `vuln` or `tag`**, basic API.
- **Membership:** **one-time $49** lifetime upgrade (same 100/100 credits + 16 IPs, most filters) — famous conversion hook: cheap, permanent, removes paywall wall.
- **Freelancer $69/mo:** 10,000 query credits, 5,120 scan credits, 5,120 monitored IPs.
- **Small Business $359/mo:** 200,000 query, 65,536 scan, 65,536 IPs.
- **Corporate $1,099/mo:** unlimited query credits, 327,680 scan/IPs, batch IP lookups, `tag` filter, premium support.
- **Enterprise:** custom — bulk data, real-time firehose, unlimited.
- Two currencies (**query credits** = searches beyond page 1; **scan credits** = on-demand scans), refreshed monthly; 1 req/sec rate limit; "grandfathered pricing" retention perk.

**Censys — credits + tiers, enterprise-heavy.** [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com](https://docs.censys.com/docs/data-access-tiers-entitlements)
- **Free:** $0 — 1 page (100 results max), 1 concurrent action, **lookup endpoints only**, no history, basic protocols, **no CPE/version, no CVE**.
- **Starter:** from **$100** — 5 pages (500 results), 7-day host + DNS history, 1 user, 2 collections, full API + MCP; still no SSO/RBAC, no software-version data, no CVE, no downloads.
- **Search / Core:** contact sales — unlimited results, 25 concurrent, 31+ day history, full protocol + CPE data, web screenshots; Core adds software/hardware versions, deep app scan, **CVE data**, live re-scan, Enrichment API (20K calls/day base, unlimited add-on), 5+ users, 15+ collections.
- **Adversary Investigation:** contact sales — all Core plus searchable threat data, CensEye, adversary dashboards, 3+ month history, certificate history.
- **Credits model:** packages start at $100, consumed per query, export, dataset purchase, or collection use; enterprise add-ons (Gold Support, Critical Infrastructure Monitoring).

**Pattern:** free tier for discovery → gate *valuable* fields (CVEs, versions, screenshots, `vuln`/`tag` filters) & *volume* (result pagination, history depth, concurrency, API credits) behind paid tiers. Data same; access to depth/breadth/freshness is what's sold.

## Ideas to steal (for OUR client-side port scanner)

- **"Services detected" framing.** Don't just print "port 443 open" — map each open port to service name &, where possible, likely product ("443 · HTTPS · nginx?"). Shodan's whole value prop compressed into one label. Our tool can map from static port→service table client-side; product guesses stay soft ("likely"/"unverified").
- **Host summary header, then port cards.** Copy host-page layout: header (IP, reverse-DNS hostname, org/ASN, geo — which our IP tool already resolves) followed by vertical list of **open-port cards**, each expandable to details. Reads instantly, scales from 1 to many ports.
- **Report real open/closed/filtered trichotomy — our differentiator.** Shodan/Censys only show "found/open". Live browser scan can distinguish **open** (connected), **closed** (refused fast), **filtered/timeout** (no response). Show all three w/ distinct color/iconography; info their cached model literally cannot give.
- **Tags as pills + "risk" hint per port.** Cheap, skimmable signal (e.g. `database`, `remote-access`, `plaintext`). Shodan's per-port "risk level" column = good model for subtle severity badge.
- **Enrich w/ InternetDB (free, no key).** For resolved IP, consider fetching `https://internetdb.shodan.io/<ip>` to label services & surface known `vulns[]`/`tags[]`/`cpes[]`. Verify CORS from browser first; if blocked, tiny server-side proxy one option, though reintroduces server outbound traffic — weigh against client-side design goal. Data weekly-stale, so frame as "last known (Shodan)" alongside our live result.
- **Facet-style summary.** Above port list, one-line rollup: "6 open · 3 filtered · top: HTTPS, SSH". Mirrors Shodan facets, orients reader.
- **CVE presentation conventions worth echoing** (from Shodan CVEDB): list CVEs w/ CVSS severity, order by **EPSS** (exploit-likelihood), flag **KEV** (known-exploited) entries. Even static badge for "known-exploited" adds credibility.
- **Freemium hooks a hobby tool can echo (without charging money).** Mechanics translate to soft product tiers, not paywalls: gate **full 65k-port deep scan** behind explicit opt-in (default = fast top-100 preset); offer **scan history** of *your own* prior scans (we already have Mongo lookup history in IP tool — reuse it); lightweight **"monitor this host"** idea (re-run + diff) echoes Shodan Monitor without infra.
- **Scan-mode presets.** Shodan sells volume; for on-demand tool useful analog = nmap-style presets — "Top 100 (fast)", "Common services", "Full range (slow)" — as segmented control, defaulting to fast.
- **Copy/wording to borrow.** Plain, benefit-first, low-noise: "see what you have exposed", "real-time results, no account needed", "actionable insights, not a cluttered dashboard." Fits CLAUDE.md copy rules (stronger, minimal em dashes).

## Limitations & caveats

- **Fundamentally different model.** Both server-side, continuously-scanning, cache-and-sell databases; we're on-demand & client-side. Their *presentation* ideas transfer; *architecture* doesn't — copying it would recreate exactly the outbound-scan/blocklist problem client-side design avoids.
- **Staleness.** Free Shodan & InternetDB refresh weekly; cached result can be wrong for live host. Any InternetDB enrichment must be labeled "last known", not "live".
- **CORS / commercial-use limits.** InternetDB free only for **non-commercial** use, may not permit browser cross-origin fetches; confirm before relying on it. Full Shodan/Censys data paid & rate-limited (Shodan 1 req/sec).
- **Authorization framing.** Their monitoring products scoped to "your own infrastructure." Browser tool scanning arbitrary targets should carry clear "only scan hosts you're authorized to" notice.
- **Exact host-page field lists** for full paid Shodan UI inferred from homepage, InternetDB schema, & secondary guides rather than logged-in page capture; treat granular layout specifics as directional, not pixel-exact (unverified where noted).

## Sources
- https://www.shodan.io/
- https://account.shodan.io/billing
- https://monitor.shodan.io/
- https://internetdb.shodan.io/
- https://developer.shodan.io/api
- https://data-status.shodan.io/ports.html
- https://www.stationx.net/how-to-use-shodan/
- https://censys.com/resources/pricing/
- https://docs.censys.com/docs/data-access-tiers-entitlements
