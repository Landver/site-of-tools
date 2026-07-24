# Shodan & Censys (internet-wide scanning services)
> The two dominant "search engines for internet-connected devices": server-side scanners that continuously crawl the public internet and sell searchable results, host dossiers, monitoring, and APIs.

## Overview

Shodan and Censys are the reference products in this space. Neither is a client-side or on-demand scanner in the sense we are building — they run massive **server-side, internet-wide scan infrastructure** on a schedule, cache everything, and sell access to the resulting database. We study them purely for **product / UX / monetization ideas**, especially how they present a host's open ports, "services detected", banners, and CVEs, and how they use freemium gating.

- **Shodan** bills itself as "the world's first search engine for Internet-connected devices" and claims 3M+ users, including 89% of the Fortune 100. It scans the internet weekly (the paid API updates closer to real time). [shodan.io](https://www.shodan.io/)
- **Censys** is the main competitor, marketed as the "Shodan alternative for internet-wide scanning", with a heavier enterprise/threat-intel and attack-surface-management (ASM) tilt. [censys.com/resources/pricing](https://censys.com/resources/pricing/)

## Port scanning / network probing — how it works

**Architecture (both): server-side, continuous, cached — the opposite of our design.**
- They operate their own distributed scanner fleet that sweeps the entire IPv4 space (and known IPv6/hostnames) on a recurring cadence, grabbing service banners and storing them. A user "search" queries that cached database; it does **not** trigger a fresh probe of the target (except paid "on-demand rescan" features). [shodan.io](https://www.shodan.io/), [censys.com/resources/pricing](https://censys.com/resources/pricing/)
- Freshness is a paid axis: Shodan's free/InternetDB data updates **weekly**; the paid Shodan API is real-time. [internetdb.shodan.io](https://internetdb.shodan.io/)

**What a host record contains.** Per IP, Shodan returns open ports, the service/protocol on each, banner text with software **product + version**, CPEs, hostnames, org/ISP/ASN, geolocation, descriptive **tags** (e.g. `vpn`, `cloud`, `self-signed`), optional **web screenshots**, and known **CVEs/vulns**. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/)

**Result "states".** Because these are cache-of-what-was-found engines, they effectively only report the **open/observed** state — an open port with a captured banner. They do not surface a live open/closed/filtered trichotomy the way an on-demand scanner (nmap, or our browser tool) must. This is a meaningful gap we can differentiate on.

**InternetDB (Shodan's free, no-auth endpoint) — the most directly relevant piece for us.** `https://internetdb.shodan.io/<ip>` returns a compact JSON for an IP: `ports[]`, `cpes[]`, `hostnames[]`, `tags[]`, and `vulns[]`. It is free for non-commercial use, needs no account or API key, and updates weekly (no banner text — lighter than the full API). [internetdb.shodan.io](https://internetdb.shodan.io/) This is a clean model of the exact "given an IP, list its ports + label services + flag known CVEs" shape our IP tool already lives near.

**Ports covered.** Shodan tracks a large, published set of ports/protocols (its data-status site lists per-port protocol, service, banner count, risk level, top product, and associated CVEs). Censys documents "41 protocols total" on Free/Starter, with the full protocol set searchable only on higher tiers. [data-status.shodan.io/ports](https://data-status.shodan.io/ports.html), [docs.censys.com data-access-tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)

## UX & result presentation

**Host detail page (Shodan).** A single IP page leads with a summary header (IP, org/ISP, ASN, geolocation, hostnames, last-seen), then a **list of open ports** where each port expands to its service banner (product, version, CPE) and any CVEs. Tags render as pills; a web service may show a screenshot thumbnail. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/)

**Search filters / facets.** A query language with `filter:value` syntax (`port:`, `country:`, `org:`, `product:`, `vuln:`, `tag:`, `has_screenshot:` …) plus **facets** that summarize a result set (top ports, top products, top countries). Note which filters are gated (see monetization). [shodan.io](https://www.shodan.io/), [stationx.net how-to-use-shodan](https://www.stationx.net/how-to-use-shodan/)

**Maps.** Geographic plot of results, up to ~1,000 at a time; zooming re-runs the query for the visible area. [stationx.net](https://www.stationx.net/how-to-use-shodan/)

**Images.** A friendly UI wrapper around the `has_screenshot` filter — a gallery of captured device/web screenshots. [stationx.net](https://www.stationx.net/how-to-use-shodan/)

**Monitor (Shodan) — alerts UX.** You register your IP ranges and get "real-time notifications when something unexpected shows up" (new open port, exposed database, data leak, phishing lookalike) within ~5 minutes of setup, delivered via email, Slack, Microsoft Teams, Discord, Telegram, Gitter, PagerDuty, or custom **webhooks**. Explicitly markets "actionable insights, not cluttered dashboards filled with noise." [monitor.shodan.io](https://monitor.shodan.io/)

**Censys presentation.** Similar host/service dossier plus **Collections** (saved searches/segments), host & DNS **history** timelines, adversary **dashboards**, `CensEye`, and certificate history on higher tiers. Notably exposes **API + MCP access** on every paid tier — i.e. an official model-context-protocol endpoint for AI agents. [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com data-access-tiers](https://docs.censys.com/docs/data-access-tiers-entitlements)

## Other tools & services offered

**Shodan:** Search engine · Monitor (network alerts) · Maps · Images · Trends (historical query analytics) · Developer **API** (REST + Streaming/firehose + Trends) · **Bulk Data** / enterprise firehose · **InternetDB** (free per-IP lookup) · **CVEDB** (open vulnerability DB API: CVE lookups, CPE-keyed search, KEV filtering, EPSS ordering, date-range queries) · Chrome/Firefox browser plugins · CLI · Snippets. [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/), [developer.shodan.io/api](https://developer.shodan.io/api)

**Censys:** Search (host / web property / certificate) · Collections · Enrichment API · deep app scan / live re-scan · web screenshots · Adversary Investigation module (threat data, CensEye, adversary dashboards) · Critical Infrastructure Monitoring add-on · API + MCP access on all paid tiers. [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com](https://docs.censys.com/docs/data-access-tiers-entitlements)

## Business / monetization model

**Shodan — credits + subscription + one lifetime hook.** [account.shodan.io/billing](https://account.shodan.io/billing)
- **Free:** $0 — 100 query credits/mo, 100 scan credits/mo, 16 monitored IPs, most filters but **no `vuln` or `tag`**, basic API.
- **Membership:** **one-time $49** lifetime upgrade (same 100/100 credits + 16 IPs, most filters) — a famous conversion hook: cheap, permanent, removes the paywall wall.
- **Freelancer $69/mo:** 10,000 query credits, 5,120 scan credits, 5,120 monitored IPs.
- **Small Business $359/mo:** 200,000 query, 65,536 scan, 65,536 IPs.
- **Corporate $1,099/mo:** unlimited query credits, 327,680 scan/IPs, batch IP lookups, `tag` filter, premium support.
- **Enterprise:** custom — bulk data, real-time firehose, unlimited.
- Two currencies (**query credits** = searches beyond page 1; **scan credits** = on-demand scans), refreshed monthly; 1 request/sec rate limit; "grandfathered pricing" retention perk.

**Censys — credits + tiers, enterprise-heavy.** [censys.com/resources/pricing](https://censys.com/resources/pricing/), [docs.censys.com](https://docs.censys.com/docs/data-access-tiers-entitlements)
- **Free:** $0 — 1 page (100 results max), 1 concurrent action, **lookup endpoints only**, no history, basic protocols, **no CPE/version, no CVE**.
- **Starter:** from **$100** — 5 pages (500 results), 7-day host + DNS history, 1 user, 2 collections, full API + MCP; still no SSO/RBAC, no software-version data, no CVE, no downloads.
- **Search / Core:** contact sales — unlimited results, 25 concurrent, 31+ day history, full protocol + CPE data, web screenshots; Core adds software/hardware versions, deep app scan, **CVE data**, live re-scan, Enrichment API (20K calls/day base, unlimited add-on), 5+ users, 15+ collections.
- **Adversary Investigation:** contact sales — all Core plus searchable threat data, CensEye, adversary dashboards, 3+ month history, certificate history.
- **Credits model:** packages start at $100, consumed per query, export, dataset purchase, or collection use; enterprise add-ons (Gold Support, Critical Infrastructure Monitoring).

**Pattern:** free tier for discovery → gate the *valuable* fields (CVEs, versions, screenshots, `vuln`/`tag` filters) and *volume* (result pagination, history depth, concurrency, API credits) behind paid tiers. The data is the same; access to depth/breadth/freshness is what's sold.

## Ideas to steal (for OUR client-side port scanner)

- **"Services detected" framing.** Don't just print "port 443 open" — map each open port to a service name and, where possible, a likely product ("443 · HTTPS · nginx?"). This is Shodan's whole value proposition compressed into one label. Our tool can do the mapping from a static port→service table client-side; product guesses stay soft ("likely"/"unverified").
- **Host summary header, then port cards.** Copy the host-page layout: a header (IP, reverse-DNS hostname, org/ASN, geo — which our IP tool already resolves) followed by a vertical list of **open-port cards**, each expandable to details. Reads instantly and scales from 1 to many ports.
- **Report a real open/closed/filtered trichotomy — our differentiator.** Shodan/Censys only show "found/open". A live browser scan can distinguish **open** (connected), **closed** (refused fast), and **filtered/timeout** (no response). Show all three with distinct color/iconography; it's information their cached model literally cannot give.
- **Tags as pills + a "risk" hint per port.** Cheap, skimmable signal (e.g. `database`, `remote-access`, `plaintext`). Shodan's per-port "risk level" column is a good model for a subtle severity badge.
- **Enrich with InternetDB (free, no key).** For a resolved IP, consider fetching `https://internetdb.shodan.io/<ip>` to label services and surface known `vulns[]`/`tags[]`/`cpes[]`. Verify CORS from the browser first; if blocked, a tiny server-side proxy is one option, though it reintroduces server outbound traffic — weigh against the client-side design goal. Data is weekly-stale, so frame it as "last known (Shodan)" alongside our live result.
- **Facet-style summary.** Above the port list, a one-line rollup: "6 open · 3 filtered · top: HTTPS, SSH". Mirrors Shodan facets and orients the reader.
- **CVE presentation conventions worth echoing** (from Shodan CVEDB): list CVEs with CVSS severity, order by **EPSS** (exploit-likelihood), and flag **KEV** (known-exploited) entries. Even a static badge for "known-exploited" adds credibility.
- **Freemium hooks a hobby tool can echo (without charging money).** The mechanics translate to soft product tiers, not paywalls: gate a **full 65k-port deep scan** behind an explicit opt-in (default = fast top-100 preset); offer **scan history** of *your own* prior scans (we already have Mongo lookup history in the IP tool — reuse it); a lightweight **"monitor this host"** idea (re-run + diff) echoes Shodan Monitor without infrastructure.
- **Scan-mode presets.** Shodan sells volume; for an on-demand tool the useful analog is nmap-style presets — "Top 100 (fast)", "Common services", "Full range (slow)" — as a segmented control, defaulting to fast.
- **Copy/wording to borrow.** Plain, benefit-first, low-noise: "see what you have exposed", "real-time results, no account needed", "actionable insights, not a cluttered dashboard." Fits the CLAUDE.md copy rules (stronger, minimal em dashes).

## Limitations & caveats

- **Fundamentally different model.** Both are server-side, continuously-scanning, cache-and-sell databases; we are on-demand and client-side. Their *presentation* ideas transfer; their *architecture* does not, and copying it would recreate exactly the outbound-scan/blocklist problem the client-side design avoids.
- **Staleness.** Free Shodan and InternetDB refresh weekly; a cached result can be wrong for a live host. Any InternetDB enrichment must be labeled "last known", not "live".
- **CORS / commercial-use limits.** InternetDB is free only for **non-commercial** use and may not permit browser cross-origin fetches; confirm before relying on it. Full Shodan/Censys data is paid and rate-limited (Shodan 1 req/sec).
- **Authorization framing.** Their monitoring products are scoped to "your own infrastructure." A browser tool that scans arbitrary targets should carry a clear "only scan hosts you're authorized to" notice.
- **Exact host-page field lists** for the full paid Shodan UI were inferred from the homepage, InternetDB schema, and secondary guides rather than a logged-in page capture; treat granular layout specifics as directional, not pixel-exact (unverified where noted).

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
