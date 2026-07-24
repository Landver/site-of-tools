# Shodan InternetDB — feasibility, limits & ToS (for the IP-tool port view)

> Can we power a "known open ports for an IP" feature on `ip.corpberry.com` off
> Shodan's free **InternetDB** endpoint? **Yes — with conditions.** It works, it's
> keyless, and it fits the IP tool. The catches are all about *data quality* and a
> genuine *ToS gray area*, not about it functioning. Everything here is
> live-verified (curl on 2026-07-24) or quoted from a primary Shodan page read the
> same day.

Companion to [`shodan-censys.md`](shodan-censys.md). Sources listed at the end.

## Verdict

**Build it, server-side, non-commercial, with a visible Shodan credit and live
per-request lookups (no storing the returned data).** Under those conditions the
practical risk is low and this is exactly the usage Shodan built InternetDB for
(keyless programmatic lookups; they even ship `nrich`/`sdlookup`). The honest
caveat: re-displaying the returned data to *your visitors* sits in an unresolved
part of Shodan's general ToS, so this is "reasonable and low-risk," not
"authorized in writing."

## What it is / how it behaves (live-verified)

- **Endpoint:** `GET https://internetdb.shodan.io/<ip>` — no API key, no account.
- **Response (200):** flat JSON —
  `{"ip","ports":[…],"hostnames":[…],"cpes":[…],"tags":[…],"vulns":[…]}`.
  Ports + reverse-DNS hostnames + CPE guesses + tags + CVE IDs. **No banners, no
  versions, no timestamps.**
- **No data → `404 {"detail":"No information available"}`.** This is the common
  case for home/residential/CGNAT IPs and anything with nothing publicly
  listening.
- **CORS:** `access-control-allow-origin: *` (GET/HEAD) — a browser *can* call it
  directly. We should still call it **server-side** anyway (see §Implementation).
- **Edge-cached** `cache-control: public, max-age=432000` (5 days) via Cloudflare.

## Rate limits

- **No key, no query/scan credits, no monthly quota** — wholly separate from the
  credit-metered main REST API (`api.shodan.io`, ~1 req/s, key + credits).
- **Documented burst:** the Shodan book says InternetDB *"has a rate limit that
  allows bursts of up to 10,000 requests per second."*
- **Real-world guardrail (community-reproduced, not in Shodan's docs):** sustained
  hammering (~**600 rapid requests**) triggers a Cloudflare **1-hour temp-ban of
  the client IP**, with `429 "Rate limit exceeded."` — and the ban lands *before*
  you see the 429. Mitigation: self-throttle to **~1 req/s**, dedupe/cache, handle
  `429` gracefully.
- **For our use** (a visitor occasionally types an IP; responses cached 5 days):
  risk is effectively nil. Live test: 12 rapid GETs → all `200`, no limit headers.

## Data freshness

- **Updated ~weekly.** InternetDB landing page + launch blog both say *"The API
  gets updated once a week."* Shodan's crawler *"is designed to randomly crawl the
  Internet once a week"* (random IP + random port), so a given IP can lag by a
  **week or more**. (The *main* platform surfaces data up to **30 days** old.)
- **Latest snapshot only — no history, no timestamp.** History/Trends are separate
  paid features. Each response is one current-ish snapshot; you can't tell *when*
  it was collected, and you can't force a refresh for free.

## Coverage (the biggest practical limitation)

- **Only IPs Shodan has recently seen with an open, internet-reachable port.**
  Public servers → usually present. **Residential / CGNAT / NAT'd / nothing-listening
  → `404`.** So "type your home IP" will very often show nothing — set that
  expectation in the UI.
- **IPv4-first.** The random crawler generates IPv4 addresses; IPv6 is found only
  indirectly (DNS, hostname scans), so IPv6 coverage is **sparse**. But it is
  **not absent** — live test: `2001:4860:4860::8888` (Google DNS v6) → `200` with
  data. So the endpoint accepts IPv6; just don't promise good coverage.

## Data-quality caveats (surface these honestly in the UI)

- **Stale/closed ports:** a listed port may have closed since the last crawl.
- **CVEs (`vulns`) are version-*inferred*, not verified** — "a fingerprinted
  version is known-affected," not "confirmed exploitable." Don't imply the host is
  hacked/vulnerable for certain.
- **No honeypot flagging** — InternetDB doesn't expose Shodan's Honeyscore, so a
  decoy host's fake ports/CVEs look real.
- **Hostnames are reverse-DNS/PTR** — reflect DNS config, often stale/generic ISP
  names, not the live service.

## ToS / licensing (clauses verified verbatim in the live ToS)

Binding terms = the InternetDB blog/FAQ **plus** the general Shodan ToS
(`static.shodan.io/legal/terms.html`; `account.shodan.io/terms` 302-redirects to
it). There is **no InternetDB-specific licence** (`openapi.json` carries no
`license`/`termsOfService`). Conditions to satisfy:

1. **Non-commercial only.** FAQ: *"free for non-commercial use… if you're using the
   InternetDB API to make money then you need an enterprise license."* corpberry
   (personal portfolio) qualifies. Adding a paywall/ads-for-the-tool/paid product
   would require an enterprise licence. *(Note: the ToS's own non-commercial clause
   is Academic/Research-account-scoped and doesn't itself bind an ordinary user —
   the binding rule is the FAQ.)*
2. **Attribution is mandatory** (ToS: *"you must attribute such usage to Shodan…
   must clearly indicate Shodan's ownership and copyright"*). Show a visible
   **plain-text** credit, e.g. *"Open-port data from Shodan InternetDB — © Shodan"*
   linking to `internetdb.shodan.io`. **No Shodan logo/trademark**, don't imply
   endorsement, don't strip proprietary notices.
3. **Re-display to visitors = gray area.** InternetDB pages are silent; the general
   ToS says *"You may not… distribute or create derivative works based on this
   Content"* and *"will not reproduce, duplicate, copy… the Services."* A live
   per-visitor lookup of factual port data is defensible (facts aren't
   copyrightable; Shodan actively promotes keyless lookups), but it isn't expressly
   authorized. **Safe posture: live per-request, attribute, and do NOT build/store/
   cache a copy of the returned data.**
4. **Automated keyless querying** is the product's intended pattern (*"No API key
   required"*, shipped scripting tools) — but note it's in tension with the general
   ToS's unconditional *"not to access… through any automated means (including…
   scripts or web crawlers)"*. Specific-over-general resolves it in practice;
   re-verify if Shodan ever signals otherwise.
5. **Don't disrupt the service** / respect any future transmission cap. Terms are
   accept-by-use, changeable at any time, governed by California law (San Diego
   jurisdiction) — **re-check before launch** and if the tool's commercial
   character ever changes.

## Implementation implications for corpberry

- **Call it server-side** even though CORS would allow the browser to — so we
  control attribution, cache/dedupe, translate `404`→"no data" and `429`→"try
  later", and keep the fetch off the visitor's own IP reputation. It's a single
  lightweight GET, **not** a scan — no Hetzner/abuse concern.
- **Do NOT extend this repo's Mongo lookup-history (`history.go`) to store
  InternetDB responses.** That would turn ephemeral use into stored "Content" and
  strengthen the ToS "reproduce/distribute" concern. Log *query metadata* (which IP
  was looked up, when) if anything — never the returned port/CVE payload.
- **Fits the existing IP tool cleanly:** we already show geo/ASN/proxy/blocklist for
  any IP; "known open ports (Shodan, ~weekly, may be stale)" is one more card on the
  same `/?ip=…` lookup — not a new subdomain concern.
- **Set expectations in copy:** "last-seen by Shodan, updated weekly, blank for most
  home connections" — so a `404` reads as normal, not broken.

## Sources
- ToS (verified verbatim): https://static.shodan.io/legal/terms.html · redirect from https://account.shodan.io/terms
- InternetDB FAQ/landing: https://internetdb.shodan.io/ · spec https://internetdb.shodan.io/openapi.json
- Launch (non-commercial, no-key, weekly, higher rate): https://blog.shodan.io/introducing-the-internetdb-api/
- Burst limit: https://book.shodan.io/developer-apis/internetdb/
- Credits model (main API, for contrast): https://help.shodan.io/the-basics/credit-types-explained · https://book.shodan.io/developer-apis/shodan-api/
- Crawl cadence: https://book.shodan.io/behind-the-scenes/crawler-algorithm/ · https://help.shodan.io/the-basics/on-demand-scanning
- Data timeframes (30-day main platform): https://help.shodan.io/mastery/data_timeline
- Cloudflare temp-ban (~600 req → 1h ban), community-reproduced: https://github.com/blacklanternsecurity/bbot/issues/2412
- 404 behavior (corroboration): https://news.ycombinator.com/item?id=24557469
