# Shodan InternetDB — feasibility, limits & ToS (for the IP-tool port view)

> Can we power "known open ports for an IP" feature on `ip.corpberry.com` off
> Shodan's free **InternetDB** endpoint? **Yes — w/ conditions.** Works, keyless,
> fits IP tool. Catches are all about *data quality* & a genuine *ToS gray area*,
> not about functioning. Everything here live-verified (curl on 2026-07-24) or
> quoted from primary Shodan page read same day.

Companion to [`shodan-censys.md`](shodan-censys.md). Sources at end.

## Verdict

**Build it, server-side, non-commercial, w/ visible Shodan credit & live
per-request lookups (no storing returned data).** Under those conditions
practical risk low & this is exactly usage Shodan built InternetDB for (keyless
programmatic lookups; they even ship `nrich`/`sdlookup`). Honest caveat:
re-displaying returned data to *your visitors* sits in unresolved part of
Shodan's general ToS, so this is "reasonable & low-risk," not "authorized in
writing."

## What it is / how it behaves (live-verified)

- **Endpoint:** `GET https://internetdb.shodan.io/<ip>` — no API key, no account.
- **Response (200):** flat JSON —
  `{"ip","ports":[…],"hostnames":[…],"cpes":[…],"tags":[…],"vulns":[…]}`.
  Ports + reverse-DNS hostnames + CPE guesses + tags + CVE IDs. **No banners, no
  versions, no timestamps.**
- **No data → `404 {"detail":"No information available"}`.** Common case for
  home/residential/CGNAT IPs & anything w/ nothing publicly listening.
- **CORS:** `access-control-allow-origin: *` (GET/HEAD) — browser *can* call it
  directly. Still call it **server-side** anyway (see §Implementation).
- **Edge-cached** `cache-control: public, max-age=432000` (5 days) via Cloudflare.

## Rate limits

- **No key, no query/scan credits, no monthly quota** — wholly separate from
  credit-metered main REST API (`api.shodan.io`, ~1 req/s, key + credits).
- **Documented burst:** Shodan book says InternetDB *"has a rate limit that
  allows bursts of up to 10,000 requests per second."*
- **Real-world guardrail (community-reproduced, not in Shodan docs):** sustained
  hammering (~**600 rapid requests**) triggers Cloudflare **1-hour temp-ban of
  client IP**, w/ `429 "Rate limit exceeded."` — ban lands *before* you see the
  429. Mitigation: self-throttle to **~1 req/s**, dedupe/cache, handle `429`
  gracefully.
- **For our use** (visitor occasionally types an IP; responses cached 5 days):
  risk effectively nil. Live test: 12 rapid GETs → all `200`, no limit headers.

## Data freshness

- **Updated ~weekly.** InternetDB landing page + launch blog both say *"The API
  gets updated once a week."* Shodan crawler *"is designed to randomly crawl the
  Internet once a week"* (random IP + random port), so given IP can lag by a
  **week or more**. (*Main* platform surfaces data up to **30 days** old.)
- **Latest snapshot only — no history, no timestamp.** History/Trends are
  separate paid features. Each response = one current-ish snapshot; can't tell
  *when* collected, can't force a refresh for free.

## Coverage (the biggest practical limitation)

- **Only IPs Shodan recently saw w/ an open, internet-reachable port.** Public
  servers → usually present. **Residential / CGNAT / NAT'd / nothing-listening →
  `404`.** So "type your home IP" will often show nothing — set that expectation
  in UI.
- **IPv4-first.** Random crawler generates IPv4 addresses; IPv6 found only
  indirectly (DNS, hostname scans), so IPv6 coverage **sparse**. But **not
  absent** — live test: `2001:4860:4860::8888` (Google DNS v6) → `200` w/ data.
  So endpoint accepts IPv6; just don't promise good coverage.

## Data-quality caveats (surface these honestly in the UI)

- **Stale/closed ports:** listed port may have closed since last crawl.
- **CVEs (`vulns`) are version-*inferred*, not verified** — "fingerprinted
  version known-affected," not "confirmed exploitable." Don't imply host is
  hacked/vulnerable for certain.
- **No honeypot flagging** — InternetDB doesn't expose Shodan Honeyscore, so a
  decoy host's fake ports/CVEs look real.
- **Hostnames are reverse-DNS/PTR** — reflect DNS config, often stale/generic ISP
  names, not live service.

## ToS / licensing (clauses verified verbatim in the live ToS)

Binding terms = InternetDB blog/FAQ **plus** general Shodan ToS
(`static.shodan.io/legal/terms.html`; `account.shodan.io/terms` 302-redirects to
it). **No InternetDB-specific licence** (`openapi.json` carries no
`license`/`termsOfService`). Conditions to satisfy:

1. **Non-commercial only.** FAQ: *"free for non-commercial use… if you're using the
   InternetDB API to make money then you need an enterprise license."* corpberry
   (personal portfolio) qualifies. Adding paywall/ads-for-the-tool/paid product
   would require enterprise licence. *(Note: ToS's own non-commercial clause is
   Academic/Research-account-scoped & doesn't itself bind ordinary user — binding
   rule is the FAQ.)*
2. **Attribution mandatory** (ToS: *"you must attribute such usage to Shodan…
   must clearly indicate Shodan's ownership and copyright"*). Show visible
   **plain-text** credit, e.g. *"Open-port data from Shodan InternetDB — © Shodan"*
   linking to `internetdb.shodan.io`. **No Shodan logo/trademark**, don't imply
   endorsement, don't strip proprietary notices.
3. **Re-display to visitors = gray area.** InternetDB pages silent; general ToS
   says *"You may not… distribute or create derivative works based on this
   Content"* & *"will not reproduce, duplicate, copy… the Services."* Live
   per-visitor lookup of factual port data defensible (facts aren't
   copyrightable; Shodan actively promotes keyless lookups), but not expressly
   authorized. **Safe posture: live per-request, attribute, do NOT build/store/
   cache a copy of returned data.**
4. **Automated keyless querying** = product's intended pattern (*"No API key
   required"*, shipped scripting tools) — but in tension w/ general ToS's
   unconditional *"not to access… through any automated means (including…
   scripts or web crawlers)"*. Specific-over-general resolves it in practice;
   re-verify if Shodan ever signals otherwise.
5. **Don't disrupt the service** / respect any future transmission cap. Terms
   accept-by-use, changeable any time, governed by California law (San Diego
   jurisdiction) — **re-check before launch** & if tool's commercial character
   ever changes.

## Implementation implications for corpberry

- **Call it server-side** even though CORS would allow browser to — so we
  control attribution, cache/dedupe, translate `404`→"no data" & `429`→"try
  later", & keep fetch off visitor's own IP reputation. Single lightweight GET,
  **not** a scan — no Hetzner/abuse concern.
- **Do NOT extend this repo's Mongo lookup-history (`history.go`) to store
  InternetDB responses.** Would turn ephemeral use into stored "Content" &
  strengthen ToS "reproduce/distribute" concern. Log *query metadata* (which IP
  looked up, when) if anything — never returned port/CVE payload.
- **Fits existing IP tool cleanly:** already show geo/ASN/proxy/blocklist for any
  IP; "known open ports (Shodan, ~weekly, may be stale)" = one more card on same
  `/?ip=…` lookup — not a new subdomain concern.
- **Set expectations in copy:** "last-seen by Shodan, updated weekly, blank for most
  home connections" — so `404` reads as normal, not broken.

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
