# BrowserLeaks (browserleaks.com)
> Reference "what your browser reveals" suite: ~20+ free, client-side (plus passive server-side) tests that fingerprint & leak-check visitor's browser. Closest public analog to our approach, but does NOT do port scanning.

## Overview
Free suite of browser privacy / fingerprinting diagnostics. Visitor lands on any test page & immediately sees "here is what your browser just told me about you." Widely treated as canonical reference for browser-side leak testing (VPN/antidetect-browser vendors benchmark against "passing BrowserLeaks").

- Created/run by security researcher (reported as "Taras"); not a company product. (partly unverified — no on-site about/FAQ page found; sourced from third-party writeups.)
- Positioned as research/diagnostic tool, not data broker. Third-party reviews: no subscription tiers, no ads, does not require/collect personal data. ([nodemaven review](https://nodemaven.com/blog/browserleaks/), [gologin review](https://gologin.com/blog/browserleaks-review-fingerprint-testing/))
- Caveat for us: **none of its tests probe TCP/UDP ports or scan local network.** Nearest thing = WebRTC local-IP disclosure. So BrowserLeaks = model for *presentation & framing*, not scan technique.

## Port scanning / network probing — how it works
**BrowserLeaks does not port-scan.** No test sends connection attempts to host ports or enumerates services. Site combines two probing styles:

1. **Client-side JavaScript probes** — browser runs JS querying Web APIs & reports what they expose. Bulk of suite (Canvas, WebGL, WebRTC, Fonts, Audio, Geolocation, Features, ClientRects, etc.).
2. **Passive server-side observation** — server reads what connection *already* revealed: HTTP headers, source IP, TLS handshake, HTTP/2 frame settings, TCP/IP stack characteristics. No active probing; inspects received req. ([browserleaks.com/ip](https://browserleaks.com/ip), [browserleaks.com/tls](https://browserleaks.com/tls))

Network-adjacent findings & their "result states":

- **WebRTC leak test** — most network-revealing test. Uses `RTCPeerConnection` ICE-candidate gathering + SDP parsing + `MediaDevices` enumeration. Reveals **local/private IP(s) behind NAT, public IP, & IPv6** even under VPN/proxy, plus enumerated media devices (mics/cameras/speakers). Discloses *addresses*, not open ports. Page did not confirm mDNS-hostname masking behavior (unverified). Results-first layout: "Your Remote IP" → WebRTC support → "Your WebRTC IP" → media devices → collapsible "How to Disable WebRTC." ([browserleaks.com/webrtc](https://browserleaks.com/webrtc))
- **DNS leak test** — checks whether DNS resolution escapes VPN/proxy tunnel to ISP's resolvers. ([browserleaks.com/dns](https://browserleaks.com/dns), homepage)
- **TCP/IP fingerprint** — passive OS guess from packet characteristics: detected OS, MTU (e.g. 1500), hop distance, **JA4T** hash. No port state. ([browserleaks.com/ip](https://browserleaks.com/ip))
- **TLS client test** — passive from handshake: TLS versions, ordered cipher-suite list (annotated for weaknesses like "NO PFS", "CBC, SHA-1"), extensions, ECH status, inner/outer SNI, **JA3/JA4 family** fingerprints (JA3, JA3_r/_n/_rn, JA4, JA4_o/_ro). JSON variant at direct API endpoint. ([browserleaks.com/tls](https://browserleaks.com/tls))
- **HTTP/2 fingerprint** — Akamai-style hash from HTTP/2 frame/settings ordering (server-side). ([browserleaks.com/ip](https://browserleaks.com/ip))
- **QUIC client test** — analogous handshake fingerprinting for QUIC. (homepage)

**Result-state vocabulary:** no open/closed/filtered (port-scan language it never needs). States: leaked vs not-leaked (WebRTC/DNS), supported / not supported / `n/a (no js)` (feature detection), hash + **uniqueness percentage** (fingerprints), security annotations on weak ciphers.

## Enumerated tests (the full client-probing suite)
Confirmed from homepage + individual pages. "Where" = data source.

| Test | What it exposes | Where |
|------|-----------------|-------|
| **IP Address** | Public IP, reverse DNS, ISP/ASN, country/state/city, HTTP request headers, TCP/IP OS fingerprint (MTU, hops, JA4T) | Server-side (passive) |
| **JavaScript** | User-Agent, screen res/color/pixel depth, platform, CPU logical cores, device memory, touch points, `webdriver` flag, battery status, timezone/locale/i18n, Network Information API (connection type/speed), audio-context props, speech-synthesis voices, Bluetooth adapter, client hints | Client JS |
| **WebRTC** | Local + public + IPv6 addresses, SDP log, media-device enumeration | Client JS |
| **Canvas** | Rendered image + MD5 hash "signature" + **uniqueness %**, plus PNG headers/CRC/color count | Client JS |
| **WebGL** | GPU vendor/renderer, WebGL params, WebGL fingerprint hash | Client JS |
| **WebGPU** | WebGPU adapter/report (newer GPU API) | Client JS |
| **Fonts** | Installed-font detection via text/glyph metric measurement | Client JS |
| **Audio** | AudioContext-based fingerprint | Client JS |
| **Geolocation** | Geolocation API lat/long with permission-prompt analysis | Client JS (permission-gated) |
| **Features / APIs** | HTML5 feature-detector matrix (supported/not) | Client JS |
| **ClientRects** | Sub-pixel `getClientRects()` bounding-box fingerprint | Client JS |
| **CSS Media Queries** | Environment via CSS media features | Client (CSS/JS) |
| **Client Hints** | UA-CH platform version, architecture, bitness | Both |
| **DNS Leak** | Which resolvers see your queries | Client-triggered |
| **TLS** | TLS versions, ciphers, extensions, JA3/JA4, ECH/SNI | Server-side (handshake) |
| **HTTP/2** | HTTP/2 settings fingerprint (Akamai hash) | Server-side |
| **QUIC** | QUIC client fingerprint | Server-side |
| **TCP/IP** | OS fingerprint, MTU, hops, JA4T | Server-side (passive) |
| **Content Filters** | Detects middleboxes/filters altering the connection/content | Both |
| **Chrome Extension Detection** | Fingerprints installed extensions via web-accessible resources | Client JS |
| **Do Not Track / GPC** | DNT header + Global Privacy Control signal | Both |
| **Legacy** | Flash / Silverlight / Java probes (historical, mostly dead) | Client plugin |

## UX & result presentation
Part worth stealing. Consistent per-test template:

- **Results-first, explanation-second.** Every page dumps detected values in table at very top, before prose. Visitor sees own leaked data instantly; "why this matters" copy sits below.
- **One test per page, deep not wide.** Each API/vector gets own dedicated URL & page, not one giant dashboard. Easy to link to & scope.
- **Value tables w/ attribute → detected-value rows,** grouped under category headings; status via checkmarks / direct values / explicit `n/a (no js)` when JS off. `n/a (no js)` marker teaches passive vs active data difference.
- **Fingerprint pages headline hash + uniqueness statistic** ("X% of users share this signature") — turns abstract hash into visceral "you are identifiable" moment.
- **Canvas shows actual rendered image** next to its hash — makes invisible technique tangible.
- **Cipher/security annotations inline** ("NO PFS", "CBC, SHA-1") flag weaknesses in results row, not separate prose.
- **Collapsible remediation blocks** ("How to Disable WebRTC") at bottom -> page is diagnosis-then-fix.
- **Explanatory copy plain-language & threat-framed**, e.g. canvas: rendering "can vary based on the web browser, operating system, graphics card... resulting in a unique image that can be used to create a fingerprint," enables "persistent tracking without cookies." Names real countermeasures (CanvasBlocker) — credible, not fear-only.
- **JSON available per test** at direct endpoints (seen on TLS page) — same feature serves HTML page + machine-readable JSON, maps directly onto our content-negotiation rule.

## Other tools & services offered
BrowserLeaks *is* the test suite — no separate product line. The ~20+ tests above = entire offering: IP/WebRTC/DNS/IPv6 leak checks, fingerprint battery (Canvas/WebGL/WebGPU/Fonts/Audio/ClientRects/CSS), protocol fingerprints (TLS/HTTP2/QUIC/TCP-IP), plus Geolocation, Features, Client Hints, Content Filters, Extension detection, DNT/GPC. Adjacent utilities implied (WHOIS / reverse-IP lookup) live inside IP tool.

## Business / monetization model
- **Free, no ads, no subscription, no login.** Multiple independent reviews: independently-run research tool, no commercial tier, no personal-data collection. ([nodemaven](https://nodemaven.com/blog/browserleaks/), [gologin](https://gologin.com/blog/browserleaks-review-fingerprint-testing/), [ipaddress.com profile](https://www.ipaddress.com/website/browserleaks.com/))
- **No commercial fingerprinting API productized** for sale (unlike FingerprintJS/Fingerprint Pro). Exposes per-test JSON endpoints for own pages, but no advertised paid API. (API-as-product: unverified/none found.)
- **Donations:** not confirmed — no about/FAQ/donate page resolved (both `/about` & `/faq` returned 404). Treat any "funded by donations" claim as (unverified).
- Net: leverage is reputation/authority, not revenue. Became industry's yardstick for "does my browser leak," which is the payoff.

## Ideas to steal (for OUR client-side port scanner)
- **Results-first layout.** Show scan table at very top instant it runs; put "how this works / what it means" below. Don't make visitor scroll to see own data.
- **Adopt explicit result-state vocabulary, show as annotated rows** — for port scanner that's `open` / `closed` / `filtered` / `timeout`, mirroring how BrowserLeaks annotates ciphers inline. Color/label each state in the row itself.
- **`n/a (no js)` pattern.** When JS required for probe, say so explicitly in cell. Great teaching signal & honest about client-side vs server-side — relevant since our scan is browser-side by design.
- **Steal framing, not fear.** Lead w/ plain "here is what your browser (and now, what your network) reveals." Pair each result w/ short concrete "what this means" copy + remediation note (collapsible), like their "How to Disable WebRTC."
- **Uniqueness / summary headline stat.** BrowserLeaks' "X% of users share this fingerprint" = emotional hook. Our analog: one-line summary like "N of M scanned ports responded" or risk headline up top, above detail table.
- **Same feature → HTML + JSON.** Their per-test JSON endpoints validate our content-negotiation golden rule: build port scanner once (domain returns structs), serve HTML to browsers/htmx & JSON to everyone else.
- **WebRTC as companion probe.** Since our scan is client-side, WebRTC local-IP disclosure box = natural low-effort add pairing w/ port scan ("here's your local IP; now here's what's reachable"). The one BrowserLeaks vector adjacent to local-network recon.
- **One vector = one page, results-first.** Keep each tool scoped, deep, independently linkable, not one mega-dashboard — matches our subdomain-per-tool architecture.
- **Honest passive-vs-active labeling.** BrowserLeaks distinguishes "server already knew this from your request" from "JS had to ask." For scanner, clearly label what browser is actively doing (so user understands scan runs on *their* machine, not our server) — exactly the abuse/blocklist concern the design is built around.

## Limitations & caveats
- **No port scanning or local-network host enumeration anywhere on site** — do not cite BrowserLeaks as prior art for scan *mechanism*; cite only for UX/framing.
- Ownership ("Taras"), donation funding, & absence of paid API from third-party writeups; **no on-site about/FAQ page reachable** (`/about` & `/faq` both 404'd) to confirm first-hand. Marked (unverified) above.
- WebRTC mDNS-hostname obfuscation behavior (modern Chrome masks local IPs as `*.local`) not confirmed on page (unverified) — worth checking before copying WebRTC copy verbatim.
- Fetched-page summaries produced by summarizer over rendered markdown; exact on-page wording of long explanatory blocks should be re-read from live pages before quoting in our copy.
- Third-party "review" sources (nodemaven, gologin, incogniton, adspower, morelogin, kameleo) = antidetect-browser / proxy vendors w/ interest in topic; fine for free/no-ads/no-login facts, not neutral on privacy claims.

## Sources
- https://browserleaks.com/ (homepage / test index)
- https://browserleaks.com/webrtc
- https://browserleaks.com/javascript
- https://browserleaks.com/canvas
- https://browserleaks.com/ip
- https://browserleaks.com/tls
- https://nodemaven.com/blog/browserleaks/
- https://gologin.com/blog/browserleaks-review-fingerprint-testing/
- https://incogniton.com/blog/test-browser-fingerprints-with-browserleaks/
- https://www.ipaddress.com/website/browserleaks.com/
- https://www.adspower.com/blog/what-is-browserleaks-ip-webrtc-leak-test
- https://kameleo.io/blog/defeat-browserleaks-step-by-step-guide
