# BrowserLeaks (browserleaks.com)
> The reference "what your browser reveals" suite: ~20+ free, client-side (plus passive server-side) tests that fingerprint and leak-check a visitor's browser. Closest public analog to our approach, though it does NOT do port scanning.

## Overview
BrowserLeaks is a free suite of browser privacy / fingerprinting diagnostics. A visitor lands on any one test page and immediately sees "here is what your browser just told me about you." It is widely treated as the canonical reference for browser-side leak testing (VPN/antidetect-browser vendors benchmark against "passing BrowserLeaks").

- Created/run by a security researcher (reported as "Taras"); not a company product. (partly unverified — no on-site about/FAQ page found; sourced from third-party writeups.)
- Positioned as a research/diagnostic tool, not a data broker. Third-party reviews state it has no subscription tiers, no ads, and does not require or collect personal data. ([nodemaven review](https://nodemaven.com/blog/browserleaks/), [gologin review](https://gologin.com/blog/browserleaks-review-fingerprint-testing/))
- Relevant caveat for us: **none of its tests probe TCP/UDP ports or scan the local network.** The nearest thing is WebRTC local-IP disclosure. So BrowserLeaks is the model for *presentation and framing*, not for the scan technique itself.

## Port scanning / network probing — how it works
**BrowserLeaks does not port-scan.** No test on the site sends connection attempts to host ports or enumerates services. The site combines two probing styles:

1. **Client-side JavaScript probes** — the browser runs JS that queries Web APIs and reports back what they expose. This is the bulk of the suite (Canvas, WebGL, WebRTC, Fonts, Audio, Geolocation, Features, ClientRects, etc.).
2. **Passive server-side observation** — the server reads what the connection *already* revealed: HTTP headers, the source IP, the TLS handshake, the HTTP/2 frame settings, TCP/IP stack characteristics. No active probing; it just inspects the request it received. ([browserleaks.com/ip](https://browserleaks.com/ip), [browserleaks.com/tls](https://browserleaks.com/tls))

Network-adjacent findings, and what "result states" they report:

- **WebRTC leak test** — the single most network-revealing test. Uses `RTCPeerConnection` ICE-candidate gathering + SDP parsing + `MediaDevices` enumeration. Reveals **local/private IP(s) behind NAT, public IP, and IPv6** even under a VPN/proxy, plus enumerated media devices (mics/cameras/speakers). It discloses *addresses*, not open ports. Page did not explicitly confirm mDNS-hostname masking behavior (unverified). Layout is results-first: "Your Remote IP" → WebRTC support → "Your WebRTC IP" → media devices → collapsible "How to Disable WebRTC." ([browserleaks.com/webrtc](https://browserleaks.com/webrtc))
- **DNS leak test** — checks whether DNS resolution escapes the VPN/proxy tunnel to the ISP's resolvers. ([browserleaks.com/dns](https://browserleaks.com/dns), homepage)
- **TCP/IP fingerprint** — passive OS guess from packet characteristics: detected OS, MTU (e.g. 1500), hop distance, and a **JA4T** hash. No port state involved. ([browserleaks.com/ip](https://browserleaks.com/ip))
- **TLS client test** — passive from the handshake: TLS versions, ordered cipher-suite list (annotated for weaknesses like "NO PFS", "CBC, SHA-1"), extensions, ECH status, inner/outer SNI, and **JA3/JA4 family** fingerprints (JA3, JA3_r/_n/_rn, JA4, JA4_o/_ro). A JSON variant is exposed at a direct API endpoint. ([browserleaks.com/tls](https://browserleaks.com/tls))
- **HTTP/2 fingerprint** — Akamai-style hash derived from HTTP/2 frame/settings ordering (server-side). ([browserleaks.com/ip](https://browserleaks.com/ip))
- **QUIC client test** — analogous handshake fingerprinting for QUIC. (homepage)

**Result-state vocabulary:** BrowserLeaks does not use open/closed/filtered (that's port-scan language it never needs). Its states are things like: leaked vs not-leaked (WebRTC/DNS), supported / not supported / `n/a (no js)` (feature detection), a hash + a **uniqueness percentage** (fingerprints), and security annotations on weak ciphers.

## Enumerated tests (the full client-probing suite)
Confirmed from homepage + individual pages. "Where" = where the data comes from.

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
This is the part worth stealing. Consistent per-test template:

- **Results-first, explanation-second.** Every page dumps the actual detected values in a table at the very top, before any prose. The visitor sees their own leaked data instantly; the "why this matters" copy sits below.
- **One test per page, deep not wide.** Each API/vector gets its own dedicated URL and page rather than one giant dashboard. Easy to link to, easy to scope.
- **Value tables with attribute → detected-value rows,** grouped under category headings; status shown via checkmarks / direct values / explicit `n/a (no js)` when JS is off. The `n/a (no js)` marker itself teaches the difference between passive and active data.
- **Fingerprint pages headline a hash + a uniqueness statistic** ("X% of users share this signature") — turns an abstract hash into a visceral "you are identifiable" moment.
- **Canvas shows the actual rendered image** next to its hash — makes an invisible technique tangible.
- **Cipher/security annotations inline** ("NO PFS", "CBC, SHA-1") flag weaknesses right in the results row rather than in separate prose.
- **Collapsible remediation blocks** ("How to Disable WebRTC") sit at the bottom, so the page is diagnosis-then-fix.
- **Explanatory copy is plain-language and threat-framed**, e.g. canvas: rendering "can vary based on the web browser, operating system, graphics card... resulting in a unique image that can be used to create a fingerprint," and it enables "persistent tracking without cookies." It names real countermeasures (CanvasBlocker) — credible, not fear-only.
- **JSON available per test** at direct endpoints (seen on the TLS page) — i.e. same feature serves an HTML page and a machine-readable JSON, which maps directly onto our content-negotiation rule.

## Other tools & services offered
BrowserLeaks *is* the test suite — there is no separate product line. The ~20+ tests above are the entire offering: IP/WebRTC/DNS/IPv6 leak checks, the fingerprint battery (Canvas/WebGL/WebGPU/Fonts/Audio/ClientRects/CSS), protocol fingerprints (TLS/HTTP2/QUIC/TCP-IP), plus Geolocation, Features, Client Hints, Content Filters, Extension detection, DNT/GPC. Adjacent utilities implied (WHOIS / reverse-IP lookup) live inside the IP tool.

## Business / monetization model
- **Free, no ads, no subscription, no login.** Multiple independent reviews describe it as an independently-run research tool with no commercial tier and no personal-data collection. ([nodemaven](https://nodemaven.com/blog/browserleaks/), [gologin](https://gologin.com/blog/browserleaks-review-fingerprint-testing/), [ipaddress.com profile](https://www.ipaddress.com/website/browserleaks.com/))
- **No commercial fingerprinting API productized** for sale (unlike FingerprintJS/Fingerprint Pro). It exposes per-test JSON endpoints for its own pages, but there's no advertised paid API. (API-as-product: unverified/none found.)
- **Donations:** not confirmed — no about/FAQ/donate page resolved (both `/about` and `/faq` returned 404). Treat any "funded by donations" claim as (unverified).
- Net: the site's leverage is reputation/authority, not revenue. It became the industry's yardstick for "does my browser leak," which is itself the payoff.

## Ideas to steal (for OUR client-side port scanner)
- **Results-first layout.** Show the scan table at the very top the instant it runs; put "how this works / what it means" below. Don't make the visitor scroll to see their own data.
- **Adopt an explicit result-state vocabulary and show it as annotated rows** — for a port scanner that's `open` / `closed` / `filtered` / `timeout`, mirroring how BrowserLeaks annotates ciphers inline. Color/label each state in the row itself.
- **`n/a (no js)` pattern.** When JS is required for a probe, say so explicitly in the cell. Great teaching signal and it's honest about what's client-side vs server-side — directly relevant since our scan is browser-side by design.
- **Steal the framing, not the fear.** Lead with plain "here is what your browser (and now, what your network) reveals." Pair each result with short, concrete "what this means" copy and a remediation note (collapsible), the way they do "How to Disable WebRTC."
- **A uniqueness / summary headline stat.** BrowserLeaks' "X% of users share this fingerprint" is the emotional hook. Our analog: a one-line summary like "N of M scanned ports responded" or a risk headline up top, above the detail table.
- **Same feature → HTML + JSON.** Their per-test JSON endpoints validate our content-negotiation golden rule: build the port scanner once (domain returns structs), serve HTML to browsers/htmx and JSON to everyone else.
- **WebRTC as a companion probe.** Since our scan is client-side, a WebRTC local-IP disclosure box is a natural, low-effort add that pairs with a port scan ("here's your local IP; now here's what's reachable"). It's the one BrowserLeaks vector adjacent to local-network reconnaissance.
- **One vector = one page, results-first.** Keep each tool scoped, deep, and independently linkable rather than one mega-dashboard — matches our subdomain-per-tool architecture.
- **Honest passive-vs-active labeling.** BrowserLeaks quietly distinguishes "the server already knew this from your request" from "JS had to ask." For a scanner, clearly label what the browser is actively doing (so the user understands the scan runs on *their* machine, not our server) — this is exactly the abuse/blocklist concern the design is built around.

## Limitations & caveats
- **No port scanning or local-network host enumeration anywhere on the site** — do not cite BrowserLeaks as prior art for the scan *mechanism*; cite it only for UX/framing.
- Ownership ("Taras"), donation funding, and the absence of a paid API are from third-party writeups; **no on-site about/FAQ page was reachable** (`/about` and `/faq` both 404'd) to confirm first-hand. Marked (unverified) above.
- WebRTC mDNS-hostname obfuscation behavior (modern Chrome masks local IPs as `*.local`) was not explicitly confirmed on the page (unverified) — worth checking before copying WebRTC copy verbatim.
- Fetched-page summaries were produced by a summarizer over rendered markdown; exact on-page wording of long explanatory blocks should be re-read from the live pages before quoting in our copy.
- Third-party "review" sources (nodemaven, gologin, incogniton, adspower, morelogin, kameleo) are antidetect-browser / proxy vendors with an interest in the topic; fine for the free/no-ads/no-login facts, but not neutral on privacy claims.

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
