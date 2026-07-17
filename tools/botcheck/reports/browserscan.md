# BrowserScan.net

A free, no-login browser-fingerprint and bot-detection checker aimed at the anti-detect-browser / multi-accounting crowd: it tells you how detectable and internally consistent your (often spoofed) browser looks, both as a categorical bot verdict and as a numeric "authenticity" trust score.

- **URL:** https://www.browserscan.net/bot-detection (bot verdict) · https://www.browserscan.net/ (full fingerprint + trust score) · https://www.browserscan.net/tls (TLS/HTTP2) · **Category:** privacy/anonymity & fingerprint tool — a self-test checker oriented to the anti-detect-browser ecosystem (AdsPower, Multilogin, GoLogin, Dolphin Anty, etc.), not an open-source test page and not an enterprise vendor's protection demo · **Requires registration:** No (the scan runs on page load; optional Google "Sign in" / "Join now" exist but are not needed).
- **Firsthand verdict for the test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"Normal"** — i.e. *not* flagged as a bot. Every framework check returned "Normal" and the CDP category did not trip, even though this browser is genuinely CDP-driven. This is a notable miss: the same browser was correctly flagged as a bot by deviceandbrowserinfo.com solely on `isAutomatedWithCDP`, and Fingerprint.com reported Developer Tools = Yes. BrowserScan's CDP detection did not catch it.

## What it is — common info

BrowserScan is a free public fingerprint checker. Its stated purpose is to show a user the full fingerprint their browser exposes plus a "browser fingerprint authenticity" score, so they can judge how identifiable and consistent they look. In practice its audience is the anti-detect-browser and multi-accounting community: operators run BrowserScan to confirm a spoofed profile looks like a coherent real browser and does not leak its real IP, timezone, or automation traces. The companion blog (blog.browserscan.net) is largely a content hub reviewing and comparing anti-detect browsers, which places the site firmly in that ecosystem; the firsthand recon also noted AdsPower affiliation/banners. The specific corporate owner is not disclosed on the site and could not be confirmed from primary sources — treat ownership as low-confidence.

It is worth separating two things a builder should not conflate: **BrowserScan.net** (the live service documented here, closed source) versus **browserscan.org**, a separate open-source lookalike (GitHub `browerscan/browerscan`) that is a different Next.js/Cloudflare codebase. The `.org` repo is *not* the source of the `.net` service; it merely implements a similar "deduction-based 0–100 scoring" idea.

## Registration / access

None required for the checker. Loading the page runs the scan automatically within a few seconds. Optional account sign-in exists but gates nothing in the free self-test. (Caveat on sourcing: the "no registration/payment" claim is corroborated firsthand and by one third-party review, not by BrowserScan's own docs — see Verification notes.)

## How it decides bot-or-not

Two distinct surfaces with two different output styles:

- **`/bot-detection` subpage** produces a *categorical* verdict. It runs a battery of named automation-framework checks and per-signal checks (Webdriver, User-Agent, CDP, Navigator) and reports each as "Normal" or flagged. The top-line result is a category label such as **Normal** vs a bot type. There is no percentage on this page.
- **Home page** produces the *numeric* **Trust Score (0–100%)** — a "fingerprint authenticity" figure over the full fingerprint (canvas, WebGL, audio, fonts, hardware, WebRTC, timezone/geo, TLS, etc.). This is a deduction/consistency model: start high and subtract for each anomaly, leak, or spoofing tell (timezone vs IP geo mismatch, WebRTC real-IP leak, UA vs platform mismatch, automation traces, TLS-vs-UA mismatch). Flagged items render in red; higher score = more coherent/"human-looking."

Semantically the score answers "does this look like a coherent, non-automated, real browser that blends in," i.e. authenticity/consistency rather than a probabilistic bot likelihood. The site itself frames its checks as the same kind of detection Cloudflare Turnstile and Google reCAPTCHA perform, and distinguishes "good bots" (search-engine crawlers) from "malicious bots" (Selenium/Puppeteer/Playwright).

## Detection approaches

- **Browser fingerprinting** — canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext, fonts, media devices, ClientRects, screen, hardware and navigator attributes, all collected client-side.
- **Headless/automation detection** — `navigator.webdriver`, Chrome DevTools Protocol (CDP) usage, and a named framework battery: WebDriver, WebDriver Advance, Selenium, NightmareJS, PhantomJS, Awesomium, CEF, CefSharp, Coaches, FMiner, Born, Phantomas, Rhino, WebdriverIO, Headless Chrome (all observed firsthand, all returned "Normal" for the test browser).
- **Deception / spoofing-anomaly detection** — the "Native Navigator" check dumps the full navigator (including `userAgentData`) and tests each method's `Function.prototype.toString()` output for `"[native code]"` to catch monkey-patched or overridden properties injected by anti-detect tooling.
- **Consistency cross-checks** — browser timezone vs IP geolocation, User-Agent vs actual platform, WebRTC-exposed IP vs proxy egress IP, and (per research) TLS/JA3 vs the browser the UA claims.
- **Network / TLS / HTTP2 fingerprinting** — server-side JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions, plus Akamai-format HTTP/2 fingerprint (SETTINGS frame, WINDOW_UPDATE, stream priority, pseudo-header ordering). Lives on `/tls`.
- **IP / proxy / geolocation reputation** — IP, ISP, proxy detection, geolocation, DNS leak, IPv6 leak.
- **Port scanning** — probes ports such as 22 (SSH) and 3389 (RDP) to reveal server/VPS/remote-desktop environments (per research).
- **Rule/deduction-based scoring**, not a documented ML classifier. Behavioral timing (typing/mouse) is described in the docs as a technique but is not clearly part of the automated one-page scan.

## Areas / signals scanned

**Client-side (JS):**
- `navigator` properties and "deceptive"/modified navigator props; `navigator.webdriver`; `userAgentData`.
- CDP traces; Selenium/WebDriver artifact keys; PhantomJS/NightmareJS/CEF/CefSharp/Awesomium markers.
- Canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext fingerprint.
- Installed fonts, media devices, ClientRects.
- Screen resolution, color depth, touch support; GPU, `hardwareConcurrency`, `deviceMemory`.
- Languages / Intl; plugins; incognito-mode detection.
- WebRTC IP leak (real IP behind VPN/proxy).
- Cookies enabled, Do Not Track.
- Legacy Java/Flash/ActiveX plugin section — present but effectively dead in modern browsers; treat as a low-value legacy signal, not an active vector.

**Server-side (IP / TLS / TCP / HTTP headers):**
- IP, ISP, proxy detection, geolocation (country/region/city/postal/lat-long); DNS leak, IPv6 leak.
- Timezone / local time vs IP geolocation.
- TLS/SSL: JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions.
- HTTP/2: SETTINGS, WINDOW_UPDATE, stream priority, pseudo-header ordering, Akamai fingerprint (hash + text).
- Open-port scan (22 SSH, 3389 RDP).

**Behavioral:** described in docs (typing/mouse timing) but not clearly wired into the automated scan; do not assume it runs on page load.

## How it scans (architecture)

Hybrid, with a meaningful client/server split.

- The bulk of the fingerprint is collected **client-side** by a JavaScript bundle (`dist/*.js`). It also spins up a **`blob:` Web Worker** to recompute fingerprint values in a second JS context — the standard cross-context trick to expose spoofing that only patches the main window.
- **Firsthand network observation:** the `/bot-detection` subpage did **not** POST its results anywhere — the categorical verdict is computed and rendered in-browser. The home-page trust-score flow **does** POST the collected fingerprint to **`api.browserscan.net`**. So the two surfaces differ operationally: the bot verdict is client-only in what we observed, while the trust score involves a backend round-trip.
- The **TLS/SSL and HTTP/2 fingerprints are inherently server-side** — derived from the raw ClientHello and HTTP/2 setup frames of the incoming connection, which client JS cannot produce. IP/geo/proxy/port-scan resolution is likewise server-side. This lets the backend independently fingerprint the actual connection and compare it to what the client JS claimed (e.g. a Chrome UA whose JA3 does not look like Chrome). The exact request wiring that correlates the two is not published, so the correlation step is inferred, not documented.

Net: decision surface is split — categorical bot checks resolve client-side; the trust score and all network-layer analysis depend on the backend.

## Scoring / output

- **`/bot-detection`:** discrete per-category results (Normal vs flagged) across Webdriver, User-Agent, CDP, Navigator, plus the framework battery — a categorical bot verdict, no percentage.
- **Home page:** a single **Trust Score percentage (0–100%)**, deduction-based. 100% = no issues detected; problem items shown in red. Independent guidance cites ~90% as a rough "looks unique/inconsistent" threshold. This percentage is the closest thing BrowserScan offers to a unified number, and it lives on the home page — **not** on the bot-detection page.

## Notable techniques

- `Function.prototype.toString()` `[native code]` probing across navigator methods to detect overridden/patched properties — detecting the *spoofing itself*, not just the spoofed value.
- `blob:` Web Worker cross-context recomputation to catch masks that only cover the main window.
- Named framework battery (15+ automation tools) reported individually rather than as one opaque score.
- Server-observed JA3/JA4 + Akamai HTTP/2 fingerprint used to catch handshake-vs-claimed-browser mismatches.
- Port scan (22/3389) to expose server/VPS/RDP setups that betray a non-consumer environment.
- Consistency triangulation: timezone vs IP geo, UA vs platform, WebRTC IP vs egress IP.

## What we observed firsthand

- Verdict: **"Normal"** (not a bot). All framework checks Normal; CDP and Dev Tool categories present but not tripped, despite this being a genuinely CDP-driven Electron browser. BrowserScan under-detected relative to peers — a concrete data point that its CDP/automation detection is weaker than deviceandbrowserinfo.com's (which flagged the identical browser on CDP alone).
- The Native Navigator check dumped the full navigator including `userAgentData` and applied the `[native code]` toString test.
- Architecture confirmed by traffic: client-side `dist/*.js` bundle + a `blob:` Web Worker. **The `/bot-detection` subpage issued no results POST.** The home-page trust-score flow POSTed the fingerprint to **`api.browserscan.net`**.

## Verification notes

The adversarial review confirmed the research is well-supported, with these corrections folded in above:

- **CapMonster review is not "independent," and there is only one.** The "multiple independent reviews confirm no registration/payment" phrasing was overstated: exactly one third-party review was located (capmonster.cloud), from a CAPTCHA-solving vendor in the same anti-detect ecosystem — promotional, same-ecosystem, not a neutral audit. Its factual sub-claims (50+ data points, canvas `toDataURL`, no login) do check out; its neutrality does not. This report treats "no registration" as corroborated by firsthand observation, not by that review.
- **Citation-to-claim looseness on "no registration":** the BrowserScan how-to-use doc cited for it does not actually state registration is unnecessary; it only describes visiting and waiting. The claim is almost certainly true (scan runs on page load) but was not documented at the cited source.
- **Do not attach the trust percentage to the bot-detection page.** The `/bot-detection` page shows discrete Webdriver/User-Agent/CDP/Navigator pass-fail results; the 0–100% authenticity score lives on the home page. Kept crisp above.
- **`browserscan.net` ≠ `browserscan.org`.** The GitHub `browerscan/browerscan` repo is a separate open-source lookalike for the `.org` domain, not the `.net` service's source. Do not collapse them.
- **Legacy plugin detection (Flash/ActiveX/Java) is anachronistic** — present as a dead legacy section, flagged as low-value rather than an active detection vector.
- **Ownership is unconfirmed** (low confidence), and the **client↔server correlation mechanism is inferred**, not documented verbatim.

Gaps an anti-bot engineer should note (things a stronger builder would add, several not clearly covered by BrowserScan):

- **UA Client Hints triangulation** — cross-check the legacy UA string, JS `navigator.userAgentData`, and the `Sec-CH-UA` / `Sec-CH-UA-Platform` / `Sec-CH-UA-Mobile` HTTP headers. Anti-detect browsers frequently desync these three; this is a primary 2024+ surface.
- **Canvas/audio/WebGL noise-injection detection** — arguably the core reason BrowserScan's audience uses it, yet not surfaced as such. Anti-detect browsers randomize canvas/audio output per session; a strong checker detects the non-determinism (or statistically improbable hashes) across repeated reads, not just one `toDataURL`.
- **Property-level headless tells** — `Notification.permission === 'denied'` while `permissions.query` state is `'default'`; empty `navigator.plugins`/`mimeTypes`; missing `window.chrome` runtime; empty `navigator.languages`. BrowserScan names webdriver/CDP but not these classic signatures.
- **TLS ordering + GREASE** — cipher-suite/extension *order* and the GREASE pattern must match the exact Chrome/Firefox build the UA claims; a reordered ClientHello from Go/Python/`curl-impersonate` is the giveaway. State the ordering dimension explicitly, not "mismatch" abstractly.
- **Passive TCP/IP (p0f-style) OS fingerprinting** — comparing OS inferred from TCP options/window size/TTL against the UA-claimed OS. Almost certainly **out of scope** for BrowserScan's JS+TLS design; note the gap deliberately (incolumitas covers it; BrowserScan does not).
- **Cross-tab / storage / TLS-session-resumption re-identification** — no evidence BrowserScan probes `localStorage`/IndexedDB persistence, evercookie stability, or TLS session-ticket resumption to link a "fresh" profile to a prior visit.

## Open source / reusable

**None for BrowserScan.net itself** — the live service is closed source. The GitHub `browerscan/browerscan` repo is a *separate* open-source lookalike backing browserscan.org (Next.js/Cloudflare, deduction-based 0–100 scoring); usable as a reference for the scoring *idea*, but it is not BrowserScan.net's code and does not include the server-side TLS/HTTP2/IP machinery.

## Sources

- [BrowserScan — home (fingerprint + trust score)](https://www.browserscan.net/)
- [BrowserScan — bot detection page (Webdriver / User-Agent / CDP / Navigator)](https://www.browserscan.net/bot-detection)
- [BrowserScan — HTTP2/SSL/TLS fingerprint page (JA3, JA4, Akamai)](https://www.browserscan.net/tls)
- [BrowserScan docs — Bot Detection (webdriver, _selenium markers, behavioral timing)](https://blog.browserscan.net/docs/bot-detection)
- [BrowserScan docs — How to Use BrowserScan](https://blog.browserscan.net/docs/how-to-use-browserscan)
- [CapMonster — BrowserScan Review 2025 (third-party, promotional / same-ecosystem)](https://capmonster.cloud/en/blog/browserscan-review-2025/)
- [GitHub — browerscan/browerscan (separate open-source project for browserscan.ORG; not browserscan.net's code)](https://github.com/browerscan/browerscan)
