# BrowserScan.net

Free, no-login browser-fingerprint and bot-detection checker aimed at anti-detect-browser / multi-accounting crowd: tells you how detectable and internally consistent your (often spoofed) browser looks, both as categorical bot verdict and numeric "authenticity" trust score.

- **URL:** https://www.browserscan.net/bot-detection (bot verdict) · https://www.browserscan.net/ (full fingerprint + trust score) · https://www.browserscan.net/tls (TLS/HTTP2) · **Category:** privacy/anonymity & fingerprint tool — self-test checker oriented to anti-detect-browser ecosystem (AdsPower, Multilogin, GoLogin, Dolphin Anty, etc.), not open-source test page, not enterprise vendor's protection demo · **Requires registration:** No (scan runs on page load; optional Google "Sign in" / "Join now" exist but not needed).
- **Firsthand verdict for test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"Normal"** — i.e. *not* flagged as bot. Every framework check returned "Normal," CDP category didn't trip, even though this browser is genuinely CDP-driven. Notable miss: same browser correctly flagged as bot by deviceandbrowserinfo.com solely on `isAutomatedWithCDP`, Fingerprint.com reported Developer Tools = Yes. BrowserScan's CDP detection didn't catch it.

## What it is — common info

BrowserScan: free public fingerprint checker. Stated purpose: show user full fingerprint their browser exposes plus "browser fingerprint authenticity" score, so they can judge how identifiable/consistent they look. In practice, audience is anti-detect-browser and multi-accounting community: operators run BrowserScan to confirm spoofed profile looks like coherent real browser, doesn't leak real IP/timezone/automation traces. Companion blog (blog.browserscan.net) largely content hub reviewing/comparing anti-detect browsers — places site firmly in that ecosystem; firsthand recon also noted AdsPower affiliation/banners. Specific corporate owner not disclosed on site, couldn't be confirmed from primary sources — treat ownership as low-confidence.

Worth separating two things builder shouldn't conflate: **BrowserScan.net** (live service documented here, closed source) vs **browserscan.org**, separate open-source lookalike (GitHub `browerscan/browerscan`) — different Next.js/Cloudflare codebase. `.org` repo is *not* source of `.net` service; just implements similar "deduction-based 0–100 scoring" idea.

## Registration / access

None required for checker. Loading page runs scan automatically within few seconds. Optional account sign-in exists but gates nothing in free self-test. (Caveat on sourcing: "no registration/payment" claim corroborated firsthand and by one third-party review, not by BrowserScan's own docs — see Verification notes.)

## How it decides bot-or-not

Two distinct surfaces, two different output styles:

- **`/bot-detection` subpage** produces *categorical* verdict. Runs battery of named automation-framework checks + per-signal checks (Webdriver, User-Agent, CDP, Navigator), reports each "Normal" or flagged. Top-line result: category label like **Normal** vs bot type. No percentage on this page.
- **Home page** produces *numeric* **Trust Score (0–100%)** — "fingerprint authenticity" figure over full fingerprint (canvas, WebGL, audio, fonts, hardware, WebRTC, timezone/geo, TLS, etc.). Deduction/consistency model: start high, subtract for each anomaly/leak/spoofing tell (timezone vs IP geo mismatch, WebRTC real-IP leak, UA vs platform mismatch, automation traces, TLS-vs-UA mismatch). Flagged items render red; higher score = more coherent/"human-looking."

Semantically score answers "does this look like coherent, non-automated, real browser that blends in," i.e. authenticity/consistency rather than probabilistic bot likelihood. Site itself frames checks as same kind of detection Cloudflare Turnstile and Google reCAPTCHA perform, distinguishes "good bots" (search-engine crawlers) from "malicious bots" (Selenium/Puppeteer/Playwright).

## Detection approaches

- **Browser fingerprinting** — canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext, fonts, media devices, ClientRects, screen, hardware and navigator attributes, all collected client-side.
- **Headless/automation detection** — `navigator.webdriver`, Chrome DevTools Protocol (CDP) usage, named framework battery: WebDriver, WebDriver Advance, Selenium, NightmareJS, PhantomJS, Awesomium, CEF, CefSharp, Coaches, FMiner, Born, Phantomas, Rhino, WebdriverIO, Headless Chrome (all observed firsthand, all "Normal" for test browser).
- **Deception / spoofing-anomaly detection** — "Native Navigator" check dumps full navigator (incl. `userAgentData`), tests each method's `Function.prototype.toString()` output for `"[native code]"` to catch monkey-patched/overridden properties injected by anti-detect tooling.
- **Consistency cross-checks** — browser timezone vs IP geolocation, User-Agent vs actual platform, WebRTC-exposed IP vs proxy egress IP, and (per research) TLS/JA3 vs browser UA claims.
- **Network / TLS / HTTP2 fingerprinting** — server-side JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions, plus Akamai-format HTTP/2 fingerprint (SETTINGS frame, WINDOW_UPDATE, stream priority, pseudo-header ordering). Lives on `/tls`.
- **IP / proxy / geolocation reputation** — IP, ISP, proxy detection, geolocation, DNS leak, IPv6 leak.
- **Port scanning** — probes ports like 22 (SSH) and 3389 (RDP) to reveal server/VPS/remote-desktop environments (per research).
- **Rule/deduction-based scoring**, not documented ML classifier. Behavioral timing (typing/mouse) described in docs as technique but not clearly part of automated one-page scan.

## Areas / signals scanned

**Client-side (JS):**
- `navigator` properties + "deceptive"/modified navigator props; `navigator.webdriver`; `userAgentData`.
- CDP traces; Selenium/WebDriver artifact keys; PhantomJS/NightmareJS/CEF/CefSharp/Awesomium markers.
- Canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext fingerprint.
- Installed fonts, media devices, ClientRects.
- Screen resolution, color depth, touch support; GPU, `hardwareConcurrency`, `deviceMemory`.
- Languages / Intl; plugins; incognito-mode detection.
- WebRTC IP leak (real IP behind VPN/proxy).
- Cookies enabled, Do Not Track.
- Legacy Java/Flash/ActiveX plugin section — present but dead in modern browsers; low-value legacy signal, not active vector.

**Server-side (IP / TLS / TCP / HTTP headers):**
- IP, ISP, proxy detection, geolocation (country/region/city/postal/lat-long); DNS leak, IPv6 leak.
- Timezone / local time vs IP geolocation.
- TLS/SSL: JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions.
- HTTP/2: SETTINGS, WINDOW_UPDATE, stream priority, pseudo-header ordering, Akamai fingerprint (hash + text).
- Open-port scan (22 SSH, 3389 RDP).

**Behavioral:** described in docs (typing/mouse timing) but not clearly wired into automated scan; don't assume it runs on page load.

## How it scans (architecture)

Hybrid, meaningful client/server split.

- Bulk of fingerprint collected **client-side** by JavaScript bundle (`dist/*.js`). Also spins up **`blob:` Web Worker** to recompute fingerprint values in second JS context — standard cross-context trick to expose spoofing that only patches main window.
- **Firsthand network observation:** `/bot-detection` subpage did **not** POST results anywhere — categorical verdict computed/rendered in-browser. Home-page trust-score flow **does** POST collected fingerprint to **`api.browserscan.net`**. So two surfaces differ operationally: bot verdict client-only in what we observed, trust score involves backend round-trip.
- **TLS/SSL and HTTP/2 fingerprints inherently server-side** — derived from raw ClientHello and HTTP/2 setup frames of incoming connection, which client JS can't produce. IP/geo/proxy/port-scan resolution likewise server-side. Lets backend independently fingerprint actual connection, compare to what client JS claimed (e.g. Chrome UA whose JA3 doesn't look like Chrome). Exact request wiring correlating the two not published — correlation step inferred, not documented.

Net: decision surface split — categorical bot checks resolve client-side; trust score and all network-layer analysis depend on backend.

## Scoring / output

- **`/bot-detection`:** discrete per-category results (Normal vs flagged) across Webdriver, User-Agent, CDP, Navigator, plus framework battery — categorical bot verdict, no percentage.
- **Home page:** single **Trust Score percentage (0–100%)**, deduction-based. 100% = no issues detected; problem items shown red. Independent guidance cites ~90% as rough "looks unique/inconsistent" threshold. Closest thing BrowserScan offers to unified number — lives on home page, **not** bot-detection page.

## Notable techniques

- `Function.prototype.toString()` `[native code]` probing across navigator methods to detect overridden/patched properties — detects *spoofing itself*, not just spoofed value.
- `blob:` Web Worker cross-context recomputation to catch masks covering only main window.
- Named framework battery (15+ automation tools) reported individually rather than one opaque score.
- Server-observed JA3/JA4 + Akamai HTTP/2 fingerprint used to catch handshake-vs-claimed-browser mismatches.
- Port scan (22/3389) to expose server/VPS/RDP setups betraying non-consumer environment.
- Consistency triangulation: timezone vs IP geo, UA vs platform, WebRTC IP vs egress IP.

## What we observed firsthand

- Verdict: **"Normal"** (not bot). All framework checks Normal; CDP and Dev Tool categories present but not tripped, despite genuinely CDP-driven Electron browser. BrowserScan under-detected relative to peers — concrete data point its CDP/automation detection weaker than deviceandbrowserinfo.com's (flagged identical browser on CDP alone).
- Native Navigator check dumped full navigator incl. `userAgentData`, applied `[native code]` toString test.
- Architecture confirmed by traffic: client-side `dist/*.js` bundle + `blob:` Web Worker. **`/bot-detection` subpage issued no results POST.** Home-page trust-score flow POSTed fingerprint to **`api.browserscan.net`**.

## Verification notes

Adversarial review confirmed research well-supported, corrections folded in above:

- **CapMonster review not "independent," only one exists.** "Multiple independent reviews confirm no registration/payment" phrasing overstated: exactly one third-party review located (capmonster.cloud), from CAPTCHA-solving vendor in same anti-detect ecosystem — promotional, same-ecosystem, not neutral audit. Factual sub-claims (50+ data points, canvas `toDataURL`, no login) check out; neutrality doesn't. Report treats "no registration" as corroborated by firsthand observation, not by that review.
- **Citation-to-claim looseness on "no registration":** BrowserScan how-to-use doc cited for it doesn't actually state registration unnecessary; only describes visiting and waiting. Claim almost certainly true (scan runs on page load) but not documented at cited source.
- **Don't attach trust percentage to bot-detection page.** `/bot-detection` page shows discrete Webdriver/User-Agent/CDP/Navigator pass-fail results; 0–100% authenticity score lives on home page. Kept crisp above.
- **`browserscan.net` ≠ `browserscan.org`.** GitHub `browerscan/browerscan` repo separate open-source lookalike for `.org` domain, not `.net` service's source. Don't collapse them.
- **Legacy plugin detection (Flash/ActiveX/Java) anachronistic** — present as dead legacy section, flagged low-value rather than active detection vector.
- **Ownership unconfirmed** (low confidence), **client↔server correlation mechanism inferred**, not documented verbatim.

Gaps anti-bot engineer should note (things stronger builder would add, several not clearly covered by BrowserScan):

- **UA Client Hints triangulation** — cross-check legacy UA string, JS `navigator.userAgentData`, `Sec-CH-UA` / `Sec-CH-UA-Platform` / `Sec-CH-UA-Mobile` HTTP headers. Anti-detect browsers frequently desync these three; primary 2024+ surface.
- **Canvas/audio/WebGL noise-injection detection** — arguably core reason BrowserScan's audience uses it, yet not surfaced as such. Anti-detect browsers randomize canvas/audio output per session; strong checker detects non-determinism (or statistically improbable hashes) across repeated reads, not just one `toDataURL`.
- **Property-level headless tells** — `Notification.permission === 'denied'` while `permissions.query` state is `'default'`; empty `navigator.plugins`/`mimeTypes`; missing `window.chrome` runtime; empty `navigator.languages`. BrowserScan names webdriver/CDP but not these classic signatures.
- **TLS ordering + GREASE** — cipher-suite/extension *order* and GREASE pattern must match exact Chrome/Firefox build UA claims; reordered ClientHello from Go/Python/`curl-impersonate` is giveaway. State ordering dimension explicitly, not "mismatch" abstractly.
- **Passive TCP/IP (p0f-style) OS fingerprinting** — comparing OS inferred from TCP options/window size/TTL against UA-claimed OS. Almost certainly **out of scope** for BrowserScan's JS+TLS design; note gap deliberately (incolumitas covers it; BrowserScan doesn't).
- **Cross-tab / storage / TLS-session-resumption re-identification** — no evidence BrowserScan probes `localStorage`/IndexedDB persistence, evercookie stability, or TLS session-ticket resumption to link "fresh" profile to prior visit.

## Open source / reusable

**None for BrowserScan.net itself** — live service closed source. GitHub `browerscan/browerscan` repo is *separate* open-source lookalike backing browserscan.org (Next.js/Cloudflare, deduction-based 0–100 scoring); usable as reference for scoring *idea*, but not BrowserScan.net's code, doesn't include server-side TLS/HTTP2/IP machinery.

## Sources

- [BrowserScan — home (fingerprint + trust score)](https://www.browserscan.net/)
- [BrowserScan — bot detection page (Webdriver / User-Agent / CDP / Navigator)](https://www.browserscan.net/bot-detection)
- [BrowserScan — HTTP2/SSL/TLS fingerprint page (JA3, JA4, Akamai)](https://www.browserscan.net/tls)
- [BrowserScan docs — Bot Detection (webdriver, _selenium markers, behavioral timing)](https://blog.browserscan.net/docs/bot-detection)
- [BrowserScan docs — How to Use BrowserScan](https://blog.browserscan.net/docs/how-to-use-browserscan)
- [CapMonster — BrowserScan Review 2025 (third-party, promotional / same-ecosystem)](https://capmonster.cloud/en/blog/browserscan-review-2025/)
- [GitHub — browerscan/browerscan (separate open-source project for browserscan.ORG; not browserscan.net's code)](https://github.com/browerscan/browerscan)
