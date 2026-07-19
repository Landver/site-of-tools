# deviceandbrowserinfo.com

Free, transparent bot-detection playground by anti-bot researcher Antoine Vastel: JS fingerprint collector reporting explicit `isBot` boolean plus exact per-signal booleans that produced it. Uniquely useful since it names every signal it checks, so you read its detection logic straight off page.

- **URL:** https://deviceandbrowserinfo.com/are_you_a_bot · **Category:** open-source-adjacent educational test page run by anti-bot researcher (not commercial vendor demo, not privacy tool) · **Requires registration:** No — checker runs on page load with no account.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"❌ You are a bot!" — `isBot: true`**. Flagged by exactly one signal: **`isAutomatedWithCDP: true`** (Chrome DevTools Protocol automation — how Electron browser is driven). Every other signal returned false. CDP detection was single most effective tell against our browser, mirroring Fingerprint.com's "Developer Tools = Yes".

## What it is — common info

Built and run by **Antoine Vastel**, browser-fingerprinting/bot-detection researcher (PhD on browser fingerprinting; ~5 years as VP of Research at DataDome; Head of Research at Castle since late 2024). Authored widely used MIT-licensed libraries **fp-collect** and **fp-scanner**. Launched deviceandbrowserinfo.com around March 2024 as personal side project to centralize practical, interactive demonstrations of signals used in fraud/bot detection: browser fingerprinting, HTTP headers, proxy/malicious-IP data, disposable emails and phone numbers, plus "learning zone" of technical write-ups.

Site is educational and free. Also exposes some bulk **data/API products** (40M+ proxy-IP database with datacenter/residential classification, disposable-email and temp-phone datasets, user-agent/header lists), but checker pages themselves open to anyone. Audience: anti-bot engineers, bot developers testing evasion, researchers — not enterprise buyers.

## Registration / access

None. `are_you_a_bot` fingerprint test, separate behavioral test (`are_you_a_bot_interactions`), `info_device` fingerprint visualizer all run immediately on load. Bulk data APIs may carry own access/rate terms, but interactive checkers don't.

## How it decides bot-or-not

Fingerprint test runs fixed battery of **20 named signal checks** in browser, each returning boolean. JavaScript collects automation and consistency signals — incl. probes re-run inside **web workers** and **iframes** — payload POSTed to backend returning `{ isBot, details }`, where `details` is per-signal boolean map. Verdict `isBot: true` if aggregation of those signals crosses (undisclosed) threshold.

Crucially, page states verbatim that **this test does not use IP reputation or user behavior** — those handled elsewhere (IP data on `info_device`; behavior in separate interactions test). So `are_you_a_bot` verdict is **pure client-side-fingerprint decision**. No ML probability score exposed; presents as transparent, reproducible signal-by-signal reporting.

## Detection approaches

- **Browser/device fingerprinting** — JS-collected navigator, screen, WebGL, hardware attributes.
- **Headless / automation-framework detection** — framework-specific global markers for Puppeteer/Headless Chrome, Selenium/ChromeDriver, Playwright, PhantomJS, Nightmare.js, Sequentum.
- **Chrome DevTools Protocol (CDP) detection** — main context and inside web workers (signal that caught our browser).
- **Cross-context consistency checks** — main JS context vs web worker vs iframe; Client-Hints vs `navigator`.
- **Server-side HTTP-header analysis** — surfaced on `info_device`; only indirectly reflected in bot test (see below).
- **Behavioral detection** — *separate* test (`are_you_a_bot_interactions`): mouse movement, typing speed, form submission, plus CDP mouse leak. Not part of fingerprint verdict.
- **TLS/TCP fingerprinting** — referenced as **planned/"future"**, not wired into current verdict.
- **Not used by this test:** IP reputation, behavior, and (per verdict correction) canvas — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the 20 named bot-test signals

Exact signals page reports (confirmed firsthand and by adversarial review):

1. `hasBotUserAgent` — bot/crawler/HeadlessChrome substring in UA (header-adjacent).
2. `hasWebdriverTrue` — `navigator.webdriver === true` in main context.
3. `hasWebdriverInFrameTrue` — same, checked inside iframe (catches incomplete evasion).
4. `isPlaywright` — Playwright globals (`window.__pwInitScripts` / `__playwright__binding__`).
5. `hasInconsistentChromeObject` — anomalies in `window.chrome`.
6. `isPhantom` — PhantomJS markers (`callPhantom` / `_phantom`).
7. `isNightmare` — Nightmare.js marker (`__nightmare`).
8. `isSequentum` — `window.external` contains "Sequentum".
9. `isSeleniumChromeDefault` — Selenium/ChromeDriver signature (`document.$cdc_...`).
10. `isHeadlessChrome` — Headless Chrome mode indicators.
11. `isWebGLInconsistent` — `UNMASKED_VENDOR/RENDERER` inconsistency.
12. `isAutomatedWithCDP` — CDP automation detected **(only true signal for our browser)**.
13. `isAutomatedWithCDPInWebWorker` — CDP detected inside web worker.
14. `hasInconsistentClientHints` — `userAgentData` vs UA mismatch (header-adjacent).
15. `hasInconsistentGPUFeatures` — GPU feature inconsistency.
16. `isIframeOverridden` — iframe `contentWindow`/behavior overrides.
17. `hasInconsistentWorkerValues` — worker vs main-thread mismatch of `userAgent`/`languages`/`hardwareConcurrency`/`platform`.
18. `hasHighHardwareConcurrency` — implausibly high CPU core count.
19. `hasHeadlessChromeDefaultScreenResolution` — headless default screen resolution (e.g. 800x600, offered as example — page doesn't print literal value).
20. `hasSuspiciousWeakSignals` — "weak signal combination" logic: cluster of individually-weak anomalies treated together as strong bot indicator.

### Server-side (IP / TLS / TCP / HTTP headers)

`info_device` visualizer separately displays server-observed data: **IP, ISP/ASN, country, ordered HTTP headers**. Header presence/ordering/consistency with claimed browser analyzed there, but **no separately-named server-side header signal among the 20** bot-test checks (only `hasBotUserAgent` and `hasInconsistentClientHints` are header-adjacent). TLS/TCP fingerprinting is future work.

### Behavioral (separate test only)

`are_you_a_bot_interactions`: mouse-movement trajectories, typing speed, form submission, CDP mouse leak. Not folded into fingerprint verdict.

## How it scans (architecture)

Confirmed via firsthand network capture:

1. Client JS loads `device_info.min.js` and `cstlxp.js`.
2. Scripts spawn **`blob:` web workers** to recompute signals in worker context (enabling `isAutomatedWithCDPInWebWorker` and `hasInconsistentWorkerValues`).
3. Collected fingerprint **POSTed to `/fingerprint_bot_test`**; backend returns **`{ isBot, details }`** (per-signal boolean map).

So collection client-side, but **verdict returned by server** (browser POSTs raw signals; server applies aggregation, returns decision). Keeps exact weighting/threshold off client. Server-side contribution beyond that is HTTP-header analysis; IP reputation and behavior explicitly out of scope for this endpoint.

## Scoring / output

Output is **boolean `isBot`** plus per-signal boolean map — no 0–100 score, no ML probability. `isBot` true when signal aggregation crosses undisclosed threshold; single strong signal (like `isAutomatedWithCDP`) enough. `hasSuspiciousWeakSignals` lets several minor anomalies combine into positive even when no single strong signal fires. Transparency (named signals, reproducible booleans) distinguishes this from commercial scorers returning opaque number.

## Notable techniques

- **CDP detection via crafted `Error.stack` getter.** `Error` object given getter on `.stack`; serializing it with `console.log` triggers getter under CDP, exposing automation. Caveat, stated by author: also flags real humans with DevTools open. (Documented in cited "detecting headless Chrome / Puppeteer, 2024" article.)
- **CDP detection inside web workers** — evasions patching main thread miss worker context.
- **Cross-context consistency** — worker/iframe values compared against main thread to catch spoofing.
- **`webdriver` checked in main frame and inside iframe** — catches partial evasion.
- **Client-Hints vs `navigator` mismatch** — spoofed UA that doesn't match `userAgentData`.
- **Framework-specific global fingerprints** for Playwright, PhantomJS, Nightmare.js, Sequentum, Selenium.
- **Weak-signal combination logic** (`hasSuspiciousWeakSignals`) — clusters of minor anomalies.
- **Known limitation for builder:** cited article itself notes CDP detection can be bypassed by automation frameworks (e.g. nodriver-style) avoiding `Runtime.enable` command. Treat CDP detection as high-signal but evadable, not definitive.

## What we observed firsthand

- Verdict: **"❌ You are a bot!" (`isBot: true`)**.
- Only `isAutomatedWithCDP: true`; all 19 other signals false. WebDriver absent, `window.chrome` present and consistent, no framework globals, WebGL reported Apple M5 Metal (not inconsistent), hardware concurrency not flagged.
- Network: `device_info.min.js` + `cstlxp.js` loaded; `blob:` web workers spawned; fingerprint **POST to `/fingerprint_bot_test`** returning `{ isBot, details }`.
- Test did **not** consult IP reputation — our datacenter/VPN egress (flagged by incolumitas and Fingerprint) played no role here. Pure fingerprint verdict, CDP alone condemned us.

## Verification notes

Adversarial review corrected several research claims; folded in above:

- **Signal count is exactly 20, all client-side JS signals** — not "~20–21" and not "client + server-side header signals." No separately-named server-side HTTP-header signal exists among the 20; only `hasBotUserAgent` and `hasInconsistentClientHints` header-adjacent.
- **Canvas is NOT a bot-test signal.** Research had listed "canvas challenge" as bot-detection technique — flagged as **unsupported**. "Canvas" appears only as descriptive prose on `info_device` visualizer, author's own fp-collect README states it deliberately avoids canvas fingerprints. Removed from this service's bot-detection signals.
- **Timezone is NOT a bot-test signal** — visualizer-only prose, not one of 20. Removed.
- **`deviceMemory` plausibility unverified** — not among 20 signals, not observed; dropped. (`hardwareConcurrency` via `hasHighHardwareConcurrency` is real.)
- **Proxy/TOR flag on `info_device` unconfirmed** — page rendered IP/ISP/country/ordered headers, but no proxy/Tor flag observed. Proxy/Tor exists as separate dataset/API, not confirmed `info_device` display element.
- **Confirmed accurate:** Vastel's bio and roles; all 9 cited URLs resolve; "this test does not use IP reputation or user behavior" verbatim; TCP/TLS labeled future; behavioral test separate; CDP-via-`Error.stack`-getter technique; `hasSuspiciousWeakSignals` as weak-combination logic; fp-scanner's README doesn't claim to power live site.

Gaps anti-bot engineer should note (service does **not** cover them, though production system typically would): AudioContext fingerprinting; Permissions-API mismatch tell (`Notification.permission` vs `Permissions.query()`); `Function.prototype.toString` native-code integrity checks against monkey-patched getters; empty `navigator.plugins`/`mimeTypes`; font enumeration; concrete `Google SwiftShader`/Mesa headless renderer tell; named network-layer standards (JA3/JA4 TLS, HTTP/2 frame/settings fingerprints, header-ordering) — site only says "TLS/TCP is future" rather than naming these as active signals.

## Open source / reusable

Exact live site code not published as single repo, fp-scanner doesn't claim to power it. But same author open-sources underlying techniques under MIT:

- **fp-scanner** (self-hosted fingerprinting + bot detection): https://github.com/antoinevastel/fpscanner
- **fp-collect** (fingerprint-collection module; deliberately excludes canvas/tracking data): https://github.com/antoinevastel/fp-collect

Builder can reuse these directly, read learning-zone articles for reasoning behind each signal.

## Sources

- [deviceandbrowserinfo.com — home](https://deviceandbrowserinfo.com/)
- [Bot detection test (are_you_a_bot)](https://deviceandbrowserinfo.com/are_you_a_bot)
- [Fingerprint visualizer (info_device)](https://deviceandbrowserinfo.com/info_device)
- [How to detect (modified, headless) Chrome instrumented with Puppeteer (2024)](https://deviceandbrowserinfo.com/learning_zone/articles/detecting-headless-chrome-puppeteer-2024)
- [How to get started in bot detection and bot development?](https://deviceandbrowserinfo.com/learning_zone/articles/getting-started-bot-detection)
- [Introducing DeviceAndBrowserInfo.com (Antoine Vastel blog)](https://antoinevastel.com/browser%20fingerprinting/2024/03/21/deviceandbrowserinfo-new-site.html)
- [Antoine Vastel — about / bots](https://antoinevastel.com/bots)
- [GitHub — antoinevastel/fpscanner](https://github.com/antoinevastel/fpscanner)
- [GitHub — antoinevastel/fp-collect](https://github.com/antoinevastel/fp-collect)
