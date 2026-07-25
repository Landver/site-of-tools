# deviceandbrowserinfo.com

Free transparent bot-detection playground by anti-bot researcher Antoine Vastel: JS FP collector reporting explicit `isBot` bool + exact per-signal bools behind it. Names every signal -> read detection logic off page.

- **URL:** https://deviceandbrowserinfo.com/are_you_a_bot · **Category:** open-source-adjacent educational test page (not vendor demo, not privacy tool) · **Registration:** No — runs on load, no account.
- **Firsthand verdict, test browser** (in-app browser reports `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"❌ You are a bot!" — `isBot: true`**. Flagged by exactly 1 signal: **`isAutomatedWithCDP: true`** (Chrome DevTools Protocol automation — how Electron browser driven). All others false. CDP = single most effective tell vs our browser, mirrors Fingerprint.com "Developer Tools = Yes".

## What it is — common info

Built & run by **Antoine Vastel**, browser-FP/bot-detection researcher (PhD browser fingerprinting; ~5yr VP Research @ DataDome; Head of Research @ Castle since late 2024). Authored widely-used MIT libs **fp-collect** & **fp-scanner**. Launched site ~March 2024 as personal side project: interactive demos of fraud/bot-detection signals — browser fingerprinting, HTTP headers, proxy/malicious-IP data, disposable emails & phones, + "learning zone" write-ups.

Educational & free. Also sells bulk **data/API products** (40M+ proxy-IP DB w/ datacenter/residential class, disposable-email & temp-phone datasets, UA/header lists), but checkers open to anyone. Audience: anti-bot engineers, bot devs testing evasion, researchers — not enterprise buyers.

## Registration / access

None. `are_you_a_bot` FP test, separate behavioral test (`are_you_a_bot_interactions`), `info_device` FP visualizer all run on load. Bulk data APIs may carry own access/rate terms; interactive checkers don't.

## How it decides bot-or-not

FP test runs fixed battery of **20 named signal checks** in browser, each returning bool. JS collects automation & consistency signals — incl. probes re-run in **web workers** & **iframes** — payload POSTed to backend returning `{ isBot, details }` (`details` = per-signal bool map). `isBot: true` if aggregation crosses undisclosed threshold.

Page states verbatim: **this test does not use IP reputation or user behavior** — handled elsewhere (IP on `info_device`; behavior in separate interactions test). So `are_you_a_bot` verdict = **pure client-side-FP decision**. No ML score; transparent signal-by-signal reporting.

## Detection approaches

- **Browser/device fingerprinting** — JS-collected navigator, screen, WebGL, hardware attrs.
- **Headless/automation-framework detection** — framework-specific global markers: Puppeteer/Headless Chrome, Selenium/ChromeDriver, Playwright, PhantomJS, Nightmare.js, Sequentum.
- **CDP detection** — main context & inside web workers (caught our browser).
- **Cross-context consistency** — main JS vs web worker vs iframe; Client-Hints vs `navigator`.
- **Server-side HTTP-header analysis** — surfaced on `info_device`; only indirectly reflected in bot test (below).
- **Behavioral detection** — *separate* test (`are_you_a_bot_interactions`): mouse movement, typing speed, form submission, + CDP mouse leak. Not in FP verdict.
- **TLS/TCP fingerprinting** — **planned/future**, not in current verdict.
- **Not used by this test:** IP reputation, behavior, & (per verdict correction) canvas — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the 20 named bot-test signals

Exact signals page reports (confirmed firsthand & adversarial review):

1. `hasBotUserAgent` — bot/crawler/HeadlessChrome substring in UA (header-adjacent).
2. `hasWebdriverTrue` — `navigator.webdriver === true` main context.
3. `hasWebdriverInFrameTrue` — same, inside iframe (catches incomplete evasion).
4. `isPlaywright` — Playwright globals (`window.__pwInitScripts` / `__playwright__binding__`).
5. `hasInconsistentChromeObject` — anomalies in `window.chrome`.
6. `isPhantom` — PhantomJS markers (`callPhantom` / `_phantom`).
7. `isNightmare` — Nightmare.js marker (`__nightmare`).
8. `isSequentum` — `window.external` contains "Sequentum".
9. `isSeleniumChromeDefault` — Selenium/ChromeDriver signature (`document.$cdc_...`).
10. `isHeadlessChrome` — Headless Chrome indicators.
11. `isWebGLInconsistent` — `UNMASKED_VENDOR/RENDERER` inconsistency.
12. `isAutomatedWithCDP` — CDP automation **(only true signal for our browser)**.
13. `isAutomatedWithCDPInWebWorker` — CDP inside web worker.
14. `hasInconsistentClientHints` — `userAgentData` vs UA mismatch (header-adjacent).
15. `hasInconsistentGPUFeatures` — GPU feature inconsistency.
16. `isIframeOverridden` — iframe `contentWindow`/behavior overrides.
17. `hasInconsistentWorkerValues` — worker vs main-thread mismatch of `userAgent`/`languages`/`hardwareConcurrency`/`platform`.
18. `hasHighHardwareConcurrency` — implausibly high CPU core count.
19. `hasHeadlessChromeDefaultScreenResolution` — headless default res (e.g. 800x600, example only — page doesn't print literal).
20. `hasSuspiciousWeakSignals` — "weak signal combination" logic: cluster of individually-weak anomalies treated together as strong bot indicator.

### Server-side (IP / TLS / TCP / HTTP headers)

`info_device` visualizer separately shows server-observed data: **IP, ISP/ASN, country, ordered HTTP headers**. Header presence/ordering/consistency w/ claimed browser analyzed there, but **no separately-named server-side header signal among the 20** bot-test checks (only `hasBotUserAgent` & `hasInconsistentClientHints` header-adjacent). TLS/TCP FP = future work.

### Behavioral (separate test only)

`are_you_a_bot_interactions`: mouse-movement trajectories, typing speed, form submission, CDP mouse leak. Not folded into FP verdict.

## How it scans (architecture)

Confirmed via firsthand network capture:

1. Client JS loads `device_info.min.js` + `cstlxp.js`.
2. Scripts spawn **`blob:` web workers** recomputing signals in worker context (enabling `isAutomatedWithCDPInWebWorker` & `hasInconsistentWorkerValues`).
3. FP **POSTed to `/fingerprint_bot_test`**; backend returns **`{ isBot, details }`** (per-signal bool map).

Collection client-side, **verdict server-returned** (browser POSTs raw signals; server aggregates, returns decision). Keeps weighting/threshold off client. Server-side contribution beyond that = HTTP-header analysis; IP reputation & behavior explicitly out of scope for this endpoint.

## Scoring / output

Output = **bool `isBot`** + per-signal bool map — no 0–100 score, no ML probability. `isBot` true when aggregation crosses undisclosed threshold; single strong signal (e.g. `isAutomatedWithCDP`) enough. `hasSuspiciousWeakSignals` lets several minor anomalies combine into positive w/o any single strong signal. Named signals + reproducible booleans distinguish this from commercial scorers returning opaque number.

## Notable techniques

- **CDP detection via crafted `Error.stack` getter.** `Error` object given getter on `.stack`; serializing w/ `console.log` triggers getter under CDP, exposing automation. Author caveat: also flags real humans w/ DevTools open. (In cited "detecting headless Chrome / Puppeteer, 2024" article.)
- **CDP detection inside web workers** — evasions patching main thread miss worker context.
- **Cross-context consistency** — worker/iframe values vs main thread catch spoofing.
- **`webdriver` checked main frame & iframe** — catches partial evasion.
- **Client-Hints vs `navigator` mismatch** — spoofed UA not matching `userAgentData`.
- **Framework-specific global fingerprints** — Playwright, PhantomJS, Nightmare.js, Sequentum, Selenium.
- **Weak-signal combination logic** (`hasSuspiciousWeakSignals`) — clusters of minor anomalies.
- **Known limitation for builder:** cited article notes CDP detection bypassable by frameworks (e.g. nodriver-style) avoiding `Runtime.enable`. Treat CDP detection as high-signal but evadable, not definitive.

## What we observed firsthand

- Verdict: **"❌ You are a bot!" (`isBot: true`)**.
- Only `isAutomatedWithCDP: true`; all 19 others false. WebDriver absent, `window.chrome` present & consistent, no framework globals, WebGL = Apple M5 Metal (not inconsistent), hardware concurrency not flagged.
- Network: `device_info.min.js` + `cstlxp.js` loaded; `blob:` web workers spawned; FP **POST to `/fingerprint_bot_test`** returning `{ isBot, details }`.
- Test did **not** consult IP reputation — our datacenter/VPN egress (flagged by incolumitas & Fingerprint) played no role. Pure FP verdict, CDP alone condemned us.

## Verification notes

Adversarial review corrected several claims; folded in above:

- **Signal count exactly 20, all client-side JS** — not "~20–21", not "client + server-side header signals." No separately-named server-side HTTP-header signal among 20; only `hasBotUserAgent` & `hasInconsistentClientHints` header-adjacent.
- **Canvas NOT a bot-test signal.** Research had listed "canvas challenge" — flagged **unsupported**. "Canvas" = descriptive prose on `info_device` only; author's fp-collect README states it deliberately avoids canvas fingerprints. Removed from signals.
- **Timezone NOT a bot-test signal** — visualizer-only prose, not one of 20. Removed.
- **`deviceMemory` plausibility unverified** — not among 20, not observed; dropped. (`hardwareConcurrency` via `hasHighHardwareConcurrency` is real.)
- **Proxy/TOR flag on `info_device` unconfirmed** — page rendered IP/ISP/country/ordered headers, no proxy/Tor flag observed. Proxy/Tor exists as separate dataset/API, not confirmed `info_device` display element.
- **Confirmed accurate:** Vastel's bio & roles; all 9 cited URLs resolve; "this test does not use IP reputation or user behavior" verbatim; TCP/TLS labeled future; behavioral test separate; CDP-via-`Error.stack`-getter technique; `hasSuspiciousWeakSignals` as weak-combination logic; fp-scanner README doesn't claim to power live site.

Gaps anti-bot engineer should note (service does **not** cover, though production system typically would): AudioContext fingerprinting; Permissions-API mismatch (`Notification.permission` vs `Permissions.query()`); `Function.prototype.toString` native-code integrity checks vs monkey-patched getters; empty `navigator.plugins`/`mimeTypes`; font enumeration; concrete `Google SwiftShader`/Mesa headless renderer tell; named network-layer standards (JA3/JA4 TLS, HTTP/2 frame/settings FP, header-ordering) — site only says "TLS/TCP is future" rather than naming these active.

## Open source / reusable

Live site code not published as single repo; fp-scanner doesn't claim to power it. But same author open-sources underlying techniques under MIT:

- **fp-scanner** (self-hosted fingerprinting + bot detection): https://github.com/antoinevastel/fpscanner
- **fp-collect** (fingerprint-collection module; deliberately excludes canvas/tracking data): https://github.com/antoinevastel/fp-collect

Builder can reuse directly; read learning-zone articles for reasoning behind each signal.

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
