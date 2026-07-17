# deviceandbrowserinfo.com

A free, transparent bot-detection playground by anti-bot researcher Antoine Vastel: a JS fingerprint collector that reports an explicit `isBot` boolean plus the exact per-signal booleans that produced it. Uniquely useful because it names every signal it checks, so you can read its detection logic straight off the page.

- **URL:** https://deviceandbrowserinfo.com/are_you_a_bot · **Category:** open-source-adjacent educational test page run by an anti-bot researcher (not a commercial vendor demo, not a privacy tool) · **Requires registration:** No — the checker runs on page load with no account.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"❌ You are a bot!" — `isBot: true`**. It was flagged by exactly one signal: **`isAutomatedWithCDP: true`** (Chrome DevTools Protocol automation — how the Electron browser is driven). Every other signal returned false. CDP detection was the single most effective tell against our browser, mirroring Fingerprint.com's "Developer Tools = Yes".

## What it is — common info

Built and run by **Antoine Vastel**, a browser-fingerprinting/bot-detection researcher (PhD on browser fingerprinting; ~5 years as VP of Research at DataDome; Head of Research at Castle since late 2024). He authored the widely used MIT-licensed libraries **fp-collect** and **fp-scanner**. He launched deviceandbrowserinfo.com around March 2024 as a personal side project to centralize practical, interactive demonstrations of the signals used in fraud/bot detection: browser fingerprinting, HTTP headers, proxy/malicious-IP data, disposable emails and phone numbers, plus a "learning zone" of technical write-ups.

The site is educational and free. It also exposes some bulk **data/API products** (a 40M+ proxy-IP database with datacenter/residential classification, disposable-email and temp-phone datasets, user-agent/header lists), but the checker pages themselves are open to anyone. Audience: anti-bot engineers, bot developers testing evasion, and researchers — not enterprise buyers.

## Registration / access

None. The `are_you_a_bot` fingerprint test, the separate behavioral test (`are_you_a_bot_interactions`), and the `info_device` fingerprint visualizer all run immediately on load. The bulk data APIs may carry their own access/rate terms, but the interactive checkers do not.

## How it decides bot-or-not

The fingerprint test runs a fixed battery of **20 named signal checks** in the browser, each returning a boolean. JavaScript collects automation and consistency signals — including probes re-run inside **web workers** and **iframes** — and the payload is POSTed to a backend that returns `{ isBot, details }`, where `details` is the per-signal boolean map. The verdict is `isBot: true` if the aggregation of those signals crosses the (undisclosed) threshold.

Crucially, the page states verbatim that **this test does not use IP reputation or user behavior** — those are handled elsewhere (IP data on `info_device`; behavior in the separate interactions test). So the `are_you_a_bot` verdict is a **pure client-side-fingerprint decision**. There is no ML probability score exposed; it presents as transparent, reproducible signal-by-signal reporting.

## Detection approaches

- **Browser/device fingerprinting** — JS-collected navigator, screen, WebGL, hardware attributes.
- **Headless / automation-framework detection** — framework-specific global markers for Puppeteer/Headless Chrome, Selenium/ChromeDriver, Playwright, PhantomJS, Nightmare.js, Sequentum.
- **Chrome DevTools Protocol (CDP) detection** — in the main context and inside web workers (the signal that caught our browser).
- **Cross-context consistency checks** — main JS context vs web worker vs iframe; Client-Hints vs `navigator`.
- **Server-side HTTP-header analysis** — surfaced on `info_device`; only indirectly reflected in the bot test (see below).
- **Behavioral detection** — a *separate* test (`are_you_a_bot_interactions`): mouse movement, typing speed, form submission, plus a CDP mouse leak. Not part of the fingerprint verdict.
- **TLS/TCP fingerprinting** — referenced as **planned/"future"**, not wired into the current verdict.
- **Not used by this test:** IP reputation, behavior, and (per the verdict correction) canvas — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the 20 named bot-test signals

These are the exact signals the page reports (confirmed firsthand and by the adversarial review):

1. `hasBotUserAgent` — bot/crawler/HeadlessChrome substring in the UA (header-adjacent).
2. `hasWebdriverTrue` — `navigator.webdriver === true` in the main context.
3. `hasWebdriverInFrameTrue` — same, checked inside an iframe (catches incomplete evasion).
4. `isPlaywright` — Playwright globals (`window.__pwInitScripts` / `__playwright__binding__`).
5. `hasInconsistentChromeObject` — anomalies in `window.chrome`.
6. `isPhantom` — PhantomJS markers (`callPhantom` / `_phantom`).
7. `isNightmare` — Nightmare.js marker (`__nightmare`).
8. `isSequentum` — `window.external` contains "Sequentum".
9. `isSeleniumChromeDefault` — Selenium/ChromeDriver signature (`document.$cdc_...`).
10. `isHeadlessChrome` — Headless Chrome mode indicators.
11. `isWebGLInconsistent` — `UNMASKED_VENDOR/RENDERER` inconsistency.
12. `isAutomatedWithCDP` — CDP automation detected **(the only true signal for our browser)**.
13. `isAutomatedWithCDPInWebWorker` — CDP detected inside a web worker.
14. `hasInconsistentClientHints` — `userAgentData` vs UA mismatch (header-adjacent).
15. `hasInconsistentGPUFeatures` — GPU feature inconsistency.
16. `isIframeOverridden` — iframe `contentWindow`/behavior overrides.
17. `hasInconsistentWorkerValues` — worker vs main-thread mismatch of `userAgent`/`languages`/`hardwareConcurrency`/`platform`.
18. `hasHighHardwareConcurrency` — implausibly high CPU core count.
19. `hasHeadlessChromeDefaultScreenResolution` — headless default screen resolution (e.g. 800x600, offered as an example — the page does not print the literal value).
20. `hasSuspiciousWeakSignals` — "weak signal combination" logic: a cluster of individually-weak anomalies treated together as a strong bot indicator.

### Server-side (IP / TLS / TCP / HTTP headers)

The `info_device` visualizer separately displays server-observed data: **IP, ISP/ASN, country, and ordered HTTP headers**. Header presence/ordering/consistency with the claimed browser is analyzed there, but there is **no separately-named server-side header signal among the 20** bot-test checks (only `hasBotUserAgent` and `hasInconsistentClientHints` are header-adjacent). TLS/TCP fingerprinting is future work.

### Behavioral (separate test only)

`are_you_a_bot_interactions`: mouse-movement trajectories, typing speed, form submission, and a CDP mouse leak. Not folded into the fingerprint verdict.

## How it scans (architecture)

Confirmed via firsthand network capture:

1. Client JS loads `device_info.min.js` and `cstlxp.js`.
2. The scripts spawn **`blob:` web workers** to recompute signals in worker context (enabling `isAutomatedWithCDPInWebWorker` and `hasInconsistentWorkerValues`).
3. The collected fingerprint is **POSTed to `/fingerprint_bot_test`**; the backend returns **`{ isBot, details }`** (the per-signal boolean map).

So the collection is client-side, but the **verdict is returned by the server** (the browser POSTs raw signals; the server applies the aggregation and returns the decision). This keeps the exact weighting/threshold off the client. Server-side contribution beyond that is HTTP-header analysis; IP reputation and behavior are explicitly out of scope for this endpoint.

## Scoring / output

Output is a **boolean `isBot`** plus a per-signal boolean map — no 0–100 score, no ML probability. `isBot` is true when the signal aggregation crosses an undisclosed threshold; a single strong signal (like `isAutomatedWithCDP`) is enough. `hasSuspiciousWeakSignals` lets several minor anomalies combine into a positive even when no single strong signal fires. The transparency (named signals, reproducible booleans) is what distinguishes this from commercial scorers that return an opaque number.

## Notable techniques

- **CDP detection via a crafted `Error.stack` getter.** An `Error` object is given a getter on `.stack`; serializing it with `console.log` triggers the getter under CDP, exposing automation. Caveat, stated by the author: it also flags real humans with DevTools open. (Documented in the cited "detecting headless Chrome / Puppeteer, 2024" article.)
- **CDP detection inside web workers** — evasions that patch the main thread miss the worker context.
- **Cross-context consistency** — worker/iframe values compared against the main thread to catch spoofing.
- **`webdriver` checked in main frame and inside an iframe** — catches partial evasion.
- **Client-Hints vs `navigator` mismatch** — spoofed UA that doesn't match `userAgentData`.
- **Framework-specific global fingerprints** for Playwright, PhantomJS, Nightmare.js, Sequentum, Selenium.
- **Weak-signal combination logic** (`hasSuspiciousWeakSignals`) — clusters of minor anomalies.
- **Known limitation for a builder:** the cited article itself notes CDP detection can be bypassed by automation frameworks (e.g. nodriver-style) that avoid the `Runtime.enable` command. Treat CDP detection as high-signal but evadable, not definitive.

## What we observed firsthand

- Verdict: **"❌ You are a bot!" (`isBot: true`)**.
- Only `isAutomatedWithCDP: true`; all 19 other signals false. WebDriver absent, `window.chrome` present and consistent, no framework globals, WebGL reported Apple M5 Metal (not inconsistent), hardware concurrency not flagged.
- Network: `device_info.min.js` + `cstlxp.js` loaded; `blob:` web workers spawned; fingerprint **POST to `/fingerprint_bot_test`** returning `{ isBot, details }`.
- The test did **not** consult IP reputation — our datacenter/VPN egress (flagged by incolumitas and Fingerprint) played no role here. This is a pure fingerprint verdict, and CDP alone condemned us.

## Verification notes

The adversarial review corrected several research claims; folded in above:

- **Signal count is exactly 20, all client-side JS signals** — not "~20–21" and not "client + server-side header signals." No separately-named server-side HTTP-header signal exists among the 20; only `hasBotUserAgent` and `hasInconsistentClientHints` are header-adjacent.
- **Canvas is NOT a bot-test signal.** Research had listed a "canvas challenge" as a bot-detection technique — this was flagged as **unsupported**. "Canvas" appears only as descriptive prose on the `info_device` visualizer, and the author's own fp-collect README states it deliberately avoids canvas fingerprints. Removed from this service's bot-detection signals.
- **Timezone is NOT a bot-test signal** — visualizer-only prose, not one of the 20. Removed.
- **`deviceMemory` plausibility is unverified** — not among the 20 signals and not observed; dropped. (`hardwareConcurrency` via `hasHighHardwareConcurrency` is real.)
- **Proxy/TOR flag on `info_device` is unconfirmed** — the page rendered IP/ISP/country/ordered headers, but no proxy/Tor flag was observed. Proxy/Tor exists as a separate dataset/API, not a confirmed `info_device` display element.
- **Confirmed accurate:** Vastel's bio and roles; all 9 cited URLs resolve; "this test does not use IP reputation or user behavior" is verbatim; TCP/TLS is labeled future; the behavioral test is separate; the CDP-via-`Error.stack`-getter technique; `hasSuspiciousWeakSignals` as the weak-combination logic; fp-scanner's README does not claim to power the live site.

Gaps an anti-bot engineer should note (this service does **not** cover them, though a production system typically would): AudioContext fingerprinting; the Permissions-API mismatch tell (`Notification.permission` vs `Permissions.query()`); `Function.prototype.toString` native-code integrity checks against monkey-patched getters; empty `navigator.plugins`/`mimeTypes`; font enumeration; the concrete `Google SwiftShader`/Mesa headless renderer tell; and named network-layer standards (JA3/JA4 TLS, HTTP/2 frame/settings fingerprints, header-ordering) — the site only says "TLS/TCP is future" rather than naming these as active signals.

## Open source / reusable

The exact live site code is not published as a single repo, and fp-scanner does not claim to power it. But the same author open-sources the underlying techniques under MIT:

- **fp-scanner** (self-hosted fingerprinting + bot detection): https://github.com/antoinevastel/fpscanner
- **fp-collect** (fingerprint-collection module; deliberately excludes canvas/tracking data): https://github.com/antoinevastel/fp-collect

A builder can reuse these directly and read the learning-zone articles for the reasoning behind each signal.

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
