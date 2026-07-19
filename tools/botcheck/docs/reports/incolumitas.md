# bot.incolumitas.com (BotOrNot)

Independent researcher's constantly-evolving testbed for headless-browser and automation detection: runs broadest publicly available battery of bot signals — client-side JS fingerprinting, live behavioral classifier, server-side TCP/IP + TLS + IP-reputation analysis of the very connection you arrived on — shows each raw result.

- **URL:** https://bot.incolumitas.com/ · **Category:** open-source-style test page run by independent security researcher (educational demo; *not* commercial vendor demo, *not* privacy tool) · **Requires registration:** No. Free, no account; tests run automatically on load. Optional interactive "challenge" needs no signup either.
- **Version observed:** v0.6.3.
- **Firsthand verdict for test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): Behavioral score never resolved off `...` (synthetic hovers alone never produced organic-enough trajectory to score). Multiple discrete tests fired red: **WEBDRIVER** failed, **HEADCHR_IFRAME** failed in old battery; **inconsistentServiceWorkerNavigatorProperty** failed in new battery. Server-side IP API correctly unmasked egress as **VPN = NordVPN**, **datacenter = CDN77/DataCamp**, geolocated **Istanbul, TR** — saw straight through datacenter proxy in-app browser egresses through.

## What it is — common info

Built and maintained by **Nikolai Tschacher**, independent security researcher who blogs at incolumitas.com about scraping, browser fingerprinting, and "cat-and-mouse game" between bot authors and anti-bot vendors. Page self-labels as *BotOrNot* / "Bot & Headless Chrome Detection Tests," versioned, explicitly a moving target: "implements widely known bot detection tests and is constantly under development." Tschacher also used it as honeypot to benchmark commercial scraping services (ScrapingBee, Bright Data/Luminati, etc.), expose their fingerprint/TLS/TCP-IP tells.

Not commercial product, no paid tier or API-key gate — exists so bot authors and defenders can see, in one place, which of their evasions hold up. Audience: scraper developers, anti-bot engineers, fingerprinting researchers.

## Registration / access

None. Load page, every test runs. Interactive challenge (fill form → confirm JS dialog → edit price table → scrape it) optional, also unauthenticated; purpose: generate real human-like interaction telemetry for behavioral classifier.

## How it decides bot-or-not

**No single unified verdict number.** Page produces two kinds of output side by side:

1. Continuous **`behavioralClassificationScore`**, float from `0` (bot) to `1` (human), where **< 0.5 = "most likely a bot."** Computed after ~1.5 s of interaction, re-computed at 4 s, 7 s, 10 s, 15 s as more telemetry accumulates (later passes use more data to trim false positives).
2. Large set of **discrete pass/fail tests** — webdriver present?, headless tells?, worker/iframe navigator consistency?, UA-vs-OS match?, datacenter IP?, timezone match?, etc. — plus rich IP-reputation JSON blob.

Human (or integrating engineer) reads behavioral score together with individual red flags to reach conclusion. Tschacher explicit that false positives are expected, whole exercise "raises the transaction cost" of automation rather than being infallible — and **client-side signals are all spoofable, so server-observed signals (IP, TCP/IP, TLS) are the ones that can't be forged** if operator understands the logic.

## Detection approaches

- **Browser fingerprinting** — navigator / canvas / WebGL / audio / font entropy via JS, including FingerprintJS-style hash (page loads `fp.min.js`).
- **Headless / automation-trace detection** — `navigator.webdriver`, headless-Chrome tells, `puppeteer-extra-stealth` patch detection, automation-framework signatures; reuses Intoli and fp-scanner test batteries.
- **Behavioral analysis** — mouse / key / scroll / timing telemetry fed to 30+ classifier ensemble producing 0–1 score (client-side).
- **Network fingerprinting (server-side)** — passive TCP/IP OS fingerprinting from SYN packet, plus JA3-style TLS fingerprint, cross-checked against claimed User-Agent OS.
- **HTTP-layer analysis (server-side)** — header dump; proxy-header and User-Agent inspection.
- **IP / proxy / VPN / datacenter reputation & geolocation** — dedicated server-side IP API, plus DNS-leak and open-port checks on proxy/VPN sub-page.
- **Cross-signal consistency correlation** — browser vs IP timezone, main-thread navigator vs Web Worker / Service Worker / iframe navigator, claimed OS vs TCP/IP-inferred OS.

## Areas / signals scanned

### Client-side (JS)

Collected by same-origin scripts (`hc2.js` main, `ua-parser.min.js`, `fpCollect.min.js`, `fpScanner.js`, `usage.js`, `fp.min.js` = FingerprintJS, `fingerprints.js`, `newTests.js`, `webworker2.js`):

- **New Detection Tests:** `puppeteerEvaluationScript`, `webdriverPresent`, `connectionRTT`, `refMatch`, `overrideTest`, `overflowTest`, `puppeteerExtraStealthUsed`, `inconsistentWebWorkerNavigatorPropery`, `inconsistentServiceWorkerNavigatorPropery`.
- **Old Detection Tests (Intoli + fp-scanner battery, same family as bot.sannysoft.com):** User-Agent, WebDriver (+ advanced), `window.chrome` object presence, permissions, plugins, languages, WebGL vendor/renderer, `HEADCHR_*` headless-Chrome checks, `HEADCHR_IFRAME`, Selenium driver artefacts, battery/memory, video codecs, etc.
- **Fingerprints:** FingerprintJS hash, Canvas fp, WebGL fp, AudioContext, enumerable fonts, screen/window geometry, permissions state, WebRTC leak, full "Browser Data" navigator dump.
- **Behavioral events:** `mousemove/down/up`, `keydown/up`, `scroll`, touch, `visibilitychange`, load/DOMContentLoaded — each timestamped.

### Server-side (IP / TLS / TCP / HTTP)

- **IP Address API** — JSON with booleans `is_bogon`, `is_mobile`, `is_satellite`, `is_crawler`, `is_datacenter`, `is_tor`, `is_proxy`, `is_vpn`, `is_abuser`, plus `vpn.service`, `datacenter`, `company` (with `abuser_score`), `asn` (with `abuser_score`), `location` (timezone, accuracy).
- **TCP/IP fingerprint** — passive analysis of SYN packet (TCP options, window size, IP fragmentation flag → OS guess), performed by tool named `zardaxt.py` in app.
- **TLS fingerprint API** — JA3-style handshake fingerprint.
- **HTTP headers dump** — full header set as server received it.
- **Proxy/VPN sub-page** — latency test (browser→server RTT vs server→client-IP RTT), WebRTC leak, TCP/IP-OS-vs-UA-OS mismatch, open-ports scan, datacenter-IP check, DNS-leak test, IP-timezone-vs-browser-timezone check, HTTP proxy-header inspection.

### Behavioral

Interactive challenge (form + confirm dialog + editable price table + scrape) engineered to elicit organic mouse/keyboard/scroll trajectories feeding 0–1 classifier. Purely synthetic pointer events didn't move our score off initial state.

## How it scans (architecture)

**Hybrid, decision split across two independent vantage points.**

- **Client side:** same-origin JS bundle harvests full browser fingerprint and continuous behavioral event stream, and — based on firsthand observation — computes `behavioralClassificationScore` **in the browser** (no fingerprint/behavioral POST to backend captured during recon; score updated locally at 1.5/4/7/10/15 s marks). Treat behavioral scorer as client-resident unless builder confirms otherwise.
- **Server side:** moment TCP connection established, backend independently derives signals client can't edit — TCP/IP OS fingerprint from SYN, JA3-style TLS fingerprint, HTTP header order/UA, IP/proxy/VPN/datacenter reputation via IP API. Served back as own JSON/report sections.

Detection power is in the **cross-check**: server-observed reality (real OS from TCP/IP, real IP timezone, real datacenter status) compared against client-declared claims (navigator UA/OS, browser timezone), main-thread navigator values compared against Web Worker / Service Worker / iframe recomputations. Spoof internally consistent in JS still collapses when SYN packet or egress IP disagrees with it.

## Scoring / output

- Behavioral: single `behavioralClassificationScore` float in `[0,1]`, ensemble of 30+ classifiers, `< 0.5` = likely bot, refined over 1.5–15 s.
- Everything else: per-test `OK`/`FAIL` booleans plus rich IP-reputation JSON. No aggregate 0–100 risk number — unlike commercial scorer, deliberately exposes each raw signal rather than collapsing them.

## Notable techniques

- **Cross-layer consistency:** claimed UA/OS vs TCP/IP-inferred OS vs TLS fingerprint vs IP-geolocated timezone — catches spoofed User-Agents that look fine in isolation.
- **Cross-context navigator re-checks:** recompute `navigator.*` inside Web Worker, Service Worker, iframe, compare to main thread (historically caught Bright Data returning `Linux x86_64` in worker while top-level UA claimed Windows). Exactly the signal that flagged our browser (`inconsistentServiceWorkerNavigatorProperty` FAIL).
- **Fingerprint-reuse detection:** spotting identical canvas/WebGL fingerprints repeated across many requests to unmask scraping-farm infrastructure (caught ScrapingBee returning constant fingerprint).
- **Stealth-patch detection:** `puppeteerExtraStealthUsed` / `overrideTest` target artefacts left by `puppeteer-extra-stealth`.
- **Impossible-geometry / overflow checks** (`overflowTest`) as headless tells.
- **Passive TCP/IP fingerprinting** via `zardaxt.py` — no active probing of client needed.
- **Latency triangulation** on proxy page: comparing browser→server RTT against server→client-IP RTT to expose proxy hop.
- **Time-staggered re-scoring** to cut false positives as interaction data grows.

## What we observed firsthand

- Behavioral score stayed unresolved (`...`) under synthetic input — classifier genuinely needs organic trajectories.
- Old battery: **WEBDRIVER FAIL**, **HEADCHR_IFRAME FAIL**. New battery: **inconsistentServiceWorkerNavigatorProperty FAIL**. (Electron/CDP-driven test browser leaks worker-context inconsistencies and iframe tells even though `navigator.webdriver` itself absent and `window.chrome` present.)
- IP API output for egress `87.249.139.226`: `is_vpn = true` (service **NordVPN**), `is_datacenter = true` (**CDN77/DataCamp**), geolocated **Istanbul, TR** — datacenter egress fully unmasked server-side.
- All detection scripts served from **same origin**; collectors client-side JS. **No fingerprint or behavioral POST to scoring backend observed** during recon — consistent with client-side behavioral scoring plus independent server-side connection analysis. (Cloudflare RUM-style analytics beacons, if any, aren't detection traffic.)

## Verification notes

Adversarial review upheld core findings but corrected several points, folded into sections above:

- **Authorship:** tool by **Nikolai Tschacher**, *not* Antoine Vastel. Some automated summaries misattributed it to Vastel since page **reuses / credits Vastel's open-source fp-scanner and fp-collect** — Vastel (ex-DataDome Head of Research) is a *source*, not the author.
- **Scoring specifics** (0–1 range, "30+ classifiers," 1.5/4/7/10/15 s cadence) come from **live page and firsthand observation**, not from 2021 "Behavioral Analysis" blog post, which is only conceptual. Treated here as confirmed by firsthand recon, not by blog.
- **CDP detection** shouldn't be reduced to open-ports / remote-debugging-port scan (real but weak — client's debug port rarely reachable from server). Dominant in-page CDP tell an engineer should implement is `Runtime.enable` / `Error.stack` serialization leak firing when DevTools Protocol client attached; research under-weighted it, so don't over-rely on port-scan vector.
- **Network fingerprinting scope:** observed TLS fingerprint is **JA3-style**, now somewhat dated. Modern builder should add **HTTP/2 fingerprinting** (Akamai h2: SETTINGS / WINDOW_UPDATE / priority-frame order) and **JA4/JA4+** alongside TCP/IP + JA3.
- **Unverified negative:** whether detector's *own* bot-detection code is open-source couldn't be confirmed either way — no public repo found, but absence isn't proof. Third-party libraries it loads (fp-scanner, fp-collect, FingerprintJS) *are* open source; bespoke scoring logic isn't published.
- **Weakly-corroborated client signals:** finer tells like `window.outerWidth < innerWidth` "impossible geometry," `Notification.permission`-vs-Permissions-API mismatch, Service-Worker data reads were only indirectly supported by research. Plausible, firsthand recon confirmed worker/iframe consistency checks and geometry/overflow tests exist, but treat exact sub-checks as reasonable rather than byte-verified.
- **Missing-angle reminders for builder** (not present or not emphasized on page as researched): JS lie/tamper detection via `Function.prototype.toString` `[native code]` checks and monkey-patch/Proxy detection; explicit `window.chrome.{runtime,loadTimes,csi,app}` consistency; User-Agent Client Hints consistency (`Sec-CH-UA` / `Sec-CH-UA-Platform` vs `navigator.userAgentData`) beyond legacy `navigator.userAgent` vs HTTP `User-Agent` check.

## Open source / reusable

Bespoke BotOrNot detection/scoring code **not published as repo**. What *is* reusable:

- **fp-scanner** and **fp-collect** (Antoine Vastel) — headless/automation test battery, loaded here as `fpScanner.js` / `fpCollect.min.js`.
- **FingerprintJS** (open-source tier) — device fingerprint hash, loaded as `fp.min.js`.
- **`zardaxt.py`** — TCP/IP (SYN-packet) OS-fingerprinting approach used server-side, named in-app.
- **Intoli headless-Chrome detection tests** — lineage of "old" battery, shared with bot.sannysoft.com.

## Sources

- [Bot / Headless Chrome Detection Tests (bot.incolumitas.com)](https://bot.incolumitas.com/)
- [incolumitas.com — Bot Detection with Behavioral Analysis](https://incolumitas.com/2021/04/11/bot-detection-with-behavioral-analysis/)
- [incolumitas.com — On the Architecture of Bot Detection Services](https://incolumitas.com/2021/07/18/on-the-architecture-of-bot-detection-services/)
- [incolumitas.com — Detecting Scraping Services](https://incolumitas.com/2021/03/11/detecting-scraping-services/)
- [niespodd/browser-fingerprinting (references bot.incolumitas.com as a test resource)](https://github.com/niespodd/browser-fingerprinting)
