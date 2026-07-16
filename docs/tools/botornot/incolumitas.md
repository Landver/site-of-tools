# bot.incolumitas.com (BotOrNot)

An independent researcher's constantly-evolving testbed for headless-browser and automation detection: it runs the broadest publicly available battery of bot signals — client-side JS fingerprinting, a live behavioral classifier, and server-side TCP/IP + TLS + IP-reputation analysis of the very connection you arrived on — and shows you each raw result.

- **URL:** https://bot.incolumitas.com/ · **Category:** open-source-style test page run by an independent security researcher (educational demo; *not* a commercial vendor demo, *not* a privacy tool) · **Requires registration:** No. Free, no account; tests run automatically on load. An optional interactive "challenge" needs no signup either.
- **Version observed:** v0.6.3.
- **Firsthand verdict for the test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): The behavioral score never resolved off `...` (synthetic hovers alone never produced an organic-enough trajectory to score). Multiple discrete tests fired red: **WEBDRIVER** failed and **HEADCHR_IFRAME** failed in the old battery; **inconsistentServiceWorkerNavigatorProperty** failed in the new battery. The server-side IP API correctly unmasked the egress as **VPN = NordVPN**, **datacenter = CDN77/DataCamp**, geolocated **Istanbul, TR** — i.e. it saw straight through the datacenter proxy the in-app browser egresses through.

## What it is — common info

Built and maintained by **Nikolai Tschacher**, an independent security researcher who blogs at incolumitas.com about scraping, browser fingerprinting, and the "cat-and-mouse game" between bot authors and anti-bot vendors. The page self-labels as *BotOrNot* / "Bot & Headless Chrome Detection Tests," is versioned, and is explicitly a moving target: it "implements widely known bot detection tests and is constantly under development." Tschacher has also used it as a honeypot to benchmark commercial scraping services (ScrapingBee, Bright Data/Luminati, etc.) and expose their fingerprint/TLS/TCP-IP tells.

It is not a commercial product and has no paid tier or API-key gate — it exists to let bot authors and defenders see, in one place, which of their evasions hold up. Audience: scraper developers, anti-bot engineers, and fingerprinting researchers.

## Registration / access

None. Load the page and every test runs. The interactive challenge (fill a form → confirm a JS dialog → edit a price table → scrape it) is optional and also unauthenticated; its purpose is to generate real human-like interaction telemetry for the behavioral classifier.

## How it decides bot-or-not

There is **no single unified verdict number**. The page produces two kinds of output side by side:

1. A continuous **`behavioralClassificationScore`**, a float from `0` (bot) to `1` (human), where **< 0.5 = "most likely a bot."** It is computed after ~1.5 s of interaction and then re-computed at 4 s, 7 s, 10 s, and 15 s as more telemetry accumulates (later passes use more data to trim false positives).
2. A large set of **discrete pass/fail tests** — webdriver present?, headless tells?, worker/iframe navigator consistency?, UA-vs-OS match?, datacenter IP?, timezone match?, etc. — plus a rich IP-reputation JSON blob.

A human (or an integrating engineer) reads the behavioral score together with the individual red flags to reach a conclusion. Tschacher is explicit that false positives are expected and that the whole exercise "raises the transaction cost" of automation rather than being infallible — and that **client-side signals are all spoofable, so the server-observed signals (IP, TCP/IP, TLS) are the ones that can't be forged** if the operator understands the logic.

## Detection approaches

- **Browser fingerprinting** — navigator / canvas / WebGL / audio / font entropy via JS, including a FingerprintJS-style hash (the page loads `fp.min.js`).
- **Headless / automation-trace detection** — `navigator.webdriver`, headless-Chrome tells, `puppeteer-extra-stealth` patch detection, automation-framework signatures; reuses the Intoli and fp-scanner test batteries.
- **Behavioral analysis** — mouse / key / scroll / timing telemetry fed to a 30+ classifier ensemble producing the 0–1 score (client-side).
- **Network fingerprinting (server-side)** — passive TCP/IP OS fingerprinting from the SYN packet, plus a JA3-style TLS fingerprint, cross-checked against the claimed User-Agent OS.
- **HTTP-layer analysis (server-side)** — header dump; proxy-header and User-Agent inspection.
- **IP / proxy / VPN / datacenter reputation & geolocation** — a dedicated server-side IP API, plus DNS-leak and open-port checks on a proxy/VPN sub-page.
- **Cross-signal consistency correlation** — browser vs IP timezone, main-thread navigator vs Web Worker / Service Worker / iframe navigator, and claimed OS vs TCP/IP-inferred OS.

## Areas / signals scanned

### Client-side (JS)

Collected by same-origin scripts (`hc2.js` main, `ua-parser.min.js`, `fpCollect.min.js`, `fpScanner.js`, `usage.js`, `fp.min.js` = FingerprintJS, `fingerprints.js`, `newTests.js`, `webworker2.js`):

- **New Detection Tests:** `puppeteerEvaluationScript`, `webdriverPresent`, `connectionRTT`, `refMatch`, `overrideTest`, `overflowTest`, `puppeteerExtraStealthUsed`, `inconsistentWebWorkerNavigatorPropery`, `inconsistentServiceWorkerNavigatorPropery`.
- **Old Detection Tests (Intoli + fp-scanner battery, same family as bot.sannysoft.com):** User-Agent, WebDriver (+ advanced), `window.chrome` object presence, permissions, plugins, languages, WebGL vendor/renderer, `HEADCHR_*` headless-Chrome checks, `HEADCHR_IFRAME`, Selenium driver artefacts, battery/memory, video codecs, etc.
- **Fingerprints:** FingerprintJS hash, Canvas fp, WebGL fp, AudioContext, enumerable fonts, screen/window geometry, permissions state, WebRTC leak, and a full "Browser Data" navigator dump.
- **Behavioral events:** `mousemove/down/up`, `keydown/up`, `scroll`, touch, `visibilitychange`, load/DOMContentLoaded — each timestamped.

### Server-side (IP / TLS / TCP / HTTP)

- **IP Address API** — JSON with booleans `is_bogon`, `is_mobile`, `is_satellite`, `is_crawler`, `is_datacenter`, `is_tor`, `is_proxy`, `is_vpn`, `is_abuser`, plus `vpn.service`, `datacenter`, `company` (with `abuser_score`), `asn` (with `abuser_score`), and `location` (timezone, accuracy).
- **TCP/IP fingerprint** — passive analysis of the SYN packet (TCP options, window size, IP fragmentation flag → OS guess), performed by a tool named `zardaxt.py` in the app.
- **TLS fingerprint API** — JA3-style handshake fingerprint.
- **HTTP headers dump** — full header set as the server received it.
- **Proxy/VPN sub-page** — a latency test (browser→server RTT vs server→client-IP RTT), WebRTC leak, TCP/IP-OS-vs-UA-OS mismatch, open-ports scan, datacenter-IP check, DNS-leak test, IP-timezone-vs-browser-timezone check, and HTTP proxy-header inspection.

### Behavioral

The interactive challenge (form + confirm dialog + editable price table + scrape) is engineered to elicit organic mouse/keyboard/scroll trajectories that feed the 0–1 classifier. Purely synthetic pointer events did not move our score off its initial state.

## How it scans (architecture)

**Hybrid, with the decision split across two independent vantage points.**

- **Client side:** the same-origin JS bundle harvests the full browser fingerprint and a continuous behavioral event stream, and — based on firsthand observation — computes the `behavioralClassificationScore` **in the browser** (no fingerprint/behavioral POST to a backend was captured during recon; the score updated locally at the 1.5/4/7/10/15 s marks). Treat the behavioral scorer as client-resident unless a builder confirms otherwise.
- **Server side:** the moment the TCP connection is established, the backend independently derives signals the client cannot edit — TCP/IP OS fingerprint from the SYN, JA3-style TLS fingerprint, HTTP header order/UA, and IP/proxy/VPN/datacenter reputation via the IP API. These are served back as their own JSON/report sections.

The detection power is in the **cross-check**: server-observed reality (real OS from TCP/IP, real IP timezone, real datacenter status) is compared against client-declared claims (navigator UA/OS, browser timezone), and main-thread navigator values are compared against Web Worker / Service Worker / iframe recomputations. A spoof that is internally consistent in JS still collapses when the SYN packet or the egress IP disagrees with it.

## Scoring / output

- Behavioral: a single `behavioralClassificationScore` float in `[0,1]`, ensemble of 30+ classifiers, `< 0.5` = likely bot, refined over 1.5–15 s.
- Everything else: per-test `OK`/`FAIL` booleans plus the rich IP-reputation JSON. No aggregate 0–100 risk number — unlike a commercial scorer, it deliberately exposes each raw signal rather than collapsing them.

## Notable techniques

- **Cross-layer consistency:** claimed UA/OS vs TCP/IP-inferred OS vs TLS fingerprint vs IP-geolocated timezone — catches spoofed User-Agents that look fine in isolation.
- **Cross-context navigator re-checks:** recompute `navigator.*` inside a Web Worker, Service Worker, and iframe and compare to the main thread (historically caught Bright Data returning `Linux x86_64` in a worker while the top-level UA claimed Windows). This is exactly the signal that flagged our browser (`inconsistentServiceWorkerNavigatorProperty` FAIL).
- **Fingerprint-reuse detection:** spotting identical canvas/WebGL fingerprints repeated across many requests to unmask scraping-farm infrastructure (caught ScrapingBee returning a constant fingerprint).
- **Stealth-patch detection:** `puppeteerExtraStealthUsed` / `overrideTest` target the artefacts left by `puppeteer-extra-stealth`.
- **Impossible-geometry / overflow checks** (`overflowTest`) as headless tells.
- **Passive TCP/IP fingerprinting** via `zardaxt.py` — no active probing of the client needed.
- **Latency triangulation** on the proxy page: comparing browser→server RTT against server→client-IP RTT to expose a proxy hop.
- **Time-staggered re-scoring** to cut false positives as interaction data grows.

## What we observed firsthand

- Behavioral score stayed unresolved (`...`) under synthetic input — the classifier genuinely needs organic trajectories.
- Old battery: **WEBDRIVER FAIL**, **HEADCHR_IFRAME FAIL**. New battery: **inconsistentServiceWorkerNavigatorProperty FAIL**. (The Electron/CDP-driven test browser leaks worker-context inconsistencies and iframe tells even though `navigator.webdriver` itself is absent and `window.chrome` is present.)
- IP API output for egress `87.249.139.226`: `is_vpn = true` (service **NordVPN**), `is_datacenter = true` (**CDN77/DataCamp**), geolocated **Istanbul, TR** — the datacenter egress was fully unmasked server-side.
- All detection scripts are served from the **same origin**; the collectors are client-side JS. **No fingerprint or behavioral POST to a scoring backend was observed** during recon — consistent with client-side behavioral scoring plus independent server-side connection analysis. (Cloudflare RUM-style analytics beacons, if any, are not detection traffic.)

## Verification notes

The adversarial review upheld the core findings but corrected several points, folded into the sections above:

- **Authorship:** the tool is by **Nikolai Tschacher**, *not* Antoine Vastel. Some automated summaries misattributed it to Vastel because the page **reuses / credits Vastel's open-source fp-scanner and fp-collect** — Vastel (ex-DataDome Head of Research) is a *source*, not the author.
- **Scoring specifics** (0–1 range, "30+ classifiers," the 1.5/4/7/10/15 s cadence) come from the **live page and firsthand observation**, not from the 2021 "Behavioral Analysis" blog post, which is only conceptual. They are treated here as confirmed by firsthand recon, not by the blog.
- **CDP detection** should not be reduced to the open-ports / remote-debugging-port scan (real but weak — the client's debug port is rarely reachable from the server). The dominant in-page CDP tell an engineer should implement is the `Runtime.enable` / `Error.stack` serialization leak that fires when a DevTools Protocol client is attached; the research under-weighted it, so don't over-rely on the port-scan vector.
- **Network fingerprinting scope:** the observed TLS fingerprint is **JA3-style**, which is now somewhat dated. A modern builder should add **HTTP/2 fingerprinting** (Akamai h2: SETTINGS / WINDOW_UPDATE / priority-frame order) and **JA4/JA4+** alongside TCP/IP + JA3.
- **Unverified negative:** whether the detector's *own* bot-detection code is open-source could not be confirmed either way — no public repo was found, but absence isn't proof. The third-party libraries it loads (fp-scanner, fp-collect, FingerprintJS) *are* open source; the bespoke scoring logic is not published.
- **Weakly-corroborated client signals:** finer tells such as `window.outerWidth < innerWidth` "impossible geometry," a `Notification.permission`-vs-Permissions-API mismatch, and Service-Worker data reads were only indirectly supported by research. They are plausible and firsthand recon confirmed worker/iframe consistency checks and geometry/overflow tests exist, but treat the exact sub-checks as reasonable rather than byte-verified.
- **Missing-angle reminders for a builder** (not present or not emphasized on the page as researched): JS lie/tamper detection via `Function.prototype.toString` `[native code]` checks and monkey-patch/Proxy detection; explicit `window.chrome.{runtime,loadTimes,csi,app}` consistency; and User-Agent Client Hints consistency (`Sec-CH-UA` / `Sec-CH-UA-Platform` vs `navigator.userAgentData`) beyond the legacy `navigator.userAgent` vs HTTP `User-Agent` check.

## Open source / reusable

The bespoke BotOrNot detection/scoring code is **not published as a repo**. What *is* reusable:

- **fp-scanner** and **fp-collect** (Antoine Vastel) — the headless/automation test battery, loaded here as `fpScanner.js` / `fpCollect.min.js`.
- **FingerprintJS** (open-source tier) — the device fingerprint hash, loaded as `fp.min.js`.
- **`zardaxt.py`** — the TCP/IP (SYN-packet) OS-fingerprinting approach used server-side, named in-app.
- **Intoli headless-Chrome detection tests** — the lineage of the "old" battery, shared with bot.sannysoft.com.

## Sources

- [Bot / Headless Chrome Detection Tests (bot.incolumitas.com)](https://bot.incolumitas.com/)
- [incolumitas.com — Bot Detection with Behavioral Analysis](https://incolumitas.com/2021/04/11/bot-detection-with-behavioral-analysis/)
- [incolumitas.com — On the Architecture of Bot Detection Services](https://incolumitas.com/2021/07/18/on-the-architecture-of-bot-detection-services/)
- [incolumitas.com — Detecting Scraping Services](https://incolumitas.com/2021/03/11/detecting-scraping-services/)
- [niespodd/browser-fingerprinting (references bot.incolumitas.com as a test resource)](https://github.com/niespodd/browser-fingerprinting)
