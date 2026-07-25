# bot.incolumitas.com (BotOrNot)

Independent researcher's ever-evolving headless-browser & automation-detection testbed: broadest public bot-signal battery — client-side JS FP, live behavioral classifier, server-side TCP/IP + TLS + IP-reputation of arrival connection — shows each raw result.

- **URL:** https://bot.incolumitas.com/ · **Category:** open-source-style test page by independent security researcher (educational demo; *not* commercial vendor demo, *not* privacy tool) · **Requires registration:** No. Free, no account; tests auto-run on load. Optional interactive "challenge" also unauthenticated.
- **Version observed:** v0.6.3.
- **Firsthand verdict, test browser** (in-app browser as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): Behavioral score never left `...` (synthetic hovers -> no organic-enough trajectory). Red: **WEBDRIVER** fail, **HEADCHR_IFRAME** fail (old battery); **inconsistentServiceWorkerNavigatorProperty** fail (new battery). Server IP API unmasked egress: **VPN = NordVPN**, **datacenter = CDN77/DataCamp**, geo **Istanbul, TR** — saw straight through datacenter proxy.

## What it is — common info

By **Nikolai Tschacher**, independent security researcher, blogs at incolumitas.com re scraping, browser FP, bot-vs-vendor "cat-and-mouse." Page self-labels *BotOrNot* / "Bot & Headless Chrome Detection Tests," versioned, explicit moving target: "implements widely known bot detection tests and is constantly under development." Tschacher also used it as honeypot to benchmark commercial scrapers (ScrapingBee, Bright Data/Luminati, etc.), expose their FP/TLS/TCP-IP tells.

Not commercial, no paid tier / API-key gate — exists so bot authors & defenders see in one place which evasions hold up. Audience: scraper devs, anti-bot engineers, FP researchers.

## Registration / access

None. Load page -> every test runs. Interactive challenge (fill form -> confirm JS dialog -> edit price table -> scrape) optional, unauthenticated; purpose: real human-like interaction telemetry for behavioral classifier.

## How it decides bot-or-not

**No single unified verdict number.** Two output kinds side by side:

1. Continuous **`behavioralClassificationScore`**, float `0` (bot) to `1` (human), **< 0.5 = "most likely a bot."** Computed after ~1.5 s interaction, re-computed at 4/7/10/15 s as telemetry accumulates (later passes -> trim false positives).
2. Large set of **discrete pass/fail tests** — webdriver?, headless tells?, worker/iframe navigator consistency?, UA-vs-OS match?, datacenter IP?, timezone match?, etc. — + rich IP-reputation JSON blob.

Human (or integrating engineer) reads score w/ individual red flags -> conclusion. Tschacher explicit: false positives expected, exercise "raises the transaction cost" vs being infallible — & **client-side signals all spoofable, so server-observed signals (IP, TCP/IP, TLS) can't be forged** if operator understands logic.

## Detection approaches

- **Browser FP** — navigator / canvas / WebGL / audio / font entropy via JS, incl FingerprintJS-style hash (loads `fp.min.js`).
- **Headless / automation-trace detection** — `navigator.webdriver`, headless-Chrome tells, `puppeteer-extra-stealth` patch detection, automation-framework sigs; reuses Intoli & fp-scanner batteries.
- **Behavioral analysis** — mouse/key/scroll/timing telemetry -> 30+ classifier ensemble -> 0–1 score (client-side).
- **Network FP (server-side)** — passive TCP/IP OS FP from SYN packet + JA3-style TLS FP, cross-checked vs claimed UA OS.
- **HTTP-layer (server-side)** — header dump; proxy-header & UA inspection.
- **IP / proxy / VPN / datacenter reputation & geo** — dedicated server-side IP API + DNS-leak & open-port checks on proxy/VPN sub-page.
- **Cross-signal consistency** — browser vs IP timezone, main-thread navigator vs Web Worker / Service Worker / iframe navigator, claimed OS vs TCP/IP-inferred OS.

## Areas / signals scanned

### Client-side (JS)

Collected by same-origin scripts (`hc2.js` main, `ua-parser.min.js`, `fpCollect.min.js`, `fpScanner.js`, `usage.js`, `fp.min.js` = FingerprintJS, `fingerprints.js`, `newTests.js`, `webworker2.js`):

- **New Detection Tests:** `puppeteerEvaluationScript`, `webdriverPresent`, `connectionRTT`, `refMatch`, `overrideTest`, `overflowTest`, `puppeteerExtraStealthUsed`, `inconsistentWebWorkerNavigatorPropery`, `inconsistentServiceWorkerNavigatorPropery`.
- **Old Detection Tests (Intoli + fp-scanner battery, same family as bot.sannysoft.com):** UA, WebDriver (+ advanced), `window.chrome` object presence, permissions, plugins, languages, WebGL vendor/renderer, `HEADCHR_*` headless-Chrome checks, `HEADCHR_IFRAME`, Selenium driver artefacts, battery/memory, video codecs, etc.
- **Fingerprints:** FingerprintJS hash, Canvas fp, WebGL fp, AudioContext, enumerable fonts, screen/window geometry, permissions state, WebRTC leak, full "Browser Data" navigator dump.
- **Behavioral events:** `mousemove/down/up`, `keydown/up`, `scroll`, touch, `visibilitychange`, load/DOMContentLoaded — each timestamped.

### Server-side (IP / TLS / TCP / HTTP)

- **IP Address API** — JSON w/ booleans `is_bogon`, `is_mobile`, `is_satellite`, `is_crawler`, `is_datacenter`, `is_tor`, `is_proxy`, `is_vpn`, `is_abuser`, + `vpn.service`, `datacenter`, `company` (w/ `abuser_score`), `asn` (w/ `abuser_score`), `location` (timezone, accuracy).
- **TCP/IP fingerprint** — passive SYN-packet analysis (TCP options, window size, IP fragmentation flag -> OS guess), by in-app tool `zardaxt.py`.
- **TLS fingerprint API** — JA3-style handshake FP.
- **HTTP headers dump** — full header set as server received it.
- **Proxy/VPN sub-page** — latency test (browser->server RTT vs server->client-IP RTT), WebRTC leak, TCP/IP-OS-vs-UA-OS mismatch, open-ports scan, datacenter-IP check, DNS-leak test, IP-timezone-vs-browser-timezone check, HTTP proxy-header inspection.

### Behavioral

Interactive challenge (form + confirm dialog + editable price table + scrape) engineered to elicit organic mouse/keyboard/scroll trajectories feeding 0–1 classifier. Synthetic pointer events alone didn't move our score off initial state.

## How it scans (architecture)

**Hybrid, decision split across two independent vantage points.**

- **Client side:** same-origin JS bundle harvests full browser FP + continuous behavioral event stream, and — per firsthand observation — computes `behavioralClassificationScore` **in browser** (no FP/behavioral POST to backend captured during recon; score updated locally at 1.5/4/7/10/15 s). Treat scorer as client-resident unless builder confirms otherwise.
- **Server side:** on TCP connect, backend independently derives client-uneditable signals — TCP/IP OS FP from SYN, JA3-style TLS FP, HTTP header order/UA, IP/proxy/VPN/datacenter reputation via IP API. Served back as own JSON/report sections.

Detection power = **cross-check**: server-observed reality (real OS from TCP/IP, real IP timezone, real datacenter status) vs client claims (navigator UA/OS, browser timezone), main-thread navigator vs Web Worker / Service Worker / iframe recomputations. Spoof internally consistent in JS still collapses when SYN packet or egress IP disagrees.

## Scoring / output

- Behavioral: single `behavioralClassificationScore` float `[0,1]`, 30+ classifier ensemble, `< 0.5` = likely bot, refined over 1.5–15 s.
- Everything else: per-test `OK`/`FAIL` booleans + rich IP-reputation JSON. No aggregate 0–100 risk number — unlike commercial scorers, deliberately exposes each raw signal vs collapsing.

## Notable techniques

- **Cross-layer consistency:** claimed UA/OS vs TCP/IP-inferred OS vs TLS FP vs IP-geo timezone — catches spoofed UAs that look fine in isolation.
- **Cross-context navigator re-checks:** recompute `navigator.*` in Web Worker, Service Worker, iframe, compare to main thread (historically caught Bright Data returning `Linux x86_64` in worker while top-level UA claimed Windows). Exactly the signal that flagged our browser (`inconsistentServiceWorkerNavigatorProperty` FAIL).
- **Fingerprint-reuse detection:** spotting identical canvas/WebGL FPs repeated across many requests -> unmask scraping-farm infra (caught ScrapingBee returning constant FP).
- **Stealth-patch detection:** `puppeteerExtraStealthUsed` / `overrideTest` target `puppeteer-extra-stealth` artefacts.
- **Impossible-geometry / overflow checks** (`overflowTest`) as headless tells.
- **Passive TCP/IP fingerprinting** via `zardaxt.py` — no active client probing needed.
- **Latency triangulation** on proxy page: browser->server RTT vs server->client-IP RTT -> expose proxy hop.
- **Time-staggered re-scoring** -> cut false positives as interaction data grows.

## What we observed firsthand

- Behavioral score stayed unresolved (`...`) under synthetic input — classifier genuinely needs organic trajectories.
- Old battery: **WEBDRIVER FAIL**, **HEADCHR_IFRAME FAIL**. New battery: **inconsistentServiceWorkerNavigatorProperty FAIL**. (Electron/CDP-driven test browser leaks worker-context inconsistencies & iframe tells even though `navigator.webdriver` absent and `window.chrome` present.)
- IP API for egress `87.249.139.226`: `is_vpn = true` (service **NordVPN**), `is_datacenter = true` (**CDN77/DataCamp**), geo **Istanbul, TR** — datacenter egress fully unmasked server-side.
- All detection scripts served from **same origin**; collectors client-side JS. **No FP or behavioral POST to scoring backend observed** during recon — consistent w/ client-side behavioral scoring + independent server-side connection analysis. (Cloudflare RUM-style analytics beacons, if any, aren't detection traffic.)

## Verification notes

Adversarial review upheld core findings but corrected several points, folded into sections above:

- **Authorship:** tool by **Nikolai Tschacher**, *not* Antoine Vastel. Auto-summaries misattribute to Vastel since page **reuses / credits Vastel's open-source fp-scanner & fp-collect** — Vastel (ex-DataDome Head of Research) = *source*, not author.
- **Scoring specifics** (0–1 range, "30+ classifiers," 1.5/4/7/10/15 s cadence) from **live page & firsthand observation**, not 2021 "Behavioral Analysis" blog (only conceptual). Confirmed by recon, not blog.
- **CDP detection** ≠ open-ports / remote-debugging-port scan (real but weak — client debug port rarely reachable from server). Dominant in-page CDP tell to implement: `Runtime.enable` / `Error.stack` serialization leak firing when DevTools Protocol client attached; research under-weighted it, don't over-rely on port-scan vector.
- **Network FP scope:** observed TLS FP = **JA3-style**, now dated. Modern builder should add **HTTP/2 fingerprinting** (Akamai h2: SETTINGS / WINDOW_UPDATE / priority-frame order) & **JA4/JA4+** alongside TCP/IP + JA3.
- **Unverified negative:** whether detector's *own* code is open-source unconfirmed either way — no public repo found, absence isn't proof. Third-party libs (fp-scanner, fp-collect, FingerprintJS) *are* open source; bespoke scoring logic isn't published.
- **Weakly-corroborated client signals:** finer tells — `window.outerWidth < innerWidth` "impossible geometry," `Notification.permission`-vs-Permissions-API mismatch, Service-Worker data reads — only indirectly supported by research. Firsthand recon confirmed worker/iframe consistency & geometry/overflow tests exist, but treat exact sub-checks as reasonable vs byte-verified.
- **Missing-angle reminders for builder** (not present/emphasized on page): JS lie/tamper detection via `Function.prototype.toString` `[native code]` checks & monkey-patch/Proxy detection; explicit `window.chrome.{runtime,loadTimes,csi,app}` consistency; UA Client Hints consistency (`Sec-CH-UA` / `Sec-CH-UA-Platform` vs `navigator.userAgentData`) beyond legacy `navigator.userAgent` vs HTTP `User-Agent`.

## Open source / reusable

Bespoke BotOrNot detection/scoring code **not published as repo**. Reusable parts:

- **fp-scanner** & **fp-collect** (Antoine Vastel) — headless/automation battery, loaded as `fpScanner.js` / `fpCollect.min.js`.
- **FingerprintJS** (open-source tier) — device FP hash, loaded as `fp.min.js`.
- **`zardaxt.py`** — TCP/IP (SYN-packet) OS-FP approach used server-side, named in-app.
- **Intoli headless-Chrome detection tests** — lineage of "old" battery, shared w/ bot.sannysoft.com.

## Sources

- [Bot / Headless Chrome Detection Tests (bot.incolumitas.com)](https://bot.incolumitas.com/)
- [incolumitas.com — Bot Detection with Behavioral Analysis](https://incolumitas.com/2021/04/11/bot-detection-with-behavioral-analysis/)
- [incolumitas.com — On the Architecture of Bot Detection Services](https://incolumitas.com/2021/07/18/on-the-architecture-of-bot-detection-services/)
- [incolumitas.com — Detecting Scraping Services](https://incolumitas.com/2021/03/11/detecting-scraping-services/)
- [niespodd/browser-fingerprinting (references bot.incolumitas.com as a test resource)](https://github.com/niespodd/browser-fingerprinting)
