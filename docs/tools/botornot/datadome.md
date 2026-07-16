# DataDome

Enterprise, edge-deployed anti-bot and online-fraud protection that scores every HTTP request in real time with server-side ML, escalating suspicious traffic to a CAPTCHA or the invisible "Device Check" client-side challenge. It is a production security product, not a public "check my browser" scorer.

- **URL:** https://datadome.co/ · **Category:** commercial anti-bot vendor (demo/lead-gen only; no anonymous self-test) · **Requires registration:** yes for the self-serve assessment — the old anonymous `bot-tester.datadome.co` now returns `{"message":"Not Found"}`; its successor "Vulnerability Scan" is account-gated (`datadome.co/signup`). Device Check has no page to visit — it only fires on a DataDome-protected customer site.
- **Firsthand verdict for the test browser:** Not obtainable firsthand — DataDome exposes no public bot-score page, so it was documented from its own engineering/threat-research blog + docs plus independent reverse-engineering, not by driving it in the browser. Reasoning about how it *would* treat our test browser (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): this is close to a worst-case profile for DataDome. The egress is a datacenter/VPN IP (blockable server-side at the edge before any JS runs), the browser is CDP-driven Electron (the exact automation-transport class its CDP detection targets), and the frozen macOS 10_15_7 User-Agent invites TLS/UA and Client-Hints consistency failures. Every other tool in this set that inspects CDP or datacenter IPs flagged this browser, so DataDome would very likely challenge or hard-block it. Treat this as inference, not an observed verdict.

## What it is — common info

DataDome is a commercial bot- and fraud-protection SaaS (founded 2015, France/US). It deploys as an edge module across 30+ points of presence and states it inspects every request in under ~2 ms, processing on the order of trillions of signals per day. It maintains an "Advanced Threat Research" team that publishes unusually detailed engineering write-ups — the primary sources for this report. Audience is enterprise site operators (e-commerce, ticketing, classifieds, streaming) defending against scraping, credential stuffing, account takeover, carding, and, more recently, unwanted LLM/AI-agent crawling. The public "bot tester" / Vulnerability Scan is marketing lead-gen showing a prospect their exposure; it is not an analysis tool for arbitrary browsers.

## Registration / access

There is no anonymous public checker. The self-serve Vulnerability Scan requires creating an account / entering your domain. "Device Check" is a product feature, never a standalone URL — it executes only when you request a protected customer site and the request looks suspicious. (Registration-flow detail is medium-confidence, from search snippets plus the confirmed 404 of the old tester URL.)

## How it decides bot-or-not

DataDome makes a per-request decision — **allow / hard-block / challenge** — computed **server-side** by a real-time ML engine. The decision is cascading and edge-first: cheap, hard-to-forge server-side signals are evaluated on the very first request (IP/ASN reputation, TCP/IP OS fingerprint, TLS ClientHello, HTTP header and protocol fingerprint), and a bad enough signal (e.g. a datacenter IP, or a TLS hash that contradicts the User-Agent) can block before any JavaScript runs. If the request survives that gate, an injected JS tag collects a large client-side fingerprint plus behavioral data, encrypts it, and POSTs it back; the server folds those signals into the score and sets/refreshes a signed `datadome` cookie carried on subsequent requests. When suspicion remains, DataDome escalates to its CAPTCHA or the invisible Device Check, which run heavier probes (notably the Picasso canvas challenge) whose results are again scored server-side. The client never learns the decision logic — it only collects and reports.

## Detection approaches

- **Browser/device fingerprinting** — client-side JS tag collecting ~190 signals (per DataDome's tag-optimization post).
- **Headless/automation detection** — generic CDP (Chrome DevTools Protocol) side-effect detection, plus framework traces.
- **Proof-of-work environment probes** — the Picasso canvas "red pill" device-class challenge.
- **Behavioral analysis** — mouse, touch, keystroke cadence, scroll velocity, click coordinates, and navigation/request sequences.
- **Server-side HTTP fingerprinting** — header ordering/presence, HTTP protocol version, browser-only headers → JA4H.
- **TLS fingerprinting** — cipher-suite list/order, extensions, curves on the ClientHello → JA3 / JA4.
- **TCP/IP-stack OS fingerprinting** — packet-level Layer 3/4 (Zardaxt-style; reportedly rare among vendors, per third-party sources).
- **IP / ASN / geolocation reputation** — datacenter vs residential vs mobile, proxy/VPN and residential-proxy detection, session reputation.
- **Signature-based detection** — known-bot repository plus a verified good-bot allowlist (search engines etc.).
- **Multi-layered ML** — supervised models, genetic algorithms, time-series analysis, anomaly/outlier detection, run in tandem.
- **LLM-crawler / AI-agent intent detection** — a newer product angle.

## Areas / signals scanned

### Client-side (JS tag / CAPTCHA / Device Check)
- `navigator` properties: `navigator.webdriver`, `plugins`, `deviceMemory`, `hardwareConcurrency`.
- GPU / WebGL renderer info and device memory.
- HTML canvas rendering via the **Picasso** device-class challenge.
- Audio/video codecs, supported media extensions, media capabilities.
- Installed fonts / font availability.
- Screen: max & current resolution, screen size, touch-action support, video quality.
- CDP/automation trace: `Error.stack` getter access triggered by `console.log` serialization (`Runtime.consoleAPICalled`) — see Verification notes on current reliability.
- **User-Agent Client Hints consistency** (a standard modern-Chromium check): `Sec-CH-UA` / `Sec-CH-UA-Platform` / `Sec-CH-UA-Mobile` vs the UA string and JS-derived platform. *(Expected of a vendor at this tier; not individually confirmed in the fetched DataDome posts.)*
- **WebRTC local/STUN IP** to pierce proxies/VPNs and expose real-IP vs proxy-IP mismatch. *(Classic anti-proxy signal; inferred, not confirmed in the DataDome sources.)*

### Server-side (IP / TLS / TCP / HTTP)
- IP address type (residential/mobile/datacenter), ASN, geolocation, proxy/VPN reputation, session reputation.
- TLS ClientHello → JA3 / JA4 hash.
- TCP/IP OS fingerprint (packet-level).
- HTTP: header ordering/presence, protocol version, UA → JA4H. An engineer should also expect **frame-level HTTP/2 fingerprinting** (SETTINGS-frame values, pseudo-header ordering, WINDOW_UPDATE/PRIORITY — Akamai-style) alongside JA4H; the fetched sources mention only generic "HTTP/1.1 vs HTTP/2" and header order, so treat the H2 frame detail as expected-but-unconfirmed.
- Signed `datadome` cookie integrity: cryptographic (HMAC-style) validation for tampering/forgery and replay checks — a core layer the client-side story alone misses.
- Consistency cross-checks: IP geolocation vs timezone vs `Accept-Language`; claimed OS/browser (UA) vs TLS/canvas/GPU-derived class.

### Behavioral
- Mouse movement trajectories/timing, touch events, keystroke cadence, scroll velocity, click coordinates.
- Request/navigation sequence and intent modeling, scored against a per-customer baseline.

## How it scans (architecture)

Hybrid, **decision on the server**, cascading edge-first:

1. **Edge, no JS required.** Every request's IP/ASN reputation, TCP/IP OS fingerprint, TLS ClientHello (JA3/JA4), and HTTP header/protocol fingerprint (JA4H) are evaluated first. Cheap kills (datacenter IP, TLS-vs-UA mismatch) happen here.
2. **Client JS tag.** DataDome injects an obfuscated tag (~26 KB gzipped per its engineering post) that collects ~190 fingerprint signals plus behavioral events, offloads heavy computation to a service worker, encrypts the payload, and POSTs it to a DataDome API endpoint. Reverse-engineering references the tag path `/include/tags.js`; the specific POST *host* (sometimes cited as `api-js.datadome.co`) is unconfirmed — see Verification notes. The response sets/refreshes the signed `datadome` cookie.
3. **Escalation.** On suspicion, DataDome serves its CAPTCHA or the invisible Device Check, which run additional probes including Picasso. Those results are POSTed back and scored server-side.

Putting the classifier server-side is deliberate: it keeps the logic out of reach of reverse engineers, and lets server-observed reality (TLS/TCP/IP) act as ground truth against which client-reported claims (UA, canvas, GPU) are checked for consistency.

## Scoring / output

The engine produces a real-time trust score per request (target < ~2 ms) by aggregating signals across request / session / IP / fingerprint over multiple time windows, then emits a decision: **allow, hard-block, or challenge**. Layers run in tandem: (1) verified good-bot allowlist + customer custom rules; (2) signature matching against a known-bot repository; (3) supervised models over fingerprints and request context; (4) genetic algorithms that autonomously mutate/test rule predicates against time-series of blocked traffic to grow new signatures; (5) behavioral/intent models; (6) time-series analysis; (7) anomaly/outlier detection at IP/session/fingerprint and whole-site level. Each site is scored against its own baseline via customer-specific models (DataDome states **"1,000+ OOTB and customer-specific models"** — see Verification notes; a widely-repeated "85,000+" figure is unverified). Picasso/Device Check add a **device-class verdict**: the client hashes the rendered canvas and the server checks whether that hash maps to the OS/browser class consistent with the claimed UA; a mismatch (e.g. a Linux-class render behind a Windows UA) blocks the user.

## Notable techniques

- **Picasso canvas proof-of-work (device-class "red pill").** Server sends a random seed of drawing instructions (curves, ellipses, gradients, fonts); the client renders invisibly, hashes the canvas, and returns it. Stable per-pixel GPU/driver/OS rendering differences reveal the true browser+OS class, catching environments that lie about themselves. Based on Google's 2016 "Picasso: Lightweight Device Class Fingerprinting" paper; a fresh seed each time defeats replay.
- **Generic CDP detection via `Error.stack`.** Define a getter on an `Error` object's non-standard `stack` property, then `console.log` the object; V8 serializes `stack` (invoking the getter) only when a CDP client has issued `Runtime.enable` — i.e. when Puppeteer/Playwright/Selenium is attached. This targets the automation *transport* rather than framework quirks. (Point-in-time — see Verification notes.)
- **TLS JA3/JA4-vs-UA inconsistency.** ML flags when the TLS handshake hash corresponds to a different OS/browser than the UA claims.
- **TCP/IP-stack OS fingerprinting** at Layer 3/4 (Zardaxt-style).
- **Genetic algorithms** that evolve detection predicates unsupervised.
- **Reverse-engineering resistance:** in-house obfuscator, tag splitting (unobfuscated CAPTCHA UI vs obfuscated signal collection), service-worker offloading to keep the tag fast.
- **Signed `datadome` cookie** with integrity + replay validation, so a captured/forged token cannot be reused.
- **Mobile SDKs with OS attestation** (worth an engineer's attention): DataDome ships native SDKs that can incorporate platform attestation (Android Play Integrity/SafetyNet, iOS App Attest/DeviceCheck) — a signal class with no browser equivalent. *(Product exists; specific attestation wiring is inferred, not confirmed in the fetched sources.)*
- **Cross-customer collective threat intelligence** (network effect): an IP/fingerprint seen attacking one protected site can be scored across the whole customer network — a hallmark not captured by the per-customer-baseline framing alone.

## What we observed firsthand

Nothing directly — DataDome has no public bot-score page, so unlike the other services in this set it could not be driven in the browser. What our recon of *sibling* tools establishes as relevant: our test browser's two most damning traits under DataDome's model were both confirmed elsewhere. (1) The egress IP `87.249.139.226` was independently classified as a NordVPN/DataCamp **datacenter** IP by multiple tools (incolumitas, Fingerprint's "data_center proxy provider", whoer's "Datacamp") — a signal DataDome evaluates server-side, pre-JS. (2) The browser is **CDP-driven Electron**, and `deviceandbrowserinfo.com` flagged it as a bot on `isAutomatedWithCDP: true` alone, while Fingerprint reported "Developer Tools: Yes" — the same CDP surface DataDome's `Error.stack` trick targets. There was no DataDome network traffic to capture (no `/include/tags.js`, no `datadome` cookie), because no site in the session was DataDome-protected.

## Verification notes

The adversarial review flagged the following; corrections are folded into the report above:

- **"85,000+ customer-specific models" is unsupported** (it appeared three times in the raw research). No DataDome source supports it; DataDome's own pages state **"1,000+ OOTB and customer-specific models."** The per-customer-baseline concept is real; the count in this report has been corrected to 1,000+ and the 85,000 figure marked unverified.
- **The "100k+ residential IPs with iOS TLS hash" example is unconfirmed.** The JA3/JA4-vs-UA mismatch *mechanism* is well documented, but that specific number/example could not be verified, so it has been dropped from the technique description (mechanism kept, figure removed).
- **The client-side POST host `api-js.datadome.co` is unconfirmed.** Reverse-engineering references the tag path `/include/tags.js`; the encrypted POST and payload are real, but the exact host is not established — stated as such above.
- **The CDP `Error.stack` / `Runtime.enable` signal is point-in-time.** It was accurate as of DataDome's June 2024 post, but later secondary reporting (Castle, Rebrowser, 2024–2025) indicates automation tools stopped auto-issuing `Runtime.enable`, neutralizing this specific detector. Presented as historically-accurate, not a durable present-day catch.
- **Antoine Vastel** authored the cited (2022–2024) blogs as DataDome's Head/VP of Research but left the company around end of 2024; this report avoids implying a current role.
- **"Server-side signals outweigh client-side scoring" is third-party inference** (ProxyHat, krowdev), not published by DataDome. The cascading edge-first architecture is well supported; the relative *weighting* is not something DataDome discloses, so it is framed as inference here.

The core mechanisms (Picasso, CDP `Error.stack`, TLS JA3/UA inconsistency, encrypted JS-tag POST + signed `datadome` cookie, multi-layer ML) come directly from DataDome's own engineering/threat-research blog and docs and are high-confidence.

## Open source / reusable

None from DataDome — the detection stack is proprietary and deliberately obfuscated. A builder can reuse the *ideas* and their public antecedents: Google's "Picasso: Lightweight Device Class Fingerprinting" paper (canvas proof-of-work), JA3/JA4 and JA4H TLS/HTTP fingerprint schemes (open specs and libraries), Zardaxt-style passive TCP/IP OS fingerprinting, and the CDP `Error.stack` detection trick (publicly described). For a JS-tag/behavioral collector to imitate, the open-source tools documented elsewhere in this set (fp-collect, fp-scanner, CreepJS, MixVisit) are the practical starting points.

## Sources

- [The Art of Bot Detection: How DataDome Uses Picasso for Device Class Fingerprinting (DataDome Threat Research)](https://datadome.co/threat-research/the-art-of-bot-detection-picasso-for-device-class-fingerprinting/)
- [How New Headless Chrome & the CDP Signal Are Impacting Bot Detection (DataDome Threat Research)](https://datadome.co/threat-research/how-new-headless-chrome-the-cdp-signal-are-impacting-bot-detection/)
- [How TLS Fingerprinting Reinforces DataDome's Protection (DataDome Engineering)](https://datadome.co/engineering/how-tls-fingerprinting-reinforces-datadomes-protection/)
- [Multi-Layered AI: A New Requirement for Sophisticated Bot Protection (DataDome)](https://datadome.co/bot-management-protection/multi-layered-machine-learning-a-new-requirement-for-sophisticated-bot-protection/)
- [DataDome's Client-Side JavaScript Tag is Faster Than Ever (DataDome Engineering)](https://datadome.co/engineering/client-side-javascript-tag-optimizations/)
- [Device Check (DataDome Docs)](https://docs.datadome.co/docs/device-check)
- [How to Bypass DataDome Anti-Scraping (Scrapfly technical guide)](https://scrapfly.io/blog/posts/how-to-bypass-datadome-anti-scraping)
- [How Websites Detect Bots in 2026 — JA4 & HTTP/2 Fingerprinting (krowdev)](https://krowdev.com/article/bot-detection-2026/)
- [DataDome Detection & How Legitimate Automation Passes (ProxyHat)](https://proxyhat.com/blog/datadome-detection-residential-proxies)
- [What exactly is DataDome's Device Check probing on our devices? (Privacy Guides community)](https://discuss.privacyguides.net/t/what-exactly-is-data-domes-device-check-probing-on-our-devices-to-prove-we-are-not-a-bot/32643)
- [DataDome (service homepage)](https://datadome.co/)
