# DataDome

Enterprise, edge-deployed anti-bot and online-fraud protection scoring every HTTP request real time with server-side ML, escalating suspicious traffic to CAPTCHA or invisible "Device Check" client-side challenge. Production security product, not public "check my browser" scorer.

- **URL:** https://datadome.co/ · **Category:** commercial anti-bot vendor (demo/lead-gen only; no anonymous self-test) · **Requires registration:** yes for self-serve assessment — old anonymous `bot-tester.datadome.co` now returns `{"message":"Not Found"}`; successor "Vulnerability Scan" account-gated (`datadome.co/signup`). Device Check has no page to visit — fires only on DataDome-protected customer site.
- **Firsthand verdict for test browser:** Not obtainable firsthand — DataDome exposes no public bot-score page, so documented from own engineering/threat-research blog + docs plus independent reverse-engineering, not by driving it in browser. Reasoning about how it *would* treat our test browser (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): close to worst-case profile for DataDome. Egress is datacenter/VPN IP (blockable server-side at edge before any JS runs), browser is CDP-driven Electron (exact automation-transport class its CDP detection targets), frozen macOS 10_15_7 User-Agent invites TLS/UA and Client-Hints consistency failures. Every other tool in this set inspecting CDP or datacenter IPs flagged this browser, so DataDome would very likely challenge or hard-block it. Treat as inference, not observed verdict.

## What it is — common info

DataDome: commercial bot- and fraud-protection SaaS (founded 2015, France/US). Deploys as edge module across 30+ points of presence, states it inspects every request in under ~2 ms, processing on order of trillions of signals per day. Maintains "Advanced Threat Research" team publishing unusually detailed engineering write-ups — primary sources for this report. Audience: enterprise site operators (e-commerce, ticketing, classifieds, streaming) defending against scraping, credential stuffing, account takeover, carding, and, more recently, unwanted LLM/AI-agent crawling. Public "bot tester" / Vulnerability Scan is marketing lead-gen showing prospect their exposure; not analysis tool for arbitrary browsers.

## Registration / access

No anonymous public checker. Self-serve Vulnerability Scan requires creating account / entering domain. "Device Check" is product feature, never standalone URL — executes only when you request protected customer site and request looks suspicious. (Registration-flow detail medium-confidence, from search snippets plus confirmed 404 of old tester URL.)

## How it decides bot-or-not

DataDome makes per-request decision — **allow / hard-block / challenge** — computed **server-side** by real-time ML engine. Decision cascading and edge-first: cheap, hard-to-forge server-side signals evaluated on very first request (IP/ASN reputation, TCP/IP OS fingerprint, TLS ClientHello, HTTP header and protocol fingerprint), bad enough signal (e.g. datacenter IP, or TLS hash contradicting User-Agent) can block before any JavaScript runs. If request survives that gate, injected JS tag collects large client-side fingerprint plus behavioral data, encrypts it, POSTs it back; server folds those signals into score, sets/refreshes signed `datadome` cookie carried on subsequent requests. When suspicion remains, DataDome escalates to CAPTCHA or invisible Device Check, running heavier probes (notably Picasso canvas challenge) whose results again scored server-side. Client never learns decision logic — only collects and reports.

## Detection approaches

- **Browser/device fingerprinting** — client-side JS tag collecting ~190 signals (per DataDome's tag-optimization post).
- **Headless/automation detection** — generic CDP (Chrome DevTools Protocol) side-effect detection, plus framework traces.
- **Proof-of-work environment probes** — Picasso canvas "red pill" device-class challenge.
- **Behavioral analysis** — mouse, touch, keystroke cadence, scroll velocity, click coordinates, navigation/request sequences.
- **Server-side HTTP fingerprinting** — header ordering/presence, HTTP protocol version, browser-only headers → JA4H.
- **TLS fingerprinting** — cipher-suite list/order, extensions, curves on ClientHello → JA3 / JA4.
- **TCP/IP-stack OS fingerprinting** — packet-level Layer 3/4 (Zardaxt-style; reportedly rare among vendors, per third-party sources).
- **IP / ASN / geolocation reputation** — datacenter vs residential vs mobile, proxy/VPN and residential-proxy detection, session reputation.
- **Signature-based detection** — known-bot repository plus verified good-bot allowlist (search engines etc.).
- **Multi-layered ML** — supervised models, genetic algorithms, time-series analysis, anomaly/outlier detection, run in tandem.
- **LLM-crawler / AI-agent intent detection** — newer product angle.

## Areas / signals scanned

### Client-side (JS tag / CAPTCHA / Device Check)
- `navigator` properties: `navigator.webdriver`, `plugins`, `deviceMemory`, `hardwareConcurrency`.
- GPU / WebGL renderer info and device memory.
- HTML canvas rendering via **Picasso** device-class challenge.
- Audio/video codecs, supported media extensions, media capabilities.
- Installed fonts / font availability.
- Screen: max & current resolution, screen size, touch-action support, video quality.
- CDP/automation trace: `Error.stack` getter access triggered by `console.log` serialization (`Runtime.consoleAPICalled`) — see Verification notes on current reliability.
- **User-Agent Client Hints consistency** (standard modern-Chromium check): `Sec-CH-UA` / `Sec-CH-UA-Platform` / `Sec-CH-UA-Mobile` vs UA string and JS-derived platform. *(Expected of vendor at this tier; not individually confirmed in fetched DataDome posts.)*
- **WebRTC local/STUN IP** to pierce proxies/VPNs, expose real-IP vs proxy-IP mismatch. *(Classic anti-proxy signal; inferred, not confirmed in DataDome sources.)*

### Server-side (IP / TLS / TCP / HTTP)
- IP address type (residential/mobile/datacenter), ASN, geolocation, proxy/VPN reputation, session reputation.
- TLS ClientHello → JA3 / JA4 hash.
- TCP/IP OS fingerprint (packet-level).
- HTTP: header ordering/presence, protocol version, UA → JA4H. Engineer should also expect **frame-level HTTP/2 fingerprinting** (SETTINGS-frame values, pseudo-header ordering, WINDOW_UPDATE/PRIORITY — Akamai-style) alongside JA4H; fetched sources mention only generic "HTTP/1.1 vs HTTP/2" and header order, so treat H2 frame detail as expected-but-unconfirmed.
- Signed `datadome` cookie integrity: cryptographic (HMAC-style) validation for tampering/forgery and replay checks — core layer client-side story alone misses.
- Consistency cross-checks: IP geolocation vs timezone vs `Accept-Language`; claimed OS/browser (UA) vs TLS/canvas/GPU-derived class.

### Behavioral
- Mouse movement trajectories/timing, touch events, keystroke cadence, scroll velocity, click coordinates.
- Request/navigation sequence and intent modeling, scored against per-customer baseline.

## How it scans (architecture)

Hybrid, **decision on server**, cascading edge-first:

1. **Edge, no JS required.** Every request's IP/ASN reputation, TCP/IP OS fingerprint, TLS ClientHello (JA3/JA4), HTTP header/protocol fingerprint (JA4H) evaluated first. Cheap kills (datacenter IP, TLS-vs-UA mismatch) happen here.
2. **Client JS tag.** DataDome injects obfuscated tag (~26 KB gzipped per its engineering post) collecting ~190 fingerprint signals plus behavioral events, offloads heavy computation to service worker, encrypts payload, POSTs to DataDome API endpoint. Reverse-engineering references tag path `/include/tags.js`; specific POST *host* (sometimes cited as `api-js.datadome.co`) unconfirmed — see Verification notes. Response sets/refreshes signed `datadome` cookie.
3. **Escalation.** On suspicion, DataDome serves CAPTCHA or invisible Device Check, running additional probes incl. Picasso. Results POSTed back, scored server-side.

Putting classifier server-side is deliberate: keeps logic out of reach of reverse engineers, lets server-observed reality (TLS/TCP/IP) act as ground truth against which client-reported claims (UA, canvas, GPU) checked for consistency.

## Scoring / output

Engine produces real-time trust score per request (target < ~2 ms) by aggregating signals across request / session / IP / fingerprint over multiple time windows, then emits decision: **allow, hard-block, or challenge**. Layers run in tandem: (1) verified good-bot allowlist + customer custom rules; (2) signature matching against known-bot repository; (3) supervised models over fingerprints and request context; (4) genetic algorithms autonomously mutating/testing rule predicates against time-series of blocked traffic to grow new signatures; (5) behavioral/intent models; (6) time-series analysis; (7) anomaly/outlier detection at IP/session/fingerprint and whole-site level. Each site scored against own baseline via customer-specific models (DataDome states **"1,000+ OOTB and customer-specific models"** — see Verification notes; widely-repeated "85,000+" figure unverified). Picasso/Device Check add **device-class verdict**: client hashes rendered canvas, server checks whether hash maps to OS/browser class consistent with claimed UA; mismatch (e.g. Linux-class render behind Windows UA) blocks user.

## Notable techniques

- **Picasso canvas proof-of-work (device-class "red pill").** Server sends random seed of drawing instructions (curves, ellipses, gradients, fonts); client renders invisibly, hashes canvas, returns it. Stable per-pixel GPU/driver/OS rendering differences reveal true browser+OS class, catches environments lying about themselves. Based on Google's 2016 "Picasso: Lightweight Device Class Fingerprinting" paper; fresh seed each time defeats replay.
- **Generic CDP detection via `Error.stack`.** Define getter on `Error` object's non-standard `stack` property, then `console.log` the object; V8 serializes `stack` (invoking getter) only when CDP client has issued `Runtime.enable` — i.e. when Puppeteer/Playwright/Selenium is attached. Targets automation *transport* rather than framework quirks. (Point-in-time — see Verification notes.)
- **TLS JA3/JA4-vs-UA inconsistency.** ML flags when TLS handshake hash corresponds to different OS/browser than UA claims.
- **TCP/IP-stack OS fingerprinting** at Layer 3/4 (Zardaxt-style).
- **Genetic algorithms** evolving detection predicates unsupervised.
- **Reverse-engineering resistance:** in-house obfuscator, tag splitting (unobfuscated CAPTCHA UI vs obfuscated signal collection), service-worker offloading to keep tag fast.
- **Signed `datadome` cookie** with integrity + replay validation, so captured/forged token can't be reused.
- **Mobile SDKs with OS attestation** (worth engineer's attention): DataDome ships native SDKs incorporating platform attestation (Android Play Integrity/SafetyNet, iOS App Attest/DeviceCheck) — signal class with no browser equivalent. *(Product exists; specific attestation wiring inferred, not confirmed in fetched sources.)*
- **Cross-customer collective threat intelligence** (network effect): IP/fingerprint seen attacking one protected site can be scored across whole customer network — hallmark not captured by per-customer-baseline framing alone.

## What we observed firsthand

Nothing directly — DataDome has no public bot-score page, so unlike other services in this set couldn't be driven in browser. What our recon of *sibling* tools establishes as relevant: our test browser's two most damning traits under DataDome's model both confirmed elsewhere. (1) Egress IP `87.249.139.226` independently classified as NordVPN/DataCamp **datacenter** IP by multiple tools (incolumitas, Fingerprint's "data_center proxy provider", whoer's "Datacamp") — signal DataDome evaluates server-side, pre-JS. (2) Browser is **CDP-driven Electron**, `deviceandbrowserinfo.com` flagged it as bot on `isAutomatedWithCDP: true` alone, Fingerprint reported "Developer Tools: Yes" — same CDP surface DataDome's `Error.stack` trick targets. No DataDome network traffic to capture (no `/include/tags.js`, no `datadome` cookie), since no site in session was DataDome-protected.

## Verification notes

Adversarial review flagged following; corrections folded into report above:

- **"85,000+ customer-specific models" unsupported** (appeared three times in raw research). No DataDome source supports it; DataDome's own pages state **"1,000+ OOTB and customer-specific models."** Per-customer-baseline concept real; count in this report corrected to 1,000+, 85,000 figure marked unverified.
- **"100k+ residential IPs with iOS TLS hash" example unconfirmed.** JA3/JA4-vs-UA mismatch *mechanism* well documented, but that specific number/example couldn't be verified, dropped from technique description (mechanism kept, figure removed).
- **Client-side POST host `api-js.datadome.co` unconfirmed.** Reverse-engineering references tag path `/include/tags.js`; encrypted POST and payload real, but exact host not established — stated as such above.
- **CDP `Error.stack` / `Runtime.enable` signal is point-in-time.** Accurate as of DataDome's June 2024 post, but later secondary reporting (Castle, Rebrowser, 2024–2025) indicates automation tools stopped auto-issuing `Runtime.enable`, neutralizing this specific detector. Presented as historically-accurate, not durable present-day catch.
- **Antoine Vastel** authored cited (2022–2024) blogs as DataDome's Head/VP of Research but left company around end of 2024; report avoids implying current role.
- **"Server-side signals outweigh client-side scoring" is third-party inference** (ProxyHat, krowdev), not published by DataDome. Cascading edge-first architecture well supported; relative *weighting* not something DataDome discloses, so framed as inference here.

Core mechanisms (Picasso, CDP `Error.stack`, TLS JA3/UA inconsistency, encrypted JS-tag POST + signed `datadome` cookie, multi-layer ML) come directly from DataDome's own engineering/threat-research blog and docs, high-confidence.

## Open source / reusable

None from DataDome — detection stack proprietary and deliberately obfuscated. Builder can reuse the *ideas* and public antecedents: Google's "Picasso: Lightweight Device Class Fingerprinting" paper (canvas proof-of-work), JA3/JA4 and JA4H TLS/HTTP fingerprint schemes (open specs and libraries), Zardaxt-style passive TCP/IP OS fingerprinting, CDP `Error.stack` detection trick (publicly described). For JS-tag/behavioral collector to imitate, open-source tools documented elsewhere in this set (fp-collect, fp-scanner, CreepJS, MixVisit) are practical starting points.

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
