# DataDome

Enterprise edge-deployed anti-bot & fraud protection. Scores every HTTP req real-time w/ server-side ML; escalates suspicious -> CAPTCHA or invisible "Device Check" client-side challenge. Production security product, not public "check my browser" scorer.

- **URL:** https://datadome.co/ · **Category:** commercial anti-bot vendor (demo/lead-gen only; no anonymous self-test) · **Requires registration:** yes for self-serve assessment — old anonymous `bot-tester.datadome.co` now returns `{"message":"Not Found"}`; successor "Vulnerability Scan" account-gated (`datadome.co/signup`). Device Check = no page to visit, fires only on DataDome-protected customer site.
- **Firsthand verdict for test browser:** Not obtainable — no public bot-score page, so documented from own engineering/threat-research blog + docs + independent reverse-engineering, not browser-driven. How it *would* treat test browser (in-app = `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): near worst-case. Egress datacenter/VPN IP (blockable server-side at edge pre-JS); CDP-driven Electron (exact automation-transport class its CDP detection targets); frozen macOS 10_15_7 UA -> TLS/UA & Client-Hints consistency failures. Every other tool inspecting CDP or datacenter IPs flagged it, so DataDome very likely challenges/hard-blocks. Inference, not observed.

## What it is — common info

Commercial bot- & fraud-protection SaaS (founded 2015, France/US). Edge module across 30+ PoPs; inspects every req < ~2 ms, ~trillions signals/day. "Advanced Threat Research" team's engineering write-ups = primary sources here. Audience: enterprise site operators (e-commerce, ticketing, classifieds, streaming) defending vs scraping, credential stuffing, account takeover, carding, & recently unwanted LLM/AI-agent crawling. Public "bot tester"/Vulnerability Scan = marketing lead-gen showing prospect their exposure; not analysis tool for arbitrary browsers.

## Registration / access

No anonymous public checker. Self-serve Vulnerability Scan requires account/domain entry. "Device Check" = product feature, never standalone URL — executes only on req to protected customer site when req looks suspicious. (Reg-flow detail medium-confidence, from search snippets + confirmed 404 of old tester URL.)

## How it decides bot-or-not

Per-req decision — **allow / hard-block / challenge** — computed **server-side** by real-time ML. Cascading, edge-first: cheap hard-to-forge server-side signals on first req (IP/ASN reputation, TCP/IP OS FP, TLS ClientHello, HTTP header & protocol FP); bad-enough signal (datacenter IP, TLS hash contradicting UA) -> block pre-JS. If req survives, injected JS tag collects large client-side FP + behavioral data, encrypts, POSTs back; server folds into score, sets/refreshes signed `datadome` cookie on later reqs. On remaining suspicion, escalates -> CAPTCHA or invisible Device Check w/ heavier probes (notably Picasso canvas challenge), again scored server-side. Client never learns decision logic — only collects & reports.

## Detection approaches

- **Browser/device fingerprinting** — client-side JS tag, ~190 signals (per DataDome tag-optimization post).
- **Headless/automation detection** — generic CDP (Chrome DevTools Protocol) side-effect detection + framework traces.
- **Proof-of-work env probes** — Picasso canvas "red pill" device-class challenge.
- **Behavioral analysis** — mouse, touch, keystroke cadence, scroll velocity, click coords, navigation/req sequences.
- **Server-side HTTP FP** — header ordering/presence, HTTP protocol version, browser-only headers -> JA4H.
- **TLS FP** — cipher-suite list/order, extensions, curves on ClientHello -> JA3 / JA4.
- **TCP/IP-stack OS FP** — packet-level L3/4 (Zardaxt-style; reportedly rare among vendors, per third-party sources).
- **IP / ASN / geolocation reputation** — datacenter vs residential vs mobile, proxy/VPN & residential-proxy detection, session reputation.
- **Signature-based** — known-bot repo + verified good-bot allowlist (search engines etc.).
- **Multi-layered ML** — supervised models, genetic algorithms, time-series analysis, anomaly/outlier detection, in tandem.
- **LLM-crawler / AI-agent intent detection** — newer product angle.

## Areas / signals scanned

### Client-side (JS tag / CAPTCHA / Device Check)
- `navigator` props: `navigator.webdriver`, `plugins`, `deviceMemory`, `hardwareConcurrency`.
- GPU / WebGL renderer info + device memory.
- Canvas rendering via **Picasso** device-class challenge.
- Audio/video codecs, supported media extensions, media capabilities.
- Installed fonts / font availability.
- Screen: max & current resolution, screen size, touch-action support, video quality.
- CDP/automation trace: `Error.stack` getter access triggered by `console.log` serialization (`Runtime.consoleAPICalled`) — see Verification notes on current reliability.
- **UA Client Hints consistency** (standard modern-Chromium check): `Sec-CH-UA` / `Sec-CH-UA-Platform` / `Sec-CH-UA-Mobile` vs UA string & JS-derived platform. *(Expected at this tier; not individually confirmed in fetched posts.)*
- **WebRTC local/STUN IP** pierces proxies/VPNs, exposes real-IP vs proxy-IP mismatch. *(Classic anti-proxy signal; inferred, not confirmed in DataDome sources.)*

### Server-side (IP / TLS / TCP / HTTP)
- IP type (residential/mobile/datacenter), ASN, geolocation, proxy/VPN reputation, session reputation.
- TLS ClientHello -> JA3 / JA4 hash.
- TCP/IP OS FP (packet-level).
- HTTP: header ordering/presence, protocol version, UA -> JA4H. Also expect **frame-level HTTP/2 fingerprinting** (SETTINGS-frame values, pseudo-header ordering, WINDOW_UPDATE/PRIORITY — Akamai-style) alongside JA4H; fetched sources mention only generic "HTTP/1.1 vs HTTP/2" & header order, so treat H2 frame detail as expected-but-unconfirmed.
- Signed `datadome` cookie integrity: cryptographic (HMAC-style) validation for tampering/forgery & replay — core layer client-side story alone misses.
- Consistency cross-checks: IP geolocation vs timezone vs `Accept-Language`; claimed OS/browser (UA) vs TLS/canvas/GPU-derived class.

### Behavioral
- Mouse trajectories/timing, touch events, keystroke cadence, scroll velocity, click coords.
- Req/navigation sequence & intent modeling, scored vs per-customer baseline.

## How it scans (architecture)

Hybrid, **decision on server**, cascading edge-first:

1. **Edge, no JS required.** Every req's IP/ASN reputation, TCP/IP OS FP, TLS ClientHello (JA3/JA4), HTTP header/protocol FP (JA4H) evaluated first. Cheap kills (datacenter IP, TLS-vs-UA mismatch) here.
2. **Client JS tag.** Injects obfuscated tag (~26 KB gzipped per engineering post) collecting ~190 FP signals + behavioral events, offloads heavy compute to service worker, encrypts payload, POSTs to DataDome API. Reverse-engineering references tag path `/include/tags.js`; POST *host* (sometimes cited `api-js.datadome.co`) unconfirmed — see Verification notes. Response sets/refreshes signed `datadome` cookie.
3. **Escalation.** On suspicion, serves CAPTCHA or invisible Device Check w/ extra probes incl. Picasso. Results POSTed back, scored server-side.

Server-side classifier deliberate: keeps logic from reverse engineers; server-observed reality (TLS/TCP/IP) = ground truth vs which client claims (UA, canvas, GPU) checked for consistency.

## Scoring / output

Real-time trust score per req (target < ~2 ms), aggregating signals across req / session / IP / FP over multiple time windows, then emits **allow, hard-block, or challenge**. Layers in tandem: (1) verified good-bot allowlist + customer custom rules; (2) signature matching vs known-bot repo; (3) supervised models over FPs & req context; (4) genetic algorithms autonomously mutating/testing rule predicates vs time-series of blocked traffic to grow new signatures; (5) behavioral/intent models; (6) time-series analysis; (7) anomaly/outlier detection at IP/session/FP & whole-site level. Each site scored vs own baseline via customer-specific models (DataDome states **"1,000+ OOTB and customer-specific models"** — see Verification notes; widely-repeated "85,000+" unverified). Picasso/Device Check add **device-class verdict**: client hashes rendered canvas, server checks hash maps to OS/browser class consistent w/ claimed UA; mismatch (e.g. Linux-class render behind Windows UA) -> block.

## Notable techniques

- **Picasso canvas proof-of-work (device-class "red pill").** Server sends random seed of drawing instructions (curves, ellipses, gradients, fonts); client renders invisibly, hashes canvas, returns. Stable per-pixel GPU/driver/OS rendering diffs reveal true browser+OS class, catch environments lying. Based on Google's 2016 "Picasso: Lightweight Device Class Fingerprinting" paper; fresh seed each time defeats replay.
- **Generic CDP detection via `Error.stack`.** Define getter on `Error`'s non-standard `stack` prop, then `console.log` the object; V8 serializes `stack` (invoking getter) only when CDP client issued `Runtime.enable` — i.e. Puppeteer/Playwright/Selenium attached. Targets automation *transport*, not framework quirks. (Point-in-time — see Verification notes.)
- **TLS JA3/JA4-vs-UA inconsistency.** ML flags TLS handshake hash = different OS/browser than UA claims.
- **TCP/IP-stack OS fingerprinting** at L3/4 (Zardaxt-style).
- **Genetic algorithms** evolving detection predicates unsupervised.
- **Reverse-engineering resistance:** in-house obfuscator, tag splitting (unobfuscated CAPTCHA UI vs obfuscated signal collection), service-worker offloading to keep tag fast.
- **Signed `datadome` cookie** w/ integrity + replay validation, so captured/forged token can't be reused.
- **Mobile SDKs w/ OS attestation** (worth engineer's attention): native SDKs w/ platform attestation (Android Play Integrity/SafetyNet, iOS App Attest/DeviceCheck) — signal class w/ no browser equivalent. *(Product exists; attestation wiring inferred, not confirmed in fetched sources.)*
- **Cross-customer collective threat intelligence** (network effect): IP/FP attacking one protected site scored across whole customer network — not captured by per-customer-baseline framing alone.

## What we observed firsthand

Nothing directly — no public bot-score page, so couldn't drive in browser. Recon of *sibling* tools establishes: test browser's 2 most damning traits under DataDome's model both confirmed elsewhere. (1) Egress IP `87.249.139.226` independently classified NordVPN/DataCamp **datacenter** by multiple tools (incolumitas, Fingerprint "data_center proxy provider", whoer "Datacamp") — signal DataDome evaluates server-side, pre-JS. (2) Browser = **CDP-driven Electron**; `deviceandbrowserinfo.com` flagged bot on `isAutomatedWithCDP: true` alone, Fingerprint reported "Developer Tools: Yes" — same CDP surface DataDome's `Error.stack` trick targets. No DataDome traffic to capture (no `/include/tags.js`, no `datadome` cookie), since no site in session was DataDome-protected.

## Verification notes

Adversarial review flagged following; corrections folded into report above:

- **"85,000+ customer-specific models" unsupported** (appeared 3x in raw research). No DataDome source supports it; DataDome's pages state **"1,000+ OOTB and customer-specific models."** Per-customer-baseline concept real; count corrected to 1,000+, 85,000 marked unverified.
- **"100k+ residential IPs with iOS TLS hash" example unconfirmed.** JA3/JA4-vs-UA mismatch *mechanism* well documented, but that number/example unverified, dropped (mechanism kept, figure removed).
- **Client-side POST host `api-js.datadome.co` unconfirmed.** Reverse-engineering references tag path `/include/tags.js`; encrypted POST & payload real, but exact host not established.
- **CDP `Error.stack` / `Runtime.enable` signal point-in-time.** Accurate as of DataDome's June 2024 post, but later secondary reporting (Castle, Rebrowser, 2024–2025) indicates automation tools stopped auto-issuing `Runtime.enable`, neutralizing this detector. Historically-accurate, not durable present-day catch.
- **Antoine Vastel** authored cited (2022–2024) blogs as DataDome's Head/VP of Research but left ~end of 2024; report avoids implying current role.
- **"Server-side signals outweigh client-side scoring" = third-party inference** (ProxyHat, krowdev), not published by DataDome. Cascading edge-first architecture well supported; relative *weighting* undisclosed, framed as inference.

Core mechanisms (Picasso, CDP `Error.stack`, TLS JA3/UA inconsistency, encrypted JS-tag POST + signed `datadome` cookie, multi-layer ML) come directly from DataDome's own engineering/threat-research blog & docs, high-confidence.

## Open source / reusable

None from DataDome — stack proprietary & deliberately obfuscated. Builder can reuse the *ideas* & public antecedents: Google's "Picasso: Lightweight Device Class Fingerprinting" paper (canvas proof-of-work), JA3/JA4 & JA4H TLS/HTTP FP schemes (open specs & libraries), Zardaxt-style passive TCP/IP OS fingerprinting, CDP `Error.stack` trick (publicly described). For JS-tag/behavioral collector to imitate, open-source tools documented elsewhere in this set (fp-collect, fp-scanner, CreepJS, MixVisit) = practical starting points.

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
