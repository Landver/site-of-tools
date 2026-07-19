# Fingerprint.com (Fingerprint Pro / Smart Signals) — playground demo

Commercial device-intelligence vendor's live playground: fingerprints your browser into persistent visitor ID, lights up suite of fraud "Smart Signals" (bot, VPN, incognito, tampering, VM, developer tools, IP blocklist, velocity) plus aggregate numeric **Suspect Score**. Passive identification-and-correlation engine, not edge WAF, not CAPTCHA.

- **URL:** https://demo.fingerprint.com/playground · **Category:** commercial anti-bot / device-intelligence vendor demo (live product playground for paid Fingerprint Pro + Smart Signals — *not* open-source test page) · **Requires registration:** No for playground (runs against your own browser instantly using Fingerprint's own key). Account/API key only needed to integrate Fingerprint into *your own* site; product pages surface "Get started" CTAs, artifact behind occasional "registration required" scrapes.
- **Firsthand verdict for test browser** (`Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): **Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, correctly identified as "Electron 42.5.1".** Smart Signals: **Bot = Not detected**, VPN = "You are using a VPN (public VPN IP, timezone mismatch)", Incognito = "You are incognito", **Developer Tools = Yes**, IP Blocklist = "data_center proxy provider", Virtual Machine = Not detected, Browser Tampering = Not detected, Privacy Settings = Not detected, High-Activity Device = Not detected, Velocity = 1 IP / 1 linked ID in 24h, Geolocation = Istanbul TR. **Suspect Score = 33.** Notably, Fingerprint did **not** classify CDP-driven Electron browser as bot even though it flagged Developer Tools, VPN, datacenter IP — bot signal targets known automation frameworks/VMs, not mere presence of debugging protocol.

## What it is — common info

Run by Fingerprint (company formerly "FingerprintJS, Inc."), device-intelligence / fraud-prevention vendor. Grew out of open-source FingerprintJS browser-fingerprinting library into commercial "Fingerprint Pro / Identification" platform layered with "Smart Signals" fraud-signal suite. Demo is sales/marketing showcase: prospect runs Fingerprint against own browser real time, watches persistent visitor ID and each Smart Signal resolve. Doubles as ~13 interactive fraud use-case demos (Playground, Coupon Fraud, Credential Stuffing, Account Sharing, Payment Fraud, Loan Risk, Paywall, Personalization, Web Scraping Prevention, Bot Firewall, SMS Pumping, VPN Detection, New Account Fraud). Audience: fraud/risk and platform engineers evaluating paid product. On 2025-07-15 Fingerprint launched refreshed Bot Detection signal plus VM Detection, Residential Proxy Detection, AI-request filtering, explicitly positioned against AI-agent / autonomous-browser fraud.

## Registration / access

Playground free, no login, no credit card. Registration (14-day trial dashboard signup) exists only to get API key for own integration, doesn't gate demo.

## How it decides bot-or-not

Lightweight JavaScript agent runs in browser, collects large device/browser fingerprint plus automation markers, POSTs identification event to Fingerprint's backend. Backend fuses those client signals with **server/network data browser cannot see or forge** — IP address, geolocation, IP blocklist membership, VPN / residential-proxy reputation, cross-request velocity — then returns **stable visitor ID (with confidence score)** and Smart Signals. Bot verdict itself produced **server-side** by ML classifier "on each API request," which both protects classification logic from reverse engineering and lets it combine client- and server-observed facts. Design **passive and frictionless**: no CAPTCHA, no proof-of-work, no interstitial challenge.

## Detection approaches

- **Browser/device fingerprinting** — 100+ signals fused into persistent visitor ID engineered to survive incognito, cookie clearing, VPN switching.
- **Headless / automation-tool detection** — identifies Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Electron, SlimerJS, headless Chrome/Firefox (lineage of open-source BotD library).
- **Bot classification (ML)** — `good` / `bad` / `notDetected`, decided per API request server-side.
- **Network / IP reputation** — geolocation, IP blocklist matching, VPN detection, residential-proxy detection (graded confidence).
- **Browser tampering / anti-detect-browser detection** — attribute-inconsistency analysis (e.g. spoofed mobile UA that doesn't match real device attributes).
- **Virtualization / emulation detection** — virtual machine, Android emulator (mobile SDK also: iOS Simulator), rooted/jailbroken device.
- **Incognito / private-mode detection.**
- **Velocity signals** — cross-request device-activity spikes (this is *not* behavioral biometrics; see below).
- **AI-agent detection & request filtering** — matches known AI-company user agents to separate benign AI (assistants, approved crawlers) from malicious automation; also reduces billable events.
- **Not present:** no behavioral biometrics, no active challenge, no TLS/JA3/JA4 or HTTP/2 transport fingerprinting (see Verification notes and capability boundary below).

## Areas / signals scanned

**Client-side (JS agent):** navigator properties (languages, plugins, platform, hardwareConcurrency, userAgent); canvas fingerprint; WebGL / GPU renderer; AudioContext fingerprint; installed fonts; screen resolution / color depth; timezone; user-agent string and self-consistency; large "Raw Device Attributes" JSON (commercial add-on, returned live in our run); `navigator.webdriver`; Chrome DevTools Protocol (CDP) artifacts; `chrome.runtime` / `window.chrome` presence; error stack traces and non-native property descriptors (tampering tells). Named consumer-facing Smart Signals in this layer include **Browser Tampering**, **Developer Tools Detection**, **Privacy-Focused Settings**, **Incognito**, **Device Rarity / High-Activity Device**.

**Server-side (IP / network):** IP address + geolocation; IP blocklist membership; VPN indicators (UA/timezone inconsistent with browser attributes); residential-proxy indicators (with confidence); virtual-machine / emulator signatures (partly server-correlated); request headers / known AI user agents; cross-request velocity. **No** TLS/JA3, TCP/IP SYN, or header-order fingerprinting — Fingerprint is JS-agent + server-correlation vendor, not inline edge proxy.

**Behavioral:** none in classical sense. Fingerprint does **not** analyze mouse trajectories, keystroke dynamics, scroll, or touch gestures. "Velocity" measures request cadence across device/IP, not human-motion biometrics — defining architectural distinction from HUMAN/PerimeterX or DataDome.

**Mobile SDK signals (native, not exercised by browser demo):** Frida instrumentation, factory-reset timestamp, geolocation spoofing, emulator / iOS Simulator, rooted / jailbroken, cloned app, MITM attack, tampered request.

## How it scans (architecture)

Confirmed via network capture during our run — four-step client+server flow:

1. **First-party proxied agent load.** JS agent served from randomized, first-party path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8/web`. (Fingerprint's default public CDN host is `fpjscdn.net/v4/<api-key>`; demo instead uses same-subdomain proxying, real deployment option that defeats adblock/tracker filters and denies bot authors fixed third-party URL to block.)
2. **Ingestion POST.** Agent collects signals, POSTs identification event to `POST /DBqbMN7zXxwl4Ei8` (same first-party path).
3. **Minimal JS agent response.** Browser receives only `{event_id, visitor_id, suspect_score}` — no detailed verdicts land in client.
4. **Trusted server-to-server fetch.** Customer's *own* server calls Fingerprint Server API (`POST /api/event/v4/<eventId>`) to retrieve full, sealed result: `{bot, vpn, ip_info(datacenter_result, asn_type:hosting), developer_tools, …}`.

**Decision made server-side.** Client-originated signals treated as untrusted; authoritative verdict fetched server-to-server, tied to `event_id` / `requestId` so client can't forge it. This server-side layer is exactly what vendor says separates Pro's accuracy from client-only open-source libraries.

## Scoring / output

Two distinct outputs, easy to conflate:

- **Bot field (categorical):** `good` (approved/known crawler — Google/Bing/Yahoo/Yandex), `bad` (automation tool or VM), or `notDetected` (human/legitimate). Demo UI renders `notDetected` as "Not detected."
- **Suspect Score (numeric):** Fingerprint's headline top-level Smart Signal — weighted aggregate of individual signals, documented range `0` to sum of all enabled signal weights. **Our test browser scored 33.** Closest thing to single "bot-or-not" number, real and prominent product feature (contrary to any "no score" framing).
- Other Smart Signals return booleans plus, where applicable, confidence indicator (e.g. VPN and residential-proxy results carry confidence). Identification returns stable `visitorId` with own confidence score (1 in our run).

## Notable techniques

- **CDP detection via `Runtime.enable` serialization side effect** — log object with getter property, observe whether getter fires; fires only when page driven over Chrome DevTools Protocol (Playwright/Puppeteer/Selenium 4). Technique real, later V8 change broke part of it. *Attribution note:* prominent public write-ups on this specific getter trick come from Rebrowser project and Castle / Antoine Vastel / DataDome; associating it specifically with Fingerprint engineers unconfirmed.
- **Persistent visitor ID** surviving incognito, cookie clearing, VPN switching — core selling point.
- **VPN detection by consistency-checking** — flags when reported UA/timezone inconsistent with browser's other attributes (precisely why our datacenter-egress browser was flagged: "public VPN IP, timezone mismatch").
- **Tampering / anti-detect-browser detection** by spotting attribute inconsistencies.
- **Fusing server/network signals invisible to browser** with client fingerprint, so client-side spoofing alone can't defeat verdict.
- **Residential-proxy detection with graded confidence** and **AI user-agent filtering**, both aimed at agentic/AI fraud.

## What we observed firsthand

Ground truth from driving playground in test browser (prefer over research where they differ):

- Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, "Electron 42.5.1" identified correctly.
- **Bot = Not detected** despite browser being CDP-driven — Fingerprint's bot signal didn't fire on our environment (whereas Developer Tools = Yes did).
- VPN = flagged ("public VPN IP, timezone mismatch"); IP Blocklist = "data_center proxy provider"; Incognito = detected; VM / Tampering / Privacy Settings / High-Activity = Not detected.
- **Suspect Score = 33.**
- Network evidence for four-step architecture above: agent served from and posting to first-party randomized path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8` (`/web` for agent, base path for ingestion); minimal `{event_id, visitor_id, suspect_score}` returned to browser; full result designed to be fetched via Server API `POST /api/event/v4/<eventId>`.

## Verification notes

Adversarial review corrected several claims in underlying research; folded in above and flagged here so rest can be trusted:

- **TLS fingerprinting claim was fabricated.** Research asserted "TLS-fingerprint-based bot detection at edge described in Fingerprint's own patents." Matching patent (US 11,799,908, edge-network TLS-fingerprint bot detection) assigned to **Akamai**, not Fingerprint, and Fingerprint's own Smart Signals reference lists **no** TLS/JA3/JA4 signal. Fingerprint is JS-agent + server-correlation vendor, not inline edge proxy. Report treats transport fingerprinting (TLS/JA3/JA4, TCP/IP, HTTP/2 frames) as **capability boundary Fingerprint does not cross** — domain of Cloudflare/Akamai/DataDome.
- **"No score" was wrong.** Bot *field* is categorical, but Fingerprint ships numeric **Suspect Score** (confirmed live at 33). Documented and headline; report treats it as primary numeric output.
- **Hashing detail corrected/unverified.** Research's "MurmurHash3 (32-bit) → 32-char hex" internally inconsistent (32-bit yields 8 hex chars). Open-source visitorId is 32-char hex hash (consistent with 128-bit MurmurHash / x64hash128), but cited repo README doesn't name algorithm, so specific algorithm name **unverified**, not stated as fact here.
- **Open-source accuracy/attribute figures unverified.** "~40–60% accuracy" and "50+ attributes" for open-source FingerprintJS not in cited README, which only says accuracy "significantly lower" than Pro. Treated as **unverified/marketing-adjacent**, omitted as fact. "100+ signals" figure for Pro *is* confirmed.
- **CDP-trick attribution** to Fingerprint engineers is **unconfirmed** (see Notable techniques).
- **Confirmed:** no-login demo running against visitor's own browser; bot values `good`/`bad`/`notDetected` (camelCase; search engines = good); agent from `fpjscdn.net/v4/<api-key>` by default; BotD and FingerprintJS both MIT and 100% client-side; 2025-07-15 launch of Bot/VM/Residential-Proxy/Request-Filtering signals.

## Open source / reusable

Two MIT-licensed client-side libraries from same company are open-source ancestors of product (demo itself runs closed Pro engine, vendor states markedly more accurate):

- **FingerprintJS** — browser fingerprinting → client-only visitor ID: https://github.com/fingerprintjs/fingerprintjs
- **BotD** — in-browser bot/automation detection (Selenium/Playwright/Puppeteer/PhantomJS/Nightmare/Electron/SlimerJS/headless): https://github.com/fingerprintjs/BotD

Builder can reuse these directly for client-side layer, but note accuracy comes from proprietary server-side fusion (IP/proxy reputation, velocity, ML classification), not open source.

## Sources

- [Fingerprint Demo — Explore use cases (demo.fingerprint.com)](https://demo.fingerprint.com/)
- [Fingerprint — Browser Bot Detection Software (product page)](https://fingerprint.com/products/bot-detection/)
- [Fingerprint blog — Announcing Smart Signals](https://fingerprint.com/blog/announcing-smart-signals/)
- [Fingerprint blog — How to Detect AI Agents & Prevent Autonomous Fraud](https://fingerprint.com/blog/how-to-detect-ai-agents/)
- [GitHub — fingerprintjs/BotD (MIT, client-side bot detection)](https://github.com/fingerprintjs/BotD)
- [GitHub — fingerprintjs/fingerprintjs (MIT, client-side fingerprinting)](https://github.com/fingerprintjs/fingerprintjs)
- [The Paypers — Fingerprint launches new Smart Signals (2025-07-15)](https://thepaypers.com/fraud-and-fincrime/news/fingerprint-launches-new-smart-signals-and-platform-upgrades)
