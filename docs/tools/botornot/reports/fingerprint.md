# Fingerprint.com (Fingerprint Pro / Smart Signals) — playground demo

A commercial device-intelligence vendor's live playground: it fingerprints your browser into a persistent visitor ID and lights up a suite of fraud "Smart Signals" (bot, VPN, incognito, tampering, VM, developer tools, IP blocklist, velocity) plus an aggregate numeric **Suspect Score**. It is a passive identification-and-correlation engine, not an edge WAF and not a CAPTCHA.

- **URL:** https://demo.fingerprint.com/playground · **Category:** commercial anti-bot / device-intelligence vendor demo (the live product playground for paid Fingerprint Pro + Smart Signals — *not* an open-source test page) · **Requires registration:** No for the playground (it runs against your own browser instantly using Fingerprint's own key). An account/API key is only needed to integrate Fingerprint into your *own* site; product pages surface "Get started" CTAs, which is the artifact behind occasional "registration required" scrapes.
- **Firsthand verdict for the test browser** (`Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): **Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, correctly identified as "Electron 42.5.1".** Smart Signals: **Bot = Not detected**, VPN = "You are using a VPN (public VPN IP, timezone mismatch)", Incognito = "You are incognito", **Developer Tools = Yes**, IP Blocklist = "data_center proxy provider", Virtual Machine = Not detected, Browser Tampering = Not detected, Privacy Settings = Not detected, High-Activity Device = Not detected, Velocity = 1 IP / 1 linked ID in 24h, Geolocation = Istanbul TR. **Suspect Score = 33.** Notably, Fingerprint did **not** classify the CDP-driven Electron browser as a bot even though it flagged Developer Tools, VPN, and the datacenter IP — the bot signal targets known automation frameworks/VMs, not the mere presence of a debugging protocol.

## What it is — common info

Run by Fingerprint (the company formerly "FingerprintJS, Inc."), a device-intelligence / fraud-prevention vendor. It grew out of the open-source FingerprintJS browser-fingerprinting library into a commercial "Fingerprint Pro / Identification" platform layered with a "Smart Signals" fraud-signal suite. The demo is a sales/marketing showcase: a prospect runs Fingerprint against their own browser in real time and watches their persistent visitor ID and each Smart Signal resolve. It doubles as ~13 interactive fraud use-case demos (Playground, Coupon Fraud, Credential Stuffing, Account Sharing, Payment Fraud, Loan Risk, Paywall, Personalization, Web Scraping Prevention, Bot Firewall, SMS Pumping, VPN Detection, New Account Fraud). Audience: fraud/risk and platform engineers evaluating a paid product. On 2025-07-15 Fingerprint launched a refreshed Bot Detection signal plus VM Detection, Residential Proxy Detection, and AI-request filtering, explicitly positioned against AI-agent / autonomous-browser fraud.

## Registration / access

The playground is free, no login, no credit card. Registration (a 14-day trial dashboard signup) exists only to get an API key for your own integration and does not gate the demo.

## How it decides bot-or-not

A lightweight JavaScript agent runs in the browser, collects a large device/browser fingerprint plus automation markers, and POSTs an identification event to Fingerprint's backend. The backend fuses those client signals with **server/network data the browser cannot see or forge** — IP address, geolocation, IP blocklist membership, VPN / residential-proxy reputation, and cross-request velocity — then returns a **stable visitor ID (with a confidence score)** and the Smart Signals. The bot verdict itself is produced **server-side** by an ML classifier "on each API request," which both protects the classification logic from reverse engineering and lets it combine client- and server-observed facts. The design is **passive and frictionless**: there is no CAPTCHA, no proof-of-work, no interstitial challenge.

## Detection approaches

- **Browser/device fingerprinting** — 100+ signals fused into a persistent visitor ID that is engineered to survive incognito, cookie clearing, and VPN switching.
- **Headless / automation-tool detection** — identifies Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Electron, SlimerJS, headless Chrome/Firefox (the lineage of the open-source BotD library).
- **Bot classification (ML)** — `good` / `bad` / `notDetected`, decided per API request server-side.
- **Network / IP reputation** — geolocation, IP blocklist matching, VPN detection, residential-proxy detection (graded confidence).
- **Browser tampering / anti-detect-browser detection** — attribute-inconsistency analysis (e.g. a spoofed mobile UA that doesn't match real device attributes).
- **Virtualization / emulation detection** — virtual machine, Android emulator (mobile SDK also: iOS Simulator), rooted/jailbroken device.
- **Incognito / private-mode detection.**
- **Velocity signals** — cross-request device-activity spikes (this is *not* behavioral biometrics; see below).
- **AI-agent detection & request filtering** — matches known AI-company user agents to separate benign AI (assistants, approved crawlers) from malicious automation; also reduces billable events.
- **Not present:** no behavioral biometrics, no active challenge, no TLS/JA3/JA4 or HTTP/2 transport fingerprinting (see Verification notes and the capability boundary below).

## Areas / signals scanned

**Client-side (JS agent):** navigator properties (languages, plugins, platform, hardwareConcurrency, userAgent); canvas fingerprint; WebGL / GPU renderer; AudioContext fingerprint; installed fonts; screen resolution / color depth; timezone; user-agent string and its self-consistency; a large "Raw Device Attributes" JSON (a commercial add-on, returned live in our run); `navigator.webdriver`; Chrome DevTools Protocol (CDP) artifacts; `chrome.runtime` / `window.chrome` presence; error stack traces and non-native property descriptors (tampering tells). Named consumer-facing Smart Signals in this layer include **Browser Tampering**, **Developer Tools Detection**, **Privacy-Focused Settings**, **Incognito**, and **Device Rarity / High-Activity Device**.

**Server-side (IP / network):** IP address + geolocation; IP blocklist membership; VPN indicators (UA/timezone inconsistent with browser attributes); residential-proxy indicators (with confidence); virtual-machine / emulator signatures (partly server-correlated); request headers / known AI user agents; cross-request velocity. **No** TLS/JA3, TCP/IP SYN, or header-order fingerprinting — Fingerprint is a JS-agent + server-correlation vendor, not an inline edge proxy.

**Behavioral:** none in the classical sense. Fingerprint does **not** analyze mouse trajectories, keystroke dynamics, scroll, or touch gestures. "Velocity" measures request cadence across a device/IP, not human-motion biometrics — a defining architectural distinction from HUMAN/PerimeterX or DataDome.

**Mobile SDK signals (native, not exercised by the browser demo):** Frida instrumentation, factory-reset timestamp, geolocation spoofing, emulator / iOS Simulator, rooted / jailbroken, cloned app, MITM attack, tampered request.

## How it scans (architecture)

Confirmed via network capture during our run — a four-step client+server flow:

1. **First-party proxied agent load.** The JS agent is served from a randomized, first-party path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8/web`. (Fingerprint's default public CDN host is `fpjscdn.net/v4/<api-key>`; the demo instead uses same-subdomain proxying, a real deployment option that defeats adblock/tracker filters and denies bot authors a fixed third-party URL to block.)
2. **Ingestion POST.** The agent collects signals and POSTs the identification event to `POST /DBqbMN7zXxwl4Ei8` (same first-party path).
3. **Minimal JS agent response.** The browser receives only `{event_id, visitor_id, suspect_score}` — no detailed verdicts land in the client.
4. **Trusted server-to-server fetch.** The customer's *own* server calls the Fingerprint Server API (`POST /api/event/v4/<eventId>`) to retrieve the full, sealed result: `{bot, vpn, ip_info(datacenter_result, asn_type:hosting), developer_tools, …}`.

**The decision is made server-side.** Client-originated signals are treated as untrusted; the authoritative verdict is fetched server-to-server and tied to an `event_id` / `requestId` so the client cannot forge it. This server-side layer is exactly what the vendor says separates Pro's accuracy from the client-only open-source libraries.

## Scoring / output

Two distinct outputs, and they are easy to conflate:

- **Bot field (categorical):** `good` (approved/known crawler — Google/Bing/Yahoo/Yandex), `bad` (automation tool or VM), or `notDetected` (human/legitimate). The demo UI renders `notDetected` as "Not detected."
- **Suspect Score (numeric):** Fingerprint's headline top-level Smart Signal — a weighted aggregate of the individual signals, documented range `0` to the sum of all enabled signal weights. **Our test browser scored 33.** This is the closest thing to a single "bot-or-not" number and it is a real, prominent product feature (contrary to any "no score" framing).
- Other Smart Signals return booleans plus, where applicable, a confidence indicator (e.g. VPN and residential-proxy results carry confidence). Identification returns a stable `visitorId` with its own confidence score (1 in our run).

## Notable techniques

- **CDP detection via the `Runtime.enable` serialization side effect** — log an object with a getter property and observe whether the getter fires; it fires only when the page is driven over the Chrome DevTools Protocol (Playwright/Puppeteer/Selenium 4). The technique is real, and a later V8 change broke part of it. *Attribution note:* the prominent public write-ups on this specific getter trick come from the Rebrowser project and Castle / Antoine Vastel / DataDome; associating it specifically with Fingerprint engineers is unconfirmed.
- **Persistent visitor ID** that survives incognito, cookie clearing, and VPN switching — the core selling point.
- **VPN detection by consistency-checking** — flags when reported UA/timezone is inconsistent with the browser's other attributes (this is precisely why our datacenter-egress browser was flagged: "public VPN IP, timezone mismatch").
- **Tampering / anti-detect-browser detection** by spotting attribute inconsistencies.
- **Fusing server/network signals invisible to the browser** with the client fingerprint, so client-side spoofing alone cannot defeat the verdict.
- **Residential-proxy detection with graded confidence** and **AI user-agent filtering**, both aimed at agentic/AI fraud.

## What we observed firsthand

Ground truth from driving the playground in the test browser (prefer over research where they differ):

- Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, "Electron 42.5.1" identified correctly.
- **Bot = Not detected** despite the browser being CDP-driven — Fingerprint's bot signal did not fire on our environment (whereas Developer Tools = Yes did).
- VPN = flagged ("public VPN IP, timezone mismatch"); IP Blocklist = "data_center proxy provider"; Incognito = detected; VM / Tampering / Privacy Settings / High-Activity = Not detected.
- **Suspect Score = 33.**
- Network evidence for the four-step architecture above: agent served from and posting to the first-party randomized path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8` (`/web` for the agent, base path for ingestion); minimal `{event_id, visitor_id, suspect_score}` returned to the browser; full result designed to be fetched via the Server API `POST /api/event/v4/<eventId>`.

## Verification notes

The adversarial review corrected several claims in the underlying research; folded in above and flagged here so the rest can be trusted:

- **TLS fingerprinting claim was fabricated.** The research asserted "TLS-fingerprint-based bot detection at the edge is described in Fingerprint's own patents." The matching patent (US 11,799,908, edge-network TLS-fingerprint bot detection) is assigned to **Akamai**, not Fingerprint, and Fingerprint's own Smart Signals reference lists **no** TLS/JA3/JA4 signal. Fingerprint is a JS-agent + server-correlation vendor, not an inline edge proxy. This report treats transport fingerprinting (TLS/JA3/JA4, TCP/IP, HTTP/2 frames) as a **capability boundary Fingerprint does not cross** — the domain of Cloudflare/Akamai/DataDome.
- **"No score" was wrong.** The bot *field* is categorical, but Fingerprint ships a numeric **Suspect Score** (confirmed live at 33). It is documented and headline; the report treats it as the primary numeric output.
- **Hashing detail corrected/unverified.** The research's "MurmurHash3 (32-bit) → 32-char hex" is internally inconsistent (32-bit yields 8 hex chars). The open-source visitorId is a 32-char hex hash (consistent with a 128-bit MurmurHash / x64hash128), but the cited repo README does not name the algorithm, so the specific algorithm name is **unverified** and not stated as fact here.
- **Open-source accuracy/attribute figures unverified.** "~40–60% accuracy" and "50+ attributes" for open-source FingerprintJS are not in the cited README, which only says accuracy is "significantly lower" than Pro. Treated as **unverified/marketing-adjacent** and omitted as fact. The "100+ signals" figure for Pro *is* confirmed.
- **CDP-trick attribution** to Fingerprint engineers is **unconfirmed** (see Notable techniques).
- **Confirmed:** no-login demo running against the visitor's own browser; bot values `good`/`bad`/`notDetected` (camelCase; search engines = good); agent from `fpjscdn.net/v4/<api-key>` by default; BotD and FingerprintJS both MIT and 100% client-side; the 2025-07-15 launch of Bot/VM/Residential-Proxy/Request-Filtering signals.

## Open source / reusable

Two MIT-licensed client-side libraries from the same company are the open-source ancestors of the product (the demo itself runs the closed Pro engine, which the vendor states is markedly more accurate):

- **FingerprintJS** — browser fingerprinting → client-only visitor ID: https://github.com/fingerprintjs/fingerprintjs
- **BotD** — in-browser bot/automation detection (Selenium/Playwright/Puppeteer/PhantomJS/Nightmare/Electron/SlimerJS/headless): https://github.com/fingerprintjs/BotD

A builder can reuse these directly for the client-side layer, but note the accuracy comes from the proprietary server-side fusion (IP/proxy reputation, velocity, ML classification), which is not open source.

## Sources

- [Fingerprint Demo — Explore use cases (demo.fingerprint.com)](https://demo.fingerprint.com/)
- [Fingerprint — Browser Bot Detection Software (product page)](https://fingerprint.com/products/bot-detection/)
- [Fingerprint blog — Announcing Smart Signals](https://fingerprint.com/blog/announcing-smart-signals/)
- [Fingerprint blog — How to Detect AI Agents & Prevent Autonomous Fraud](https://fingerprint.com/blog/how-to-detect-ai-agents/)
- [GitHub — fingerprintjs/BotD (MIT, client-side bot detection)](https://github.com/fingerprintjs/BotD)
- [GitHub — fingerprintjs/fingerprintjs (MIT, client-side fingerprinting)](https://github.com/fingerprintjs/fingerprintjs)
- [The Paypers — Fingerprint launches new Smart Signals (2025-07-15)](https://thepaypers.com/fraud-and-fincrime/news/fingerprint-launches-new-smart-signals-and-platform-upgrades)
