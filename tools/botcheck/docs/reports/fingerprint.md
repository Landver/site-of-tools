# Fingerprint.com (Fingerprint Pro / Smart Signals) — playground demo

Commercial device-intel vendor live playground: fingerprints browser -> persistent visitor ID + fraud "Smart Signals" (bot, VPN, incognito, tampering, VM, dev tools, IP blocklist, velocity) + aggregate numeric **Suspect Score**. Passive identify-and-correlate engine; not edge WAF, not CAPTCHA.

- **URL:** https://demo.fingerprint.com/playground · **Category:** commercial anti-bot / device-intel vendor demo (live playground for paid Fingerprint Pro + Smart Signals, *not* open-source test page) · **Requires registration:** No for playground (runs vs own browser instantly w/ Fingerprint's key). Account/API key only to integrate into *own* site; product pages show "Get started" CTAs, artifact behind occasional "registration required" scrapes.
- **Firsthand verdict, test browser** (`Claude/… Chrome/148 Electron/42.5.1`, macOS, egress `87.249.139.226` = NordVPN / DataCamp datacenter, Istanbul): **Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, correctly IDed "Electron 42.5.1".** Smart Signals: **Bot = Not detected**, VPN = "public VPN IP, timezone mismatch", Incognito = yes, **Dev Tools = Yes**, IP Blocklist = "data_center proxy provider", VM/Tampering/Privacy Settings/High-Activity Device = Not detected, Velocity = 1 IP / 1 linked ID / 24h, Geo = Istanbul TR. **Suspect Score = 33.** Notably did **not** classify CDP-driven Electron as bot despite flagged Dev Tools, VPN, datacenter IP — bot signal targets known automation frameworks/VMs, not mere debug-protocol presence.

## What it is — common info

Run by Fingerprint (formerly "FingerprintJS, Inc."), device-intel / fraud-prevention vendor. Grew from open-source FingerprintJS FP library -> commercial "Fingerprint Pro / Identification" platform + "Smart Signals" fraud suite. Demo = sales showcase: prospect runs it vs own browser real-time, watches visitor ID + each signal resolve. Also ~13 fraud use-case demos (Playground, Coupon Fraud, Credential Stuffing, Account Sharing, Payment Fraud, Loan Risk, Paywall, Personalization, Web Scraping Prevention, Bot Firewall, SMS Pumping, VPN Detection, New Account Fraud). Audience: fraud/risk & platform engineers evaluating paid product. 2025-07-15: launched refreshed Bot Detection + VM Detection, Residential Proxy Detection, AI-request filtering, explicitly vs AI-agent / autonomous-browser fraud.

## Registration / access

Playground free, no login, no card. Registration (14-day trial dashboard signup) only yields API key for own integration; doesn't gate demo.

## How it decides bot-or-not

Lightweight JS agent in browser collects large device/browser FP + automation markers, POSTs identification event to backend. Backend fuses client signals w/ **server/network data browser can't see or forge** (IP, geo, IP blocklist, VPN / residential-proxy reputation, cross-request velocity) -> **stable visitor ID (w/ confidence)** + Smart Signals. Bot verdict produced **server-side** by ML classifier "on each API request": protects logic from reverse engineering + combines client & server facts. Design **passive & frictionless**: no CAPTCHA, no proof-of-work, no interstitial.

## Detection approaches

- **Browser/device fingerprinting** — 100+ signals -> persistent visitor ID engineered to survive incognito, cookie clearing, VPN switching.
- **Headless / automation detection** — Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Electron, SlimerJS, headless Chrome/Firefox (BotD library lineage).
- **Bot classification (ML)** — `good` / `bad` / `notDetected`, per API request server-side.
- **Network / IP reputation** — geo, IP blocklist, VPN, residential-proxy (graded confidence).
- **Tampering / anti-detect-browser detection** — attribute-inconsistency analysis (e.g. spoofed mobile UA not matching real device attrs).
- **Virtualization / emulation** — VM, Android emulator (mobile SDK also iOS Simulator), rooted/jailbroken.
- **Incognito / private-mode detection.**
- **Velocity signals** — cross-request device-activity spikes (*not* behavioral biometrics; see below).
- **AI-agent detection & request filtering** — matches known AI-company UAs -> separate benign AI (assistants, approved crawlers) from malicious automation; also cuts billable events.
- **Not present:** no behavioral biometrics, no active challenge, no TLS/JA3/JA4 or HTTP/2 transport fingerprinting (see Verification notes & boundary below).

## Areas / signals scanned

**Client-side (JS agent):** navigator props (languages, plugins, platform, hardwareConcurrency, userAgent); canvas FP; WebGL / GPU renderer; AudioContext FP; installed fonts; screen res / color depth; timezone; UA string & self-consistency; large "Raw Device Attributes" JSON (commercial add-on, returned live in our run); `navigator.webdriver`; CDP artifacts; `chrome.runtime` / `window.chrome` presence; error stack traces & non-native property descriptors (tampering tells). Named consumer-facing Smart Signals here: **Browser Tampering**, **Developer Tools Detection**, **Privacy-Focused Settings**, **Incognito**, **Device Rarity / High-Activity Device**.

**Server-side (IP / network):** IP + geo; IP blocklist; VPN (UA/timezone inconsistent w/ browser attrs); residential-proxy (w/ confidence); VM / emulator signatures (partly server-correlated); request headers / known AI UAs; cross-request velocity. **No** TLS/JA3, TCP/IP SYN, or header-order FP — JS-agent + server-correlation vendor, not inline edge proxy.

**Behavioral:** none classical. Does **not** analyze mouse trajectories, keystrokes, scroll, touch. "Velocity" = request cadence across device/IP, not human-motion biometrics — defining distinction from HUMAN/PerimeterX or DataDome.

**Mobile SDK signals (native, not exercised by browser demo):** Frida instrumentation, factory-reset timestamp, geo spoofing, emulator / iOS Simulator, rooted / jailbroken, cloned app, MITM attack, tampered request.

## How it scans (architecture)

Confirmed via network capture — four-step client+server flow:

1. **First-party proxied agent load.** Agent served from randomized first-party path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8/web`. (Default public CDN = `fpjscdn.net/v4/<api-key>`; demo uses same-subdomain proxying, real deploy option defeating adblock/tracker filters & denying bot authors a fixed third-party URL to block.)
2. **Ingestion POST.** Agent POSTs identification event to `POST /DBqbMN7zXxwl4Ei8` (same first-party path).
3. **Minimal agent response.** Browser gets only `{event_id, visitor_id, suspect_score}` — no detailed verdicts client-side.
4. **Trusted server-to-server fetch.** Customer's *own* server calls Server API (`POST /api/event/v4/<eventId>`) for full sealed result: `{bot, vpn, ip_info(datacenter_result, asn_type:hosting), developer_tools, …}`.

**Decision server-side.** Client signals treated untrusted; authoritative verdict fetched server-to-server, tied to `event_id` / `requestId` so client can't forge. This layer = what vendor says separates Pro's accuracy from client-only open-source libs.

## Scoring / output

Two distinct, easily-conflated outputs:

- **Bot field (categorical):** `good` (approved/known crawler — Google/Bing/Yahoo/Yandex), `bad` (automation tool or VM), `notDetected` (human/legit). UI renders `notDetected` as "Not detected."
- **Suspect Score (numeric):** headline top-level Smart Signal — weighted aggregate of signals, range `0` to sum of all enabled signal weights. **Our browser = 33.** Closest to single "bot-or-not" number, real & prominent (contra any "no score" framing).
- Other signals return booleans + where applicable confidence (e.g. VPN & residential-proxy). Identification returns stable `visitorId` w/ own confidence (1 in our run).

## Notable techniques

- **CDP detection via `Runtime.enable` serialization side effect** — log object w/ getter property, observe if getter fires; fires only when page driven over CDP (Playwright/Puppeteer/Selenium 4). Real; later V8 change broke part of it. *Attribution:* prominent public write-ups on this getter trick from Rebrowser project & Castle / Antoine Vastel / DataDome; tying it specifically to Fingerprint engineers unconfirmed.
- **Persistent visitor ID** surviving incognito, cookie clearing, VPN switching — core selling point.
- **VPN detection by consistency-check** — flags reported UA/timezone inconsistent w/ browser's other attrs (why our datacenter-egress browser flagged: "public VPN IP, timezone mismatch").
- **Tampering / anti-detect-browser detection** by spotting attribute inconsistencies.
- **Fusing server/network signals invisible to browser** w/ client FP, so client-side spoofing alone can't defeat verdict.
- **Residential-proxy detection w/ graded confidence** & **AI UA filtering**, both vs agentic/AI fraud.

## What we observed firsthand

Ground truth from driving playground in test browser (prefer over research where they differ):

- Visitor ID `eP0MrBluBCpKECWLP0wo`, Confidence 1, "Electron 42.5.1" correct.
- **Bot = Not detected** despite CDP-driven browser — bot signal didn't fire (whereas Dev Tools = Yes did).
- VPN flagged ("public VPN IP, timezone mismatch"); IP Blocklist = "data_center proxy provider"; Incognito detected; VM / Tampering / Privacy Settings / High-Activity = Not detected.
- **Suspect Score = 33.**
- Network evidence for four-step architecture: agent served from & posting to first-party randomized path `demo.fingerprint.com/DBqbMN7zXxwl4Ei8` (`/web` = agent, base = ingestion); minimal `{event_id, visitor_id, suspect_score}` to browser; full result designed for Server API `POST /api/event/v4/<eventId>`.

## Verification notes

Adversarial review corrected several research claims; folded in above & flagged here so rest can be trusted:

- **TLS fingerprinting claim fabricated.** Research asserted "TLS-fingerprint bot detection at edge in Fingerprint's own patents." Matching patent (US 11,799,908, edge-network TLS-fingerprint bot detection) assigned to **Akamai**, not Fingerprint; Fingerprint's Smart Signals reference lists **no** TLS/JA3/JA4 signal. = JS-agent + server-correlation vendor, not inline edge proxy. Report treats transport FP (TLS/JA3/JA4, TCP/IP, HTTP/2 frames) as **boundary Fingerprint doesn't cross** — Cloudflare/Akamai/DataDome domain.
- **"No score" was wrong.** Bot *field* categorical, but ships numeric **Suspect Score** (confirmed live at 33). Documented & headline; report treats as primary numeric output.
- **Hashing detail corrected/unverified.** Research's "MurmurHash3 (32-bit) → 32-char hex" internally inconsistent (32-bit -> 8 hex chars). Open-source visitorId = 32-char hex hash (consistent w/ 128-bit MurmurHash / x64hash128), but cited repo README doesn't name algorithm -> specific name **unverified**, not stated as fact.
- **Open-source accuracy/attribute figures unverified.** "~40–60% accuracy" & "50+ attributes" for open-source FingerprintJS not in cited README (only says accuracy "significantly lower" than Pro). Treated **unverified/marketing-adjacent**, omitted as fact. "100+ signals" for Pro *is* confirmed.
- **CDP-trick attribution** to Fingerprint engineers **unconfirmed** (see Notable techniques).
- **Confirmed:** no-login demo vs visitor's own browser; bot values `good`/`bad`/`notDetected` (camelCase; search engines = good); agent from `fpjscdn.net/v4/<api-key>` by default; BotD & FingerprintJS both MIT & 100% client-side; 2025-07-15 launch of Bot/VM/Residential-Proxy/Request-Filtering signals.

## Open source / reusable

Two MIT client-side libs from same company = open-source ancestors (demo runs closed Pro engine, vendor states markedly more accurate):

- **FingerprintJS** — browser FP -> client-only visitor ID: https://github.com/fingerprintjs/fingerprintjs
- **BotD** — in-browser bot/automation detection (Selenium/Playwright/Puppeteer/PhantomJS/Nightmare/Electron/SlimerJS/headless): https://github.com/fingerprintjs/BotD

Reuse for client-side layer, but accuracy comes from proprietary server-side fusion (IP/proxy reputation, velocity, ML), not open source.

## Sources

- [Fingerprint Demo — Explore use cases (demo.fingerprint.com)](https://demo.fingerprint.com/)
- [Fingerprint — Browser Bot Detection Software (product page)](https://fingerprint.com/products/bot-detection/)
- [Fingerprint blog — Announcing Smart Signals](https://fingerprint.com/blog/announcing-smart-signals/)
- [Fingerprint blog — How to Detect AI Agents & Prevent Autonomous Fraud](https://fingerprint.com/blog/how-to-detect-ai-agents/)
- [GitHub — fingerprintjs/BotD (MIT, client-side bot detection)](https://github.com/fingerprintjs/BotD)
- [GitHub — fingerprintjs/fingerprintjs (MIT, client-side fingerprinting)](https://github.com/fingerprintjs/fingerprintjs)
- [The Paypers — Fingerprint launches new Smart Signals (2025-07-15)](https://thepaypers.com/fraud-and-fincrime/news/fingerprint-launches-new-smart-signals-and-platform-upgrades)
