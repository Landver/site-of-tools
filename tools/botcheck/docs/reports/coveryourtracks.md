# EFF Cover Your Tracks

Browser-fingerprint uniqueness and tracker-blocking self-test run by EFF. **Not a bot detector** — measures how identifiable/trackable *your own* browser is, whether privacy extensions actually stop trackers. Documented here for signal set and architecture, overlapping heavily with what real anti-bot vendors collect.

- **URL:** https://coveryourtracks.eff.org/ · **Category:** privacy/anonymity & fingerprinting tool (open source, non-profit; successor to Panopticlick) · **Requires registration:** No — fully open, anonymous, no account/email.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict produced.** Tool has no bot/human output by design, and in our session interactive results flow didn't fully render in Electron browser. Nothing here would label our automation a bot; at most our environment would register as highly-unique (therefore very trackable) fingerprint.

## What it is — common info

Cover Your Tracks (CYT) run by **Electronic Frontier Foundation** (EFF), US digital-rights non-profit. Direct successor to **Panopticlick**, 2010 research project (originally by Peter Eckersley) first demonstrating browsers uniquely identifiable via fingerprinting. EFF rebranded/relaunched as Cover Your Tracks **November 2020**.

Purpose: **educational/advocacy**, opposite goal of commercial anti-bot product: show user own fingerprint, quantify how unique/trackable it is, test whether blockers work, pressure browser ecosystem toward stronger anti-fingerprinting defenses. Key advance over Panopticlick: Panopticlick only told you *whether* browser was unique; CYT itemizes *every* contributing signal, quantifies each in bits, adds tracker-blocker effectiveness testing. Audience: privacy-conscious end users, journalists, researchers — not site operators trying to block automation.

## Registration / access

None. Load page, click "Test your browser." No login, email, key. EFF states only anonymous, aggregated data collected. (High confidence; confirmed on tool's own pages.)

## How it decides bot-or-not

Doesn't. **CYT makes no bot/human decision, has no bot classifier.** What it computes instead:

1. **Fingerprint uniqueness** — how identifying browser's attributes are, expressed in "bits of identifying information" and "one in X browsers share this" breakdown.
2. **Tracker-protection verdict** — plain-language assessment (roughly: strong / some / no protection against web tracking) based on whether simulated trackers blocked and whether fingerprint unique, near-unique, or randomized.

For anti-bot engineer, relevant framing is the **corollary**: headless/automated browser fed to CYT typically produces broken or highly-unique canvas/WebGL fingerprint. CYT reports that as "unique" (privacy problem for user); real detector reads same anomaly as bot tell. Collection vector identical — only scoring intent differs.

## Detection approaches

- **Passive attribute fingerprinting** — read navigator/screen/header properties.
- **Active probing fingerprinting** — canvas 2D, WebGL, AudioContext rendering hashes; font/plugin enumeration.
- **Entropy / information-theory scoring** — each attribute compared against rolling population to compute Shannon surprisal (`log2(X)` bits).
- **Tracker-blocking simulation** — actively loads ads/beacons/trackers from EFF-controlled simulator domains to see which browser's blockers stop.
- **Not used (important):** no `navigator.webdriver`/CDP/headless automation checks, no behavioral/mouse analysis, no TLS/JA3 fingerprinting, no IP/proxy/VPN reputation, no CAPTCHA/challenge, no ML bot classifier. Not built to catch bots.

## Areas / signals scanned

### Client-side (JS)
- User-Agent (also read server-side), platform (`navigator.platform`), language.
- Screen size and color depth.
- Time zone and time zone offset.
- Browser plugin details; system font enumeration (JS; Flash historically).
- Cookies-enabled flag; limited supercookie / DOM-storage test.
- **Canvas** fingerprint hash (2D rendering).
- **WebGL** fingerprint hash + unmasked `WEBGL_debug_renderer_info` vendor/renderer strings.
- **AudioContext** fingerprint (confirmed via live result payloads exposing "audio" whorl, rather than About/blog pages).
- Touch support; hardware concurrency (logical cores).
- Ad blocker used (inferred).
- *Unverified / low-confidence attributes:* "CPU class" (`navigator.cpuClass`, legacy IE-only property — likely carried-over artifact, not confirmed in current metric set) and "device memory" (`navigator.deviceMemory` — plausible but not seen in inspected payloads).

### Server-side (HTTP headers only)
- Passively records request headers: `User-Agent`, `HTTP_ACCEPT`, `DNT` (Do Not Track).
- No TLS/JA3 analysis, no IP-reputation scoring. Client IP stored only as **HMAC (keyed hash)**, not used for uniqueness score.

### Behavioral
- None.

## How it scans (architecture)

**Hybrid, but not in anti-bot sense.** JavaScript fingerprinting script runs client-side, actively computes canvas/WebGL/AudioContext hashes, enumerates fonts/plugins, reads navigator/screen properties. Also triggers loads of tracker resources from EFF simulator domains to test URL-based, domain-based, heuristic/cookie-based blocking separately.

Collected fingerprint then **POSTed as JSON ("whorls") to EFF's server** — Python backend, MySQL database. Server:
- passively logs HTTP request headers;
- compares each submitted attribute against **"totals" table** counting how often each value seen over **rolling ~45-day epoch**, turning raw attributes into entropy/uniqueness figure;
- stores visitor IP only as HMAC keyed hash with key-refresh mechanism ("so repeat visits are de-duplicated" rationale reasonable inference, not explicitly confirmed statement).

**No-JS results path** (`results-nojs`) also exists, scores using only HTTP headers.

**Where decision is made:** uniqueness scoring **entirely server-side over client-submitted JSON fingerprint.** For adversarial audience this is decisive architectural fact — fingerprint trivially **spoofable and replayable**, so design unusable for real bot detection. Fine for CYT's purpose (measuring honest browser's exposure) but exactly the property bot detector can't tolerate.

## Scoring / output

Two outputs, no single number, no bot score:

1. **Uniqueness in "bits of identifying information."** For each attribute tool reports "one in X browsers have this value"; surprisal is `log2(X)` bits, overall figure is combined entropy across all metrics. Higher bits = more unique = more trackable. X and population drawn from server's rolling ~45-day epoch database, so score **relative to that recent sample, not absolute.** Real observed CYT results land roughly in **~13–19 bit** range. (Any specific "unique among the N tested / at least N.NN bits" pair should be treated as illustrative — precise figures cited in secondary research weren't sourced.)
2. **Tracker-protection assessment** — plain-language verdict from blocking simulation plus fingerprint uniqueness. Notably, EFF explicitly credits **fingerprint randomization** as valid defense: randomized fingerprint can register as "unique" here yet still defeat trackers since its value changes each visit.

## Notable techniques

- **Canvas fingerprinting** — render text/graphics to 2D canvas, hash pixels to expose GPU/driver/font-rasterization differences.
- **WebGL fingerprinting** — hash rendered scene plus unmasked vendor/renderer strings.
- **AudioContext fingerprinting** — derive fingerprint from audio-stack DSP output differences.
- **Entropy quantification in bits** with per-attribute "one in X" breakdown — main advance over Panopticlick's binary unique/not-unique verdict.
- **Rolling ~45-day epoch "totals" table** so uniqueness reflects recent population rather than all-time skew.
- **Purpose-built tracker-simulator domains** to test blocking modes separately: third-party simulators `trackersimulator.org`, `eviltracker.net`, `do-not-tracker.org`, **plus first-party simulator `firstpartysimulator.net` / `firstpartysimulator.org`** — latter arguably primary fingerprinting host (no-JS fingerprint served from `firstpartysimulator.net/fingerprint-nojs`).
- **HMAC-hashing visitor IP** with rotating key so raw IPs not stored.
- **Versioned fingerprint schema** ("v2 whorls" seen in live URLs), indicating collected vector set evolves over time. Real surface deeper than headline list — also touches WebGL extensions/parameters (beyond just unmasked vendor/renderer) and font-metric/`getClientRects`-style geometry.

## What we observed firsthand

- No bot verdict exists to report; CYT doesn't classify bot vs human.
- Interactive results flow **didn't fully render** in our Electron in-app browser this session, so no live entropy figure captured.
- Our egress IP (`87.249.139.226`, NordVPN/DataCamp datacenter, Istanbul) irrelevant to CYT's score — unlike other tools in this set (incolumitas, Fingerprint, whoer flagged it as VPN/datacenter), CYT does no IP-reputation analysis, wouldn't surface it.
- No fingerprint-POST or backend scoring traffic captured firsthand (flow stalled before submission), consistent with client-JS-collects-then-POSTs-to-EFF-backend architecture described above.

## Verification notes

Adversarial review confirmed research well supported overall. Corrections folded into this report:

- **Simulator domain list was incomplete.** Added first-party simulator `firstpartysimulator.net` / `firstpartysimulator.org` alongside three third-party domains; first-party host likely primary fingerprinting endpoint.
- **Audio fingerprinting genuine but sourced from result payloads, not About/blog pages** — noted inline.
- **"CPU class" flagged as unverified** (legacy IE-only `navigator.cpuClass`; likely carried-over artifact) and **"device memory" as low-confidence** (not seen in inspected payloads) — both demoted from confirmed signal list.
- **Specific example score figures** ("324,397 tested," "18.31 bits") in research read as invented illustration, dropped — only plausible ~13–19 bit magnitude range stated.
- **HMAC-IP de-duplication rationale is inference**, not explicitly confirmed purpose — labeled as such.

No fabricated citations or endpoints introduced; network endpoints stated here limited to firsthand notes, simulator/fingerprint domains come from verified research.

## Open source / reusable

- **`github.com/EFForg/cover-your-tracks`** — full application, AGPL v3. Python backend + MySQL totals table, Docker / docker-compose deploy. Formerly named `EFForg/panopticlick`. Builder can reuse client-side fingerprint collectors (canvas/WebGL/audio/font enumeration) and, more usefully, its **entropy/"bits of identifying information" scoring model** — but note AGPL obligations and entropy math needs population database to be meaningful.

## Sources

- [Cover Your Tracks (home) — EFF](https://coveryourtracks.eff.org/)
- [About Cover Your Tracks — EFF](https://coveryourtracks.eff.org/about)
- [Cover Your Tracks fingerprint results (no-JS view)](https://coveryourtracks.eff.org/results-nojs)
- [Introducing Cover Your Tracks! — EFF Deeplinks blog](https://www.eff.org/deeplinks/2020/11/introducing-cover-your-tracks)
- [Find Out How Ad Trackers Follow You On the Web — EFF press release](https://www.eff.org/press/releases/find-out-how-online-trackers-follow-you-web-effs-cover-your-tracks-tool)
- [EFForg/cover-your-tracks README (architecture, 45-day epoch totals, AGPLv3)](https://github.com/EFForg/cover-your-tracks/blob/master/README.md)
- [Cover Your Tracks browser fingerprint exposure analysis — DataDome (third-party; 403 to automated fetch, cited from search summary only)](https://datadome.co/anti-detect-tools/coveryourtracks/)
