# EFF Cover Your Tracks

A browser-fingerprint uniqueness and tracker-blocking self-test run by the EFF. **It is not a bot detector** — it measures how identifiable/trackable *your own* browser is and whether your privacy extensions actually stop trackers. Documented here for its signal set and architecture, which overlap heavily with what real anti-bot vendors collect.

- **URL:** https://coveryourtracks.eff.org/ · **Category:** privacy/anonymity & fingerprinting tool (open source, non-profit; successor to Panopticlick) · **Requires registration:** No — fully open, anonymous, no account/email.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict produced.** The tool has no bot/human output by design, and in our session the interactive results flow did not fully render in the Electron browser. There is nothing here that would label our automation as a bot; at most our environment would register as a highly-unique (therefore very trackable) fingerprint.

## What it is — common info

Cover Your Tracks (CYT) is run by the **Electronic Frontier Foundation** (EFF), a US digital-rights non-profit. It is the direct successor to **Panopticlick**, the 2010 research project (originally by Peter Eckersley) that first demonstrated browsers are uniquely identifiable via fingerprinting. EFF rebranded and relaunched it as Cover Your Tracks in **November 2020**.

Its purpose is **educational/advocacy**, the opposite goal of a commercial anti-bot product: show a user their own fingerprint, quantify how unique/trackable it is, test whether their blockers work, and pressure the browser ecosystem toward stronger anti-fingerprinting defenses. The key advance over Panopticlick: Panopticlick only told you *whether* your browser was unique; CYT additionally itemizes *every* contributing signal, quantifies each in bits, and adds tracker-blocker effectiveness testing. Audience: privacy-conscious end users, journalists, and researchers — not site operators trying to block automation.

## Registration / access

None. Load the page, click "Test your browser." No login, email, or key. EFF states only anonymous, aggregated data is collected. (High confidence; confirmed on the tool's own pages.)

## How it decides bot-or-not

It doesn't. **CYT makes no bot/human decision and has no bot classifier.** What it computes instead is two things:

1. **Fingerprint uniqueness** — how identifying your browser's attributes are, expressed in "bits of identifying information" and a "one in X browsers share this" breakdown.
2. **Tracker-protection verdict** — a plain-language assessment (roughly: strong / some / no protection against web tracking) based on whether simulated trackers were blocked and whether your fingerprint is unique, near-unique, or randomized.

For an anti-bot engineer the relevant framing is the **corollary**: a headless/automated browser fed to CYT typically produces a broken or highly-unique canvas/WebGL fingerprint. CYT reports that as "unique" (a privacy problem for the user); a real detector reads the same anomaly as a bot tell. The collection vector is identical — only the scoring intent differs.

## Detection approaches

- **Passive attribute fingerprinting** — read navigator/screen/header properties.
- **Active probing fingerprinting** — canvas 2D, WebGL, and AudioContext rendering hashes; font/plugin enumeration.
- **Entropy / information-theory scoring** — each attribute compared against a rolling population to compute Shannon surprisal (`log2(X)` bits).
- **Tracker-blocking simulation** — actively attempts to load ads/beacons/trackers from EFF-controlled simulator domains to see which the browser's blockers stop.
- **Not used (important):** no `navigator.webdriver`/CDP/headless automation checks, no behavioral/mouse analysis, no TLS/JA3 fingerprinting, no IP/proxy/VPN reputation, no CAPTCHA/challenge, no ML bot classifier. It is not built to catch bots.

## Areas / signals scanned

### Client-side (JS)
- User-Agent (also read server-side), platform (`navigator.platform`), language.
- Screen size and color depth.
- Time zone and time zone offset.
- Browser plugin details; system font enumeration (JS; Flash historically).
- Cookies-enabled flag; limited supercookie / DOM-storage test.
- **Canvas** fingerprint hash (2D rendering).
- **WebGL** fingerprint hash + unmasked `WEBGL_debug_renderer_info` vendor/renderer strings.
- **AudioContext** fingerprint (confirmed via live result payloads exposing an "audio" whorl, rather than from the About/blog pages).
- Touch support; hardware concurrency (logical cores).
- Ad blocker used (inferred).
- *Unverified / low-confidence attributes:* "CPU class" (`navigator.cpuClass`, a legacy IE-only property — likely a carried-over artifact, not confirmed in the current metric set) and "device memory" (`navigator.deviceMemory` — plausible but not seen in inspected payloads).

### Server-side (HTTP headers only)
- Passively records request headers: `User-Agent`, `HTTP_ACCEPT`, `DNT` (Do Not Track).
- No TLS/JA3 analysis and no IP-reputation scoring. The client IP is stored only as an **HMAC (keyed hash)**, not used for the uniqueness score.

### Behavioral
- None.

## How it scans (architecture)

**Hybrid, but not in the anti-bot sense.** A JavaScript fingerprinting script runs client-side and actively computes the canvas/WebGL/AudioContext hashes, enumerates fonts/plugins, and reads navigator/screen properties. It also triggers loads of tracker resources from EFF simulator domains to test URL-based, domain-based, and heuristic/cookie-based blocking separately.

The collected fingerprint is then **POSTed as JSON ("whorls") to EFF's server** — a Python backend with a MySQL database. The server:
- passively logs the HTTP request headers;
- compares each submitted attribute against a **"totals" table** counting how often each value has been seen over a **rolling ~45-day epoch**, turning raw attributes into an entropy/uniqueness figure;
- stores the visitor IP only as an HMAC keyed hash with a key-refresh mechanism (the "so repeat visits are de-duplicated" rationale is a reasonable inference, not an explicitly confirmed statement).

A **no-JS results path** (`results-nojs`) also exists and scores using only the HTTP headers.

**Where the decision is made:** uniqueness scoring is **entirely server-side over a client-submitted JSON fingerprint.** For an adversarial audience this is the decisive architectural fact — the fingerprint is trivially **spoofable and replayable**, so the design is unusable for real bot detection. That is fine for CYT's purpose (it is measuring the honest browser's exposure) but is exactly the property a bot detector cannot tolerate.

## Scoring / output

Two outputs, no single number and no bot score:

1. **Uniqueness in "bits of identifying information."** For each attribute the tool reports "one in X browsers have this value"; the surprisal is `log2(X)` bits, and the overall figure is the combined entropy across all metrics. Higher bits = more unique = more trackable. X and the population are drawn from the server's rolling ~45-day epoch database, so the score is **relative to that recent sample, not absolute.** Real observed CYT results land roughly in the **~13–19 bit** range. (Any specific "unique among the N tested / at least N.NN bits" pair should be treated as illustrative — the precise figures cited in secondary research were not sourced.)
2. **Tracker-protection assessment** — a plain-language verdict from the blocking simulation plus fingerprint uniqueness. Notably, EFF explicitly credits **fingerprint randomization** as a valid defense: a randomized fingerprint can register as "unique" here yet still defeat trackers because its value changes each visit.

## Notable techniques

- **Canvas fingerprinting** — render text/graphics to a 2D canvas, hash pixels to expose GPU/driver/font-rasterization differences.
- **WebGL fingerprinting** — hash a rendered scene plus unmasked vendor/renderer strings.
- **AudioContext fingerprinting** — derive a fingerprint from audio-stack DSP output differences.
- **Entropy quantification in bits** with a per-attribute "one in X" breakdown — the main advance over Panopticlick's binary unique/not-unique verdict.
- **Rolling ~45-day epoch "totals" table** so uniqueness reflects a recent population rather than all-time skew.
- **Purpose-built tracker-simulator domains** to test blocking modes separately: the third-party simulators `trackersimulator.org`, `eviltracker.net`, `do-not-tracker.org`, **plus the first-party simulator `firstpartysimulator.net` / `firstpartysimulator.org`** — the latter is arguably the primary fingerprinting host (the no-JS fingerprint is served from `firstpartysimulator.net/fingerprint-nojs`).
- **HMAC-hashing the visitor IP** with a rotating key so raw IPs are not stored.
- **Versioned fingerprint schema** ("v2 whorls" seen in live URLs), indicating the collected vector set evolves over time. The real surface is deeper than the headline list — it also touches WebGL extensions/parameters (beyond just unmasked vendor/renderer) and font-metric/`getClientRects`-style geometry.

## What we observed firsthand

- No bot verdict exists to report; CYT does not classify bot vs human.
- The interactive results flow **did not fully render** in our Electron in-app browser this session, so no live entropy figure was captured.
- Our egress IP (`87.249.139.226`, NordVPN/DataCamp datacenter, Istanbul) is irrelevant to CYT's score — unlike the other tools in this set (incolumitas, Fingerprint, whoer flagged it as VPN/datacenter), CYT does no IP-reputation analysis and would not surface it.
- No fingerprint-POST or backend scoring traffic was captured firsthand (the flow stalled before submission), consistent with the client-JS-collects-then-POSTs-to-EFF-backend architecture described above.

## Verification notes

The adversarial review confirmed the research is well supported overall. Corrections folded into this report:

- **Simulator domain list was incomplete.** Added the first-party simulator `firstpartysimulator.net` / `firstpartysimulator.org` alongside the three third-party domains; the first-party host is likely the primary fingerprinting endpoint.
- **Audio fingerprinting is genuine but sourced from result payloads, not the About/blog pages** — noted inline.
- **"CPU class" flagged as unverified** (legacy IE-only `navigator.cpuClass`; likely a carried-over artifact) and **"device memory" as low-confidence** (not seen in inspected payloads) — both demoted from the confirmed signal list.
- **The specific example score figures** ("324,397 tested," "18.31 bits") in the research read as invented illustration and were dropped; only the plausible ~13–19 bit magnitude range is stated.
- **The HMAC-IP de-duplication rationale is an inference**, not an explicitly confirmed purpose — labeled as such.

No fabricated citations or endpoints were introduced; network endpoints stated here are limited to those in the firsthand notes, and the simulator/fingerprint domains come from the verified research.

## Open source / reusable

- **`github.com/EFForg/cover-your-tracks`** — the full application, AGPL v3. Python backend + MySQL totals table, Docker / docker-compose deploy. Formerly named `EFForg/panopticlick`. A builder can reuse its client-side fingerprint collectors (canvas/WebGL/audio/font enumeration) and, more usefully, its **entropy/"bits of identifying information" scoring model** — but note the AGPL obligations and that the entropy math needs a population database to be meaningful.

## Sources

- [Cover Your Tracks (home) — EFF](https://coveryourtracks.eff.org/)
- [About Cover Your Tracks — EFF](https://coveryourtracks.eff.org/about)
- [Cover Your Tracks fingerprint results (no-JS view)](https://coveryourtracks.eff.org/results-nojs)
- [Introducing Cover Your Tracks! — EFF Deeplinks blog](https://www.eff.org/deeplinks/2020/11/introducing-cover-your-tracks)
- [Find Out How Ad Trackers Follow You On the Web — EFF press release](https://www.eff.org/press/releases/find-out-how-online-trackers-follow-you-web-effs-cover-your-tracks-tool)
- [EFForg/cover-your-tracks README (architecture, 45-day epoch totals, AGPLv3)](https://github.com/EFForg/cover-your-tracks/blob/master/README.md)
- [Cover Your Tracks browser fingerprint exposure analysis — DataDome (third-party; 403 to automated fetch, cited from search summary only)](https://datadome.co/anti-detect-tools/coveryourtracks/)
