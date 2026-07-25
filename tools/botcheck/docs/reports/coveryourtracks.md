# EFF Cover Your Tracks

EFF browser-FP uniqueness & tracker-blocking self-test. **Not a bot detector** — measures how identifiable/trackable *your own* browser is + whether privacy extensions stop trackers. Documented for signal set & architecture, heavily overlapping real anti-bot vendor collection.

- **URL:** https://coveryourtracks.eff.org/ · **Category:** privacy/anonymity & FP tool (open source, non-profit; Panopticlick successor) · **Registration:** No — open, anonymous, no account/email.
- **Firsthand verdict, test browser** (in-app browser reports `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict.** No bot/human output by design; interactive results didn't fully render in our Electron browser. Nothing labels our automation a bot; at most env = highly-unique (thus very trackable) FP.

## What it is — common info

Cover Your Tracks (CYT), by **Electronic Frontier Foundation** (EFF), US digital-rights non-profit. Direct successor to **Panopticlick**, 2010 research project (orig. Peter Eckersley) first showing browsers uniquely ID'able via FP. Rebranded/relaunched as CYT **Nov 2020**.

Purpose: **educational/advocacy**, opposite of commercial anti-bot: show user own FP, quantify uniqueness/trackability, test blockers, pressure ecosystem toward stronger anti-FP defenses. Advance over Panopticlick: latter told only *whether* browser unique; CYT itemizes *every* signal, quantifies each in bits, adds tracker-blocker testing. Audience: privacy-conscious users, journalists, researchers — not operators blocking automation.

## Registration / access

None. Load page, click "Test your browser." No login/email/key. EFF states only anonymous, aggregated data collected. (High confidence; confirmed on tool's own pages.)

## How it decides bot-or-not

Doesn't. **No bot/human decision, no bot classifier.** Computes instead:

1. **FP uniqueness** — how identifying attributes are, in "bits of identifying information" & "one in X browsers share this" breakdown.
2. **Tracker-protection verdict** — plain-language (~strong / some / no protection vs tracking) from whether simulated trackers blocked & whether FP unique, near-unique, or randomized.

Relevant framing for anti-bot engineer = **corollary**: headless/automated browser -> broken or highly-unique canvas/WebGL FP. CYT reports "unique" (user privacy problem); real detector reads same anomaly as bot tell. Collection vector identical — only scoring intent differs.

## Detection approaches

- **Passive attribute FP** — read navigator/screen/header props.
- **Active probing FP** — canvas 2D, WebGL, AudioContext rendering hashes; font/plugin enumeration.
- **Entropy / info-theory scoring** — each attribute vs rolling population -> Shannon surprisal (`log2(X)` bits).
- **Tracker-blocking simulation** — loads ads/beacons/trackers from EFF-controlled simulator domains to see which blockers stop.
- **Not used (important):** no `navigator.webdriver`/CDP/headless checks, no behavioral/mouse analysis, no TLS/JA3 FP, no IP/proxy/VPN reputation, no CAPTCHA/challenge, no ML classifier. Not built to catch bots.

## Areas / signals scanned

### Client-side (JS)
- User-Agent (also server-side), platform (`navigator.platform`), language.
- Screen size + color depth.
- Time zone + TZ offset.
- Browser plugin details; system font enumeration (JS; Flash historically).
- Cookies-enabled flag; limited supercookie / DOM-storage test.
- **Canvas** FP hash (2D rendering).
- **WebGL** FP hash + unmasked `WEBGL_debug_renderer_info` vendor/renderer strings.
- **AudioContext** FP (confirmed via live result payloads exposing "audio" whorl, not About/blog pages).
- Touch support; hardware concurrency (logical cores).
- Ad blocker used (inferred).
- *Unverified / low-confidence:* "CPU class" (`navigator.cpuClass`, legacy IE-only — likely carried-over artifact, not confirmed in current metric set) & "device memory" (`navigator.deviceMemory` — plausible, not seen in inspected payloads).

### Server-side (HTTP headers only)
- Passively records headers: `User-Agent`, `HTTP_ACCEPT`, `DNT`.
- No TLS/JA3, no IP-reputation. Client IP stored only as **HMAC (keyed hash)**, not used for uniqueness score.

### Behavioral
- None.

## How it scans (architecture)

**Hybrid, but not anti-bot sense.** JS FP script client-side: computes canvas/WebGL/AudioContext hashes, enumerates fonts/plugins, reads navigator/screen props. Also triggers tracker-resource loads from EFF simulator domains to test URL-based, domain-based, heuristic/cookie-based blocking separately.

Collected FP then **POSTed as JSON ("whorls") to EFF server** — Python backend, MySQL DB. Server:
- passively logs HTTP headers;
- compares each attribute vs **"totals" table** counting how often each value seen over **rolling ~45-day epoch** -> entropy/uniqueness figure;
- stores visitor IP only as HMAC keyed hash w/ key-refresh ("repeat visits de-duplicated" rationale = reasonable inference, not confirmed).

**No-JS path** (`results-nojs`) also exists, scores using HTTP headers only.

**Where decision made:** uniqueness scoring **entirely server-side over client-submitted JSON FP.** For adversarial audience = decisive fact — FP trivially **spoofable & replayable**, so unusable for real bot detection. Fine for CYT's purpose (measuring honest browser exposure) but exactly the property a bot detector can't tolerate.

## Scoring / output

Two outputs, no single number, no bot score:

1. **Uniqueness in "bits of identifying information."** Per attribute: "one in X browsers have this value"; surprisal = `log2(X)` bits, overall = combined entropy across all metrics. Higher bits = more unique = more trackable. X & population from server's rolling ~45-day epoch DB, so score **relative to recent sample, not absolute.** Real observed CYT results land ~**13–19 bits**. (Any specific "unique among N tested / at least N.NN bits" pair = illustrative — precise figures in secondary research weren't sourced.)
2. **Tracker-protection assessment** — verdict from blocking sim + FP uniqueness. EFF explicitly credits **FP randomization** as valid defense: randomized FP can register "unique" here yet still defeat trackers since value changes each visit.

## Notable techniques

- **Canvas FP** — render text/graphics to 2D canvas, hash pixels to expose GPU/driver/font-rasterization diffs.
- **WebGL FP** — hash rendered scene + unmasked vendor/renderer strings.
- **AudioContext FP** — from audio-stack DSP output diffs.
- **Entropy quantification in bits** w/ per-attribute "one in X" breakdown — main advance over Panopticlick's binary verdict.
- **Rolling ~45-day epoch "totals" table** so uniqueness reflects recent population, not all-time skew.
- **Purpose-built tracker-simulator domains** testing blocking modes separately: third-party sims `trackersimulator.org`, `eviltracker.net`, `do-not-tracker.org`, **plus first-party sim `firstpartysimulator.net` / `firstpartysimulator.org`** — latter arguably primary FP host (no-JS FP served from `firstpartysimulator.net/fingerprint-nojs`).
- **HMAC-hashing visitor IP** w/ rotating key so raw IPs not stored.
- **Versioned FP schema** ("v2 whorls" in live URLs) — vector evolves over time. Real surface deeper than headline list — also WebGL extensions/parameters (beyond unmasked vendor/renderer) & font-metric/`getClientRects`-style geometry.

## What we observed firsthand

- No bot verdict; CYT doesn't classify bot vs human.
- Interactive results **didn't fully render** in our Electron in-app browser, so no live entropy figure captured.
- Egress IP (`87.249.139.226`, NordVPN/DataCamp datacenter, Istanbul) irrelevant to CYT's score — unlike other tools in this set (incolumitas, Fingerprint, whoer flagged it VPN/datacenter), CYT does no IP-reputation analysis, wouldn't surface it.
- No FP-POST or backend scoring traffic captured (flow stalled before submission), consistent w/ client-JS-collects-then-POSTs-to-EFF-backend architecture above.

## Verification notes

Adversarial review confirmed research well supported overall. Corrections folded in:

- **Simulator domain list incomplete.** Added first-party sim `firstpartysimulator.net` / `firstpartysimulator.org` alongside three third-party domains; first-party host likely primary FP endpoint.
- **Audio FP genuine but sourced from result payloads, not About/blog pages** — noted inline.
- **"CPU class" flagged unverified** (legacy IE-only `navigator.cpuClass`; likely carried-over artifact) & **"device memory" low-confidence** (not seen in inspected payloads) — both demoted from confirmed list.
- **Specific example scores** ("324,397 tested," "18.31 bits") read as invented illustration, dropped — only plausible ~13–19 bit range stated.
- **HMAC-IP de-duplication rationale = inference**, not confirmed — labeled as such.

No fabricated citations/endpoints introduced; network endpoints limited to firsthand notes + simulator/FP domains from verified research.

## Open source / reusable

- **`github.com/EFForg/cover-your-tracks`** — full app, AGPL v3. Python backend + MySQL totals table, Docker / docker-compose deploy. Formerly `EFForg/panopticlick`. Builder can reuse client-side FP collectors (canvas/WebGL/audio/font enumeration) &, more usefully, its **entropy/"bits of identifying information" scoring model** — but AGPL obligations apply & entropy math needs a population DB to mean anything.

## Sources

- [Cover Your Tracks (home) — EFF](https://coveryourtracks.eff.org/)
- [About Cover Your Tracks — EFF](https://coveryourtracks.eff.org/about)
- [Cover Your Tracks fingerprint results (no-JS view)](https://coveryourtracks.eff.org/results-nojs)
- [Introducing Cover Your Tracks! — EFF Deeplinks blog](https://www.eff.org/deeplinks/2020/11/introducing-cover-your-tracks)
- [Find Out How Ad Trackers Follow You On the Web — EFF press release](https://www.eff.org/press/releases/find-out-how-online-trackers-follow-you-web-effs-cover-your-tracks-tool)
- [EFForg/cover-your-tracks README (architecture, 45-day epoch totals, AGPLv3)](https://github.com/EFForg/cover-your-tracks/blob/master/README.md)
- [Cover Your Tracks browser fingerprint exposure analysis — DataDome (third-party; 403 to automated fetch, cited from search summary only)](https://datadome.co/anti-detect-tools/coveryourtracks/)
