# Pixelscan.net

Free, closed-source browser-fingerprint "multichecker" that judges a setup less on *what* it is than whether every signal tells **same story** — core weapon is internal-consistency cross-validation, aimed squarely at anti-detect / proxy / automation users wanting to know if mask leaks.

- **URL:** https://pixelscan.net/ · **Category:** privacy/anonymity & fingerprint tool (commercial, closed-source; audience is anti-detect/automation operators, not privacy consumers). **Not** an anti-bot vendor demo — doesn't sell bot protection to websites — and **not** an open-source test page. · **Requires registration:** No. Free, no signup/install, runs in seconds.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict produced.** Live report is JS + Cloudflare-gated, didn't render in our Electron browser — scan button never advanced past landing state. That bootstrap failure is itself mild signal our environment looks non-standard, but no scored result captured to report.

## What it is — common info

Pixelscan run by unnamed "small team" (per own `/manifest` page); no founders or parent company disclosed, only contact is `partners@pixelscan.net`. Stated purpose: let you "detect how your setup looks to anti-fraud systems, platform checks, and data-collecting tools." Unusually candid about who it serves — manifest names anti-detect browsers, account farming, proxies, location spoofing, and automation scripts/bots as intended use cases. In other words: QA tool for evasion operators — run masked browser through it, tells you where mask is inconsistent enough for real anti-fraud system to notice.

Landing page heavy with proxy/anti-detect marketing (Multilogin, NodeMaven partners; captcha-solver blog posts), appears monetized through affiliate/partner deals with those vendors plus paid detection **bounty program** (`/bounty`) paying for PoCs bypassing or detecting specific anti-detect browsers, proxies, frameworks. Advertises "no-honeypot / no-data-selling" and "Zero Data Stored" stance, positioning itself as *not* feeding anti-fraud vendors — trust signal to evasion community.

Caveat throughout: near-identical sister site, **pixelscan.dev**, exists with same branding, pushes TLS/ASN "network intelligence" story. Secondary write-ups routinely conflate the two, so some server-side TLS claims firmly documented only for `.dev`, merely plausible for `.net` (see Verification notes).

## Registration / access

None. Public checker free, installs nothing, no account/login required. Executes series of JavaScript tests directly in browser, completes in few seconds. Separate `/bot-check` page dedicated to human-vs-bot verdicts.

## How it decides bot-or-not

Pixelscan's central thesis: **coherence, not uniqueness**. Collects large parameter set (reviews and bot-check page cite roughly ~73 parameters — marketing/review figure, not independently auditable), cross-references them, flags every combination that "should not occur together." Canonical example, quoted by Proxidize: if browser claims Chrome-on-Windows but canvas/WebGL rendering matches Mac GPU, or browser timezone says UTC+3 while IP geolocates to New York, those mismatches flagged. Masked/anti-detect browser can have every field individually plausible and still fail, since fields contradict each other — that "irregular connection between fingerprint parameters" is what Pixelscan built to surface. Mirrors how large anti-fraud systems reason; Pixelscan explicitly name-checks platforms like Facebook, Google, Amazon as audience it emulates.

Dedicated bot-check runs named automation probes, returns binary human/bot verdict; fingerprint check returns "Consistent" vs "Inconsistent" style result. **No single numeric trust score** — output is consistency verdict plus per-module pass/warn/fail states. Exact weighting/algorithm undisclosed (closed source).

## Detection approaches

- **Fingerprint consistency cross-validation (primary):** flag parameter combinations that can't legitimately co-occur — UA/platform vs canvas/WebGL GPU vs timezone vs IP geolocation/ASN.
- **Automation-framework / headless detection:** named probes for Selenium, Puppeteer, Playwright, Electron, PhantomJS, chromedriver, plus `navigator.webdriver`, CDP (Chrome DevTools Protocol) markers, tampered/overridden JS functions, unusual window properties.
- **Browser fingerprinting (uniqueness + coherence):** canvas, WebGL, AudioContext, fonts, screen, navigator props.
- **Network / IP reputation:** ASN classification (datacenter vs residential vs mobile), proxy/VPN detection, IP blacklist lookup, DNS leak test.
- **Leak detection:** WebRTC real-IP exposure; DNS resolver leak.
- **Location cross-check:** IP geolocation vs browser timezone vs language/locale.
- **Server/edge network analysis:** IP/ASN/geolocation reconciliation; TLS/JA3 documented for sister site `pixelscan.dev`, inferred (not confirmed) for `.net`.
- **No behavioral biometrics.** No mouse-movement, keystroke-dynamics, or event-timing analysis. Pixelscan is static-fingerprint + consistency + network tool. For anti-bot engineer this is both defining characteristic and real evasion gap — bot producing coherent static fingerprint on clean residential IP has nothing behavioral to trip over here.

## Areas / signals scanned

**Client-side (JS, in visitor's browser):**
- `navigator.webdriver` flag; `navigator.platform` / user-agent consistency.
- Canvas fingerprint hash; WebGL vendor/renderer strings + hash; AudioContext hash.
- Installed fonts; screen/resolution properties; language/locale.
- Timezone (and alignment with IP geolocation).
- WebRTC (real IP leak).
- Automation markers surfaced on bot-check UI: `navigatorWebdriver` ("Navigator Clear"), CDP ("CDP Clear"), `tamperedFunctions` ("tamperedFunctions Detected"), `unusualWindowProperties`.
- Headless-mode indicators; chromedriver / Electron / PhantomJS signatures.

**Server-side (IP / network / HTTP):**
- IP address → ASN → geolocation, classified datacenter / residential / mobile.
- Proxy / VPN detection; IP blacklist status.
- DNS resolver / leak.
- HTTP headers.
- TLS / JA3 fingerprint — firmly documented for `pixelscan.dev`'s `/network` page, only inferred for `.net`.

**Behavioral:** none observed or documented.

## How it scans (architecture)

**Hybrid, primarily client-side, with mandatory server round-trip.** Core engine is JavaScript run in visitor's own browser: collects canvas/WebGL/audio hashes, fonts, screen, navigator properties, automation flags (webdriver, CDP, tampered functions, unusual window props), WebRTC, timezone/locale, then cross-validates them for contradictions.

In parallel, same connection analyzed at server/edge: IP resolved to ASN + geolocation, classified datacenter/residential/mobile, checked against proxy/VPN and blacklist databases, and (per `pixelscan.dev`'s network page) captured behind Cloudflare for TLS/JA3. Two halves then reconciled — browser-claimed timezone/UA vs server-observed IP geolocation/ASN — the crux of the "consistency" verdict.

**Firsthand network evidence** shows modules are backend-served, so backend round-trip definitely occurs (decision not purely in-page): distinct server endpoints observed —
- `/s/api/blp` — IP blacklist check
- `/s/api/p`, `/s/api/s`, `/s/api/m` — module data (proxy / scan-state / modules)

Front end gated by **Unleash feature flags** and Cloudflare. Whether full fingerprint JSON is POSTed for scoring or evaluated in-page and then reconciled server-side isn't explicitly documented, but server-side IP/ASN/blacklist results confirm at least one backend round-trip integral to verdict.

## Scoring / output

No single numeric trust score. Two output surfaces:
- **Fingerprint check** → consistency/coherence verdict ("Consistent" vs "Inconsistent"), plus per-module pass/warn/fail (IP blacklist, proxy, VPN, DNS leak, WebRTC, location).
- **Bot-check (`/bot-check`)** → binary verdict. UI headline reads **"You're Definitely a Human"** vs **"Bot Behavior Detected"**; internal per-test state labels use "Human Detected" / "Bot Detected."

Every flagged contradiction lowers outcome; tool rewards coherence, not distinctiveness. Weighting undisclosed.

## Notable techniques

- **Consistency as primary weapon:** catching anti-detect browsers whose fields are each valid but mutually contradictory (UA/platform vs canvas/WebGL GPU vs timezone vs IP geo/ASN). Whole point of the tool, most transferable idea for "bot-or-not" builder — collect broadly, then score the *joint distribution*, not each field in isolation.
- **`tamperedFunctions` probe:** mechanism (not spelled out on-page, but standard technique the name implies) is `Function.prototype.toString()` "[native code]" checks plus detection of `Proxy` / `Object.defineProperty` / getter overrides that stealth plugins (e.g. puppeteer-extra-stealth) install to hide `navigator.webdriver` and friends. Anti-evasion core, the interesting part for builder.
- **Named automation probes on bot-check UI:** `navigatorWebdriver`, CDP ("CDP Clear"), `tamperedFunctions`, `unusualWindowProperties`; framework signatures for Selenium/Puppeteer/Playwright/Electron/PhantomJS/chromedriver.
- **Timezone/locale/UA reconciled against server-side IP geolocation + ASN class** (datacenter/residential/mobile) — client-claim-vs-network-reality cross-check.
- **Crowdsourced detection R&D** via paid bounty program.
- **"No-honeypot / no-data-selling" positioning** as trust play toward evasion community.

**Gaps worth noting for builder (this tool does *not* do these):** no behavioral biometrics; no explicit User-Agent Client Hints consistency check (`navigator.userAgentData` / `getHighEntropyValues()` vs legacy UA string — primary modern spoofed-UA tell); no documented HTTP/2 frame fingerprint or HTTP header-**order** analysis (distinct from TLS/JA3); no evidence of active proxy/VPN probing (latency/RTT, MTU/TCP-stack, STUN candidate inspection) beyond passive ASN/blacklist DB lookups. Rigorous engine would add internal timezone self-consistency (`Intl.DateTimeFormat().resolvedOptions().timeZone` vs `Date.getTimezoneOffset()`) as check separate from timezone-vs-IP.

## What we observed firsthand

- Landing page advertises "No registration / 100% secure / Takes 5 seconds / Zero Data Stored," surrounded by anti-detect/proxy partner marketing (Multilogin, NodeMaven; captcha-solver posts).
- Live report is JS + Cloudflare-gated and **didn't render** in our Electron browser — clicking scan button never advanced flow, so obtained **no verdict** for test browser. Bootstrap failure a weak-but-real signal environment looked non-standard to the page.
- Modules backend-served. Observed server endpoints: `/s/api/blp` (blacklist), `/s/api/p`, `/s/api/s`, `/s/api/m` (module data). Front end uses **Unleash** feature flags.
- Consistent with its reputation for "your connection is not consistent / automation detected" verdict driven by internal-consistency checks rather than single score.

Where firsthand and research disagree, firsthand observation wins — notably, we could confirm backend endpoints and render-gating firsthand, but couldn't confirm any scored verdict, canvas-DB behavior, or TLS/JA3 on `.net`.

## Verification notes

Adversarial review flagged several research claims this report corrected or demoted:

- **Canvas-hash comparison against a "database of genuine real-device fingerprints"** — *unverified.* Couldn't be confirmed on any primary Pixelscan page or fetched Proxidize breakdown, which only supports consistency/cross-validation logic. Treat as inference, not documented fact; dropped from confirmed technique list.
- **"~99.5% of bots caught instantaneously, remainder in <1s"** — *unverified / conflated.* This two-stage timing appears only on third-party review sites (dicloak/hidemium), not on pixelscan.net. Pixelscan's own home page advertises **"99.95% Accuracy Rate,"** different metric from different source. Both marketing figures; neither independently auditable. Report cites neither as factual capability.
- **"~73 parameters"** — marketing/review figure, unverifiable against closed source; presented as such.
- **Rebrowser citation** does *not* corroborate automation-framework/CDP/TLS detection — fetched Rebrowser page lists only canvas/WebGL/IP-geo/WebRTC/hardware. Automation-probe details here rest on Pixelscan's own `/bot-check` UI and firsthand endpoint capture, not Rebrowser.
- **TLS / JA3** — firmly documented for sister site **pixelscan.dev** (its `/network` "Network Intelligence – IP, ASN & TLS Fingerprint Analysis" page runs on Cloudflare edge runtime), only *inferred* for pixelscan.net. Caveat deliberately kept, not softened.
- **Verdict wording** corrected to actual UI headlines: "You're Definitely a Human" / "Bot Behavior Detected."
- **GitHub presence** is promotional only: org handle `pixelscan-fingerprint-checker`, repo `pixelscan-browser-fingerprint-check` (1 star, updated Sep 2025) — SEO/marketing repo, **no detection source code**. Consistent with "no open source."
- Research confidence **medium-high** on client-side JS + consistency verdict, lower on scoring internals, canvas-DB claim, `.net` TLS specifics.

## Open source / reusable

**None.** Pixelscan closed-source and unauditable. Only public GitHub artifact (`pixelscan-fingerprint-checker` / `pixelscan-browser-fingerprint-check`) is promotional, contains no detection logic. Builder takes away the *methodology* — broad collection + joint-consistency scoring + `Function.prototype.toString` tamper checks — not any reusable code. (For reusable open-source collectors, see sibling reports on CreepJS, fp-scanner/fp-collect, MixVisit.)

## Sources

- [Pixelscan — home](https://pixelscan.net/)
- [Pixelscan bot-check](https://pixelscan.net/bot-check)
- [Pixelscan manifest / mission](https://pixelscan.net/manifest)
- [Pixelscan bounty program](https://pixelscan.net/bounty)
- [Pixelscan blog index](https://pixelscan.net/blog/)
- [Proxidize — Pixelscan: How to Check Your Browser Fingerprint](https://proxidize.com/blog/pixelscan/)
- [Rebrowser — Pixelscan browser fingerprint analysis](https://rebrowser.net/browser-fingerprints/pixelscan)
- [GitHub org: pixelscan-fingerprint-checker (promotional, no detection source)](https://github.com/pixelscan-fingerprint-checker)
