# Pixelscan.net

A free, closed-source browser-fingerprint "multichecker" that judges a setup less on *what* it is than on whether every signal tells the **same story** — its core weapon is internal-consistency cross-validation, aimed squarely at anti-detect / proxy / automation users who want to know if their mask leaks.

- **URL:** https://pixelscan.net/ · **Category:** privacy/anonymity & fingerprint tool (commercial, closed-source; audience is anti-detect/automation operators, not privacy consumers). It is **not** an anti-bot vendor demo — it does not sell bot protection to websites — and **not** an open-source test page. · **Requires registration:** No. Free, no signup/install, runs in seconds.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict was produced.** The live report is JS + Cloudflare-gated and did not render in our Electron browser — the scan button never advanced past the landing state. That failure to bootstrap is itself a mild signal that our environment looks non-standard, but we captured no scored result to report.

## What it is — common info

Pixelscan is run by an unnamed "small team" (per its own `/manifest` page); no founders or parent company are disclosed, and the only contact is `partners@pixelscan.net`. Its stated purpose is to let you "detect how your setup looks to anti-fraud systems, platform checks, and data-collecting tools." It is unusually candid about who it serves — the manifest names anti-detect browsers, account farming, proxies, location spoofing, and automation scripts/bots as intended use cases. In other words, it is a QA tool for evasion operators: run your masked browser through it, and it tells you where the mask is inconsistent enough for a real anti-fraud system to notice.

The landing page is heavy with proxy/anti-detect marketing (Multilogin, NodeMaven partners; captcha-solver blog posts) and it appears monetized through affiliate/partner deals with those vendors plus a paid detection **bounty program** (`/bounty`) that pays for PoCs bypassing or detecting specific anti-detect browsers, proxies, and frameworks. It advertises a "no-honeypot / no-data-selling" and "Zero Data Stored" stance, positioning itself as *not* feeding anti-fraud vendors — a trust signal to the evasion community.

Caveat carried throughout: a near-identical sister site, **pixelscan.dev**, exists with the same branding and pushes a TLS/ASN "network intelligence" story. Secondary write-ups routinely conflate the two, so some server-side TLS claims are firmly documented only for `.dev` and merely plausible for `.net` (see Verification notes).

## Registration / access

None. The public checker is free, installs nothing, and requires no account or login. It executes a series of JavaScript tests directly in the browser and completes in a few seconds. There is a separate `/bot-check` page dedicated to human-vs-bot verdicts.

## How it decides bot-or-not

Pixelscan's central thesis is **coherence, not uniqueness**. It collects a large parameter set (reviews and its bot-check page cite roughly ~73 parameters — a marketing/review figure, not independently auditable), then cross-references them and flags every combination that "should not occur together." The canonical example, quoted by Proxidize: if the browser claims Chrome-on-Windows but the canvas/WebGL rendering matches a Mac GPU, or the browser timezone says UTC+3 while the IP geolocates to New York, those mismatches are flagged. A masked/anti-detect browser can have every field individually plausible and still fail, because the fields contradict each other — that "irregular connection between fingerprint parameters" is what Pixelscan is built to surface. This mirrors how large anti-fraud systems reason, and Pixelscan explicitly name-checks platforms like Facebook, Google, and Amazon as the audience it emulates.

The dedicated bot-check runs named automation probes and returns a binary human/bot verdict; the fingerprint check returns a "Consistent" vs "Inconsistent" style result. There is **no single numeric trust score** — the output is a consistency verdict plus per-module pass/warn/fail states. The exact weighting/algorithm is undisclosed (closed source).

## Detection approaches

- **Fingerprint consistency cross-validation (primary):** flag parameter combinations that cannot legitimately co-occur — UA/platform vs canvas/WebGL GPU vs timezone vs IP geolocation/ASN.
- **Automation-framework / headless detection:** named probes for Selenium, Puppeteer, Playwright, Electron, PhantomJS, chromedriver, plus `navigator.webdriver`, CDP (Chrome DevTools Protocol) markers, tampered/overridden JS functions, and unusual window properties.
- **Browser fingerprinting (uniqueness + coherence):** canvas, WebGL, AudioContext, fonts, screen, navigator props.
- **Network / IP reputation:** ASN classification (datacenter vs residential vs mobile), proxy/VPN detection, IP blacklist lookup, DNS leak test.
- **Leak detection:** WebRTC real-IP exposure; DNS resolver leak.
- **Location cross-check:** IP geolocation vs browser timezone vs language/locale.
- **Server/edge network analysis:** IP/ASN/geolocation reconciliation; TLS/JA3 documented for the sister site `pixelscan.dev`, inferred (not confirmed) for `.net`.
- **No behavioral biometrics.** There is no mouse-movement, keystroke-dynamics, or event-timing analysis. Pixelscan is a static-fingerprint + consistency + network tool. For an anti-bot engineer this is both a defining characteristic and a real evasion gap — a bot that produces a coherent static fingerprint on a clean residential IP has nothing behavioral to trip over here.

## Areas / signals scanned

**Client-side (JS, in the visitor's browser):**
- `navigator.webdriver` flag; `navigator.platform` / user-agent consistency.
- Canvas fingerprint hash; WebGL vendor/renderer strings + hash; AudioContext hash.
- Installed fonts; screen/resolution properties; language/locale.
- Timezone (and its alignment with IP geolocation).
- WebRTC (real IP leak).
- Automation markers surfaced on the bot-check UI: `navigatorWebdriver` ("Navigator Clear"), CDP ("CDP Clear"), `tamperedFunctions` ("tamperedFunctions Detected"), `unusualWindowProperties`.
- Headless-mode indicators; chromedriver / Electron / PhantomJS signatures.

**Server-side (IP / network / HTTP):**
- IP address → ASN → geolocation, classified datacenter / residential / mobile.
- Proxy / VPN detection; IP blacklist status.
- DNS resolver / leak.
- HTTP headers.
- TLS / JA3 fingerprint — firmly documented for `pixelscan.dev`'s `/network` page, only inferred for `.net`.

**Behavioral:** none observed or documented.

## How it scans (architecture)

**Hybrid, primarily client-side, with a mandatory server round-trip.** The core engine is JavaScript run in the visitor's own browser: it collects canvas/WebGL/audio hashes, fonts, screen, navigator properties, automation flags (webdriver, CDP, tampered functions, unusual window props), WebRTC, and timezone/locale, then cross-validates them for contradictions.

In parallel, the same connection is analyzed at the server/edge: the IP is resolved to ASN + geolocation, classified datacenter/residential/mobile, checked against proxy/VPN and blacklist databases, and (per `pixelscan.dev`'s network page) captured behind Cloudflare for TLS/JA3. The two halves are then reconciled — browser-claimed timezone/UA vs server-observed IP geolocation/ASN — which is the crux of the "consistency" verdict.

**Firsthand network evidence** shows the modules are backend-served, so a backend round-trip definitely occurs (the decision is not purely in-page): distinct server endpoints were observed —
- `/s/api/blp` — IP blacklist check
- `/s/api/p`, `/s/api/s`, `/s/api/m` — module data (proxy / scan-state / modules)

The front end is gated by **Unleash feature flags** and Cloudflare. Whether a full fingerprint JSON is POSTed for scoring or evaluated in-page and then reconciled server-side is not explicitly documented, but the server-side IP/ASN/blacklist results confirm at least one backend round-trip is integral to the verdict.

## Scoring / output

No single numeric trust score. Two output surfaces:
- **Fingerprint check** → a consistency/coherence verdict ("Consistent" vs "Inconsistent"), plus per-module pass/warn/fail (IP blacklist, proxy, VPN, DNS leak, WebRTC, location).
- **Bot-check (`/bot-check`)** → a binary verdict. The UI headline reads **"You're Definitely a Human"** vs **"Bot Behavior Detected"**; the internal per-test state labels use "Human Detected" / "Bot Detected."

Every flagged contradiction lowers the outcome; the tool rewards coherence, not distinctiveness. Weighting is undisclosed.

## Notable techniques

- **Consistency as the primary weapon:** catching anti-detect browsers whose fields are each valid but mutually contradictory (UA/platform vs canvas/WebGL GPU vs timezone vs IP geo/ASN). This is the whole point of the tool and the most transferable idea for a "bot-or-not" builder — collect broadly, then score the *joint distribution*, not each field in isolation.
- **`tamperedFunctions` probe:** the mechanism (not spelled out on-page, but this is the standard technique the name implies) is `Function.prototype.toString()` "[native code]" checks plus detection of `Proxy` / `Object.defineProperty` / getter overrides that stealth plugins (e.g. puppeteer-extra-stealth) install to hide `navigator.webdriver` and friends. This anti-evasion core is the interesting part for a builder.
- **Named automation probes on the bot-check UI:** `navigatorWebdriver`, CDP ("CDP Clear"), `tamperedFunctions`, `unusualWindowProperties`; framework signatures for Selenium/Puppeteer/Playwright/Electron/PhantomJS/chromedriver.
- **Timezone/locale/UA reconciled against server-side IP geolocation + ASN class** (datacenter/residential/mobile) — the client-claim-vs-network-reality cross-check.
- **Crowdsourced detection R&D** via the paid bounty program.
- **"No-honeypot / no-data-selling" positioning** as a trust play toward the evasion community.

**Gaps worth noting for a builder (this tool does *not* do these):** no behavioral biometrics; no explicit User-Agent Client Hints consistency check (`navigator.userAgentData` / `getHighEntropyValues()` vs the legacy UA string — a primary modern spoofed-UA tell); no documented HTTP/2 frame fingerprint or HTTP header-**order** analysis (distinct from TLS/JA3); and no evidence of active proxy/VPN probing (latency/RTT, MTU/TCP-stack, STUN candidate inspection) beyond passive ASN/blacklist DB lookups. A rigorous engine would add internal timezone self-consistency (`Intl.DateTimeFormat().resolvedOptions().timeZone` vs `Date.getTimezoneOffset()`) as a check separate from timezone-vs-IP.

## What we observed firsthand

- Landing page advertises "No registration / 100% secure / Takes 5 seconds / Zero Data Stored," surrounded by anti-detect/proxy partner marketing (Multilogin, NodeMaven; captcha-solver posts).
- The live report is JS + Cloudflare-gated and **did not render** in our Electron browser — clicking the scan button never advanced the flow, so we obtained **no verdict** for the test browser. This bootstrap failure is a weak-but-real signal that the environment looked non-standard to the page.
- Modules are backend-served. Observed server endpoints: `/s/api/blp` (blacklist), `/s/api/p`, `/s/api/s`, `/s/api/m` (module data). Front end uses **Unleash** feature flags.
- Consistent with its reputation for the "your connection is not consistent / automation detected" verdict driven by internal-consistency checks rather than a single score.

Where firsthand and research disagree, the firsthand observation wins — notably, we could confirm the backend endpoints and the render-gating firsthand, but could not confirm any scored verdict, canvas-DB behavior, or TLS/JA3 on `.net`.

## Verification notes

The adversarial review flagged several research claims that this report has corrected or demoted:

- **Canvas-hash comparison against a "database of genuine real-device fingerprints"** — *unverified.* This could not be confirmed on any primary Pixelscan page or the fetched Proxidize breakdown, which only supports the consistency/cross-validation logic. Treat it as an inference, not documented fact; it has been dropped from the confirmed technique list.
- **"~99.5% of bots caught instantaneously, remainder in <1s"** — *unverified / conflated.* This two-stage timing appears only on third-party review sites (dicloak/hidemium), not on pixelscan.net. Pixelscan's own home page advertises a **"99.95% Accuracy Rate,"** a different metric from a different source. Both are marketing figures; neither is independently auditable. This report cites neither as a factual capability.
- **"~73 parameters"** — marketing/review figure, unverifiable against closed source; presented as such.
- **Rebrowser citation** does *not* corroborate automation-framework/CDP/TLS detection — the fetched Rebrowser page lists only canvas/WebGL/IP-geo/WebRTC/hardware. The automation-probe details here rest on Pixelscan's own `/bot-check` UI and the firsthand endpoint capture, not Rebrowser.
- **TLS / JA3** — firmly documented for the sister site **pixelscan.dev** (its `/network` "Network Intelligence – IP, ASN & TLS Fingerprint Analysis" page runs on a Cloudflare edge runtime), and only *inferred* for pixelscan.net. This caveat is deliberately kept, not softened.
- **Verdict wording** corrected to the actual UI headlines: "You're Definitely a Human" / "Bot Behavior Detected."
- **GitHub presence** is promotional only: the org handle is `pixelscan-fingerprint-checker` and the repo `pixelscan-browser-fingerprint-check` (1 star, updated Sep 2025) — an SEO/marketing repo, **no detection source code**. Consistent with "no open source."
- Research confidence is **medium-high** on the client-side JS + consistency verdict, lower on scoring internals, the canvas-DB claim, and `.net` TLS specifics.

## Open source / reusable

**None.** Pixelscan is closed-source and unauditable. The only public GitHub artifact (`pixelscan-fingerprint-checker` / `pixelscan-browser-fingerprint-check`) is promotional and contains no detection logic. A builder takes away the *methodology* — broad collection + joint-consistency scoring + `Function.prototype.toString` tamper checks — not any reusable code. (For reusable open-source collectors, see the sibling reports on CreepJS, fp-scanner/fp-collect, and MixVisit.)

## Sources

- [Pixelscan — home](https://pixelscan.net/)
- [Pixelscan bot-check](https://pixelscan.net/bot-check)
- [Pixelscan manifest / mission](https://pixelscan.net/manifest)
- [Pixelscan bounty program](https://pixelscan.net/bounty)
- [Pixelscan blog index](https://pixelscan.net/blog/)
- [Proxidize — Pixelscan: How to Check Your Browser Fingerprint](https://proxidize.com/blog/pixelscan/)
- [Rebrowser — Pixelscan browser fingerprint analysis](https://rebrowser.net/browser-fingerprints/pixelscan)
- [GitHub org: pixelscan-fingerprint-checker (promotional, no detection source)](https://github.com/pixelscan-fingerprint-checker)
