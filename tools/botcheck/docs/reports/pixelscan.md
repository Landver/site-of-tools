# Pixelscan.net

Free, closed-source browser-FP "multichecker". Judges setup by whether every signal tells **same story**, not *what* it is. Core weapon = internal-consistency cross-validation, for anti-detect/proxy/automation users checking if mask leaks.

- **URL:** https://pixelscan.net/ · **Category:** privacy/anonymity & FP tool (commercial, closed-source; audience = anti-detect/automation operators, not privacy consumers). **Not** anti-bot vendor demo (doesn't sell bot protection to sites), **not** open-source test page. · **Registration:** No. Free, no signup/install, seconds.
- **Firsthand verdict, test browser** (in-app browser reports `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No verdict.** Live report JS + Cloudflare-gated, didn't render in our Electron browser; scan button never advanced past landing. Bootstrap failure itself = mild signal env looks non-standard, but no scored result.

## What it is — common info

Run by unnamed "small team" (per own `/manifest`); no founders/parent disclosed, only contact `partners@pixelscan.net`. Stated purpose: "detect how your setup looks to anti-fraud systems, platform checks, data-collecting tools." Candid re who it serves — manifest names anti-detect browsers, account farming, proxies, location spoofing, automation scripts/bots as intended uses. = QA tool for evasion operators: run masked browser through it, tells where mask inconsistent enough for real anti-fraud to notice.

Landing page heavy w/ proxy/anti-detect marketing (Multilogin, NodeMaven partners; captcha-solver posts); monetized via affiliate/partner deals + paid detection **bounty program** (`/bounty`) paying PoCs that bypass/detect specific anti-detect browsers, proxies, frameworks. Advertises "no-honeypot / no-data-selling" & "Zero Data Stored," positioning as *not* feeding anti-fraud vendors — trust signal to evasion community.

Caveat throughout: near-identical sister site **pixelscan.dev** exists, same branding, pushes TLS/ASN "network intelligence" story. Write-ups conflate the two, so some server-side TLS claims firmly documented only for `.dev`, merely plausible for `.net` (see Verification notes).

## Registration / access

None. Free, installs nothing, no account/login. Runs series of JS tests in-browser, completes in seconds. Separate `/bot-check` page for human-vs-bot verdicts.

## How it decides bot-or-not

Thesis: **coherence, not uniqueness**. Collects large param set (reviews & bot-check page cite ~73 params — marketing figure, not auditable), cross-references, flags every combo that "should not occur together." Canonical example (per Proxidize): browser claims Chrome-on-Windows but canvas/WebGL rendering matches Mac GPU, or timezone UTC+3 while IP geolocates NYC. Masked browser can have every field individually plausible & still fail, since fields contradict each other — that "irregular connection between FP params" is what Pixelscan surfaces. Mirrors how large anti-fraud reason; name-checks Facebook, Google, Amazon as audience it emulates.

Bot-check runs named automation probes -> binary human/bot verdict; FP check -> "Consistent" vs "Inconsistent." **No single numeric trust score** — output = consistency verdict + per-module pass/warn/fail. Weighting/algorithm undisclosed (closed source).

## Detection approaches

- **FP consistency cross-validation (primary):** flag param combos that can't legitimately co-occur — UA/platform vs canvas/WebGL GPU vs timezone vs IP geo/ASN.
- **Automation-framework / headless detection:** named probes for Selenium, Puppeteer, Playwright, Electron, PhantomJS, chromedriver, plus `navigator.webdriver`, CDP (Chrome DevTools Protocol) markers, tampered/overridden JS fns, unusual window props.
- **Browser FP (uniqueness + coherence):** canvas, WebGL, AudioContext, fonts, screen, navigator props.
- **Network / IP reputation:** ASN class (datacenter/residential/mobile), proxy/VPN detection, IP blacklist lookup, DNS leak test.
- **Leak detection:** WebRTC real-IP exposure; DNS resolver leak.
- **Location cross-check:** IP geo vs browser timezone vs language/locale.
- **Server/edge network analysis:** IP/ASN/geo reconciliation; TLS/JA3 documented for sister `pixelscan.dev`, inferred (not confirmed) for `.net`.
- **No behavioral biometrics.** No mouse-movement, keystroke-dynamics, event-timing. Static-FP + consistency + network tool. For anti-bot engineer = both defining trait & real evasion gap: bot producing coherent static FP on clean residential IP has nothing behavioral to trip on here.

## Areas / signals scanned

**Client-side (JS, in visitor's browser):**
- `navigator.webdriver` flag; `navigator.platform` / UA consistency.
- Canvas FP hash; WebGL vendor/renderer strings + hash; AudioContext hash.
- Installed fonts; screen/resolution props; language/locale.
- Timezone (& alignment w/ IP geo).
- WebRTC (real IP leak).
- Automation markers on bot-check UI: `navigatorWebdriver` ("Navigator Clear"), CDP ("CDP Clear"), `tamperedFunctions` ("tamperedFunctions Detected"), `unusualWindowProperties`.
- Headless indicators; chromedriver / Electron / PhantomJS signatures.

**Server-side (IP / network / HTTP):**
- IP -> ASN -> geo, classified datacenter / residential / mobile.
- Proxy / VPN detection; IP blacklist status.
- DNS resolver / leak.
- HTTP headers.
- TLS / JA3 FP — firmly documented for `pixelscan.dev`'s `/network` page, only inferred for `.net`.

**Behavioral:** none observed or documented.

## How it scans (architecture)

**Hybrid, primarily client-side, w/ mandatory server round-trip.** Core engine = JS in visitor's browser: collects canvas/WebGL/audio hashes, fonts, screen, navigator props, automation flags (webdriver, CDP, tampered fns, unusual window props), WebRTC, timezone/locale, then cross-validates for contradictions.

In parallel, same connection analyzed server/edge-side: IP -> ASN + geo, classified datacenter/residential/mobile, checked vs proxy/VPN & blacklist DBs, and (per `pixelscan.dev` network page) captured behind Cloudflare for TLS/JA3. Two halves reconciled — browser-claimed timezone/UA vs server-observed IP geo/ASN — crux of "consistency" verdict.

**Firsthand:** modules backend-served, so backend round-trip definitely occurs (decision not purely in-page). Endpoints observed:
- `/s/api/blp` — IP blacklist check
- `/s/api/p`, `/s/api/s`, `/s/api/m` — module data (proxy / scan-state / modules)

Front end gated by **Unleash feature flags** + Cloudflare. Whether full FP JSON POSTed for scoring or evaluated in-page then reconciled server-side isn't documented, but server-side IP/ASN/blacklist results confirm >=1 backend round-trip integral to verdict.

## Scoring / output

No single numeric trust score. Two surfaces:
- **FP check** -> consistency verdict ("Consistent" vs "Inconsistent"), plus per-module pass/warn/fail (IP blacklist, proxy, VPN, DNS leak, WebRTC, location).
- **Bot-check (`/bot-check`)** -> binary verdict. UI headline: **"You're Definitely a Human"** vs **"Bot Behavior Detected"**; internal per-test labels "Human Detected" / "Bot Detected."

Every flagged contradiction lowers outcome; rewards coherence, not distinctiveness. Weighting undisclosed.

## Notable techniques

- **Consistency as primary weapon:** catches anti-detect browsers whose fields each valid but mutually contradictory (UA/platform vs canvas/WebGL GPU vs timezone vs IP geo/ASN). Most transferable idea for "bot-or-not" builder — collect broadly, score the *joint distribution*, not each field alone.
- **`tamperedFunctions` probe:** mechanism (name implies) = `Function.prototype.toString()` "[native code]" checks + detecting `Proxy` / `Object.defineProperty` / getter overrides stealth plugins (e.g. puppeteer-extra-stealth) install to hide `navigator.webdriver` & friends. Anti-evasion core.
- **Named automation probes on bot-check UI:** `navigatorWebdriver`, CDP ("CDP Clear"), `tamperedFunctions`, `unusualWindowProperties`; framework signatures for Selenium/Puppeteer/Playwright/Electron/PhantomJS/chromedriver.
- **Timezone/locale/UA reconciled vs server-side IP geo + ASN class** (datacenter/residential/mobile) — client-claim-vs-network-reality cross-check.
- **Crowdsourced detection R&D** via paid bounty program.
- **"No-honeypot / no-data-selling" positioning** as trust play toward evasion community.

**Gaps for builder (tool does *not* do):** no behavioral biometrics; no explicit UA Client Hints consistency check (`navigator.userAgentData` / `getHighEntropyValues()` vs legacy UA string — primary modern spoofed-UA tell); no documented HTTP/2 frame FP or HTTP header-**order** analysis (distinct from TLS/JA3); no active proxy/VPN probing (latency/RTT, MTU/TCP-stack, STUN candidate inspection) beyond passive ASN/blacklist DB lookups. Rigorous engine would add internal timezone self-consistency (`Intl.DateTimeFormat().resolvedOptions().timeZone` vs `Date.getTimezoneOffset()`), separate from timezone-vs-IP.

## What we observed firsthand

- Landing page advertises "No registration / 100% secure / Takes 5 seconds / Zero Data Stored," surrounded by anti-detect/proxy partner marketing (Multilogin, NodeMaven; captcha-solver posts).
- Live report JS + Cloudflare-gated & **didn't render** in our Electron browser; scan button never advanced flow, so **no verdict**. Bootstrap failure = weak-but-real signal env looked non-standard to page.
- Modules backend-served. Endpoints: `/s/api/blp` (blacklist), `/s/api/p`, `/s/api/s`, `/s/api/m` (module data). Front end uses **Unleash** feature flags.
- Consistent w/ reputation for "your connection is not consistent / automation detected" verdict driven by internal-consistency checks not single score.

Where firsthand & research disagree, firsthand wins — confirmed backend endpoints & render-gating, but couldn't confirm any scored verdict, canvas-DB behavior, or TLS/JA3 on `.net`.

## Verification notes

Adversarial review flagged claims this report corrected/demoted:

- **Canvas-hash vs "DB of genuine real-device FPs"** — *unverified.* Not confirmable on any primary Pixelscan page or fetched Proxidize breakdown (only supports consistency/cross-validation logic). Inference, not fact; dropped from confirmed technique list.
- **"~99.5% bots caught instantaneously, remainder <1s"** — *unverified / conflated.* Two-stage timing only on third-party reviews (dicloak/hidemium), not pixelscan.net. Home page advertises **"99.95% Accuracy Rate,"** different metric, different source. Both marketing; neither auditable. Report cites neither as factual.
- **"~73 parameters"** — marketing figure, unverifiable vs closed source; presented as such.
- **Rebrowser citation** does *not* corroborate automation-framework/CDP/TLS detection — fetched Rebrowser page lists only canvas/WebGL/IP-geo/WebRTC/hardware. Automation-probe details here rest on Pixelscan's own `/bot-check` UI + firsthand endpoint capture.
- **TLS / JA3** — firmly documented for sister **pixelscan.dev** (its `/network` "Network Intelligence – IP, ASN & TLS Fingerprint Analysis" page runs on Cloudflare edge runtime), only *inferred* for pixelscan.net. Caveat kept.
- **Verdict wording** corrected to actual UI headlines: "You're Definitely a Human" / "Bot Behavior Detected."
- **GitHub presence** promotional only: org `pixelscan-fingerprint-checker`, repo `pixelscan-browser-fingerprint-check` (1 star, updated Sep 2025) — SEO/marketing repo, **no detection source**. Consistent w/ "no open source."
- Research confidence **medium-high** on client-side JS + consistency verdict, lower on scoring internals, canvas-DB claim, `.net` TLS specifics.

## Open source / reusable

**None.** Closed-source & unauditable. Only public GitHub artifact (`pixelscan-fingerprint-checker` / `pixelscan-browser-fingerprint-check`) promotional, no detection logic. Builder takeaway = *methodology* — broad collection + joint-consistency scoring + `Function.prototype.toString` tamper checks — not reusable code. (For reusable open-source collectors, see sibling reports on CreepJS, fp-scanner/fp-collect, MixVisit.)

## Sources

- [Pixelscan — home](https://pixelscan.net/)
- [Pixelscan bot-check](https://pixelscan.net/bot-check)
- [Pixelscan manifest / mission](https://pixelscan.net/manifest)
- [Pixelscan bounty program](https://pixelscan.net/bounty)
- [Pixelscan blog index](https://pixelscan.net/blog/)
- [Proxidize — Pixelscan: How to Check Your Browser Fingerprint](https://proxidize.com/blog/pixelscan/)
- [Rebrowser — Pixelscan browser fingerprint analysis](https://rebrowser.net/browser-fingerprints/pixelscan)
- [GitHub org: pixelscan-fingerprint-checker (promotional, no detection source)](https://github.com/pixelscan-fingerprint-checker)
