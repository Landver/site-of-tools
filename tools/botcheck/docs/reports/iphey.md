# iphey.com

Free, real-time browser-fingerprint + IP "trustworthiness" checker aimed at anti-detect-browser / proxy / multi-accounting crowd. Runs entirely on page load, collects ~70 device signals in browser, renders single trust verdict plus five per-area statuses. Self-test / demo for open-source **MixVisit** fingerprinting engine, not enterprise anti-bot WAF.

- **URL:** https://iphey.com/ · **Category:** commercial fingerprint / anonymity tool (free public demo of MixVisit SDK) · **Requires registration:** No — free, instant, no account or download.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): resolved to **"Trust Good" (Trustworthy, green)**. Despite datacenter/VPN egress and frozen/spoofed UA, iphey didn't flag our browser — useful data point on how permissive its consistency-only model is (does no CDP/automation-protocol detection, the one signal that catches this browser elsewhere).

## What it is — common info

iphey.com: privacy-facing "how do I look to websites" checker. Front page states fingerprinting **"powered by MixVisit."** MixVisit (mixvisit.com, GitHub org `mixvisit-service`) ships open-source JS fingerprint library, `@mix-visit/lite` (MIT), sells commercial visitor-identification / device-tracking product on top of it. iphey effectively free, privacy-facing showcase for that engine.

Audience explicitly anti-detect / proxy ecosystem: people validating GoLogin, Multilogin, Kameleo, AdsPower profiles and VPN/proxy setups, troubleshooting account bans. Framing inverted from anti-bot vendor: instead of "is this a bot," answers "does my spoofed/masked setup look like consistent real user, or does it leak tells that'll get me banned?" Firsthand session confirmed heavy antidetect/proxy partner advertising (GoLogin, Floppydata, 1browser).

Corporate ownership of iphey/MixVisit not publicly disclosed. Third-party reviews come from competitors in same space (Pixelscan, GoLogin, Multilogin, DiCloak).

## Registration / access

None. Public checker free, fingerprints instantly on page load, no login, signup, or download. Matches open-source example app: SvelteKit page fingerprinting on load, stores repeat-visit history only in browser's own `localStorage`.

## How it decides bot-or-not

iphey does **not** frame itself as bot detector, and per cited Pixelscan review does **not** perform dedicated bot / headless-automation classification the way DataDome or deviceandbrowserinfo do (see Verification notes). Judgment is **consistency / coherence** verdict:

1. Collect ~70 client-side signals (see below), hash ~60 stable ones into 128-bit `fingerprintHash` in browser.
2. Independently **feature-detect true rendering engine and version** (Blink/Gecko/WebKit/Trident/EdgeHTML), cross-check against claimed `User-Agent`. Mismatch means spoofed UA or anti-detect browser.
3. Cross-check **geolocation coherence**: IP-derived country/timezone/language vs `Intl` timezone vs `navigator.language(s)` vs HTML5 Geolocation API, and WebRTC-leaked real IP vs proxy IP.
4. Classify the **IP/network**: datacenter/hosting ASN vs residential, whether IP matches claimed location.
5. Compare fingerprint against **crowdsourced database of real-people fingerprints** for outlier/plausibility detection — fingerprint no real user has (e.g. from randomizing anti-detect browser) looks fake.

"Trustworthy" result means signals internally consistent, IP clean, geolocation matches. Anti-detect browsers and clumsy spoofing get flagged when signals contradict each other. Crucially, our CDP-driven Electron browser passed — presents self-consistent Chrome-on-macOS fingerprint, iphey has no automation-protocol probe to catch the driver.

## Detection approaches

- **Passive client-side fingerprinting** — ~60 device/browser parameters + ~10 contextual parameters, hashed to 128-bit fingerprint.
- **Consistency checking** — feature-detected true engine/version vs claimed UA; core anti-detect-browser catcher.
- **Automation / headless tells** — `navigator.webdriver`; full enumeration of `window` globals and `navigator` properties to spot injected artifacts; enumeration of built-in native methods to spot patched/overridden prototypes; DevTools-open detection. (No CDP/DevTools-Protocol detection — see What we observed.)
- **IP / network reputation** — geo+ASN lookup; datacenter-vs-residential; IP-vs-claimed-location.
- **Cross-signal geolocation coherence** — IP country/timezone vs `Intl` timezone vs `navigator.language(s)` vs Geolocation API.
- **WebRTC STUN IP-leak** — reveals real local/public IP behind VPN/proxy.
- **Crowdsourced outlier detection** — comparison against real-people fingerprint DB.
- **Hardware/rendering fingerprints** — Canvas, WebGL, AudioContext, clientRects, fonts; instability or implausibility exposes randomizing browsers.
- **ML / behavioral / TLS-JA3** — **not present** in open-source engine (no mouse/behavioral tracking, no documented ML classifier). Server-side TLS/HTTP-2 fingerprinting unverified either way (see Verification notes).

## Areas / signals scanned

### Client-side (JS) — bulk of the tool

Verified directly against `@mix-visit/lite` source. Stable device parameters (`client-parameters/index.ts`) and contextual parameters (`contextual-client-parameters/index.ts`) cover:

- **navigator.***: `userAgent`, `platform`, `vendor`, `product`, `appVersion`, `languages`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `oscpu`, `doNotTrack`, `pdfViewerEnabled`, `cookieEnabled`, **`webdriver`**.
- **navigator.userAgentData** + `getHighEntropyValues` (architecture, bitness, model, platformVersion, uaFullVersion, wow64, fullVersionList).
- **Full enumeration of ALL `navigator` properties and ALL `window` global objects** (registry key is `globalObjests` — sic, repo typo) — automation-artifact / anomaly surface.
- **Enumeration of built-in native object methods** (`buildInObjects.ts` — Array, Date, Function, Navigator, WebAssembly, RTCRtpReceiver, GPU, etc.) to detect tampered prototypes.
- `navigator.plugins` and `mimeTypes`; legacy probes (ActiveX, Silverlight, Flash, Java).
- **Canvas** (2D text/image), **WebGL** (GPU vendor/renderer + params) and **WebGPU**, **AudioContext** fp + base latency.
- **Fonts**: installed fonts, font preferences, font rendering, CSS system fonts/colors.
- **Screen**: resolution, screen frame/available area, color depth, `devicePixelRatio`, color gamut, HDR, HDCP, monochrome depth, inverted/forced colors, contrast / reduced-motion / reduced-transparency prefs.
- **Timezone / locale**: `Intl.DateTimeFormat().resolvedOptions()` + `getTimezoneOffset` fallback + full `Intl` locale data.
- **Storage/DB**: cookies, sessionStorage, localStorage, indexedDB, openDatabase, storage quota.
- **Hardware/device APIs**: Battery, Bluetooth, Network Information, `deviceMemory`/`performance.memory`, touch support.
- Math function results, media/DRM capabilities, speech-synthesis voices, computed-style properties, CSS/color-space support, WebKit APIs.
- **Contextual (side-effecting) params**: WebRTC STUN, DevTools-open state, Geolocation permission/coords, IP/geo lookup, Global Privacy Control signal.

### Server-side (IP / TLS / HTTP headers)

- **IP intelligence** fetched *client-side* in open-source code: engine calls `https://ipgeo.myip.link/`, gets back ip / asn / org / city / country / region / timezone / languages. iphey's own homepage additionally advertises **DNS leak test, IP blacklist/reputation, VPN check, standalone Bot Check** as tools it offers — these live in iphey's proprietary layer, not open-source engine.
- iphey's backend necessarily also sees connecting IP and HTTP request headers. Whether it does **HTTP-header-vs-JS coherence** (Accept-Language vs `navigator.languages`; `Sec-CH-UA` / `Sec-CH-UA-Platform` request headers vs `getHighEntropyValues`) or **TLS/JA3-JA4 / HTTP-2 fingerprinting** is **unverified** — that layer closed. Don't assume it either does or doesn't.

### Behavioral

None in open-source engine. No mouse-movement, keystroke, or timing capture. One marketing summary loosely calls it "behavioral scoring"; not supported by the code.

## How it scans (architecture)

**Primarily client-side, with thin proprietary verdict layer.**

- Engine (`@mix-visit/lite`, `MixVisit.ts`) is pure browser JS. Runs in visitor's browser, collects ~70 parameters, computes stable 128-bit `fingerprintHash` locally (x64 128-bit MurmurHash-style, `utils/hashing.ts`). Hash is an **identity**, not a score.
- IP/geo data pulled client-side from `ipgeo.myip.link`.
- **Trustworthiness verdict** ("Trustworthy / Suspicious" judgment and comparison against crowdsourced real-fingerprint database) is iphey's own server/app layer, **not** in open-source repo. Open-source library only gathers signals and hashes them.
- Decision therefore split: signal collection and fingerprint hash happen in client; verdict and crowd-comparison happen in iphey's proprietary backend. Since collector is open source, entire signal surface transparent and reproducible — only final scoring formula and reference DB opaque.

## Scoring / output

- One **overall trust verdict** rendered as green/yellow/red label. Firsthand, ours read as **"Trust Good"** (image alt text) = Trustworthy. Third-party reviews describe labels roughly Trustworthy / Suspicious / Unreliable, but exact three-word triad not confirmed by any cited source (see Verification notes).
- **Five per-area statuses**, each marked reliable/consistent vs masked/counterfeit/unreliable: **BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE** (firsthand-confirmed as five groups).
- **No confirmed 0–100 numeric score.** One AI-style review claims 0–100 scale; live UI shows word labels, not numeric scale. Treat "0–100 score" as unconfirmed / likely wrong.
- Verdict is a **rule/consistency judgment**, not documented ML classifier: flags contradictions among signals (`webdriver=true`; UA vs feature-detected engine; IP country/timezone/language vs browser `Intl`/`navigator.language`/Geolocation; WebRTC-leaked real IP vs proxy IP; datacenter/hosting ASN; implausible fingerprint outlier vs crowd DB).

## Notable techniques

- **Engine-vs-UA consistency probing** (`utils/browser.ts`): feature-detects real engine, compares to claimed UA. Verified Chromium probes use `webkitResolveLocalFileSystemURL` + `BatteryManager` + `navigator.vendor`; Gecko uses `buildID` + `onmozfullscreenchange`; WebKit uses `ApplePayError` + `navigator.vendor`. `isChromium86OrNewer()` version-band check exists. (Specific "RTCEncodedAudioFrame + absent MediaSettingsRange" signature from research is FingerprintJS pattern, was **not** in source — see Verification notes.)
- **Full window-global + navigator-property enumeration** to surface injected automation globals and property-shape anomalies.
- **Native-method enumeration** to detect prototype tampering by stealth/spoofing frameworks.
- **DevTools-open detection**: Web Worker running `debugger` and timing the pause, plus `outerWidth − innerWidth > 160px` discrepancy.
- **WebRTC STUN leak** (`stun.l.google.com:19302`) with private-IP regex classification, to expose real IP behind VPN/proxy.
- **Crowdsourced real-people fingerprint DB** for outlier detection.
- **Canvas/WebGL/Audio/clientRects/font** fingerprints that expose randomizing anti-detect browsers via unstable or implausible values.
- Reviews report it can sometimes name *which* anti-detect browser is in use.

## What we observed firsthand

- **No registration; free; runs in-browser real time.** Heavy antidetect/proxy partner advertising (GoLogin, Floppydata, 1browser).
- **Single trust verdict** — Trustworthy (green) / Suspicious / Not Trustworthy (red). Ours resolved to **"Trust Good"** = Trustworthy.
- **Five signal groups**, each with status: BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE.
- Fingerprint tech confirmed **"powered by MixVisit"** — open-source lib `github.com/mixvisit-service/mixvisit`, plus commercial site mixvisit.com.
- Method framing observed on-page: compares your fingerprint against DB of real-people fingerprints "so that you are not banned by the servers" — tells antidetect users whether mask looks human. Data called out: UA, Canvas, WebRTC, AudioContext, fonts, plugins, timezone, GPU.
- **Mechanism observed:** client-side JS (MixVisit) collects and evaluates trust in-browser. **No obvious fingerprint POST to iphey backend captured** in our session (contrast with e.g. deviceandbrowserinfo and Fingerprint.com, where fingerprint POST clearly visible). Consistent with open-source design where collection/hashing local; crowd-comparison call, if any, not observed.
- **Key contrast:** same in-app browser was flagged as bot by deviceandbrowserinfo.com purely via `isAutomatedWithCDP`, and Fingerprint.com reported "Developer Tools = Yes" and VPN/datacenter IP. iphey caught **none** of this, returned Trustworthy — evidence its model is consistency-only, lacks CDP/automation-protocol and (at least visibly) IP-reputation gating strong enough to flag datacenter-egress, CDP-driven Electron browser presenting coherent fingerprint.

## Verification notes

Adversarial review confirmed research well-supported but flagged following; corrections folded into this doc:

- **Section count corrected to five.** Live front page shows Browser, **Location**, IP address, Hardware, Software. Research had listed four (omitting Location). Firsthand notes agree: five groups.
- **"0–100 numeric score" unsupported / likely wrong.** Cited Pixelscan review finds no numeric score, live UI uses word labels. Documented here as unconfirmed, not fact.
- **"Trustworthy / Suspicious / Unreliable" triad not confirmed by any cited source** — a paraphrase. Verified live label is "Trust Score" with wording like "Trust Good," plus per-section reliable/masked/counterfeit language. Reported as approximate.
- **Engine-probe signature "RTCEncodedAudioFrame + absent MediaSettingsRange ⇒ Chromium 86+" is not in the source.** Real `browser.ts` uses `webkitResolveLocalFileSystemURL`/`BatteryManager`/`navigator.vendor` (Chromium), `buildID`/`onmozfullscreenchange` (Gecko), `ApplePayError`/`navigator.vendor` (WebKit). RTCEncodedAudioFrame pairing was embellishment; corrected above.
- **Parameter count corrected up:** ~60 stable client parameters + ~10 contextual ≈ **~70 total**, not the "~55 + ~10 ≈ 65" research stated.
- **Citation-support mismatch:** Pixelscan review actually states iphey does **not** do bot/VM/spoof detection (framing as limitation vs Pixelscan). So iphey must **not** be cited as evidence it performs dedicated spoof/VM/bot classification — strength is consistency checking, not automation detection.
- **"No server-side TLS/JA3" stated too definitively.** Only client engine inspected; iphey's server/verdict layer closed. Absence of TLS/JA3/HTTP-2 fingerprinting is assumption about un-inspected backend, framed here as unverified rather than confirmed negative.
- **Missing angles (open questions for builder):** server-side TLS/JA3-JA4 and HTTP-2 (SETTINGS-frame) fingerprinting; HTTP-header-vs-JS coherence (`Sec-CH-UA*` request headers vs `getHighEntropyValues`, Accept-Language vs `navigator.languages`); DNS-leak and IP-blacklist/reputation (advertised on iphey's homepage but outside open-source engine); named CDP/Selenium artifacts (`$cdc_`, `__webdriver_evaluate`, HeadlessChrome UA token, missing `chrome.runtime`) beyond generic `webdriver` + global enumeration.

## Open source / reusable

**Yes — collection engine reusable and MIT-licensed.**

- **`github.com/mixvisit-service/mixvisit`** — `@mix-visit/lite` fingerprint COLLECTION engine plus SvelteKit example app iphey built on. Builder can lift whole client-side signal surface: `client-parameters/` (device params), `contextual-client-parameters/` (WebRTC STUN leak, DevTools detector, geolocation, IP/geo lookup), `utils/browser.ts` (engine-vs-UA probes), `buildInObjects.ts` (native-method tamper detection), `utils/hashing.ts` (x64 128-bit hash).
- **Not open source:** iphey's trustworthiness scoring/verdict logic and its crowdsourced real-fingerprint database. You get signals and hash for free; you must build scoring and reference corpus yourself.

## Sources

- [iphey.com — real-time browser fingerprinting test (front page)](https://iphey.com/)
- [mixvisit-service/mixvisit — GitHub repo (MIT, @mix-visit/lite engine + example app)](https://github.com/mixvisit-service/mixvisit)
- [MixVisit lite — client-parameter registry (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/client-parameters/index.ts)
- [MixVisit lite — navigator collector incl. webdriver + userAgentData high-entropy (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/client-parameters/navigator.ts)
- [MixVisit lite — engine/UA consistency probes (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/utils/browser.ts)
- [MixVisit lite — contextual params registry (globalObjects, devToolsOpen, webrtc, geolocation, location) (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/contextual-client-parameters/index.ts)
- [MixVisit lite — WebRTC STUN IP-leak detector (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/contextual-client-parameters/webrtc.ts)
- [MixVisit lite — DevTools-open detector (Worker debugger + window-size) (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/contextual-client-parameters/devToolsDetector.ts)
- [MixVisit lite — IP/ASN/geo lookup via ipgeo.myip.link (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/contextual-client-parameters/location.ts)
- [MixVisit lite — MixVisit orchestrator + fingerprintHash (source)](https://raw.githubusercontent.com/mixvisit-service/mixvisit/main/packages/mixvisit-lite/src/MixVisit.ts)
- [GoLogin — How to Pass Iphey](https://gologin.com/blog/how-to-pass-iphey/)
- [Pixelscan — IPhey Checker Review 2026](https://pixelscan.net/blog/iphey-review/)
- [MixVisit — commercial product site](https://www.mixvisit.com/)
