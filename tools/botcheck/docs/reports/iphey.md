# iphey.com

A free, real-time browser-fingerprint + IP "trustworthiness" checker aimed at the anti-detect-browser / proxy / multi-accounting crowd. It runs entirely on page load, collects ~70 device signals in the browser, and renders a single trust verdict plus five per-area statuses. It is a self-test / demo for the open-source **MixVisit** fingerprinting engine, not an enterprise anti-bot WAF.

- **URL:** https://iphey.com/ · **Category:** commercial fingerprint / anonymity tool (free public demo of the MixVisit SDK) · **Requires registration:** No — free, instant, no account or download.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): resolved to **"Trust Good" (Trustworthy, green)**. Despite the datacenter/VPN egress and the frozen/spoofed UA, iphey did not flag our browser — a useful data point on how permissive its consistency-only model is (it does no CDP/automation-protocol detection, which is the one signal that catches this browser elsewhere).

## What it is — common info

iphey.com is a privacy-facing "how do I look to websites" checker. Its front page states the fingerprinting is **"powered by MixVisit."** MixVisit (mixvisit.com, GitHub org `mixvisit-service`) ships an open-source JS fingerprint library, `@mix-visit/lite` (MIT), and sells a commercial visitor-identification / device-tracking product on top of it. iphey is effectively the free, privacy-facing showcase for that engine.

Its audience is explicitly the anti-detect / proxy ecosystem: people validating GoLogin, Multilogin, Kameleo, AdsPower profiles and VPN/proxy setups, and troubleshooting account bans. The framing is inverted from an anti-bot vendor: instead of "is this a bot," it answers "does my spoofed/masked setup look like a consistent real user, or does it leak tells that will get me banned?" The firsthand session confirmed heavy antidetect/proxy partner advertising (GoLogin, Floppydata, 1browser).

Corporate ownership of iphey/MixVisit is not publicly disclosed. Third-party reviews come from competitors in the same space (Pixelscan, GoLogin, Multilogin, DiCloak).

## Registration / access

None. The public checker is free and fingerprints instantly on page load with no login, signup, or download. This matches the open-source example app: a SvelteKit page that fingerprints on load and stores repeat-visit history only in the browser's own `localStorage`.

## How it decides bot-or-not

iphey does **not** frame itself as a bot detector, and per the cited Pixelscan review it does **not** perform dedicated bot / headless-automation classification the way DataDome or deviceandbrowserinfo do (see Verification notes). Its judgment is a **consistency / coherence** verdict:

1. Collect ~70 client-side signals (see below) and hash the ~60 stable ones into a 128-bit `fingerprintHash` in the browser.
2. Independently **feature-detect the true rendering engine and version** (Blink/Gecko/WebKit/Trident/EdgeHTML), then cross-check it against the claimed `User-Agent`. A mismatch means a spoofed UA or an anti-detect browser.
3. Cross-check **geolocation coherence**: IP-derived country/timezone/language vs `Intl` timezone vs `navigator.language(s)` vs the HTML5 Geolocation API, and the WebRTC-leaked real IP vs the proxy IP.
4. Classify the **IP/network**: datacenter/hosting ASN vs residential, and whether the IP matches the claimed location.
5. Compare the fingerprint against a **crowdsourced database of real-people fingerprints** for outlier/plausibility detection — a fingerprint no real user has (e.g. from a randomizing anti-detect browser) looks fake.

A "Trustworthy" result means the signals are internally consistent, the IP is clean, and geolocation matches. Anti-detect browsers and clumsy spoofing get flagged when signals contradict each other. Crucially, our CDP-driven Electron browser passed — it presents a self-consistent Chrome-on-macOS fingerprint, and iphey has no automation-protocol probe to catch the driver.

## Detection approaches

- **Passive client-side fingerprinting** — ~60 device/browser parameters + ~10 contextual parameters, hashed to a 128-bit fingerprint.
- **Consistency checking** — feature-detected true engine/version vs claimed UA; the core anti-detect-browser catcher.
- **Automation / headless tells** — `navigator.webdriver`; full enumeration of `window` globals and `navigator` properties to spot injected artifacts; enumeration of built-in native methods to spot patched/overridden prototypes; DevTools-open detection. (No CDP/DevTools-Protocol detection — see What we observed.)
- **IP / network reputation** — geo+ASN lookup; datacenter-vs-residential; IP-vs-claimed-location.
- **Cross-signal geolocation coherence** — IP country/timezone vs `Intl` timezone vs `navigator.language(s)` vs Geolocation API.
- **WebRTC STUN IP-leak** — reveals the real local/public IP behind a VPN/proxy.
- **Crowdsourced outlier detection** — comparison against a real-people fingerprint DB.
- **Hardware/rendering fingerprints** — Canvas, WebGL, AudioContext, clientRects, fonts; instability or implausibility exposes randomizing browsers.
- **ML / behavioral / TLS-JA3** — **not present** in the open-source engine (no mouse/behavioral tracking, no documented ML classifier). Server-side TLS/HTTP-2 fingerprinting is unverified either way (see Verification notes).

## Areas / signals scanned

### Client-side (JS) — the bulk of the tool

Verified directly against the `@mix-visit/lite` source. The stable device parameters (`client-parameters/index.ts`) and contextual parameters (`contextual-client-parameters/index.ts`) cover:

- **navigator.***: `userAgent`, `platform`, `vendor`, `product`, `appVersion`, `languages`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `oscpu`, `doNotTrack`, `pdfViewerEnabled`, `cookieEnabled`, **`webdriver`**.
- **navigator.userAgentData** + `getHighEntropyValues` (architecture, bitness, model, platformVersion, uaFullVersion, wow64, fullVersionList).
- **Full enumeration of ALL `navigator` properties and ALL `window` global objects** (registry key is `globalObjests` — sic, a repo typo) — the automation-artifact / anomaly surface.
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

- **IP intelligence** is fetched *client-side* in the open-source code: the engine calls `https://ipgeo.myip.link/` and gets back ip / asn / org / city / country / region / timezone / languages. iphey's own homepage additionally advertises **DNS leak test, IP blacklist/reputation, VPN check, and a standalone Bot Check** as tools it offers — these live in iphey's proprietary layer, not the open-source engine.
- iphey's backend necessarily also sees the connecting IP and HTTP request headers. Whether it does **HTTP-header-vs-JS coherence** (Accept-Language vs `navigator.languages`; `Sec-CH-UA` / `Sec-CH-UA-Platform` request headers vs `getHighEntropyValues`) or **TLS/JA3-JA4 / HTTP-2 fingerprinting** is **unverified** — that layer is closed. Do not assume it either does or does not.

### Behavioral

None in the open-source engine. No mouse-movement, keystroke, or timing capture. One marketing summary loosely calls it "behavioral scoring"; that is not supported by the code.

## How it scans (architecture)

**Primarily client-side, with a thin proprietary verdict layer.**

- The engine (`@mix-visit/lite`, `MixVisit.ts`) is pure browser JS. It runs in the visitor's browser, collects the ~70 parameters, and computes a stable 128-bit `fingerprintHash` locally (x64 128-bit MurmurHash-style, `utils/hashing.ts`). The hash is an **identity**, not a score.
- IP/geo data is pulled client-side from `ipgeo.myip.link`.
- The **trustworthiness verdict** (the "Trustworthy / Suspicious" judgment and the comparison against the crowdsourced real-fingerprint database) is iphey's own server/app layer and is **not** in the open-source repo. The open-source library only gathers signals and hashes them.
- The decision is therefore split: signal collection and the fingerprint hash happen in the client; the verdict and crowd-comparison happen in iphey's proprietary backend. Because the collector is open source, the entire signal surface is transparent and reproducible — only the final scoring formula and the reference DB are opaque.

## Scoring / output

- One **overall trust verdict** rendered as a green/yellow/red label. Firsthand, ours read as **"Trust Good"** (image alt text) = Trustworthy. Third-party reviews describe labels along the lines of Trustworthy / Suspicious / Unreliable, but that exact three-word triad is not confirmed by any cited source (see Verification notes).
- **Five per-area statuses**, each marked reliable/consistent vs masked/counterfeit/unreliable: **BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE** (firsthand-confirmed as five groups).
- **No confirmed 0–100 numeric score.** One AI-style review claims a 0–100 scale; the live UI shows word labels, not a numeric scale. Treat "0–100 score" as unconfirmed / likely wrong.
- The verdict is a **rule/consistency judgment**, not a documented ML classifier: it flags contradictions among signals (`webdriver=true`; UA vs feature-detected engine; IP country/timezone/language vs browser `Intl`/`navigator.language`/Geolocation; WebRTC-leaked real IP vs proxy IP; datacenter/hosting ASN; implausible fingerprint outlier vs the crowd DB).

## Notable techniques

- **Engine-vs-UA consistency probing** (`utils/browser.ts`): feature-detects the real engine and compares to the claimed UA. Verified Chromium probes use `webkitResolveLocalFileSystemURL` + `BatteryManager` + `navigator.vendor`; Gecko uses `buildID` + `onmozfullscreenchange`; WebKit uses `ApplePayError` + `navigator.vendor`. An `isChromium86OrNewer()` version-band check exists. (The specific "RTCEncodedAudioFrame + absent MediaSettingsRange" signature from the research is a FingerprintJS pattern and was **not** in the source — see Verification notes.)
- **Full window-global + navigator-property enumeration** to surface injected automation globals and property-shape anomalies.
- **Native-method enumeration** to detect prototype tampering by stealth/spoofing frameworks.
- **DevTools-open detection**: a Web Worker running `debugger` and timing the pause, plus an `outerWidth − innerWidth > 160px` discrepancy.
- **WebRTC STUN leak** (`stun.l.google.com:19302`) with private-IP regex classification, to expose the real IP behind a VPN/proxy.
- **Crowdsourced real-people fingerprint DB** for outlier detection.
- **Canvas/WebGL/Audio/clientRects/font** fingerprints that expose randomizing anti-detect browsers via unstable or implausible values.
- Reviews report it can sometimes name *which* anti-detect browser is in use.

## What we observed firsthand

- **No registration; free; runs in-browser in real time.** Heavy antidetect/proxy partner advertising (GoLogin, Floppydata, 1browser).
- **Single trust verdict** — Trustworthy (green) / Suspicious / Not Trustworthy (red). Ours resolved to **"Trust Good"** = Trustworthy.
- **Five signal groups**, each with a status: BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE.
- Fingerprint tech confirmed **"powered by MixVisit"** — open-source lib `github.com/mixvisit-service/mixvisit`, plus the commercial site mixvisit.com.
- Method framing observed on-page: compares your fingerprint against a DB of real-people fingerprints "so that you are not banned by the servers" — i.e. it tells antidetect users whether their mask looks human. Data called out: UA, Canvas, WebRTC, AudioContext, fonts, plugins, timezone, GPU.
- **Mechanism observed:** client-side JS (MixVisit) collects and evaluates trust in-browser. **No obvious fingerprint POST to an iphey backend was captured** in our session (contrast with, e.g., deviceandbrowserinfo and Fingerprint.com, where the fingerprint POST was clearly visible). This is consistent with the open-source design where collection/hashing are local; the crowd-comparison call, if any, was not observed.
- **Key contrast:** the same in-app browser was flagged as a bot by deviceandbrowserinfo.com purely via `isAutomatedWithCDP`, and Fingerprint.com reported "Developer Tools = Yes" and a VPN/datacenter IP. iphey caught **none** of this and returned Trustworthy — evidence that its model is consistency-only and lacks CDP/automation-protocol and (at least visibly) IP-reputation gating strong enough to flag a datacenter-egress, CDP-driven Electron browser presenting a coherent fingerprint.

## Verification notes

The adversarial review confirmed the research is well-supported but flagged the following; these corrections are folded into this doc:

- **Section count corrected to five.** The live front page shows Browser, **Location**, IP address, Hardware, Software. Research had listed four (omitting Location). Firsthand notes agree: five groups.
- **"0–100 numeric score" is unsupported / likely wrong.** The cited Pixelscan review finds no numeric score and the live UI uses word labels. Documented here as unconfirmed, not fact.
- **The "Trustworthy / Suspicious / Unreliable" triad is not confirmed by any cited source** — it is a paraphrase. The verified live label is a "Trust Score" with wording like "Trust Good," plus per-section reliable/masked/counterfeit language. Reported as approximate.
- **The engine-probe signature "RTCEncodedAudioFrame + absent MediaSettingsRange ⇒ Chromium 86+" is not in the source.** The real `browser.ts` uses `webkitResolveLocalFileSystemURL`/`BatteryManager`/`navigator.vendor` (Chromium), `buildID`/`onmozfullscreenchange` (Gecko), `ApplePayError`/`navigator.vendor` (WebKit). The RTCEncodedAudioFrame pairing was an embellishment; corrected above.
- **Parameter count corrected up:** ~60 stable client parameters + ~10 contextual ≈ **~70 total**, not the "~55 + ~10 ≈ 65" the research stated.
- **Citation-support mismatch:** the Pixelscan review actually states iphey does **not** do bot/VM/spoof detection (framing it as a limitation vs Pixelscan). So iphey must **not** be cited as evidence that it performs dedicated spoof/VM/bot classification — its strength is consistency checking, not automation detection.
- **"No server-side TLS/JA3" is stated too definitively.** Only the client engine was inspected; iphey's server/verdict layer is closed. The absence of TLS/JA3/HTTP-2 fingerprinting is an assumption about an un-inspected backend, framed here as unverified rather than a confirmed negative.
- **Missing angles (open questions for a builder):** server-side TLS/JA3-JA4 and HTTP-2 (SETTINGS-frame) fingerprinting; HTTP-header-vs-JS coherence (`Sec-CH-UA*` request headers vs `getHighEntropyValues`, Accept-Language vs `navigator.languages`); DNS-leak and IP-blacklist/reputation (advertised on iphey's homepage but outside the open-source engine); and named CDP/Selenium artifacts (`$cdc_`, `__webdriver_evaluate`, HeadlessChrome UA token, missing `chrome.runtime`) beyond generic `webdriver` + global enumeration.

## Open source / reusable

**Yes — the collection engine is reusable and MIT-licensed.**

- **`github.com/mixvisit-service/mixvisit`** — the `@mix-visit/lite` fingerprint COLLECTION engine plus the SvelteKit example app that iphey is built on. A builder can lift the whole client-side signal surface: `client-parameters/` (device params), `contextual-client-parameters/` (WebRTC STUN leak, DevTools detector, geolocation, IP/geo lookup), `utils/browser.ts` (engine-vs-UA probes), `buildInObjects.ts` (native-method tamper detection), and `utils/hashing.ts` (x64 128-bit hash).
- **Not open source:** iphey's trustworthiness scoring/verdict logic and its crowdsourced real-fingerprint database. You get the signals and the hash for free; you must build the scoring and the reference corpus yourself.

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
