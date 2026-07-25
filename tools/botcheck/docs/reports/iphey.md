# iphey.com

Free real-time browser-FP + IP "trustworthiness" checker for anti-detect-browser / proxy / multi-accounting crowd. Runs on page load, collects ~70 device signals in-browser -> 1 trust verdict + 5 per-area statuses. Self-test/demo for open-source **MixVisit** FP engine, not enterprise anti-bot WAF.

- **URL:** https://iphey.com/ · **Category:** commercial FP / anonymity tool (free MixVisit SDK demo) · **Requires registration:** No — free, instant, no account/download.
- **Firsthand verdict** (in-app browser reports `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **"Trust Good" (Trustworthy, green)**. Despite datacenter/VPN egress & frozen/spoofed UA, unflagged — shows how permissive its consistency-only model is (no CDP/automation-protocol detection, the one signal catching this browser elsewhere).

## What it is — common info

Privacy-facing "how do I look to websites" checker. Front page: FP **"powered by MixVisit."** MixVisit (mixvisit.com, GitHub org `mixvisit-service`) ships open-source JS FP lib `@mix-visit/lite` (MIT), sells commercial visitor-ID / device-tracking product on top. iphey = free showcase for that engine.

Audience = anti-detect / proxy: people validating GoLogin, Multilogin, Kameleo, AdsPower profiles & VPN/proxy setups, troubleshooting bans. Framing inverted from anti-bot vendor: not "is this a bot" but "does my spoofed/masked setup look like consistent real user, or leak tells -> ban?" Session confirmed heavy antidetect/proxy partner ads (GoLogin, Floppydata, 1browser).

iphey/MixVisit ownership undisclosed. Third-party reviews from same-space competitors (Pixelscan, GoLogin, Multilogin, DiCloak).

## Registration / access

None. Free, FPs instantly on page load, no login/signup/download. Matches open-source example app: SvelteKit page FPs on load, stores repeat-visit history only in `localStorage`.

## How it decides bot-or-not

iphey does **not** frame itself as bot detector; per cited Pixelscan review does **not** do dedicated bot / headless-automation classification like DataDome or deviceandbrowserinfo (see Verification notes). Judgment = **consistency / coherence** verdict:

1. Collect ~70 client-side signals (below), hash ~60 stable -> 128-bit `fingerprintHash` in-browser.
2. Independently **feature-detect true engine & version** (Blink/Gecko/WebKit/Trident/EdgeHTML), cross-check vs claimed `User-Agent`. Mismatch -> spoofed UA or anti-detect browser.
3. **Geo coherence**: IP country/timezone/language vs `Intl` timezone vs `navigator.language(s)` vs HTML5 Geolocation API, & WebRTC-leaked real IP vs proxy IP.
4. **IP/network**: datacenter/hosting ASN vs residential, IP-matches-claimed-location?
5. Compare FP vs **crowdsourced DB of real-people FPs** for outlier/plausibility — FP no real user has (e.g. randomizing anti-detect browser) looks fake.

"Trustworthy" = signals consistent, IP clean, geo matches. Anti-detect browsers & clumsy spoofing flagged when signals contradict. Crucially our CDP-driven Electron browser passed — presents self-consistent Chrome-on-macOS FP, iphey has no automation-protocol probe to catch the driver.

## Detection approaches

- **Passive client-side FPing** — ~60 device/browser params + ~10 contextual, hashed -> 128-bit FP.
- **Consistency checking** — feature-detected true engine/version vs claimed UA; core anti-detect catcher.
- **Automation / headless tells** — `navigator.webdriver`; full enum of `window` globals & `navigator` props for injected artifacts; enum of built-in native methods for patched prototypes; DevTools-open detection. (No CDP/DevTools-Protocol detection — see What we observed.)
- **IP / network reputation** — geo+ASN lookup; datacenter-vs-residential; IP-vs-claimed-location.
- **Cross-signal geo coherence** — IP country/timezone vs `Intl` timezone vs `navigator.language(s)` vs Geolocation API.
- **WebRTC STUN IP-leak** — real local/public IP behind VPN/proxy.
- **Crowdsourced outlier detection** — vs real-people FP DB.
- **Hardware/rendering FPs** — Canvas, WebGL, AudioContext, clientRects, fonts; instability/implausibility exposes randomizing browsers.
- **ML / behavioral / TLS-JA3** — **not present** in open-source engine (no mouse/behavioral tracking, no documented ML classifier). Server-side TLS/HTTP-2 FPing unverified (see Verification notes).

## Areas / signals scanned

### Client-side (JS) — bulk of the tool

Verified vs `@mix-visit/lite` source. Stable device params (`client-parameters/index.ts`) & contextual params (`contextual-client-parameters/index.ts`) cover:

- **navigator.***: `userAgent`, `platform`, `vendor`, `product`, `appVersion`, `languages`, `hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`, `oscpu`, `doNotTrack`, `pdfViewerEnabled`, `cookieEnabled`, **`webdriver`**.
- **navigator.userAgentData** + `getHighEntropyValues` (architecture, bitness, model, platformVersion, uaFullVersion, wow64, fullVersionList).
- **Full enum of ALL `navigator` props & ALL `window` globals** (registry key `globalObjests` — sic, repo typo) — automation-artifact / anomaly surface.
- **Enum of built-in native object methods** (`buildInObjects.ts` — Array, Date, Function, Navigator, WebAssembly, RTCRtpReceiver, GPU, etc.) -> detect tampered prototypes.
- `navigator.plugins` & `mimeTypes`; legacy probes (ActiveX, Silverlight, Flash, Java).
- **Canvas** (2D text/image), **WebGL** (GPU vendor/renderer + params) & **WebGPU**, **AudioContext** fp + base latency.
- **Fonts**: installed fonts, font prefs, font rendering, CSS system fonts/colors.
- **Screen**: resolution, screen frame/available area, color depth, `devicePixelRatio`, color gamut, HDR, HDCP, monochrome depth, inverted/forced colors, contrast / reduced-motion / reduced-transparency prefs.
- **Timezone / locale**: `Intl.DateTimeFormat().resolvedOptions()` + `getTimezoneOffset` fallback + full `Intl` locale data.
- **Storage/DB**: cookies, sessionStorage, localStorage, indexedDB, openDatabase, storage quota.
- **Hardware/device APIs**: Battery, Bluetooth, Network Information, `deviceMemory`/`performance.memory`, touch support.
- Math fn results, media/DRM capabilities, speech-synthesis voices, computed-style props, CSS/color-space support, WebKit APIs.
- **Contextual (side-effecting) params**: WebRTC STUN, DevTools-open state, Geolocation permission/coords, IP/geo lookup, Global Privacy Control signal.

### Server-side (IP / TLS / HTTP headers)

- **IP intelligence** fetched *client-side* in open-source code: engine calls `https://ipgeo.myip.link/`, gets ip / asn / org / city / country / region / timezone / languages. iphey homepage additionally advertises **DNS leak test, IP blacklist/reputation, VPN check, standalone Bot Check** — these live in iphey's proprietary layer, not open-source engine.
- iphey backend necessarily also sees connecting IP & HTTP req headers. Whether it does **HTTP-header-vs-JS coherence** (Accept-Language vs `navigator.languages`; `Sec-CH-UA` / `Sec-CH-UA-Platform` req headers vs `getHighEntropyValues`) or **TLS/JA3-JA4 / HTTP-2 FPing** = **unverified** — that layer closed. Don't assume either way.

### Behavioral

None in open-source engine. No mouse-movement, keystroke, or timing capture. One marketing summary loosely calls it "behavioral scoring"; not supported by code.

## How it scans (architecture)

**Primarily client-side, w/ thin proprietary verdict layer.**

- Engine (`@mix-visit/lite`, `MixVisit.ts`) = pure browser JS. Runs in visitor browser, collects ~70 params, computes stable 128-bit `fingerprintHash` locally (x64 128-bit MurmurHash-style, `utils/hashing.ts`). Hash = **identity**, not score.
- IP/geo data pulled client-side from `ipgeo.myip.link`.
- **Trustworthiness verdict** (Trustworthy/Suspicious judgment & comparison vs crowdsourced real-FP DB) = iphey's own server/app layer, **not** in open-source repo. Open-source library only gathers signals & hashes.
- Decision split: signal collection & FP hash in client; verdict & crowd-comparison in iphey proprietary backend. Since collector open source, entire signal surface transparent & reproducible — only final scoring formula & reference DB opaque.

## Scoring / output

- One **overall trust verdict** = green/yellow/red label. Firsthand, ours = **"Trust Good"** (image alt text) = Trustworthy. Third-party reviews describe labels roughly Trustworthy / Suspicious / Unreliable, but exact 3-word triad not confirmed by any cited source (see Verification notes).
- **Five per-area statuses**, each marked reliable/consistent vs masked/counterfeit/unreliable: **BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE** (firsthand-confirmed as 5 groups).
- **No confirmed 0–100 numeric score.** One AI-style review claims 0–100 scale; live UI shows word labels, not numeric scale. Treat "0–100 score" as unconfirmed / likely wrong.
- Verdict = **rule/consistency judgment**, not documented ML classifier: flags contradictions (`webdriver=true`; UA vs feature-detected engine; IP country/timezone/language vs browser `Intl`/`navigator.language`/Geolocation; WebRTC-leaked real IP vs proxy IP; datacenter/hosting ASN; implausible FP outlier vs crowd DB).


## Notable techniques

- **Engine-vs-UA consistency probing** (`utils/browser.ts`): feature-detects real engine vs claimed UA. Verified Chromium probes use `webkitResolveLocalFileSystemURL` + `BatteryManager` + `navigator.vendor`; Gecko uses `buildID` + `onmozfullscreenchange`; WebKit uses `ApplePayError` + `navigator.vendor`. `isChromium86OrNewer()` version-band check exists. (Specific "RTCEncodedAudioFrame + absent MediaSettingsRange" signature from research = FingerprintJS pattern, **not** in source — see Verification notes.)
- **Full window-global + navigator-property enum** -> surface injected automation globals & property-shape anomalies.
- **Native-method enum** -> detect prototype tampering by stealth/spoofing frameworks.
- **DevTools-open detection**: Web Worker running `debugger` timing the pause, plus `outerWidth − innerWidth > 160px` discrepancy.
- **WebRTC STUN leak** (`stun.l.google.com:19302`) w/ private-IP regex classification -> real IP behind VPN/proxy.
- **Crowdsourced real-people FP DB** for outlier detection.
- **Canvas/WebGL/Audio/clientRects/font** FPs expose randomizing anti-detect browsers via unstable/implausible values.
- Reviews report it can sometimes name *which* anti-detect browser is in use.

## What we observed firsthand

- **No registration; free; runs in-browser real time.** Heavy antidetect/proxy partner ads (GoLogin, Floppydata, 1browser).
- **Single trust verdict** — Trustworthy (green) / Suspicious / Not Trustworthy (red). Ours = **"Trust Good"** = Trustworthy.
- **Five signal groups**, each w/ status: BROWSER, LOCATION, IP ADDRESS, HARDWARE, SOFTWARE.
- FP tech confirmed **"powered by MixVisit"** — open-source lib `github.com/mixvisit-service/mixvisit`, plus commercial mixvisit.com.
- Method framing on-page: compares your FP vs DB of real-people FPs "so that you are not banned by the servers" — tells antidetect users whether mask looks human. Data called out: UA, Canvas, WebRTC, AudioContext, fonts, plugins, timezone, GPU.
- **Mechanism observed:** client-side JS (MixVisit) collects & evaluates trust in-browser. **No obvious FP POST to iphey backend captured** in our session (contrast deviceandbrowserinfo & Fingerprint.com, where FP POST clearly visible). Consistent w/ open-source design: collection/hashing local; crowd-comparison call, if any, not observed.
- **Key contrast:** same in-app browser flagged as bot by deviceandbrowserinfo.com purely via `isAutomatedWithCDP`, & Fingerprint.com reported "Developer Tools = Yes" + VPN/datacenter IP. iphey caught **none**, returned Trustworthy — evidence its model = consistency-only, lacks CDP/automation-protocol and (at least visibly) IP-reputation gating strong enough to flag datacenter-egress, CDP-driven Electron browser presenting coherent FP.

## Verification notes

Adversarial review confirmed research well-supported but flagged following; corrections folded in:

- **Section count = five.** Live front page shows Browser, **Location**, IP address, Hardware, Software. Research listed four (omitting Location). Firsthand notes agree: five groups.
- **"0–100 numeric score" unsupported / likely wrong.** Cited Pixelscan review finds no numeric score; live UI uses word labels. Documented as unconfirmed, not fact.
- **"Trustworthy / Suspicious / Unreliable" triad not confirmed by any cited source** — a paraphrase. Verified live label = "Trust Score" w/ wording like "Trust Good," plus per-section reliable/masked/counterfeit language. Reported as approximate.
- **Engine-probe signature "RTCEncodedAudioFrame + absent MediaSettingsRange ⇒ Chromium 86+" not in source.** Real `browser.ts` uses `webkitResolveLocalFileSystemURL`/`BatteryManager`/`navigator.vendor` (Chromium), `buildID`/`onmozfullscreenchange` (Gecko), `ApplePayError`/`navigator.vendor` (WebKit). RTCEncodedAudioFrame pairing = embellishment; corrected above.
- **Parameter count corrected up:** ~60 stable client params + ~10 contextual ≈ **~70 total**, not the "~55 + ~10 ≈ 65" research stated.
- **Citation-support mismatch:** Pixelscan review actually states iphey does **not** do bot/VM/spoof detection (framing as limitation vs Pixelscan). So iphey must **not** be cited as evidence it does dedicated spoof/VM/bot classification — strength = consistency checking, not automation detection.
- **"No server-side TLS/JA3" stated too definitively.** Only client engine inspected; iphey server/verdict layer closed. Absence of TLS/JA3/HTTP-2 FPing = assumption about un-inspected backend, framed as unverified not confirmed negative.
- **Missing angles (open questions for builder):** server-side TLS/JA3-JA4 & HTTP-2 (SETTINGS-frame) FPing; HTTP-header-vs-JS coherence (`Sec-CH-UA*` req headers vs `getHighEntropyValues`, Accept-Language vs `navigator.languages`); DNS-leak & IP-blacklist/reputation (advertised on iphey homepage but outside open-source engine); named CDP/Selenium artifacts (`$cdc_`, `__webdriver_evaluate`, HeadlessChrome UA token, missing `chrome.runtime`) beyond generic `webdriver` + global enum.

## Open source / reusable

**Yes — collection engine reusable & MIT-licensed.**

- **`github.com/mixvisit-service/mixvisit`** — `@mix-visit/lite` FP COLLECTION engine plus SvelteKit example app iphey built on. Builder can lift whole client-side signal surface: `client-parameters/` (device params), `contextual-client-parameters/` (WebRTC STUN leak, DevTools detector, geolocation, IP/geo lookup), `utils/browser.ts` (engine-vs-UA probes), `buildInObjects.ts` (native-method tamper detection), `utils/hashing.ts` (x64 128-bit hash).
- **Not open source:** iphey's trustworthiness scoring/verdict logic & crowdsourced real-FP DB. You get signals & hash free; must build scoring & reference corpus yourself.

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
