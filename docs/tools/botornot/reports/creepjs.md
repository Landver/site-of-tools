# CreepJS

An open-source, client-side browser-fingerprinting research page whose real specialty is **tamper / "lie" detection**: it recomputes the same signals across execution contexts and tortures native JS APIs to expose spoofed or automated browsers. It is not a commercial bot scorer, but the anti-detect and scraping industry treats "passing CreepJS" as a benchmark, so it is a useful reference for any bot-or-not builder.

- **URL:** https://abrahamjuliot.github.io/creepjs/ · **Category:** open-source test page (fingerprinting / anti-fingerprinting research tool, used de-facto as an automation-detection benchmark) · **Requires registration:** No — static GitHub Pages, runs automatically on load, no account.
- **Firsthand verdict for the test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): CreepJS did **not** issue a hard "bot" verdict — its headless module read `chromium: true, 44% like headless, 0% headless, 0% stealth`. Its strength showed elsewhere: it **caught the User-Agent spoof** (UA string claims macOS Catalina `10_15_7` while `userAgentData` reports macOS `26.5.1` — Electron freezes the UA at 10_15_7), surfaced a **timezone inconsistency** (reported `Europe/Moscow` while the egress IP geolocates to Istanbul), and **leaked the egress IP `87.249.139.226`** plus media devices via WebRTC. So it read the browser as a real Chromium engine (not headless) but flagged multiple lies/inconsistencies a naive fingerprint would miss.

## What it is — common info

CreepJS is a research and education project by developer **Abraham Juliot** (GitHub `abrahamjuliot`). Per its README the stated purpose is to "shed light on weaknesses and privacy leaks among modern anti-fingerprinting extensions and browsers" — i.e. it is explicitly built to test how well privacy tools and stealth/automation setups hold up, not to be sold as a fingerprinting library. The README lists targeted tools including Tor Browser, Firefox RFP, Brave, ungoogled-chromium, puppeteer-extra, FakeBrowser, uBlock Origin, NoScript, CanvasBlocker, Chameleon, and ScriptSafe.

Because it is unusually good at catching spoofing, the scraping / anti-detect ecosystem (ZenRows, Undetectable, Dolphin Anty, Rebrowser, iProyal, etc.) uses it as a pass/fail bench for stealth browsers. The "CreepJS" name is trademarked; the README warns that the **only official deployment is on GitHub Pages** and that any `.com`/`.org`/custom-domain "CreepJS" is an unauthorized mirror or potential honeypot.

Audience: researchers, privacy-tool authors, and the anti-detect community — not enterprise site operators (unlike DataDome/Fingerprint).

## Registration / access

None. Visit the URL; the page runs in-browser and renders results. No login, signup, API key, or paywall exists anywhere in the source or on the page.

## How it decides bot-or-not

CreepJS does not produce a single authoritative "bot: yes/no" the way a commercial vendor does. It runs a large battery of fingerprint collectors, then applies three overlapping judgments:

1. **Lie/tamper count** — how many native APIs show evidence of being overridden, proxied, or spoofed. This is its signature and the most load-bearing signal.
2. **Headless/stealth ratings** — three percentages (`like headless`, `headless`, `stealth`) derived from known headless-Chrome and stealth-plugin tells.
3. **Crowd-blending / rarity** — how common your fingerprint is versus a population of prior visitors (this is the piece that depends on a backend; see caveats below).

A boolean "bad bot" flag (`getBotHash` in `src/utils/crypto.ts`) fires if any of a fixed set of patterns is present — a worker-scope lie, a platform-version lie, a `Function.prototype.toString` Proxy leak, an out-of-range feature version, an extreme lie count (>100 lies, a bad OS/font match, or **any** lie classed as "stealth"), a blocked worker scope, or (server-computed) excessive loose fingerprints / low crowd-blending. When it fires, the UI shows **"locked"** in place of a score. In short: a low/locked result means either high rarity/entropy **or** detected tampering — the engine deliberately conflates "you're spoofing" with "you're suspicious."

## Detection approaches

- **Fingerprinting** — broad high-entropy collection (canvas, WebGL, audio, fonts, screen, Intl, math/engine quirks, etc.).
- **JS tampering / "lie" detection** — probing native functions for prototype, descriptor, `toString`, and error-behavior anomalies. Its core technique.
- **Headless / automation detection** — a dedicated module with `likeHeadless` / `headless` / `stealth` signal groups (SwiftShader, missing GPU, taskbar/viewport geometry, permissions bug, chrome-object anomalies, etc.).
- **Anti-fingerprinting / privacy-tool "resistance"** — detecting Tor, Firefox RFP, Brave, and extensions.
- **Cross-scope consistency** — recomputing signals in Web Worker / Service Worker / iframe and comparing to the main window and to `userAgentData` and fonts, to catch contradictions.
- **Crowd-blending / entropy** — rarity of the fingerprint against a visitor population (backend-dependent — see architecture).
- **NOT present:** no behavioral biometrics, no TLS/TCP/network fingerprinting, no IP-reputation/proxy scoring, no CAPTCHA/proof-of-work challenge. (See Verification notes.)

## Areas / signals scanned

### Client-side (JS) — the overwhelming majority

- **Navigator** (~80 props): `userAgent`, `appVersion`, `platform`, `vendor`, `plugins`, `mimeTypes`, `userAgentData` high-entropy hints, `webdriver`, `pdfViewerEnabled`, DNT, GPC, WebGPU, permissions.
- **Direct automation tells:** `navigator.webdriver`; `HeadlessChrome` substring in UA/appVersion (checked in both main and worker scope).
- **Canvas 2D:** image/blob/paint/text/emoji rendering + `TextMetrics`.
- **WebGL:** images/pixels, GPU parameters, `UNMASKED_RENDERER_WEBGL` (GPU model), SwiftShader software-renderer check.
- **Audio:** `AudioContext`/`OfflineAudioContext` signature (sum, gain, freq, time, trap, copy).
- **Fonts:** installed/loadable fonts via `FontFace`, plus OS/platform inference from the font set.
- **Speech synthesis** voices (local/remote/lang/default).
- **Screen & window geometry:** screen vs avail vs `innerWidth`/`outerHeight` vs `visualViewport`, taskbar-absent check, color depth, touch.
- **Timezone + Intl** (locale entropy, self-consistency of timezone vs device — note: consistency is checked internally, never against the connection IP).
- **DOMRect / SVGRect** geometry and emoji DomRect measurements.
- **CSS** system styles, computed styles, media queries (`prefers-color-scheme`, etc.).
- **JS runtime** Math results and console/error-stack engine signatures; `window` keys and `HTMLElement` keys (version/engine fingerprint).
- **Cross-scope:** dedicated/shared/service worker scope UA/GPU/locale vs main; iframe `contentWindow` / behemoth-iframe behavior.
- **WebRTC:** host connection, ICE foundation/IP candidates, SDP capabilities, STUN, media devices (client-side candidate enumeration — this is what leaked our egress IP; it is **not** IP-reputation scoring).
- **Chrome object:** presence/index, `chrome.runtime.sendMessage`/`connect` integrity.
- **Permissions bug:** `navigator.permissions.query('notifications')` vs `Notification.permission` mismatch.
- Media capabilities/codecs, MIME types, battery/network status, Web Share / content-index / contacts-manager presence.

### Server-side

Effectively none of the network layer. The only server dependency is the **crowd-blending / prediction** aggregation (visitor-sample store + hash-to-device decoding), which is not part of the pure client fingerprint. There is **no** HTTP-header, TLS/JA3, TCP/IP, or IP-reputation analysis.

### Behavioral

None. CreepJS is a one-shot, page-load fingerprint. There is no mouse/pointer movement, keystroke timing, scroll/touch cadence, or interaction-timing analysis.

## How it scans (architecture)

**Predominantly client-side.** The bundled script (`src/creep.ts` compiled to `docs/creep.js`) runs ~19–21 fingerprinting modules concurrently (`Promise.all`) in the browser. It computes a raw fingerprint (`window.Fingerprint`) and a privacy-hardened variant (`window.Creep`), produces the main **FP ID** hash plus per-component hashes and a **fuzzy** hash (`hashify` / `getFuzzyHash` in `src/utils/crypto.ts`), runs lie detection (`src/lies/index.ts`), computes the headless/stealth ratings (`src/headless/index.ts`), does resistance detection, and computes the partial bot signature (`getBotHash`). Even the UA-lie parser (`decryptUserAgent`) is a **local** routine, not a server call.

**Server component (design-inferred, not observed live).** The source's prediction module (`src/prediction/index.ts`) accepts server-supplied `decryptionData` and a numeric `crowdBlendingScore` as parameters, and `getBotHash` explicitly leaves two patterns — `excessiveLooseFingerprints` and `crowdBlendingScoreIsLow` — marked "compute on server." This is strong evidence the author **designed for** a backend that stores visitor samples, decodes the hash into a predicted OS/device/GPU, and computes crowd rarity. That backend is **not** in the public repo, and — importantly — **no backend POST was observed firsthand** (only 4 GETs to github.io; the optional shared-visitor DB API did not fire / was blocked). The committed `docs/creep.js` build likewise shows no `fetch`/XHR/`sendBeacon` to a backend. So treat the crowd-blending pipeline as an inferred design contract, not a confirmed live mechanism (see Verification notes).

**Where the decision is made:** the tamper/headless/lie logic is entirely **client-side** and self-contained; only the crowd-rarity portion of the verdict would live server-side.

## Scoring / output

Firsthand, the page rendered: an **FP ID** (main fingerprint hash), a **Fuzzy hash** (locality/similarity hash), a **percentage with a letter grade** (surfaced in the UI as a "trust score"), and a **LIES** count.

- The visible percentage-with-grade corresponds to the **Crowd-Blending Score** (0–100%), which `src/prediction/index.ts` grades ≥90 A, ≥80 B, ≥70 C, ≥60 D, else F. Higher = your fingerprint is common / blends in; lower = rare / suspicious. Third-party blogs loosely call this the "trust score." Because it is server-computed and no backend call was observed, whether the live static page truly populates this from a server or renders a client-side fallback is **unverified**.
- **Headless ratings:** each of `likeHeadless` / `headless` / `stealth` = `(matched signals / total signals) × 100`, shown as "% like headless / % headless / % stealth" (ours: 44 / 0 / 0).
- **Lie detection:** a running `totalLies` count across probed APIs.
- **Boolean bot flag:** the 8-bit `botHash`; if any pattern fires, `badBot` is set and the UI shows **"locked"** instead of a crowd-blending score.

There is **no** single unified 0–100 "bot probability." An operator reads the combination of lies, headless %, and rarity.

## Notable techniques

- **Native-function torture ("lie" detection, `src/lies/index.ts` `queryLies`):** for each API function it checks `toString()` against known `[native code]` output, checks for illegal own-properties/descriptors (`prototype`/`arguments`/`caller`/`toString`), and traps whether calling / `new` / `apply` / class-`extends` throws the correct `TypeError`.
- **Proxy detection via error-stack inspection:** `Object.create(new Proxy(fn,{})).toString()` and reading `fn.arguments`/`caller`, then verifying stack frames (`at Function.toString` / `at Object.toString` / strict-mode markers). Catches the `Function.prototype.toString` Proxy that `puppeteer-extra-stealth` installs.
- **`hasBadChromeRuntime`** *(in the headless/stealth module, not the lies module):* instantiates `chrome.runtime.sendMessage`/`connect` and inspects for `prototype` presence / wrong error constructor to catch a faked `chrome.runtime`.
- **`hasHighChromeIndex`:** checks whether `chrome` appears among the last ~50 `window` keys — stealth patches inject it late.
- **`hasIframeProxy`:** builds an iframe with `srcdoc` and inspects `contentWindow` to detect a proxied window.
- **`hasKnownBgColor`:** renders CSS system color `ActiveText` and checks for `rgb(255,0,0)` — a headless tell.
- **Permissions bug:** `permissions.query('notifications')` returning `prompt` while `Notification.permission` is `denied` — classic headless-Chrome inconsistency.
- **Cross-scope GPU/UA comparison:** main-thread WebGL `UNMASKED_RENDERER` vs Web Worker `webglRenderer` (`hasBadWebGL`); worker-scope UA vs window-scope fonts to catch platform-version lies.
- **SwiftShader** software-renderer detection (headless has no real GPU).
- **Taskbar/viewport geometry** (`screen == avail`, `innerWidth == screen.width`) indicating no OS chrome.
- **Server-side crowd-blending** (design): decode a fingerprint hash into a predicted OS/device/GPU from a sample DB, flag fingerprints that are too rare or have too many "loose" variants.

## What we observed firsthand

- 100% client-side in this session: only **4 GET requests to github.io**, **no backend POST**. The optional shared-visitor DB API did not fire (blocked or unreachable).
- Headless module: `chromium: true, 44% like headless, 0% headless, 0% stealth` — read as a genuine Chromium engine, not flagged as headless or stealth-patched.
- **UA spoof caught:** UA claims macOS Catalina `10_15_7`, `userAgentData` reports macOS `26.5.1` → mismatch flagged. (Electron freezes the UA at 10_15_7; this is exactly the kind of platform-version lie CreepJS is built to surface.)
- **Timezone inconsistency:** reported `Europe/Moscow` while the egress IP geolocates to Istanbul — an inconsistency it surfaces (though note it only checks timezone/Intl *self*-consistency, never against the connection IP; the Istanbul reading came from a different tool).
- **WebRTC leaked** the egress IP `87.249.139.226` plus media devices.
- Broad areas rendered: WebRTC, Timezone, Intl, Headless, Resistance, Worker, WebGL (images/pixels/78 params/75 exts/gpu), Screen, Canvas 2D, Fonts, DOMRect, SVGRect, Audio, Speech, Media codecs, feature/version detection, CSS media queries, computed style, Math, Error stacks, Window keys, HTMLElement keys, Navigator (80 props), Status (rtt/downlink, battery, storage, memory).

## Verification notes

The adversarial review confirmed the client-side pipeline in full against CreepJS's own source, and flagged the following — all folded into the text above:

- **Backend POST/scoring is inference, not observed live.** The research originally stated as fact that the live site "POSTs the fingerprint/hash to a backend that stores visitor samples … and computes the crowd-blending score." No `fetch`/XHR/`sendBeacon` exists in the committed `docs/creep.js`, and firsthand recon saw **no backend POST** — matching the research's own footnote. What is genuinely supported: `prediction/index.ts` *accepts* server-supplied `crowdBlendingScore`/`decryptionData`, and `getBotHash` carries two "compute on server" comments. That proves the author *designed for* a server, not that the static deployment actively transmits/receives one. This report frames the crowd-blending/prediction layer as design-inferred throughout.
- **Whether the live static page populates a server-computed score is unverified** for the same reason — the visible percentage/grade may be server-fed or a client fallback.
- **`hasBadChromeRuntime` attribution corrected:** it lives in the headless module's "stealth" group, not in `src/lies/index.ts`. `queryLies` contains no `chrome.runtime` check.
- **One README quote could not be re-verified word-for-word** (the "conduct research and provide education, not to create a fingerprinting library" phrasing). The first purpose quote, the target-tool list, and the trademark/honeypot warning were confirmed; this report paraphrases rather than quotes the unverified line.
- **Scope caveats an anti-bot engineer must not miss:** CreepJS has **no behavioral biometrics**, **no TLS/JA3/JA4 or TCP/IP or HTTP header-order fingerprinting** (structurally impossible for pure JS), **no IP/proxy/datacenter reputation or IP-vs-geo cross-check**, **no CAPTCHA / proof-of-work challenge**, and **no session/velocity or cross-site reputation** (it scores one isolated page load; "crowd-blending" is fingerprint rarity in a visitor sample, not longitudinal reputation). It also does not do the real-world server-side Client-Hints check (comparing received `Sec-CH-UA`/`Accept-Language` headers against JS-reported values). "Passing CreepJS" therefore says nothing about the network, behavioral, IP, or challenge layers that production stacks (DataDome, HUMAN, Akamai, Kasada, Cloudflare) rely on.

## Open source / reusable

- **`github.com/abrahamjuliot/creepjs`** — MIT-licensed **client** code, subject to a trademark policy on the "CreepJS" name. Directly reusable modules for a builder: `src/lies/index.ts` (native-function tamper detection, the highest-value piece), `src/headless/index.ts` (headless/stealth signal battery + rating math), `src/utils/crypto.ts` (`hashify`/`getFuzzyHash`/`getBotHash`), and the per-signal collectors (canvas, WebGL, audio, fonts, workers, WebRTC).
- **Not open source:** the backend that stores visitor samples and computes crowd-blending / prediction decoding — a builder would have to implement the population store and rarity scoring themselves.

## Sources

- [CreepJS GitHub repository (README, source, license)](https://github.com/abrahamjuliot/creepjs)
- [CreepJS README (raw) — purpose, test list, targeted tools, trademark policy](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/README.md)
- [CreepJS `src/headless/index.ts` — likeHeadless/headless/stealth signals and rating math](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/src/headless/index.ts)
- [CreepJS `src/utils/crypto.ts` — getBotHash bot patterns and "compute on server" markers](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/src/utils/crypto.ts)
- [CreepJS `src/lies/index.ts` — native-function lie detection and Proxy/stack techniques](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/src/lies/index.ts)
- [CreepJS `src/prediction/index.ts` — crowdBlendingScore grade tiers and server decryptionData](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/src/prediction/index.ts)
- [CreepJS `docs/index.html` — live page structure and displayed sections](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/docs/index.html)
- [CreepJS `src/creep.ts` — main orchestration of fingerprint modules](https://raw.githubusercontent.com/abrahamjuliot/creepjs/master/src/creep.ts)
- [DeepWiki: abrahamjuliot/creepjs architecture overview](https://deepwiki.com/abrahamjuliot/creepjs)
- [Undetectable.io — CreepJS browser fingerprint test explainer](https://undetectable.io/blog/creepjs-browser-fingerprint-test/)
- [CreepJS live service](https://abrahamjuliot.github.io/creepjs/)
