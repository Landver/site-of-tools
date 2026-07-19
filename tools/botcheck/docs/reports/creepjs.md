# CreepJS

Open-source, client-side browser-fingerprinting research page whose real specialty: **tamper / "lie" detection** — recomputes same signals across execution contexts, tortures native JS APIs to expose spoofed/automated browsers. Not commercial bot scorer, but anti-detect and scraping industry treats "passing CreepJS" as benchmark, so useful reference for any bot-or-not builder.

- **URL:** https://abrahamjuliot.github.io/creepjs/ · **Category:** open-source test page (fingerprinting / anti-fingerprinting research tool, used de-facto as automation-detection benchmark) · **Requires registration:** No — static GitHub Pages, runs automatically on load, no account.
- **Firsthand verdict for test browser** (in-app browser reporting as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): CreepJS did **not** issue hard "bot" verdict — headless module read `chromium: true, 44% like headless, 0% headless, 0% stealth`. Strength showed elsewhere: **caught User-Agent spoof** (UA string claims macOS Catalina `10_15_7` while `userAgentData` reports macOS `26.5.1` — Electron freezes UA at 10_15_7), surfaced **timezone inconsistency** (reported `Europe/Moscow` while egress IP geolocates to Istanbul), **leaked egress IP `87.249.139.226`** plus media devices via WebRTC. Read browser as real Chromium engine (not headless) but flagged multiple lies/inconsistencies naive fingerprint would miss.

## What it is — common info

CreepJS: research/education project by developer **Abraham Juliot** (GitHub `abrahamjuliot`). Per README, stated purpose: "shed light on weaknesses and privacy leaks among modern anti-fingerprinting extensions and browsers" — i.e. explicitly built to test how well privacy tools and stealth/automation setups hold up, not sold as fingerprinting library. README lists targeted tools incl. Tor Browser, Firefox RFP, Brave, ungoogled-chromium, puppeteer-extra, FakeBrowser, uBlock Origin, NoScript, CanvasBlocker, Chameleon, ScriptSafe.

Because unusually good at catching spoofing, scraping / anti-detect ecosystem (ZenRows, Undetectable, Dolphin Anty, Rebrowser, iProyal, etc.) uses it as pass/fail bench for stealth browsers. "CreepJS" name trademarked; README warns **only official deployment is on GitHub Pages** — any `.com`/`.org`/custom-domain "CreepJS" is unauthorized mirror or potential honeypot.

Audience: researchers, privacy-tool authors, anti-detect community — not enterprise site operators (unlike DataDome/Fingerprint).

## Registration / access

None. Visit URL; page runs in-browser, renders results. No login, signup, API key, paywall anywhere in source or on page.

## How it decides bot-or-not

CreepJS doesn't produce single authoritative "bot: yes/no" like commercial vendor. Runs large battery of fingerprint collectors, applies three overlapping judgments:

1. **Lie/tamper count** — how many native APIs show evidence of being overridden, proxied, or spoofed. Signature move, most load-bearing signal.
2. **Headless/stealth ratings** — three percentages (`like headless`, `headless`, `stealth`) derived from known headless-Chrome and stealth-plugin tells.
3. **Crowd-blending / rarity** — how common your fingerprint is vs population of prior visitors (depends on backend; see caveats below).

Boolean "bad bot" flag (`getBotHash` in `src/utils/crypto.ts`) fires if any of fixed set of patterns present — worker-scope lie, platform-version lie, `Function.prototype.toString` Proxy leak, out-of-range feature version, extreme lie count (>100 lies, bad OS/font match, or **any** lie classed "stealth"), blocked worker scope, or (server-computed) excessive loose fingerprints / low crowd-blending. When fires, UI shows **"locked"** instead of score. Low/locked result means either high rarity/entropy **or** detected tampering — engine deliberately conflates "you're spoofing" with "you're suspicious."

## Detection approaches

- **Fingerprinting** — broad high-entropy collection (canvas, WebGL, audio, fonts, screen, Intl, math/engine quirks, etc.).
- **JS tampering / "lie" detection** — probing native functions for prototype, descriptor, `toString`, error-behavior anomalies. Core technique.
- **Headless / automation detection** — dedicated module with `likeHeadless` / `headless` / `stealth` signal groups (SwiftShader, missing GPU, taskbar/viewport geometry, permissions bug, chrome-object anomalies, etc.).
- **Anti-fingerprinting / privacy-tool "resistance"** — detecting Tor, Firefox RFP, Brave, extensions.
- **Cross-scope consistency** — recomputing signals in Web Worker / Service Worker / iframe, comparing to main window and `userAgentData` and fonts, to catch contradictions.
- **Crowd-blending / entropy** — rarity of fingerprint against visitor population (backend-dependent — see architecture).
- **NOT present:** no behavioral biometrics, no TLS/TCP/network fingerprinting, no IP-reputation/proxy scoring, no CAPTCHA/proof-of-work challenge. (See Verification notes.)

## Areas / signals scanned

### Client-side (JS) — overwhelming majority

- **Navigator** (~80 props): `userAgent`, `appVersion`, `platform`, `vendor`, `plugins`, `mimeTypes`, `userAgentData` high-entropy hints, `webdriver`, `pdfViewerEnabled`, DNT, GPC, WebGPU, permissions.
- **Direct automation tells:** `navigator.webdriver`; `HeadlessChrome` substring in UA/appVersion (checked in both main and worker scope).
- **Canvas 2D:** image/blob/paint/text/emoji rendering + `TextMetrics`.
- **WebGL:** images/pixels, GPU parameters, `UNMASKED_RENDERER_WEBGL` (GPU model), SwiftShader software-renderer check.
- **Audio:** `AudioContext`/`OfflineAudioContext` signature (sum, gain, freq, time, trap, copy).
- **Fonts:** installed/loadable fonts via `FontFace`, plus OS/platform inference from font set.
- **Speech synthesis** voices (local/remote/lang/default).
- **Screen & window geometry:** screen vs avail vs `innerWidth`/`outerHeight` vs `visualViewport`, taskbar-absent check, color depth, touch.
- **Timezone + Intl** (locale entropy, self-consistency of timezone vs device — note: consistency checked internally, never against connection IP).
- **DOMRect / SVGRect** geometry and emoji DomRect measurements.
- **CSS** system styles, computed styles, media queries (`prefers-color-scheme`, etc.).
- **JS runtime** Math results and console/error-stack engine signatures; `window` keys and `HTMLElement` keys (version/engine fingerprint).
- **Cross-scope:** dedicated/shared/service worker scope UA/GPU/locale vs main; iframe `contentWindow` / behemoth-iframe behavior.
- **WebRTC:** host connection, ICE foundation/IP candidates, SDP capabilities, STUN, media devices (client-side candidate enumeration — this leaked our egress IP; **not** IP-reputation scoring).
- **Chrome object:** presence/index, `chrome.runtime.sendMessage`/`connect` integrity.
- **Permissions bug:** `navigator.permissions.query('notifications')` vs `Notification.permission` mismatch.
- Media capabilities/codecs, MIME types, battery/network status, Web Share / content-index / contacts-manager presence.

### Server-side

Effectively none of network layer. Only server dependency: **crowd-blending / prediction** aggregation (visitor-sample store + hash-to-device decoding), not part of pure client fingerprint. **No** HTTP-header, TLS/JA3, TCP/IP, or IP-reputation analysis.

### Behavioral

None. CreepJS one-shot, page-load fingerprint. No mouse/pointer movement, keystroke timing, scroll/touch cadence, interaction-timing analysis.

## How it scans (architecture)

**Predominantly client-side.** Bundled script (`src/creep.ts` compiled to `docs/creep.js`) runs ~19–21 fingerprinting modules concurrently (`Promise.all`) in browser. Computes raw fingerprint (`window.Fingerprint`) and privacy-hardened variant (`window.Creep`), produces main **FP ID** hash plus per-component hashes and **fuzzy** hash (`hashify` / `getFuzzyHash` in `src/utils/crypto.ts`), runs lie detection (`src/lies/index.ts`), computes headless/stealth ratings (`src/headless/index.ts`), does resistance detection, computes partial bot signature (`getBotHash`). Even UA-lie parser (`decryptUserAgent`) is **local** routine, not server call.

**Server component (design-inferred, not observed live).** Source's prediction module (`src/prediction/index.ts`) accepts server-supplied `decryptionData` and numeric `crowdBlendingScore` as parameters, `getBotHash` explicitly leaves two patterns — `excessiveLooseFingerprints` and `crowdBlendingScoreIsLow` — marked "compute on server." Strong evidence author **designed for** backend storing visitor samples, decoding hash into predicted OS/device/GPU, computing crowd rarity. That backend **not** in public repo, and — importantly — **no backend POST observed firsthand** (only 4 GETs to github.io; optional shared-visitor DB API didn't fire / was blocked). Committed `docs/creep.js` build likewise shows no `fetch`/XHR/`sendBeacon` to backend. So treat crowd-blending pipeline as inferred design contract, not confirmed live mechanism (see Verification notes).

**Where decision is made:** tamper/headless/lie logic entirely **client-side** and self-contained; only crowd-rarity portion of verdict would live server-side.

## Scoring / output

Firsthand, page rendered: **FP ID** (main fingerprint hash), **Fuzzy hash** (locality/similarity hash), **percentage with letter grade** (surfaced in UI as "trust score"), **LIES** count.

- Visible percentage-with-grade corresponds to **Crowd-Blending Score** (0–100%), which `src/prediction/index.ts` grades ≥90 A, ≥80 B, ≥70 C, ≥60 D, else F. Higher = fingerprint common / blends in; lower = rare / suspicious. Third-party blogs loosely call this "trust score." Server-computed, no backend call observed — whether live static page truly populates this from server or renders client-side fallback **unverified**.
- **Headless ratings:** each of `likeHeadless` / `headless` / `stealth` = `(matched signals / total signals) × 100`, shown as "% like headless / % headless / % stealth" (ours: 44 / 0 / 0).
- **Lie detection:** running `totalLies` count across probed APIs.
- **Boolean bot flag:** 8-bit `botHash`; if any pattern fires, `badBot` set, UI shows **"locked"** instead of crowd-blending score.

**No** single unified 0–100 "bot probability." Operator reads combination of lies, headless %, rarity.

## Notable techniques

- **Native-function torture ("lie" detection, `src/lies/index.ts` `queryLies`):** for each API function checks `toString()` against known `[native code]` output, checks illegal own-properties/descriptors (`prototype`/`arguments`/`caller`/`toString`), traps whether calling / `new` / `apply` / class-`extends` throws correct `TypeError`.
- **Proxy detection via error-stack inspection:** `Object.create(new Proxy(fn,{})).toString()` and reading `fn.arguments`/`caller`, then verifying stack frames (`at Function.toString` / `at Object.toString` / strict-mode markers). Catches `Function.prototype.toString` Proxy that `puppeteer-extra-stealth` installs.
- **`hasBadChromeRuntime`** *(in headless/stealth module, not lies module):* instantiates `chrome.runtime.sendMessage`/`connect`, inspects for `prototype` presence / wrong error constructor to catch faked `chrome.runtime`.
- **`hasHighChromeIndex`:** checks whether `chrome` appears among last ~50 `window` keys — stealth patches inject it late.
- **`hasIframeProxy`:** builds iframe with `srcdoc`, inspects `contentWindow` to detect proxied window.
- **`hasKnownBgColor`:** renders CSS system color `ActiveText`, checks for `rgb(255,0,0)` — headless tell.
- **Permissions bug:** `permissions.query('notifications')` returning `prompt` while `Notification.permission` is `denied` — classic headless-Chrome inconsistency.
- **Cross-scope GPU/UA comparison:** main-thread WebGL `UNMASKED_RENDERER` vs Web Worker `webglRenderer` (`hasBadWebGL`); worker-scope UA vs window-scope fonts to catch platform-version lies.
- **SwiftShader** software-renderer detection (headless has no real GPU).
- **Taskbar/viewport geometry** (`screen == avail`, `innerWidth == screen.width`) indicating no OS chrome.
- **Server-side crowd-blending** (design): decode fingerprint hash into predicted OS/device/GPU from sample DB, flag fingerprints too rare or with too many "loose" variants.

## What we observed firsthand

- 100% client-side this session: only **4 GET requests to github.io**, **no backend POST**. Optional shared-visitor DB API didn't fire (blocked or unreachable).
- Headless module: `chromium: true, 44% like headless, 0% headless, 0% stealth` — read as genuine Chromium engine, not flagged headless or stealth-patched.
- **UA spoof caught:** UA claims macOS Catalina `10_15_7`, `userAgentData` reports macOS `26.5.1` → mismatch flagged. (Electron freezes UA at 10_15_7; exactly kind of platform-version lie CreepJS built to surface.)
- **Timezone inconsistency:** reported `Europe/Moscow` while egress IP geolocates to Istanbul — inconsistency it surfaces (though only checks timezone/Intl *self*-consistency, never against connection IP; Istanbul reading came from different tool).
- **WebRTC leaked** egress IP `87.249.139.226` plus media devices.
- Broad areas rendered: WebRTC, Timezone, Intl, Headless, Resistance, Worker, WebGL (images/pixels/78 params/75 exts/gpu), Screen, Canvas 2D, Fonts, DOMRect, SVGRect, Audio, Speech, Media codecs, feature/version detection, CSS media queries, computed style, Math, Error stacks, Window keys, HTMLElement keys, Navigator (80 props), Status (rtt/downlink, battery, storage, memory).

## Verification notes

Adversarial review confirmed client-side pipeline in full against CreepJS's own source, flagged following — all folded into text above:

- **Backend POST/scoring is inference, not observed live.** Research originally stated as fact that live site "POSTs fingerprint/hash to backend that stores visitor samples … computes crowd-blending score." No `fetch`/XHR/`sendBeacon` exists in committed `docs/creep.js`, firsthand recon saw **no backend POST** — matching research's own footnote. What's genuinely supported: `prediction/index.ts` *accepts* server-supplied `crowdBlendingScore`/`decryptionData`, `getBotHash` carries two "compute on server" comments. Proves author *designed for* server, not that static deployment actively transmits/receives one. Report frames crowd-blending/prediction layer as design-inferred throughout.
- **Whether live static page populates server-computed score is unverified** for same reason — visible percentage/grade may be server-fed or client fallback.
- **`hasBadChromeRuntime` attribution corrected:** lives in headless module's "stealth" group, not `src/lies/index.ts`. `queryLies` contains no `chrome.runtime` check.
- **One README quote couldn't be re-verified word-for-word** (the "conduct research and provide education, not to create a fingerprinting library" phrasing). First purpose quote, target-tool list, trademark/honeypot warning confirmed; this report paraphrases rather than quotes unverified line.
- **Scope caveats anti-bot engineer must not miss:** CreepJS has **no behavioral biometrics**, **no TLS/JA3/JA4 or TCP/IP or HTTP header-order fingerprinting** (structurally impossible for pure JS), **no IP/proxy/datacenter reputation or IP-vs-geo cross-check**, **no CAPTCHA / proof-of-work challenge**, **no session/velocity or cross-site reputation** (scores one isolated page load; "crowd-blending" is fingerprint rarity in visitor sample, not longitudinal reputation). Also doesn't do real-world server-side Client-Hints check (comparing received `Sec-CH-UA`/`Accept-Language` headers against JS-reported values). "Passing CreepJS" says nothing about network, behavioral, IP, or challenge layers production stacks (DataDome, HUMAN, Akamai, Kasada, Cloudflare) rely on.

## Open source / reusable

- **`github.com/abrahamjuliot/creepjs`** — MIT-licensed **client** code, subject to trademark policy on "CreepJS" name. Directly reusable modules for builder: `src/lies/index.ts` (native-function tamper detection, highest-value piece), `src/headless/index.ts` (headless/stealth signal battery + rating math), `src/utils/crypto.ts` (`hashify`/`getFuzzyHash`/`getBotHash`), per-signal collectors (canvas, WebGL, audio, fonts, workers, WebRTC).
- **Not open source:** backend storing visitor samples, computing crowd-blending / prediction decoding — builder would have to implement population store and rarity scoring themselves.

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
