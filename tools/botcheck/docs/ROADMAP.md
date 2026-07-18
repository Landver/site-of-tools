# Bot check — roadmap: what to build next & why

The single "what's next" doc for `botcheck`. It has two parts:

1. **The competitor-gap audit** (the bulk of this doc): every capability, signal,
   technique, and reporting feature that one or more of the twelve researched
   services provide and our own [`botcheck`](README.md) tool does **not** (or
   does more weakly) — each rated by value-to-us, effort, and status.
2. **The internal backlog** ([jump](#internal-backlog-by-effort-non-competitor-driven)):
   effort-layered features we want regardless of any competitor, including the ones
   the newly-available MongoDB unlocks.

For how the tool works today and why it's designed the way it is, see
[`../botcheck.md`](README.md) (design + reference); for how the competitor
services work and how our test browser scored against them, see
[`RESEARCH.md`](RESEARCH.md).

## Build status (what's shipped)

botcheck is **built and live**. It shipped in phases: routing + content
negotiation, the server-only scorer reusing `iptools`, the vendored JS collector,
the client-vs-server cross-checks + the ≥3-soft-signal combo rule, and polish
(`Accept-CH` opt-in, the "your request" card, IP2Location attribution). The
Layer-1 and Layer-2 signal sets in the
[internal backlog](#internal-backlog-by-effort-non-competitor-driven) below are
implemented; their "remaining candidates" and all of Layer 3 are not. This doc is
the forward view — the current design lives in [`../botcheck.md`](README.md).

**Quick-win batch shipped (2026-07-17):** the first four quick wins below are now
live — **G01** (a UA-`Chrome/NNN`-major vs `userAgentData` `Chromium`-entry
cross-check), **G02** (`navigator.productSub` engine constant), **G05**
(feature-detect the real Blink/Gecko/WebKit engine vs the engine the UA claims),
and **G53** (on-page scope disclosure). They added three consistency rules (35 →
38) and the collector reports `fullVersionList`, `productSub`, and a
feature-detected `engine`.

**Second quick-win batch shipped (2026-07-17):** every remaining quick win is now
live — **G04** (deep native-tamper detection: descriptor/own-property sanity with
per-spec enumerability, call/new `TypeError` traps, and a
`Function.prototype.toString` Proxy probe), **G03** (cross-context diff beyond UA
— languages, `hardwareConcurrency`, `userAgentData.platform`, worker WebGL — plus
a Service-Worker context served from `/botcheck-sw.js`), **G07+G08** (WebGL
vendor/renderer coherence + GPU-family-vs-claimed-OS coherence), and **G06**
(HTTP header presence/value consistency, soft-tier). The rule set grew 38 → 50,
and the collector payload is now versioned (`v: 2`) so a stale cached collector
skips the damning-when-false G04 rules instead of reading as tampered. A
real-Chrome E2E pass caught and fixed one false positive before deploy: WebIDL
operations are `enumerable: true` by spec, so the descriptor probe now asserts
enumerability per target family (ECMA-262 vs WebIDL) instead of blanket-false.

**Good-bot / AI-agent classification shipped (2026-07-17): G36.** Recognised
crawlers and AI agents are now named ([`goodbots.go`](../goodbots.go)) instead of
lumped in with curl/scrapers, and a fourth verdict **`good-bot`** downgrades them —
but ONLY when the egress ASN **number** is the operator's single-tenant crawler ASN,
which an outsider can't originate traffic from (Apple/Yandex/Baidu/Naver/Seznam/
Anthropic/Meta/ByteDance). It matches the ASN *number*, not the owner *name*: a name
substring ("yandex") also matches the operator's rentable public cloud (Yandex Cloud
is a separate AS200350), which would let a scraper on a rented VM verify itself.
Multi-tenant crawlers (Googlebot/Bingbot on shared Google/Microsoft ASNs) and
cloud-hosted agents (GPTBot on Azure) are recognised but stay unverified and fully
penalised, so a copied User-Agent never escapes the bot score (the no-evasion
invariant). `bot_user_agent` was widened to every allowlist token (several —
`Meta-ExternalAgent`, `Claude-User` — carry no generic `bot` substring). Follow-up
for full coverage: a published-IP-range check to verify the multi-tenant and
cloud-hosted operators that share their ASN with paying tenants.

**Review follow-up (2026-07-17, same day):** an adversarial review of the batch
above fixed two false positives before they mattered — the version check now
compares the UA against the `Chromium` `fullVersionList` entry (not the fork's
branded `uaFullVersion`, which made real **Opera/Vivaldi/Yandex/Samsung** score
"suspicious"), and `productSub` derives its expected engine from `engineFromUA`
(so **iOS Firefox**, WebKit under an FxiOS token, is no longer flagged). The
`pdfViewerEnabled` soft tell was **dropped**: it fires on ordinary desktop Chrome
with the "Download PDFs" setting or the `AlwaysOpenPdfExternally` enterprise policy
(a user preference, not a headless tell) and correlates with `empty_plugins`,
eroding the soft-cluster margin — low value for its false-fire cost. Unused
high-entropy fields (`platformVersion`/`architecture`/`bitness`/`model`/
`uaFullVersion`) were trimmed from the collector and struct. Regression tests now
cover Opera, desktop Safari, and iOS Safari/Firefox/Chrome.

## What this is built from

- The twelve firsthand service reports in this folder (`deviceandbrowserinfo`,
  `incolumitas`, `sannysoft`, `creepjs`, `fingerprint`, `browserscan`, `pixelscan`,
  `iphey`, `whoer`, `amiunique`, `coveryourtracks`, `datadome`) — see the
  [RESEARCH.md](RESEARCH.md) for the cross-service summary.
- Our **shipped** implementation, read as ground truth (not the design doc):
  [`botcheck/scoring.go`](../scoring.go) (the 50 detection rules),
  [`botcheck/botcheck.go`](../botcheck.go) (the `Signals` struct +
  scorer), [`botcheck/handler.go`](../handler.go) (server signals),
  and [`shared/static/js/botcheck.js`](../../../shared/static/js/botcheck.js) (the
  vendored collector).

Each competitor capability was compared against that code, and **every claimed gap
was verified against the real source** to remove false "we don't do X" entries.
None survived: of 62 items, 0 were things we actually already ship, 16 are things
we do in a narrower form (**Partial**), 31 are genuine blind spots (**Not built**),
and 15 are already acknowledged in our design docs as **Deferred**.

## How to read the ratings

Each row carries **`Sev · Effort · Status`**:

- **Sev** (severity) = value **to our tool specifically** — a stateless, no-ML
  self-test page on a personal portfolio (MongoDB is now available but botcheck
  doesn't use it yet), *not* an enterprise WAF. A cheap
  client signal we simply forgot rates higher than DataDome-scale behavioral ML,
  which is near-worthless at our scale.
- **Effort** = `trivial` → `low` → `medium` → `high-infra` (needs edge/TLS/packet
  access) → `ml-or-db` (needs persistence in MongoDB — now available but unused by
  botcheck — or a trained model).
- **Status** = **Not built** (true blind spot) · **Partial** (we do a weaker
  version) · **Deferred (documented)** (already an acknowledged gap in our docs).

## Executive summary

`botcheck` already ships a credible client + server **consistency** scorer: 50
tiered rules, cross-context (worker/iframe) UA checks, UA/Client-Hints/timezone/IP
cross-checks, and IP2Proxy datacenter/VPN/Tor classification, all fused
server-side and shown as a transparent per-signal breakdown. The gaps fall into
three clean buckets:

1. **Cheap client signals we don't collect yet — the real opportunity.** Ten
   low/trivial-effort items (see [Quick wins](#quick-wins-highest-value-lowest-cost)).
   Most extend collectors we *already have*: richer high-entropy Client Hints,
   deeper native-tamper/lie detection, broader cross-context diffs, engine
   feature-detection, GPU-vs-OS coherence. These are pure deterministic Go/JS
   rules that fit the existing scorer with no new infra.

2. **Structural blind spots needing infra, ML, or persistence botcheck doesn't
   use yet.** The network layer (TLS **JA3/JA4**, HTTP/2 frames, TCP SYN, header
   order), crowd **rarity/entropy**, persistent **identity**, **behavioral**
   biometrics, and an **ML** risk model. Most are already documented as deferred.
   The network-layer ones are genuinely out of reach while nginx/Cloudflare
   terminate TLS in front of Go. The DB-backed ones are now *unblocked* — **MongoDB
   is available** (a `site-of-tools` database + a `platform/mongo.go` client) — but
   botcheck persists nothing yet, so they stay build-it tasks; the ML ones conflict
   with the no-ML rule. These are correctly parked, not oversights.

3. **Intentional non-goals.** Enforcement/inline-WAF decisions, CAPTCHA / active
   challenges / proof-of-work, signed verdict tokens, and collector obfuscation.
   The enterprise vendors do these; for a transparent self-test tool that blocks
   nothing they would be the *wrong* design. Listed for completeness, flagged as
   non-goals.

## What they do well that we don't (the qualitative read)

Beyond individual signals, several services model good *practices* worth copying:

- **Scope honesty & transparency.** deviceandbrowserinfo states plainly that its
  verdict does **not** use IP reputation or behavior; incolumitas warns that "false
  positives are expected" and versions its signals openly. That candor is what
  makes a checker trusted as a reference. We're transparent per-signal but never
  state our scope boundaries or caveats (G53, G55).
- **Depth of lie/tamper detection.** CreepJS doesn't just check `toString`
  `[native code]` — it walks property descriptors, traps whether `call`/`new`
  throw the right `TypeError`, and detects the `Function.prototype.toString` Proxy
  that stealth plugins install. We do the shallow version on four methods (G04,
  G17, G22).
- **Feature-detecting the *real* engine.** iphey/MixVisit feature-detect Blink vs
  Gecko vs WebKit and compare to the claimed UA, instead of trusting the UA string
  a spoofer controls (G05).
- **Naming the environment back to the user.** Fingerprint says "Electron 42.5.1"
  and attaches per-signal confidence; CreepJS splits `likeHeadless` / `headless` /
  `stealth` so "real engine but patched" reads differently from "headless build."
  We detect embedded runtimes but never surface the name or sub-scores (G56, G49,
  G50).
- **A raw dump for the debugging audience.** sannysoft/CreepJS show the full raw
  fingerprint; we only show pass/fail rows (G54).
- **Entropy framing.** AmIUnique/EFF report "one in X browsers share this" — a
  ready-made explainability and weighting model (needs a population corpus we don't
  have) (G58, G40).
- **The unforgeable network layer.** The edge-owners (DataDome, BrowserScan,
  incolumitas) cross-check the TLS/TCP/HTTP2 handshake against the claimed browser
  — the one class of signal a JS spoofer can't touch, and the one we structurally
  can't see behind nginx (G26–G30, G48).
- **Good-bot / AI-agent classification.** DataDome and Fingerprint separate
  verified Googlebot-style crawlers and known AI-company agents from malicious
  automation; we now separate them (G36, shipped): recognised crawlers/agents are
  named, and verified ones (ASN-corroborated) get a distinct `good-bot` verdict.

## Quick wins (highest value, lowest cost)

The `Not built` / `Partial` items at `trivial`/`low` effort with real value to a
self-test tool — **all ten are shipped as of 2026-07-17** (the quick-win program
is complete; open work starts at the medium-effort / infra / DB-backed rows).
IDs link into the full tables below.

| # | Quick win | Effort | Why it's cheap here |
|---|---|---|---|
| G01 | Expand userAgentData high-entropy hints + platformVersion coherence | trivial | We request platform ONLY. Request platformVersion + uaFullVersion + fullVersionList too and add a rule comparing UA-embedded OS version vs userAgentData.platformVersion. This is the exact Electron/spoof catch we cite in our design, made stronger for near-zero cost. |
| G02 | navigator.productSub / oscpu / buildID / pdfViewerEnabled | trivial | Drop-in client fields + consistency rules; productSub and pdfViewerEnabled are already flagged as candidates in the internal backlog (Layer 1). |
| G53 | Explicit on-page scope disclosure (what the verdict does/doesn't use) | trivial | One-paragraph trust win: say plainly we use client fingerprint + headers + IP reputation, no behavior/ML, and that VPN/privacy users may score suspicious by design. |
| G04 | Deep native-function tamper / lie detection _(shipped)_ | low | We only run the '[native code]' toString check on 4 methods. Extend it: (1) descriptor/own-property sanity on the same natives, (2) verify call/new throw correct TypeErrors, (3) add the Proxy-via-error-stack probe to catch stealth-plugin Function.toString proxies. Pure client JS, deterministic, fits our scorer — this is the single highest-leverage cheap upgrade. |
| G03 | Broaden cross-context (worker/iframe/SW) comparison beyond UA _(shipped)_ | low | We already spawn worker + iframe and compare UA. Cheaply extend the same collectors to also diff languages, hardwareConcurrency, platform, and (if collected) GPU renderer across those contexts, and add a Service Worker context. Each mismatch is a strong consistency tell we're currently leaving on the table. |
| G05 | Feature-detect true engine and compare to claimed UA | low | We compare UA vs userAgentData.platform but never feature-detect the real engine. Add a small engine-probe module and one rule (feature-detected engine family vs UA-claimed browser). Cheap, deterministic, and robust against UA spoofing. |
| G08 | WebGL/GPU identity vs claimed OS/UA coherence _(shipped)_ | low | We read UNMASKED_RENDERER only to flag software renderers (swiftshader/llvmpipe). Add a coherence rule: GPU vendor family (Apple/Intel/NVIDIA/AMD/Adreno) vs UA-claimed OS. Cheap, catches spoofed-OS anti-detect browsers our software-renderer check ignores. |
| G36 | Good-bot allowlist + AI-agent/LLM-crawler classification _(shipped)_ | low | **Shipped** in [`goodbots.go`](../goodbots.go): an allowlist of good crawlers + AI agents, ASN-**number** corroboration for single-tenant operators, and a `good-bot` verdict for verified ones. Recognition never reduces the score by itself (no evasion). |
| G06 | HTTP header value/presence consistency vs claimed browser _(shipped)_ | low | Cheap server-side rule set; validate against the CF/nginx path first (proxies can rewrite/strip these) — same caveat that made sec_fetch_missing soft. |
| G07 | WebGL vendor/renderer/feature internal inconsistency _(shipped)_ | low | Collect the vendor string too (we only keep the renderer) and add a vendor/renderer coherence rule. |

## Full gap list

Grouped by category, sorted within each by severity then effort. Every row is one
capability a competitor provides that we don't fully match; the final column states
what they do and the recommended move for our stack.

### Client-side detection signals

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G01 | Expand userAgentData high-entropy hints + platformVersion coherence | CreepJS, iphey.com, Fingerprint.com | medium · trivial · **Shipped** | Pull the full getHighEntropyValues set (architecture, bitness, model, platformVersion, uaFullVersion, fullVersionList) and cross-check against the UA. CreepJS caught a UA claiming macOS 10_15_7 while userAgentData reported macOS 26.5.1 — the frozen-Electron/spoof tell. → **We request platform ONLY. Request platformVersion + uaFullVersion + fullVersionList too and add a rule comparing UA-embedded OS version vs userAgentData.platformVersion. This is the exact Electron/spoof catch we cite in our design, made stronger for near-zero cost.** |
| G02 | navigator.productSub / oscpu / buildID / pdfViewerEnabled | iphey.com, AmIUnique.org, CreepJS | medium · trivial · **Shipped (productSub only; pdfViewerEnabled dropped as a user-setting false-fire, oscpu/buildID skipped)** | productSub is a classic engine tell (Chromium is always '20030107', Gecko '20100101'); oscpu/buildID/pdfViewerEnabled add OS/engine consistency and a headless tell (pdfViewerEnabled often false headless). → **Shipped productSub as an engine-aware consistency rule. pdfViewerEnabled was tried then dropped: it is false on ordinary desktop Chrome with "Download PDFs" set or the AlwaysOpenPdfExternally policy, so it flags a user preference, not headless.** |
| G03 | Broaden cross-context (worker/iframe/SW) comparison beyond UA | deviceandbrowserinfo.com, bot.incolumitas, CreepJS | medium · low · **Shipped** | Recompute and diff more than the UA across contexts — languages, hardwareConcurrency, platform, and even WebGL renderer/fonts — between main thread, Web Worker, Service Worker, and iframe. Caught Bright Data returning Linux in a worker while the top UA claimed Windows. → **Shipped 2026-07-17:** worker + iframe also report languages/cores/`userAgentData.platform` and the worker tries an OffscreenCanvas WebGL renderer; a Service-Worker context was added (`/botcheck-sw.js`, served by the app, no fetch handler, unregistered after the probe). Four new consistency rules (`context_language/cores/platform/webgl_mismatch`) plus the SW side of `context_ua_mismatch`, each firing only when both sides confidently report. |
| G04 | Deep native-function tamper / lie detection | CreepJS, deviceandbrowserinfo.com, bot.incolumitas, BrowserScan.net, Pixelscan, Fingerprint.com | medium · low · **Shipped** | Go well beyond a toString '[native code]' check: CreepJS's queryLies checks each API for illegal own-properties/descriptors (prototype/arguments/caller), traps whether call/new/apply/class-extends throw the correct TypeError, and detects the Function.prototype.toString Proxy that puppeteer-extra-stealth installs via error-stack frame inspection. bot.incolumitas targets stealth-plugin artefacts directly (puppeteerExtraStealthUsed, overrideTest). → **Shipped 2026-07-17:** three new probes — descriptor/own-property sanity (with per-spec enumerability: WebIDL ops are `enumerable: true`, ECMA-262 built-ins are not — asserting blanket-false false-fired every real browser), call/new `TypeError` traps, and a toString-Proxy probe (shape differential vs a control native + error-stack apply-frame inspection). Rules: `tostring_proxy` (hard), `native_descriptor_tamper` + `native_callnew_tamper` (consistency, since legit privacy extensions can patch DOM APIs). The payload is versioned (`v: 2`) so a stale cached collector skips these instead of reading as tampered. |
| G05 | Feature-detect true engine and compare to claimed UA _(we do a narrower version)_ | iphey.com, CreepJS | medium · low · **Shipped** | Feature-detect the actual rendering engine/version (Chromium via webkitResolveLocalFileSystemURL + BatteryManager + vendor; Gecko via buildID + onmozfullscreenchange; WebKit via ApplePayError) and cross-check against the claimed UA — catches spoofed UAs and anti-detect browsers a string parse misses. → **We compare UA vs userAgentData.platform but never feature-detect the real engine. Add a small engine-probe module and one rule (feature-detected engine family vs UA-claimed browser). Cheap, deterministic, and robust against UA spoofing.** |
| G06 | HTTP header value/presence consistency vs claimed browser | AmIUnique.org, incolumitas, DataDome | medium · low · **Shipped** | Inspect the presence and VALUES of Accept, Accept-Encoding, Upgrade-Insecure-Requests, Connection, Cache-Control etc. and check them for coherence with the claimed browser (beyond just header order). → **Shipped 2026-07-17:** three soft rules (`accept_encoding_missing`, `accept_language_missing`, `accept_nav_mismatch`) keyed on `looksLikeBrowser(UA)` — soft precisely because proxies can strip/rewrite headers (the `sec_fetch_missing` caveat). Upgrade-Insecure-Requests is captured but deliberately unused: Safari never sends it, so any rule requiring it would false-positive real Safari. |
| G07 | WebGL vendor/renderer/feature internal inconsistency | deviceandbrowserinfo.com, incolumitas | medium · low · **Shipped** | Check UNMASKED_VENDOR vs UNMASKED_RENDERER and the GPU parameter/feature set for internal self-contradiction (distinct from our software-renderer test and from GPU-vs-OS coherence). → **Shipped 2026-07-17:** the collector reports the vendor string too, and `webgl_vendor_mismatch` fires when vendor and renderer parse to different confident families (e.g. vendor Apple vs renderer NVIDIA). Verified against real reporting styles (ANGLE shim pairs, Safari's generalised "Apple Inc."/"Apple GPU", Firefox driver strings) so no real browser contradicts itself. |
| G08 | WebGL/GPU identity vs claimed OS/UA coherence | Pixelscan, CreepJS, DataDome, iphey.com, deviceandbrowserinfo.com | medium · low · **Shipped** | Cross-check the unmasked GPU vendor/renderer against the claimed platform (e.g. a Chrome-on-Windows UA whose canvas/WebGL renderer matches an Apple/Metal GPU is flagged). CreepJS also diffs worker-scope WebGL renderer vs main (hasBadWebGL). → **Shipped 2026-07-17:** `gpu_os_mismatch` fires only on enumerated impossible pairs (Apple GPU on Windows/Linux/Android, desktop NVIDIA/AMD on iOS/Android, Adreno/Mali on macOS/iOS) — deliberately silent on AMD+macOS (Intel Macs), Adreno+Windows (Snapdragon ARM), Intel+Android, and unknown GPUs. The worker-vs-main WebGL diff half shipped with G03 (`context_webgl_mismatch`). |
| G09 | WebRTC local/public IP leak (STUN, mDNS candidates) | bot.incolumitas, CreepJS, BrowserScan.net, Pixelscan, iphey.com, whoer.net | medium · medium · Deferred (documented) | Use a STUN request (e.g. stun.l.google.com:19302) to enumerate ICE candidates and extract the real local (RFC1918) and public IP behind a VPN/proxy, then flag a WebRTC-real-IP vs egress-IP mismatch. → **Highest-value deferred client signal — it pierces the exact proxy layer our IP2Proxy lookup can only classify. Revisit: it's pure client JS, no infra. Collect candidates client-side, POST them, and add one rule (WebRTC public IP != egress IP). We deferred it as async/flaky, but modern mDNS-obfuscated candidates are still a usable leak/consistency signal.** |
| G10 | Cheap headless render tells (battery, broken-image, hairline, system-color) | sannysoft, CreepJS, bot.incolumitas, iphey.com | low · trivial · **Not built** | Small client render/behavior probes: getBattery presence/behavior (CHR_BATTERY), broken-image 0x0 natural dimensions, Modernizr 0.5px hairline offsetHeight quirk, and CreepJS's hasKnownBgColor (render CSS system color ActiveText, expect rgb(255,0,0) in headless). → **Add a couple as soft-cluster members (they slot into our existing >=3-quirk model without false-positiving alone). hasKnownBgColor and broken-image are the most modern-relevant; battery/hairline are increasingly dated. Cheap parity wins.** |
| G11 | iframe proxy/override detection + webdriver-in-iframe | CreepJS, deviceandbrowserinfo.com | low · trivial · Partial | CreepJS's hasIframeProxy builds a srcdoc iframe and inspects contentWindow for a proxied window; deviceandbrowserinfo re-checks navigator.webdriver inside an iframe (hasWebdriverInFrameTrue) to catch evasions that only patch the main frame. → **We already create an iframe for UA recompute — also read navigator.webdriver inside it and add a contentWindow-proxy check. Near-free given the iframe already exists.** |
| G12 | Additional fingerprint-entropy surfaces (audio, WebGPU, DOMRect, media devices, speech, touch) | CreepJS, bot.incolumitas, Fingerprint.com, BrowserScan.net, iphey.com, AmIUnique.org, EFF Cover Your Tracks | low · low · **Not built** | Collect AudioContext fingerprint, WebGPU capabilities, DOMRect/SVGRect/clientRects geometry, media-device enumeration, speech-synthesis voices, and touch/maxTouchPoints as fingerprint entropy and (in CreepJS) cross-context consistency inputs. → **Limited standalone bot-tell value for us and mostly useful only with a crowd/rarity DB we don't have. Touch (vs mobile UA) and audio (stability across draws, like our canvas check) are the two with real consistency value — consider those; defer the rest as entropy-only.** |
| G13 | Broaden automation-framework signature battery | BrowserScan.net, sannysoft, deviceandbrowserinfo.com, bot.incolumitas | low · low · Partial | Cover more frameworks by name: Sequentum (window.external), Awesomium, CEF/CefSharp, FMiner, Rhino, WebdriverIO, SlimerJS, plus puppeteer-extra-stealth and puppeteer evaluation-script artefacts. BrowserScan reports 15+ individually. → **We cover Selenium/Playwright/PhantomJS/Nightmare + a regex sweep and treat CEF as an embedded-runtime token. Add the cheap missing globals (Sequentum via window.external, __nightmare already, Awesomium/CefSharp markers). Diminishing returns after the top frameworks, but trivial to extend the existing global sweep.** |
| G14 | CDP / navigator recheck in a Service Worker context | bot.incolumitas, CreepJS | low · low · Partial | Run CDP and navigator consistency checks inside a Service Worker (not just a Web Worker); bot.incolumitas's inconsistentServiceWorkerNavigatorPropery flagged an Electron/CDP browser whose main-thread webdriver read clean. → **We run CDP checks in main + Web Worker. Adding a Service Worker context is a modest incremental catch surface; nice-to-have after the worker-property-breadth expansion, not urgent.** |
| G15 | CSS media-query / computed-style / display-capability fingerprint | CreepJS, iphey.com | low · low · **Not built** | Probe prefers-color-scheme, color gamut, HDR/HDCP, forced/inverted colors, reduced-motion/transparency, devicePixelRatio, CSS system colors and computed styles. → **Cheap client probes; add a few (devicePixelRatio vs screen, forced-colors) as consistency/entropy surfaces.** |
| G16 | DevTools-open detection (debugger timing + window-size delta) | iphey.com, Fingerprint.com | low · low · **Not built** | iphey times a `debugger` statement in a worker and checks outerWidth - innerWidth > 160px; Fingerprint exposes a 'Developer Tools' Smart Signal. A weaker automation proxy than CDP but a distinct signal. → **Optional. Our CDP-via-Error.stack already fires on DevTools/automation, and a debugger-timing probe is intrusive (pauses the page) and false-positives on real users with DevTools open. Skip unless we want a soft-tier corroborating signal.** |
| G17 | Full window-global enumeration + navigator prototype descriptor walk | sannysoft, CreepJS, iphey.com, Pixelscan | low · low · Partial | Enumerate all window globals and walk navigator's prototype property descriptors to surface injected automation globals and getter overrides (faked webdriver/plugins), rather than only reading spoofable values. → **We do a regex sweep for cdc_/selenium/webdriver but not a general prototype-descriptor walk. Add a navigator prototype descriptor check (abnormal descriptor on webdriver/plugins = tell) and an unusual-window-property scan. Complements the tamper-depth work.** |
| G18 | Impossible-geometry / recursion-overflow headless tells | bot.incolumitas, sannysoft | low · low · **Not built** | overflowTest / resOverflow deliberately trigger a recursion stack overflow and read the error message/signature; plus impossible screen/window geometry checks used as headless indicators. → **Mostly legacy PhantomJS-era tells with limited modern value. Skip the overflow probe; we already cover several geometry anomalies (availScreen>physical, outer<inner, 800x600) in our soft cluster.** |
| G19 | Incognito / private-mode detection | Fingerprint.com, BrowserScan.net, Pixelscan | low · low · **Not built** | Detect private/incognito mode via storage-quota and filesystem-API heuristics and surface it as a signal. → **Low value as a bot tell (humans use incognito constantly) and the detection tricks are brittle/version-specific. Skip, or add only as an informational (non-scoring) line if we want parity in the report.** |
| G20 | Privacy/anti-detect tool resistance detection | CreepJS | low · low · **Not built** | Detect Tor Browser, Firefox RFP, Brave, ungoogled-chromium, and extensions (uBlock/NoScript/CanvasBlocker/Chameleon/ScriptSafe) and measure how well the mask holds. → **Niche (serves the anti-detect audience, not bot detection). Skip, or add a small informational readout later. Not a scoring signal for us.** |
| G21 | Storage/quota, Network Information, MediaCapabilities/EME, GPC, full Permissions enumeration | iphey.com, CreepJS, AmIUnique.org, incolumitas | low · low · **Not built** | Probe localStorage/indexedDB presence + quota, Network Information (rtt/downlink/effectiveType — incolumitas' connectionRTT), MediaCapabilities/EME-DRM, Global Privacy Control, and enumerate all Permissions states. → **Cheap additional entropy/consistency surfaces; connectionRTT vs IP geo is a genuinely new cross-check.** |
| G22 | chrome.runtime integrity + late-injection index checks | CreepJS | low · low · Partial | hasBadChromeRuntime instantiates chrome.runtime.sendMessage/connect and inspects for missing prototype / wrong error constructor to unmask a faked chrome object; hasHighChromeIndex flags 'chrome' appearing among the last ~50 window keys (stealth patches inject it late). → **We only check window.chrome presence. Add the runtime-integrity probe and the window-key-index check — both catch the common stealth trick of bolting on a fake window.chrome. Small, deterministic additions.** |
| G23 | JS-engine fingerprint (Math results, window/HTMLElement key sets, error-stack) | CreepJS | low · medium · **Not built** | Fingerprint the JS engine/version from Math function results, Error-stack engine signatures, and window/HTMLElement key enumeration; flag out-of-range feature versions. → **Strong engine-vs-claimed-UA cross-check (V8/JSC/SpiderMonkey), but needs careful per-engine reference tables — already noted in the internal backlog (Layer 2).** |
| G24 | Virtual-machine / emulator detection | Fingerprint.com | low · medium · **Not built** | Flag VM signatures and Android emulators (partly server-correlated) and treat a VM as bot=bad. → **Browser-observable VM tells overlap heavily with our software-renderer (swiftshader/llvmpipe) check, which we already have. Little incremental value client-only; skip dedicated VM detection.** |
| G25 | Mobile SDK native signals (root/jailbreak, Frida, emulator, OS attestation) | Fingerprint.com, DataDome | low · high-infra · **Not built** | Native mobile SDKs collect Frida instrumentation, root/jailbreak, emulator/simulator, cloned-app, MITM, tampered-request, and platform attestation (Play Integrity/SafetyNet, App Attest/DeviceCheck) — a signal class with no browser equivalent. → **Not applicable — botcheck is a web page with no mobile app/SDK. Note as an out-of-scope capability class, not a gap to close.** |

### Network-layer fingerprinting (edge/transport)

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G26 | HTTP/2 frame fingerprint (Akamai-style) | BrowserScan.net, DataDome, bot.incolumitas | medium · high-infra · Deferred (documented) | Fingerprint the HTTP/2 setup: SETTINGS frame values, WINDOW_UPDATE, stream PRIORITY, and pseudo-header ordering (Akamai hash format), folded by DataDome into JA4H. Distinguishes real browser h2 stacks from HTTP clients that fake the UA. → **Documented as deferred. Same blocker as TLS (proxy terminates h2). If a JA4-capable edge is added for TLS, capture the h2 fingerprint in the same pass. Otherwise leave deferred; it is genuinely out of reach behind nginx.** |
| G27 | TLS ClientHello fingerprint (JA3/JA4) | bot.incolumitas, BrowserScan.net, DataDome, Pixelscan (pixelscan.dev) | medium · high-infra · Deferred (documented) | Hash the raw TLS ClientHello (cipher-suite list/order, extensions, curves, GREASE) into JA3/JA4 and cross-check that the handshake matches the browser the UA claims (e.g. a Chrome UA whose JA3 isn't Chrome's is a hard tell). BrowserScan surfaces JA3/JA3-hash/JA4 + cipher/extension detail; DataDome flags TLS-vs-UA class mismatch at the edge before JS runs. → **Our design docs already acknowledge this is blocked because nginx/Cloudflare terminate TLS and crypto/tls hides the ClientHello. Realistic path: run a small TLS-passthrough listener (or use CF/nginx JA4 header exposure like ssl_preread / a uTLS-style sidecar) to capture JA4 and add one cross-check rule (JA4-implied browser vs claimed UA). High value as an unforgeable signal, but keep it explicitly optional so the tool still runs behind a terminating proxy.** |
| G28 | DNS-leak and IPv6-leak tests | bot.incolumitas, BrowserScan.net, whoer.net, iphey.com | low · high-infra · **Not built** | Induce the browser to resolve vendor-controlled hostnames and correlate the resolver's IP/geo (and any IPv6 path) against the egress IP — DNS/IPv6 egressing outside the proxy reveals the real network. → **Skip. Requires controlled DNS infrastructure and unique per-session subdomains — heavy infra that mostly serves the anti-detect/VPN audience, not a bot self-test. Note as an aware omission.** |
| G29 | HTTP header order / casing analysis | bot.incolumitas, deviceandbrowserinfo.com, DataDome | low · high-infra · Deferred (documented) | Inspect the order and casing of received HTTP headers (real browsers emit a stable, characteristic order) and flag HTTP-client-shaped ordering; DataDome folds header order into JA4H, and detects browser-only headers being absent. → **Deferred because nginx normalizes header order before Go sees it. If ever fronted by a Go-native TLS listener, Echo could read the raw order. Low priority; note it stays blind as long as nginx is in front.** |
| G30 | Passive TCP/IP SYN OS fingerprint (p0f/zardaxt) | bot.incolumitas, DataDome, whoer.net | low · high-infra · Deferred (documented) | Passively infer the real OS from the SYN packet (TCP options, window size, IP fragmentation flag) and cross-check it against the claimed UA/OS. bot.incolumitas uses zardaxt.py; DataDome does Layer 3/4 fingerprinting at the edge. → **Deferred and correctly so — requires raw packet access below the proxy/load balancer, which our container/edge topology doesn't grant. Keep on the acknowledged-gap list; not worth the infra for a self-test tool.** |
| G31 | Proxy detection via latency triangulation | bot.incolumitas | low · high-infra · **Not built** | Compare browser-to-server RTT against server-to-client-IP RTT; a large asymmetry exposes a proxy/VPN hop even when the IP looks clean. → **Skip for now. Interesting but needs active server-initiated probing to the client IP and careful timing; low incremental value over our existing IP2Proxy datacenter/VPN/Tor flags.** |
| G32 | Server-side open-port scan (22/3389) | bot.incolumitas, BrowserScan.net, whoer.net | low · high-infra · **Not built** | Scan the connecting IP for open SSH (22) / RDP (3389) and other ports to reveal VPS/server/remote-desktop hosts that betray a non-consumer, automation-oriented environment. bot.incolumitas also treats a reachable CDP remote-debug port as a (weak) automation vector. → **Skip. Active outbound port-scanning from the server is abuse-adjacent, slow, frequently blocked, and off-brand for a stateless self-test page. Not worth building.** |

### Behavioral / interaction analysis

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G33 | Optional interactive challenge to elicit organic telemetry | bot.incolumitas | low · medium · **Not built** | Offer an unauthenticated task (fill a form, confirm a dialog, edit and scrape a table) engineered to generate organic mouse/keyboard/scroll trajectories for the behavioral classifier. → **Only worth it if behavioral scoring is ever built (which is itself deferred). Skip until then.** |
| G34 | Behavioral biometrics (mouse/keystroke/scroll/touch ensemble) | bot.incolumitas, deviceandbrowserinfo.com, DataDome, BrowserScan.net | low · ml-or-db · Deferred (documented) | Collect a timestamped interaction stream and score it with an ensemble (bot.incolumitas: 30+ classifiers, re-scored at 1.5/4/7/10/15s; DataDome: per-customer baselines) to separate organic motion from synthetic input. → **Deferred. High cost (needs an ML ensemble + a training corpus), conflicts with our pure/deterministic/no-ML scorer, and low value for a page that auto-runs on load with no required interaction. Keep deferred.** |
| G35 | Navigation-sequence / intent modeling (incl. LLM-agent intent) | DataDome, Fingerprint.com | low · ml-or-db · **Not built** | Model the sequence of requests/navigation and infer intent vs a baseline, including a newer AI-agent/LLM-crawler intent angle. → **Out of scope for a single-page self-test; ML + multi-request context.** |

### IP reputation depth, crowd-blending & rarity

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G36 | Good-bot allowlist + AI-agent/LLM-crawler classification | DataDome, Fingerprint.com, BrowserScan.net | medium · low · **Shipped** | Distinguish verified good bots (Googlebot/Bingbot etc.) from malicious automation, and (Fingerprint/DataDome) classify known AI-company user agents to separate benign AI assistants/crawlers from bad bots. → **Shipped ([`goodbots.go`](../goodbots.go)): a curated crawler + AI-agent allowlist, a `good-bot` verdict, and ASN-**number** corroboration (the crawler's own AS, distinct from any cloud the operator resells under the same name). The downgrade is granted ONLY for single-tenant operator ASNs (Apple/Yandex/Baidu/Naver/Seznam/Anthropic/Meta/ByteDance) an outsider can't originate from — multi-tenant clouds (Googlebot on AS15169, GPTBot on Azure) are recognised-but-unverified and still penalised, so no UA-spoof escapes. Full coverage of the cloud operators needs a published-IP-range check (follow-up).** |
| G37 | IP blacklist / DNSBL / abuser-score reputation | bot.incolumitas, BrowserScan.net, Pixelscan, whoer.net | medium · ml-or-db · **Not built** | Look up the egress IP against blacklists/DNSBLs and return an abuser_score / blacklist flag beyond mere datacenter/VPN/Tor classification. → **Our IP2Proxy PX12 gives datacenter/VPN/Tor/proxy but no reputation/abuser score. Adding a bundled DNSBL/reputation dataset (or an offline blocklist BIN) would strengthen the network tier without breaking statelessness. Medium value; check whether an IP2Location/IP2Proxy tier or a static blocklist can be bind-mounted like the existing BINs.** |
| G38 | Surface ASN/ISP and name the specific VPN/hosting provider _(we do a narrower version)_ | bot.incolumitas, Fingerprint.com, Pixelscan, whoer.net | low · low · Partial | Name the ASN/ISP/company and the specific VPN service (bot.incolumitas identified NordVPN behind DataCamp/CDN77) rather than only a boolean datacenter/VPN flag. → **IP2Proxy/IP2Location records typically carry ISP/ASN/provider fields we may already have in the BINs but don't surface. Add these to the 'your request' card for transparency — cheap and improves the report without new data sources.** |
| G39 | Cross-customer / collective threat intelligence | DataDome | low · ml-or-db · **Not built** | Score an IP/fingerprint seen attacking one protected site across the entire customer network (network effect), plus a maintained known-bot signature repository grown by genetic algorithms. → **Not applicable — we're a single self-test page with no protected-site network. Note as an enterprise-only capability we intentionally don't pursue.** |
| G40 | Crowd-blending / fingerprint rarity / uniqueness entropy | CreepJS, Fingerprint.com, iphey.com, AmIUnique.org, EFF Cover Your Tracks, deviceandbrowserinfo.com, Pixelscan | low · ml-or-db · Deferred (documented) | Score a fingerprint against a visitor population: rarity/'one in X', Shannon-entropy bits per attribute, crowd-blending score with letter grades, or outlier detection against a real-people fingerprint DB — a rare/impossible fingerprint reads as fake. → **Deferred while botcheck stays stateless in practice. Requires a population corpus + storage; **MongoDB is now available** for the storage half, so accumulating a corpus and adding a minimal rarity table is the first crowd feature worth prototyping — but it's not a self-test priority.** |
| G41 | Fingerprint-reuse detection across requests | bot.incolumitas | low · ml-or-db · **Not built** | Flag identical canvas/WebGL fingerprints repeated across many requests to unmask scraping-farm infrastructure (caught ScrapingBee returning a constant fingerprint). → **Requires cross-request state, which botcheck's stateless design avoids today (MongoDB is now available to back it). Defer with the broader crowd/DB work; not meaningful for a single-shot self-test anyway.** |
| G42 | Fuzzy / locality-sensitive fingerprint hash + surfaced FP ID | CreepJS, incolumitas, Fingerprint.com | low · ml-or-db · **Not built** | Compute both an exact fingerprint ID and a separate fuzzy/LSH hash so near-identical fingerprints cluster even when one attribute changes; surface the ID to the user. → **Lands alongside rarity scoring now that MongoDB is available; not meaningful until botcheck actually persists fingerprints.** |
| G43 | Request velocity per device / IP over time windows | Fingerprint.com, DataDome | low · ml-or-db · **Not built** | Count distinct IPs / linked IDs per device (and requests per IP) over rolling windows to flag bursts and linkage. → **Needs cross-request state — bends the stateless rule; sits below the domain service, backed by MongoDB (now available, not yet used by botcheck) — see the internal backlog, Layer 2.** |
| G44 | Residential-proxy detection (distinct from datacenter/VPN) | Fingerprint.com, DataDome, Pixelscan | low · ml-or-db · Partial | Detect residential proxies (graded confidence), the hard case aimed at agentic/AI fraud, separate from datacenter/VPN classification. → **PX12 may already tag some residential proxies; verify which proxy types the bundled BIN classifies and surface them. True residential-proxy detection at competitor quality needs a specialized feed we won't maintain — accept partial coverage.** |

### Persistent identity & history

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G45 | Evercookie / supercookie persistence test | whoer.net, AmIUnique.org, EFF Cover Your Tracks | low · low · **Not built** | Test whether a supercookie/DOM-storage persistence vector survives, surfacing tracking/persistence exposure. → **This is a privacy-exposure test, not bot detection. Out of scope for our tool; skip.** |
| G46 | Returning-visitor result history / timeline | AmIUnique.org, iphey.com, EFF Cover Your Tracks | low · medium · Deferred (documented) | Persist prior results (server corpus or browser localStorage) so a user can revisit and see how their fingerprint/result changed over time, with a selectable time window. → **A localStorage-only history (no server persistence) would respect our stateless server rule and give a nice UX touch. Low priority but the cheapest 'history' option if we want it.** |
| G47 | Stable persistent visitor ID / device matching | Fingerprint.com, CreepJS, iphey.com, bot.incolumitas | low · ml-or-db · Deferred (documented) | Produce a stable device/visitor ID (Fingerprint: survives incognito/cookie-clear/VPN switching; CreepJS: FP ID + fuzzy locality hash; iphey: 128-bit hash) for cross-session correlation. → **Deferred and off-mission for a stateless self-test. A within-request fingerprint hash (no storage) could be shown for transparency cheaply, but persistent cross-session identity needs storage (MongoDB is now available) and botcheck deliberately isn't stateful yet. Keep deferred.** |

### Scoring model & cross-layer fusion

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G48 | Cross-layer OS coherence (UA/OS vs TCP vs TLS vs GPU) | bot.incolumitas, DataDome, BrowserScan.net | medium · high-infra · Deferred (documented) | Correlate claimed UA/OS against TCP/IP-inferred OS, TLS-implied OS, and GPU/canvas-derived device class, so an internally-consistent JS spoof still collapses when the packet or handshake disagrees. This cross-check is the whole point of their transport fingerprints. → **This is the payoff rule for the TLS/TCP work above and can't exist without those inputs. Sequence it after any JA4 capture lands: one rule comparing transport-implied OS vs UA-parsed OS. Until then, we already do the JS-layer half (UA vs userAgentData.platform).** |
| G49 | Per-signal confidence indicators | Fingerprint.com | low · low · **Not built** | Attach a confidence level to individual signals (VPN, residential-proxy) and to the overall identification, so consumers can weight uncertain signals. → **Our tiered weights already encode rough confidence (hard/consistency/soft). A light per-row confidence label could be layered on cheaply for richer reporting, but it's cosmetic. Low priority.** |
| G50 | Separate like-headless / headless / stealth ratings + chromium readout | CreepJS | low · low · **Not built** | Report three independent percentages (likeHeadless / headless / stealth) plus a chromium:true/false engine boolean, separating a genuine engine quirk from active stealth patching. → **A presentation idea: derive a couple of sub-scores from existing signals so 'real engine but patched' reads differently from 'headless build'.** |
| G51 | Time-staggered re-scoring as telemetry accumulates | bot.incolumitas | low · low · **Not built** | Recompute the verdict at intervals (1.5/4/7/10/15s) so later passes use more interaction data and trim false positives. → **Only meaningful with behavioral telemetry (deferred). Our single-shot fuse is appropriate for a stateless self-test. Skip unless behavioral scoring lands.** |
| G52 | ML risk model / trained classifier over the signal vector | bot.incolumitas, Fingerprint.com, DataDome | low · ml-or-db · Deferred (documented) | Replace/augment hand-weighted rules with a supervised classifier (Fingerprint: server-side ML bot verdict; DataDome: supervised + genetic + anomaly ensembles per-customer baseline). → **Deliberately deferred — our value proposition is a transparent, deterministic, no-ML scorer whose every deduction is explainable. Keep the pure scorer; note ML as an intentional non-goal, not a blind spot.** |

### Reporting, transparency & UX

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G53 | Explicit on-page scope disclosure (what the verdict does/doesn't use) | deviceandbrowserinfo.com, incolumitas | medium · trivial · **Shipped** | State verbatim what the verdict is and isn't based on (deviceandbrowserinfo: 'does NOT use IP reputation or behavior'; incolumitas: 'false positives are expected'). → **One-paragraph trust win: say plainly we use client fingerprint + headers + IP reputation, no behavior/ML, and that VPN/privacy users may score suspicious by design.** |
| G54 | Raw fingerprint / device-attributes dump for inspection | sannysoft, bot.incolumitas, Fingerprint.com, CreepJS | low · trivial · Partial | Expose the full raw collected fingerprint (navigator dump, screen, canvas hashes, full JSON payload) so a user/engineer can diff a masked browser against expectations. → **We show a per-signal flagged/ok/not-collected breakdown but not a raw values dump. Add a collapsible 'raw fingerprint JSON' section — trivial given we already have the fused payload, and it materially helps the debugging audience. Our JSON API already exposes the server-side view; extend it to include the client payload.** |
| G55 | Educational per-signal explanations / learning zone | deviceandbrowserinfo.com, CreepJS, bot.incolumitas | low · low · Partial | Pair each signal with a technical write-up of why it fires and its limitations (deviceandbrowserinfo's 'learning zone'; bot.incolumitas is openly versioned with author caveats), building trust as a reference. → **Our breakdown is transparent but terse. Add short per-signal 'why this matters' tooltips/expanders and an honest limitations note (e.g. CDP false-positives on real DevTools users). Cheap, and it's exactly what makes these pages trusted references — a strong fit for a portfolio tool.** |
| G56 | Name the detected environment (browser/engine version, anti-detect browser) | Fingerprint.com, iphey.com | low · low · Partial | State the detected environment plainly ('Electron 42.5.1') as a credibility flex; iphey can sometimes name which anti-detect browser is in use. → **We detect embedded-runtime tokens (Electron/CEF/etc.) but don't prominently name+version the environment back to the user. Surface a 'detected environment' line in the report — cheap credibility using data we already parse.** |
| G57 | Purpose-scoped report pages (verdict / behavior / network separated) | deviceandbrowserinfo.com, incolumitas, BrowserScan.net | low · medium · **Not built** | Split into distinct pages — fingerprint verdict vs behavioral test vs network/IP+header (+TLS) visualizer — so each concern is scannable in isolation. → **Largely a deliberate choice (one page is simpler); revisit only if the signal table outgrows one screen.** |
| G58 | Bits-of-entropy / 'one in X' per-attribute reporting | AmIUnique.org, EFF Cover Your Tracks | low · ml-or-db · Deferred (documented) | Report each attribute's identifying power in Shannon-entropy bits and 'one in X browsers share this value', giving a ready-made explainability/weighting model. → **Meaningful only against a population corpus we don't have (ties to the crowd-rarity gap). Defer with that work. The entropy framing is, however, a good reference for how to weight signals if we ever build the corpus.** |

### Enforcement / production-integration features

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G59 | Active challenge / CAPTCHA / server-seeded canvas device-class proof-of-work | DataDome | low · medium · Deferred (documented) | DataDome's Picasso: the server sends a random seed of drawing instructions, the client renders invisibly and returns a hash; stable GPU/driver/OS rendering differences reveal the true device class, with a fresh seed defeating replay. Also CAPTCHA/invisible Device Check escalation. → **Active challenges/CAPTCHA/PoW are a deliberate non-goal (off-brand, we never issue/solve challenges). Note: our canvas check is stability/blank only, not server-seeded device-class hashing — but adding Picasso-style seeding crosses into active-challenge territory we've ruled out. Keep deferred.** |
| G60 | Signed verdict token / cookie integrity + replay protection | DataDome, Fingerprint.com | low · medium · Deferred (documented) | Emit a cryptographically signed verdict (DataDome's HMAC datadome cookie with replay checks; Fingerprint's sealed result tied to event_id fetched server-to-server) so a captured verdict can't be forged or reused. → **Only relevant if the verdict gates something downstream, which it doesn't (self-test). Deferred correctly. Our transparency (showing the full breakdown to the client) is the opposite design intent and appropriate here.** |
| G61 | Enforcement mode / inline WAF decision | DataDome, Fingerprint.com | low · high-infra · Deferred (documented) | Act on the verdict inline — allow/hard-block/challenge at the edge (DataDome), or feed a passive verdict into a customer's block decision (Fingerprint). → **Intentionally off-brand — botcheck is a self-test that blocks nothing. Keep as an explicit non-goal in the docs, not a gap to close.** |

### Collector architecture

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G62 | Anti-reverse-engineering / integrity hardening of the collector | DataDome, Fingerprint.com | low · high-infra · **Not built** | Protect the collection tag: obfuscation, UI/signal tag-splitting, service-worker offload, encrypted payloads, randomized first-party load path to defeat blockers and forgery. → **Deliberately off-scope and against the grain — our collector is intentionally readable and vendored; a self-test tool has no adversary to hide from.** |

## Deferred by design & explicit non-goals (recap)

These appear in the tables above but are grouped here so they aren't mistaken for
oversights:

- **Blocked by topology (edge/TLS):** TLS JA3/JA4 (G27), HTTP/2 frame fingerprint
  (G26), TCP SYN fingerprint (G30), HTTP header order/casing (G29), and the
  cross-layer OS-coherence rule that depends on them (G48). All blind as long as
  nginx/Cloudflare terminate TLS in front of Go.
- **Needs a stored corpus (MongoDB is now available, but botcheck doesn't use it
  yet):** crowd rarity & entropy (G40, G58), fuzzy hashing (G42), fingerprint-reuse
  (G41), request velocity (G43), persistent visitor ID (G47), returning-visitor
  history (G46, cheap via localStorage only).
- **Conflicts with no-ML / stateless:** behavioral biometrics (G34), intent
  modeling (G35), ML risk model (G52), time-staggered re-scoring (G51).
- **Off-brand non-goals for a self-test tool:** enforcement / inline WAF (G61),
  active challenge / CAPTCHA / Picasso-style PoW (G59), signed verdict tokens
  (G60), collector obfuscation/hardening (G62), evercookie/supercookie test (G45),
  server-side port scanning (G32).
- **Not applicable to a web page:** mobile-SDK native signals (G25),
  cross-customer threat intelligence (G39).

## Note on method & confidence

Produced by a fan-out over the twelve reports (one extractor each), a synthesis
pass against the shipped code, and two independent verification passes: an
adversarial code-verifier that re-read `botcheck/*.go` + the collector to reject
any false gap (it rejected none), and a completeness critic that surfaced 13
capabilities the first pass missed (folded in above). Severity/effort/status
reflect our stack's constraints as of this writing; re-check the code before acting
on any single row, since the collector and rule set evolve.

---

## Internal backlog by effort (non-competitor-driven)

The gap list above is framed against competitors. This is the complementary view:
everything we want to add **regardless of any competitor**, ordered by complexity
against our stack (one Go binary, a vendored JS collector, no npm, MongoDB now
available but not yet used by botcheck, and nginx/Cloudflare terminating TLS in
front, so the raw connection isn't visible to Go). Every client signal is
spoofable, so new signals should prefer the **cross-check** shape — browser claim
vs. a second context / the connection / the population — over standalone tells.
Where an item also appears in the competitor audit above, its `G##` is noted.

### Layer 1 — Simple (no new deps or infra; pure-Go rules over collected fields)

**Shipped:**

| Signal | Tier | Idea |
|---|---|---|
| `vendor_mismatch` | consistency | Chromium UA but `navigator.vendor` ≠ `"Google Inc."` |
| `app_version_mismatch` | consistency | `navigator.appVersion` ≠ UA without the `Mozilla/` prefix |
| `language_primary_mismatch` | consistency | `navigator.language` ≠ `navigator.languages[0]` |
| `screen_avail_impossible` | soft | `availWidth/Height` larger than the physical screen |
| `low_color_depth` | soft | `screen.colorDepth` < 16 |
| `sec_fetch_missing` | soft | Browser UA but no `Sec-Fetch-*` request header |
| `productsub_mismatch` | consistency | `navigator.productSub` ≠ the engine's constant (`20030107` WebKit/Blink, `20100101` Gecko), engine inferred via `engineFromUA` so iOS browsers are WebKit — G02, shipped 2026-07-17 |

**Remaining candidates (same shape, drop-in later):**

- `maxTouchPoints` > 0 on a desktop UA, or `ontouchstart` present without touch — touch/UA mismatch.
- `navigator.plugins` vs `mimeTypes` coherence (plugins present, mimeTypes empty).
- Zero `outerHeight`/`innerHeight` (a headless tell).
- `Accept-Encoding` / `Accept-Language` header absent on a browser UA — **shipped 2026-07-17 via G06** as the soft `accept_encoding_missing` / `accept_language_missing` rules (soft, not hard, exactly because proxies can strip these — the `sec_fetch_missing` caveat).
- `Accept` without `text/html` on a browser-UA request — **shipped 2026-07-17 via G06** as the soft `accept_nav_mismatch` rule.

### Layer 2 — Medium (more collection / tuning; still no new infra or deps)

**Shipped:**

| Signal | Tier | Idea |
|---|---|---|
| `tz_self_inconsistent` | consistency | `Intl….timeZone` (IANA) vs `getTimezoneOffset()` — Go resolves the zone with `time.LoadLocation` (embeds `time/tzdata`) at request time (threaded in as `Signals.Now`, keeping `Evaluate` pure). IP-independent. |
| `canvas_unstable` | consistency | Two identical canvas draws hashing differently ⇒ noise-injecting anti-fingerprint tool. |
| `canvas_blank` | soft | The drawn canvas has no non-transparent pixels ⇒ blocked / headless. |
| `ch_brands_mismatch` | consistency | Parse the `Sec-CH-UA` header brand list and compare to JS `userAgentData.brands` (GREASE decoy ignored). |
| `missing_proprietary_codecs` | soft | Browser UA but neither H.264 nor AAC (`canPlayType`) ⇒ stripped / headless build. |
| `no_fonts` | soft | Zero probe fonts detectable via the `measureText` width technique ⇒ neutralised font surface / font-less VM. |
| `ua_chrome_version_mismatch` | consistency | UA `Chrome/NNN` major ≠ the `Chromium` (or `Google Chrome`) `fullVersionList` entry — compares the engine version, so Chromium forks whose branded version diverges (Opera/Vivaldi/Samsung) don't false-positive — G01, shipped 2026-07-17. |
| `engine_ua_mismatch` | consistency | Feature-detected engine (`-moz-appearance`⇒Gecko, `GestureEvent`⇒WebKit, `-webkit-app-region`/`webkitRequestFileSystem`⇒Blink) ≠ the engine the UA claims — G05, shipped 2026-07-17. |

**Remaining candidates (not yet built):**

- **Fuller media-codec / font-diversity matrices** — beyond the current H.264/AAC pair and the zero-fonts floor, score against expected per-browser codec sets and typical font-count ranges (needs careful thresholds to avoid mobile false positives).
- **JS engine tells** (G23) — `Error` stack format, `Function.prototype.toString` quirks, `Math`/number formatting differences (V8 vs SpiderMonkey vs JSC) vs the claimed browser.
- **WebRTC** (G09) — collect ICE candidates: local-IP leak, presence of an mDNS `.local` candidate, and `srflx` public IP vs the server-observed IP. (Async/flaky — deferred deliberately.)
- **Request velocity** (G43) — an in-memory per-IP counter (a `sync.Map` with TTL) to flag bursts. Introduces process state, so it bends the current stateless rule; better backed by MongoDB (now available, not yet used by botcheck), sitting below the domain service.

### Layer 3 — Hard (new infrastructure, dependencies, ML, or a stored corpus)

> MongoDB is now available (a `site-of-tools` database + a `platform/mongo.go`
> client), so the DB-backed items below are no longer *blocked* on provisioning a
> database — what remains is building the corpus/logic and wiring it below the
> domain service. botcheck does not use Mongo yet.

- **TLS fingerprint (JA3/JA4)** (G27) — the connection's TLS ClientHello vs the UA-implied stack. Blocked today: Cloudflare/nginx terminate TLS. Paths: an nginx/OpenResty JA3 module forwarding an `X-JA3` header, or terminating TLS in Go on this subdomain and peeking the ClientHello. Real work — infra.
- **HTTP/2 frame fingerprint (Akamai-style)** (G26) — SETTINGS / WINDOW_UPDATE / header-priority ordering. nginx downgrades to HTTP/1.1 before Go sees it; needs Go-terminated h2 or edge capture.
- **TCP/IP SYN fingerprint (p0f / zardaxt)** (G30) — OS inferred from SYN packet fields vs UA OS. Needs raw packet capture on the host.
- **Behavioral biometrics** (G34) — stream mouse/keystroke/scroll/touch events and classify (incolumitas runs a 30+ classifier ensemble). Needs an event pipeline and a trained model. ML.
- **Fingerprint rarity / crowd-blending** (G40) — store every fingerprint and score how rare the combination is. MongoDB is now available for the corpus; lands naturally as one more `Check` once storage sits below the domain service (not built yet).
- **Stable visitor ID / returning-device matching** (G47) — probabilistic identity across sessions (FingerprintJS-Pro style). Needs storage (MongoDB now available) and matching logic.
- **ML risk model** (G52) — a trained classifier (logistic / gradient-boosted) over the whole signal vector, replacing the hand-tuned weights. Needs labelled data, training, and serving.
- **Active challenge / proof-of-work / invisible CAPTCHA** (G59) — deliberately out of scope: we never issue or solve CAPTCHAs, and a self-test tool blocks nothing.

