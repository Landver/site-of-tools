# Bot check — client-collected signals (the vendored collector)

*(part of the [botcheck docs index](README.md))* — see
[signals-server.md](signals-server.md) for server-observed half, and
[collector-provenance.md](collector-provenance.md) for OSS projects this
borrows technique from.

Plain HTML can't read `navigator`/`canvas`/`WebGL`, so JS collector justified
under CLAUDE.md golden rule #4. Collector builds one JSON object, POSTs it.
Payload carries version (`v`, currently **4**); rules whose fields are
damning-when-false (G04 deep-tamper probes, added v2, G17/G22 integrity
OK-bools + touch/mimeTypes fields, added v3, G15/G21 env-section reads, added
v4) skip older payloads, so returning visitor with stale cached collector never
reads as tampered.

- **Hard automation tells** — `navigator.webdriver`; automation-framework
  globals (`$cdc_*`/`$wdc_*`, `__selenium*`/`__webdriver*`, `__playwright`/`__pw_*`
  + Playwright binding hooks, `_phantom`/`callPhantom`, `__nightmare`, wider
  Selenium/Watir canon, Sequentum in `window.external`, plus suspect-name sweep
  of both `document` and `window` own properties); the **CDP probe**
  (`Error.stack` getter + `console.debug` serialization trick firing when
  DevTools-Protocol client sent `Runtime.enable`, run in main thread, Worker,
  Service Worker). **2026-07-19 finding:** CDP probe confirmed dead against
  five real CDP-driven automation frameworks, downgraded to soft tier — see
  [the CDP-trap check status](testing/checks/cdp_both.md)
  before assuming this still works as strong tell.
- **Lie / tamper detection** — shallow `Function.prototype.toString()`
  `[native code]` check on key natives, plus deep G04 probes: property-
  descriptor/own-property sanity (per-spec enumerability — WebIDL operations
  are `enumerable: true`, ECMA-262 built-ins are not), call/new `TypeError`
  traps, `Function.prototype.toString` Proxy probe (shape differential vs
  control native + error-stack apply-frame inspection) — the
  puppeteer-extra-stealth hallmark. G17/G22 additions: **Navigator.prototype
  accessor-descriptor walk** (`webdriver`/`plugins`/`languages` must be native,
  getter-only, enumerable+configurable accessors living on prototype, never own
  properties on instance) and **chrome.runtime integrity** (genuine
  `sendMessage`/`connect` are native non-constructors — no own `prototype`, and
  `new fn()` throws `TypeError`; stealth-bolted fake gets shape or error
  constructor wrong) plus **late-injection index** ('chrome' among last ~50
  window keys means bolted on after page setup). **2026-07-19 finding:** all
  evaded by current `puppeteer-extra-plugin-stealth` — see
  [the multi-framework matrix results](testing/findings/2026-07-19-multi-framework-matrix-results.md).
- **Cross-context consistency** — recompute `navigator.{userAgent, languages,
  hardwareConcurrency, userAgentData.platform}` inside Web Worker, Service
  Worker (served from `/botcheck-sw.js`), and iframe, plus WebGL renderer
  inside Worker; `navigator.webdriver` itself re-read only in iframe and
  Service Worker (Worker instead adds OffscreenCanvas WebGL read), iframe also
  reports whether its `contentWindow` is a Proxy. POST all copies so Go can
  diff them (top-frame-only spoofs collapse here). **Family that actually
  caught `puppeteer-extra-plugin-stealth`** in 2026-07-19 audit when
  purpose-built stealth checks above didn't — see
  [the multi-framework matrix results](testing/findings/2026-07-19-multi-framework-matrix-results.md).
- **Classic headless tells** — impossible permission state (`prompt` while
  `denied`); `window.chrome` presence; empty `plugins`/`languages`; plugins
  without `mimeTypes`; software WebGL renderer (SwiftShader/Mesa); default
  `800x600` screen / available screen area larger than physical screen (not
  `screen == avail`, which is common and never flagged) /
  `outerWidth < innerWidth` / zero `outerHeight`; implausible
  `hardwareConcurrency`/`deviceMemory`; guaranteed-loadable 1×1 image that
  fails; mobile UA reporting zero touch points.
- **Fingerprint surfaces (for consistency, not raw entropy)** — canvas 2D
  stability/blank checks (no hash transmitted), WebGL vendor + renderer
  strings, probe-font count (not a font list, no AudioContext hash — neither
  implemented) — used for GPU-vs-claimed-OS coherence and spoof/noise-
  stability, not uniqueness score.
- **The cross-check most free tools skip (our differentiator)** —
  `navigator.userAgentData.getHighEntropyValues(["fullVersionList"])`,
  triangulated against legacy UA string (`ua_chrome_version_mismatch`). UA's
  `Chrome/NNN` major must match **`Chromium` brand entry** of
  `fullVersionList` (true engine version — comparing against fork's *branded*
  version, e.g. Opera's, would false-positive, so we read Chromium entry
  specifically). This is CreepJS/Electron catch: UA-string spoof leaving
  `userAgentData` untouched disagrees here. Sec-CH-UA header's brand list
  separately cross-checked against `userAgentData.brands`
  (`ch_brands_mismatch`), no rule compares it to `fullVersionList`.
- **Real-engine feature detection** — probe capabilities unique to one engine
  (`-moz-appearance` ⇒ Gecko, `GestureEvent` ⇒ WebKit, `-webkit-app-region` /
  `webkitRequestFileSystem` ⇒ Blink), cross-check detected engine against one
  UA claims — robust against spoofed UA string a parse would trust.
- **Engine constants** — `navigator.productSub` fixed per-engine value
  (`20030107` on WebKit/Blink, `20100101` on Gecko); value disagreeing with
  engine UA claims (derived via same `engineFromUA` helper, so iOS browsers
  correctly treated as WebKit) is patched-runtime tell. Second, independent
  engine check fingerprints **JS engine** from `Error` stack format (V8
  ` at ` frames, SpiderMonkey's proprietary `fileName`/`lineNumber`, JSC
  otherwise), compares against UA-claimed engine (Blink⇒V8, Gecko⇒SpiderMonkey,
  WebKit⇒JSC).
- **Timezone** — `Intl.DateTimeFormat().resolvedOptions().timeZone` +
  `getTimezoneOffset()`, compared to IP timezone from IP2Location.
- **WebRTC candidate IPs** — `RTCPeerConnection` against public STUN server
  (`stun.l.google.com:19302`, ~1.5 s harvest, mDNS `.local` names skipped)
  collects ICE candidate IPs; Go compares only **public** candidates against
  server-observed egress IP (private/loopback/link-local/ULA/CGNAT excluded —
  host candidate ≠ egress is normal NAT — only egress's own address family
  compared, so dual-stack stays silent). Public candidate that isn't egress
  pierces VPN/proxy.
- **The v4 `env` section (G15/G21)** — one additive object of cheap
  environment/API probes, all fail-to-absent (missing key is "not supplied,"
  never evidence): `window.matchMedia` presence, devicePixelRatio,
  prefers-color-scheme / forced-colors / reduced-motion / dynamic-range /
  color-gamut media queries, `navigator.connection` sample (effectiveType /
  downlink / rtt / saveData — absent on most Firefox/Safari installs, which is
  normal), rounded storage-quota MB, `navigator.globalPrivacyControl`,
  two-name Permissions sample, EME ClearKey availability. Only two feed rules
  (`matchmedia_missing`, `netinfo_incoherent`); rest are entropy for raw dump,
  deliberately **never scored** — user preferences and hardware capabilities
  aren't bot tells, quota explicitly not incognito detector (G19, skipped).

For full per-signal roadmap (what's shipped, what's not, why) see
[roadmap/client-signals.md](roadmap/client-signals.md).
