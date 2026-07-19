# Bot check — client-collected signals (the vendored collector)

*(part of the [botcheck docs index](README.md))* — see
[signals-server.md](signals-server.md) for the server-observed half, and
[collector-provenance.md](collector-provenance.md) for what OSS projects this
borrows technique from.

Plain HTML can't read `navigator`/`canvas`/`WebGL`, so a JS collector is justified
under CLAUDE.md golden rule #4. The collector builds one JSON object and POSTs it.
The payload carries a version (`v`, currently **4**); rules whose fields are
damning-when-false (the G04 deep-tamper probes, added in v2, the G17/G22
integrity OK-bools + touch/mimeTypes fields, added in v3, and the G15/G21
env-section reads, added in v4) skip older payloads, so
a returning visitor with a stale cached collector never reads as tampered.

- **Hard automation tells** — `navigator.webdriver`; automation-framework globals
  (`$cdc_*`/`$wdc_*`, `__selenium*`/`__webdriver*`, `__playwright`/`__pw_*` +
  Playwright binding hooks, `_phantom`/`callPhantom`, `__nightmare`, the wider
  Selenium/Watir canon, Sequentum in `window.external`, plus a suspect-name sweep
  of both `document` and `window` own properties); the **CDP probe**
  (`Error.stack` getter + `console.debug` serialization trick that fires when a
  DevTools-Protocol client sent `Runtime.enable`, run in the main thread, a
  Worker, and the Service Worker). **2026-07-19 finding:** the CDP probe was
  confirmed dead against five real CDP-driven automation frameworks and
  downgraded to soft tier — see
  [testing/findings-log.md](testing/findings-log.md) before assuming this
  still works as a strong tell.
- **Lie / tamper detection** — the shallow `Function.prototype.toString()`
  `[native code]` check on key natives, plus the deep G04 probes: property-
  descriptor/own-property sanity (with per-spec enumerability — WebIDL operations
  are `enumerable: true`, ECMA-262 built-ins are not), call/new `TypeError`
  traps, and a `Function.prototype.toString` Proxy probe (shape differential vs a
  control native + error-stack apply-frame inspection) — the
  puppeteer-extra-stealth hallmark. The G17/G22 additions: a **Navigator.prototype
  accessor-descriptor walk** (`webdriver`/`plugins`/`languages` must be native,
  getter-only, enumerable+configurable accessors living on the prototype, never
  own properties on the instance) and **chrome.runtime integrity** (genuine
  `sendMessage`/`connect` are native non-constructors — no own `prototype`, and
  `new fn()` throws a `TypeError`; a stealth-bolted fake gets the shape or the
  error constructor wrong) plus the **late-injection index** ('chrome' among the
  last ~50 window keys means it was bolted on after page setup). **2026-07-19
  finding:** all of these were evaded by the current `puppeteer-extra-plugin-stealth`
  — see [testing/findings-log.md](testing/findings-log.md).
- **Cross-context consistency** — recompute `navigator.{userAgent, languages,
  hardwareConcurrency, userAgentData.platform, webdriver}` + WebGL renderer inside
  a Web Worker, a Service Worker (served from `/botcheck-sw.js`), and an iframe
  (which also reports whether its `contentWindow` is a Proxy); POST all copies so
  Go can diff them (top-frame-only spoofs collapse here). **This is the family
  that actually caught `puppeteer-extra-plugin-stealth`** in the 2026-07-19 audit
  when the purpose-built stealth checks above didn't — see
  [testing/findings-log.md](testing/findings-log.md).
- **Classic headless tells** — impossible permission state (`prompt` while
  `denied`); `window.chrome` presence; empty `plugins`/`languages`; plugins
  without `mimeTypes`; software WebGL renderer (SwiftShader/Mesa); default
  `800x600` / `screen == avail` / `outerWidth < innerWidth` / zero `outerHeight`;
  implausible `hardwareConcurrency`/`deviceMemory`; a guaranteed-loadable 1×1
  image that fails; a mobile UA reporting zero touch points.
- **Fingerprint surfaces (for consistency, not raw entropy)** — canvas 2D hash,
  WebGL vendor/renderer + params, AudioContext hash, font list — used for
  GPU-vs-claimed-OS coherence and spoof/noise-stability, not a uniqueness score.
- **The cross-check most free tools skip (our differentiator)** —
  `navigator.userAgentData.getHighEntropyValues(["fullVersionList"])`, triangulated
  against the legacy UA string *and* the `Sec-CH-UA` request headers. The UA's
  `Chrome/NNN` major must match the **`Chromium` brand entry** of `fullVersionList`
  (the true engine version — comparing against a fork's *branded* version, e.g.
  Opera's, would false-positive, so we read the Chromium entry specifically). This
  is the CreepJS/Electron catch: a UA-string spoof that leaves `userAgentData`
  untouched disagrees here.
- **Real-engine feature detection** — probe capabilities unique to one engine
  (`-moz-appearance` ⇒ Gecko, `GestureEvent` ⇒ WebKit, `-webkit-app-region` /
  `webkitRequestFileSystem` ⇒ Blink) and cross-check the detected engine against
  the one the UA claims — robust against a spoofed UA string a parse would trust.
- **Engine constants** — `navigator.productSub` is a fixed per-engine value
  (`20030107` on WebKit/Blink, `20100101` on Gecko); a value that disagrees with
  the engine the UA claims (derived via the same `engineFromUA` helper, so iOS
  browsers are correctly treated as WebKit) is a patched-runtime tell. A second,
  independent engine check fingerprints the **JS engine** from the `Error` stack
  format (V8 ` at ` frames, SpiderMonkey's proprietary `fileName`/`lineNumber`,
  JSC otherwise) and compares it against the UA-claimed engine (Blink⇒V8,
  Gecko⇒SpiderMonkey, WebKit⇒JSC).
- **Timezone** — `Intl.DateTimeFormat().resolvedOptions().timeZone` +
  `getTimezoneOffset()`, compared to the IP timezone from IP2Location.
- **WebRTC candidate IPs** — an `RTCPeerConnection` against a public STUN server
  (`stun.l.google.com:19302`, ~1.5 s harvest, mDNS `.local` names skipped)
  collects ICE candidate IPs; Go compares only **public** candidates against the
  server-observed egress IP (private/loopback/link-local/ULA/CGNAT excluded — a
  host candidate ≠ egress is normal NAT — and only the egress's own address
  family is compared, so dual-stack stays silent). A public candidate that isn't
  the egress pierces a VPN/proxy.
- **The v4 `env` section (G15/G21)** — one additive object of cheap
  environment/API probes, all fail-to-absent (a missing key is "not supplied",
  never evidence): `window.matchMedia` presence, devicePixelRatio,
  prefers-color-scheme / forced-colors / reduced-motion / dynamic-range /
  color-gamut media queries, a `navigator.connection` sample (effectiveType /
  downlink / rtt / saveData — absent on most Firefox/Safari installs, which is
  normal), the rounded storage-quota MB, `navigator.globalPrivacyControl`, a
  two-name Permissions sample, and EME ClearKey availability. Only two of these
  feed rules (`matchmedia_missing`, `netinfo_incoherent`); the rest are entropy
  for the raw dump and are deliberately **never scored** — user preferences and
  hardware capabilities are not bot tells, and the quota is explicitly not an
  incognito detector (G19, skipped).

For the full per-signal roadmap (what's shipped, what's not, and why) see
[roadmap/client-signals.md](roadmap/client-signals.md).
