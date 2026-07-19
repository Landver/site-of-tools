# 2026-07-19 — read `puppeteer-extra-plugin-stealth`'s source: why the 4 G04/G22 probes stopped working

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Per next-steps.md item 3, fetched current source of
`berstend/puppeteer-extra`'s `packages/puppeteer-extra-plugin-stealth/evasions/`
from GitHub (plugin version tested in
[multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md),
2.11.2). `_utils/index.js` is shared helper nearly every evasion module
builds on, explains all four dead probes at once — none of it
stealth-specific cleverness anymore, just small, generic, well-tested
utility library:

- **`stripProxyFromErrors`** wraps every Proxy trap in try/catch, rewrites
  any thrown error's `.stack` to strip Proxy's own frames, anchored on
  hardcoded V8 stack-frame string
  (`` at Object.newHandler.<computed> [as ${trap}]  ``, with blacklist
  fallback). Defeats stack-trace-based Proxy detection — presumably
  mechanism behind now-dead `native_callnew_tamper`.
- **`patchToString`/`redirectToString`** make every patched function's
  `.toString()` report `[native code]` correctly, including
  self-referential edge case (calling `.toString()` on
  `Function.prototype.toString` itself resolves via dedicated branch).
  Defeats `tostring_proxy`.
- **`replaceProperty`** always spreads *original* property descriptor
  (`Object.getOwnPropertyDescriptor(obj, propName)`) before applying
  overrides, preserving `enumerable`/`configurable`/`writable`. Defeats
  descriptor-based tamper checks like `native_descriptor_tamper` — same
  WebIDL-vs-ECMA-262 enumerability nuance G04 batch's own real-Chrome E2E
  pass had to account for (see roadmap/changelog.md's second quick-win
  batch entry).
- **`navigator_proto_tamper`**'s target, `navigator.webdriver`, needs no JS
  patch at all post-Chrome-89 per `evasions/navigator.webdriver/index.js` —
  plugin's `beforeLaunch` hook just appends
  `--disable-blink-features=AutomationControlled` to launch args. Nothing
  at JS layer for prototype-walk probe to catch in modern Chrome; whole
  evasion happens before page ever loads.
- **`chrome.runtime`**'s evasion (`evasions/chrome.runtime/index.js`) only
  activates when `'runtime' in window.chrome` already false *and* origin
  secure (HTTPS) — meaning presence/absence of `chrome.runtime` was never
  a reliable signal even in principle: stealth fakes it perfectly (real
  captured `STATIC_DATA`, correctly-erroring `sendMessage`/`connect`
  mocks) exactly when it would otherwise be missing, no-op when it's
  already there. Reframes `chrome_runtime_tamper` question from
  [real-Chrome baseline entry](2026-07-19-chrome-runtime-real-chrome-baseline.md):
  even fully organic sample resolving "absent on real Chrome too" wouldn't
  make presence-checking safe against stealth-equipped adversary, only
  against naive one.

**One concrete, untested idea for sharper probe:** `stripProxyFromErrors`
does single anchor-based splice per stack trace — finds one anchor line,
removes everything above it. Probe triggering *two* nested proxy-trap
throws in one call (trap that, while throwing, itself touches second
patched property) could plausibly produce stack with proxy artifacts on
both sides of single anchor, which current single-pass stripping wouldn't
fully clean. Not yet built or verified against live stealth session —
next-steps.md item 3 still open.
