# 2026-07-19 — read `puppeteer-extra-plugin-stealth`'s source: why the 4 G04/G22 probes stopped working

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

Per next-steps.md item 3, fetched the current source of
`berstend/puppeteer-extra`'s `packages/puppeteer-extra-plugin-stealth/evasions/`
from GitHub (the plugin version tested in the
[multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md),
2.11.2). `_utils/index.js` is the shared helper nearly every evasion module
builds on, and it explains all four dead probes at once — none of it is
stealth-specific cleverness anymore, it's a small, generic, well-tested
utility library:

- **`stripProxyFromErrors`** wraps every Proxy trap in a try/catch and
  rewrites any thrown error's `.stack` to strip the Proxy's own frames,
  anchored on a hardcoded V8 stack-frame string
  (`` at Object.newHandler.<computed> [as ${trap}]  ``, with a blacklist
  fallback). This is what defeats stack-trace-based Proxy detection —
  presumably the mechanism behind the now-dead `native_callnew_tamper`.
- **`patchToString`/`redirectToString`** make every patched function's
  `.toString()` report `[native code]` correctly, including the
  self-referential edge case (calling `.toString()` on
  `Function.prototype.toString` itself resolves via a dedicated branch). This
  is what defeats `tostring_proxy`.
- **`replaceProperty`** always spreads the *original* property descriptor
  (`Object.getOwnPropertyDescriptor(obj, propName)`) before applying
  overrides, preserving `enumerable`/`configurable`/`writable`. This is what
  defeats descriptor-based tamper checks like `native_descriptor_tamper` —
  the same WebIDL-vs-ECMA-262 enumerability nuance the G04 batch's own
  real-Chrome E2E pass had to account for (see roadmap/changelog.md's second
  quick-win batch entry).
- **`navigator_proto_tamper`**'s target, `navigator.webdriver`, needs no JS
  patch at all post-Chrome-89 per `evasions/navigator.webdriver/index.js` —
  the plugin's `beforeLaunch` hook just appends
  `--disable-blink-features=AutomationControlled` to the launch args. There's
  nothing at the JS layer for a prototype-walk probe to catch in modern
  Chrome; the whole evasion happens before the page ever loads.
- **`chrome.runtime`**'s evasion (`evasions/chrome.runtime/index.js`) only
  activates when `'runtime' in window.chrome` is already false *and* the
  origin is secure (HTTPS) — meaning presence/absence of `chrome.runtime`
  was never a reliable signal even in principle: stealth fakes it
  perfectly (real captured `STATIC_DATA`, correctly-erroring
  `sendMessage`/`connect` mocks) exactly when it would otherwise be missing,
  and is a no-op when it's already there. This reframes the
  `chrome_runtime_tamper` question from the
  [real-Chrome baseline entry](2026-07-19-chrome-runtime-real-chrome-baseline.md):
  even a fully organic sample resolving "absent on real Chrome too" wouldn't
  make presence-checking safe against a stealth-equipped adversary, only
  against a naive one.

**One concrete, untested idea for a sharper probe:** `stripProxyFromErrors`
does a single anchor-based splice per stack trace — it finds one anchor line
and removes everything above it. A probe that triggers *two* nested
proxy-trap throws in one call (a trap that, in the course of throwing, itself
touches a second patched property) could plausibly produce a stack with
proxy artifacts on both sides of the single anchor, which the current
single-pass stripping wouldn't fully clean. Not yet built or verified against
a live stealth session — next-steps.md item 3 is still open.
