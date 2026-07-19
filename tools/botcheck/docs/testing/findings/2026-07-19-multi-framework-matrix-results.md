# 2026-07-19 — multi-framework matrix results

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Five frameworks run via `Workflow` in parallel, each in own
`automation-harness/frameworks/<name>/` subfolder against local dev
instance:

| Framework | Setup | Live score | What actually caught it |
|---|---|---|---|
| Playwright (headless chromium) | ok | 0/100 bot | `webdriver` + `iframe_webdriver` (−60 each), `bot_user_agent` matched "headlesschrome" (−60), `software_renderer` (SwiftShader, −40), `permission_impossible` (−25) |
| Selenium + chromedriver (real "Chrome for Testing" binary) | ok | 0/100 bot | Same webdriver/UA hits, **plus `framework_globals` caught all 7 of chromedriver's classic `$cdc_...` markers** (−60) — this check works great against classic Selenium |
| `puppeteer-extra` + `puppeteer-extra-plugin-stealth` 2.11.2 | ok | 25/100 bot | See deep-dive below — headline result of the whole audit |
| Raw CDP (`chrome-remote-interface`, hand-spawned Chromium, no `--enable-automation`) | ok | 40/100 bot | **Almost entirely `bot_user_agent` matching "headlesschrome" in the UA** (−60) plus one sub-threshold soft flag. Every automation-protocol check (webdriver, frameworkGlobals, all three CDP checks) read clean. |
| Nightmare (~2015-2018, Electron-based) | failed to install | n/a | Ancient Electron 2.0.18 has no darwin-arm64 build (404); its Node-v24-incompatible `extract-zip@1.7.0` postinstall step corrupts the darwin-x64 fallback under Rosetta. Expected, not pursued further — the `__nightmare` WINDOW_MARKERS entry stays unexercised. |

**Headline finding — puppeteer-extra-stealth deep-dive.** Single most
important result of whole audit. Six checks codebase built to target this
class of stealth patch — `tostring_proxy`, `native_descriptor_tamper`,
`native_callnew_tamper`, `navigator_proto_tamper`, `chrome_runtime_tamper`,
`chrome_late_injection` — **were evaded, all six, cleanly.** (Three of
six — `tostring_proxy`, `native_descriptor_tamper`, `chrome_runtime_tamper`
— have code comments naming `puppeteer-extra-plugin-stealth` specifically;
`navigator_proto_tamper` and `chrome_late_injection` describe general
stealth-patch shape without naming a plugin, and `native_callnew_tamper`
shares its section comment with `native_descriptor_tamper`.)
`navigator.webdriver` itself was hidden everywhere (main thread, iframe,
and Service Worker all read `false`) — more thorough hide than naive
delete-only patch. Yet **tool still scored it 25/100, "bot," not human.**
What actually caught it: three of architecture's own cross-context
consistency checks, none stealth-specific:

- `context_ua_mismatch` (−35): main thread, Worker, and iframe UA all
  successfully patched to clean `Chrome/150.0.0.0` with no "Headless"
  token — but **Service Worker** leaked real, unpatched
  `HeadlessChrome/150.0.0.0` UA. Stealth's UA-override evasion never
  reaches Service Worker realm.
- `context_cores_mismatch` (−20): main thread `hardwareConcurrency` was
  spoofed to `4`, but Worker and Service Worker both reported real `10`.
- `context_webgl_mismatch` (−20): main thread WebGL was spoofed to generic
  `Intel Iris OpenGL Engine` / `Intel Inc.`, but Worker's independent
  OffscreenCanvas WebGL read leaked real host GPU, `ANGLE (Apple, ANGLE
  Metal Renderer: Apple M5, …)`.

Exactly this tool's core design thesis — "strongest checks are the
cross-layer/cross-context consistency ones," per `botcheck.go`'s own
package doc — validated against real, current, actively-maintained
adversarial tool. Six checks specifically built to catch stealth's
*signature* all missed; checks built to catch stealth's *incompleteness*
caught it anyway. Good news for architecture, bad news for those six
specific checks, which need own follow-up (see
[next-steps.md](../next-steps.md)) since stealth has evidently moved past
what they detect.

**Raw-CDP finding — actual remaining gap, worse than initially scoped.**
Score 40/100 "bot" against hand-rolled CDP client with no
`--enable-automation` and no stealth patching at all — but nearly entire
deduction (−60 of non-soft total) came from one crude signal: literal
substring `"headlesschrome"` in default Chromium UA. Every architectural
check (webdriver, frameworkGlobals, all three CDP checks) read clean,
correctly, since nothing was patched or hidden — nothing automation-shaped
about this session except word "Headless" in its User-Agent. **A custom
client that also normalizes its UA (trivial — one line) would very likely
score close to 100/human against everything exercised in this audit.**
Same shape of gap the very first manual check in this audit found against
Claude's own in-app browser tool: careful, internally-consistent,
non-stealth client currently has almost nothing standing in its way. Not a
code bug to patch — structural limitation of what client-side JS can
detect about a disciplined custom automation client that doesn't announce
itself. Documented here rather than "fixed" because there's no honest fix
for it at this layer; see [next-steps.md](../next-steps.md) for what next
layer of defense would need.

**`chrome_runtime_tamper` — investigated, promising fix reverted.**
Stealth-evasion finding above prompted tightening `chromeRuntimeOK()` to
flag `window.chrome` existing while totally lacking `runtime` (stealth's
chrome evasion adds `app`/`csi` but skips `runtime` entirely). Verified
this closed stealth gap (score dropped 25 → 5 with fix applied). But
before shipping it, checked whether it would false-positive on real users
— and found official **"Chrome for Testing" binary itself lacks
`chrome.runtime` entirely**, headless AND headful, even with
`--enable-automation` stripped from launch args and `navigator.webdriver`
patched to `undefined` (about as close to "non-automated" as that binary
can be made to look). So absence is a property of that Chrome
*distribution*, not proof of automation — and this audit's sandbox has no
genuine consumer-Chrome binary to check whether regular Chrome behaves
differently. Reverted rather than ship unverified rule that could score
real human visitors as tampered. Full reasoning inline at
`chromeRuntimeOK()` comment in [botcheck.js](../../../../../shared/static/js/botcheck.js) and in
[`../../../report.go`](../../../report.go)'s `chrome_runtime_tamper`
explanation. Single most valuable open item in
[next-steps.md](../next-steps.md) — real, closeable gap, just not closeable
without a genuine consumer Chrome sample.
