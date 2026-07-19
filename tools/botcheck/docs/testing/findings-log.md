# Bot check — automation-test findings log

*(part of the [botcheck docs index](../README.md), see [README.md](README.md)
for the harness architecture)* — dated entries, newest section at the bottom
of each date. See [next-steps.md](next-steps.md) for the prioritized to-do list
these findings produced.

## 2026-07-19 — CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)

`cdpTrap()` ([botcheck.js](../../../../shared/static/js/botcheck.js)) —
backing `cdp_both`/`cdp_main_only`/`cdp_sw_only` — defines a getter on an
`Error`'s `.stack` and calls `console.debug()` on it, expecting a CDP client
with `Runtime.enable` active to invoke the getter while building an object
preview. Tested against **six** genuinely CDP-driven sessions and it fired
**zero** times in every one:

1. Claude's own in-app CDP-driven browser tool (the original trigger for this audit).
2. A genuine, un-stealthed Puppeteer session, headless AND headful, with a
   `page.on('console', …)` listener explicitly forcing console-message capture
   (and a plain-object property getter through `console.debug()` — rules out
   anything `Error.stack`-specific).
3. Playwright, headless chromium — `cdpMainThread`/`cdpWorker`/`swCDP` all `false`.
4. Selenium + chromedriver, driving the real "Google Chrome for Testing" binary
   — same result, all three `false`, despite chromedriver's session genuinely
   running over CDP.
5. A hand-rolled `chrome-remote-interface` client, Chromium spawned directly,
   Page/Runtime/Network domains explicitly enabled for the whole session,
   deliberately with **no** `--enable-automation` flag — still all `false`.
6. `puppeteer-extra` + `puppeteer-extra-plugin-stealth` — also all `false`
   (unsurprising given #2-5, but confirmed).

Net: this was never one browser evading it. The technique's premise — CDP
preview generation invokes property getters — doesn't hold on current Chromium
regardless of transport. **Fixed** by honest recalibration rather than deletion
(kept running — it's free when silent, and might catch a future Chromium
regression or an older engine): moved `cdp_both`, `cdp_main_only`, and
`cdp_sw_only` from hard (40pts) / consistency (15pts each) down into the
soft-heuristics section of `scoring.go` (weight 8, only bites as part of a ≥3
cluster like every other soft signal), physically relocated to the file's own
"Soft heuristics" block, and rewrote their `report.go` explanations to state
the 2026-07-19 finding plainly instead of the old "DevTools-open false
positive" framing (which implied the trap works against real automation and
just has a narrow blind spot — it doesn't, full stop, as far as this audit can
tell). `go test ./... -race` green after the change — nothing in the existing
suite asserted a specific tier for these three IDs, only `.Triggered` booleans,
so this was safe to change without touching test expectations.

## 2026-07-19 — `webdriver_sw`: confirmed across 3 frameworks, left as-is (documentation fix only)

Playwright, Selenium/chromedriver, and the original Puppeteer session all show
the same pattern: main thread `webdriver: true` and iframe `iframeWebdriver:
true` correctly, but the Service Worker `swWebdriver: false` — for the *same*
automated session, three separate frameworks, not a fluke. The SW script itself
is written correctly (the `swScript` const in [handler.go](../../handler.go),
`navigator.webdriver===true`) — Chromium's `ServiceWorkerGlobalScope` appears to
simply not carry the `--enable-automation` flag into `navigator.webdriver`
there, regardless of patching.

**Not re-tiered** (unlike the CDP trio): this isn't a low-precision signal that
sometimes false-positives on humans (the DevTools-open problem) — it's a signal
that structurally never fires true against tested real automation. Tier doesn't
change anything for a check that never triggers either way, so the only
substantive fix available was correcting `report.go`'s explanation text (was:
"a third JavaScript realm automation tools rarely bother to patch," implying
it usually catches unpatched automation — the opposite of what's observed) to
state plainly that a clean reading here isn't reassuring. Left running as a
hard tell on the chance it does fire someday (a genuine positive would still
be strong evidence); just stopped pretending a miss means anything.

## 2026-07-19 — `webglGPU()` bug: FIXED

`webglGPU()` in [botcheck.js](../../../../shared/static/js/botcheck.js) referenced an
undefined variable `c` instead of creating its own canvas (unlike
`canvasProbe()`/`detectFonts()`, which each make their own). Reproduced directly
in a real page: throws `ReferenceError: c is not defined`, silently swallowed by
`safe()`, so `webglVendor`/`webglRenderer` came back `""` on **every** request —
bot or human, headless or headful — since this code shipped. Confirmed via the
raw fingerprint dump in both a headless and a headful live Puppeteer run: the
top-level fields were empty in both, while the Worker's independent
OffscreenCanvas WebGL read (a separately-written probe) correctly got the real
GPU string (`ANGLE (Apple, ANGLE Metal Renderer: Apple M5, …)`) in both — proving
a real GPU was available and the bug, not absence of hardware, was what zeroed
the top-level fields.

**Fixed:** added `const c = document.createElement("canvas");` at the top of
`webglGPU()`. Verified the fix directly (same reproduction, now returns real
vendor/renderer instead of throwing). `go test ./... -race` still green (this
bug was invisible to it — see [README.md](README.md)'s "why this needed real
browsers"). This had been silently neutering three rules for every visitor
since it shipped: `software_renderer` (40 pts, hard), `webgl_vendor_mismatch`
(20 pts), `gpu_os_mismatch` (25 pts) — 85 points of scoring logic that had
never evaluated a single real fingerprint.

**Deployed 2026-07-19** (same day, after review) — merged to `master` and
confirmed live on `https://botcheck.corpberry.com/` via CI/CD.

## 2026-07-19 — multi-framework matrix results

Five frameworks run via `Workflow` in parallel, each in its own
`verify-cdp/frameworks/<name>/` subfolder against the local dev instance:

| Framework | Setup | Live score | What actually caught it |
|---|---|---|---|
| Playwright (headless chromium) | ok | 0/100 bot | `webdriver` + `iframe_webdriver` (−60 each), `bot_user_agent` matched "headlesschrome" (−60), `software_renderer` (SwiftShader, −40), `permission_impossible` (−25) |
| Selenium + chromedriver (real "Chrome for Testing" binary) | ok | 0/100 bot | Same webdriver/UA hits, **plus `framework_globals` caught all 7 of chromedriver's classic `$cdc_...` markers** (−60) — this specific check works great against classic Selenium |
| `puppeteer-extra` + `puppeteer-extra-plugin-stealth` 2.11.2 | ok | 25/100 bot | See deep-dive below — the headline result of this whole audit |
| Raw CDP (`chrome-remote-interface`, hand-spawned Chromium, no `--enable-automation`) | ok | 40/100 bot | **Almost entirely `bot_user_agent` matching "headlesschrome" in the UA** (−60) plus one sub-threshold soft flag. Every automation-protocol check (webdriver, frameworkGlobals, all three CDP checks) read clean. |
| Nightmare (~2015-2018, Electron-based) | failed to install | n/a | Ancient Electron 2.0.18 has no darwin-arm64 build (404) and its Node-v24-incompatible `extract-zip@1.7.0` postinstall step corrupts the darwin-x64 fallback under Rosetta. Expected, not pursued further — the `__nightmare` WINDOW_MARKERS entry stays unexercised. |

**Headline finding — puppeteer-extra-stealth deep-dive.** This is the single
most important result of the whole audit. Six checks the codebase built to
target this class of stealth patch — `tostring_proxy`,
`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`,
`chrome_runtime_tamper`, `chrome_late_injection` — **were evaded, all six,
cleanly.** (Three of the six — `tostring_proxy`, `native_descriptor_tamper`,
`chrome_runtime_tamper` — have code comments that name
`puppeteer-extra-plugin-stealth` specifically; `navigator_proto_tamper` and
`chrome_late_injection` describe the general stealth-patch shape without
naming a plugin, and `native_callnew_tamper` shares its section comment with
`native_descriptor_tamper`.) `navigator.webdriver` itself was hidden
everywhere (main thread, iframe, and Service Worker all read `false`) — a more
thorough hide than a naive delete-only patch. And yet **the tool still scored
it 25/100, "bot," not human.** What actually caught it were three of the
architecture's own cross-context consistency checks, none of which are
stealth-specific:

- `context_ua_mismatch` (−35): main thread, Worker, and iframe UA were all
  successfully patched to a clean `Chrome/150.0.0.0` with no "Headless" token —
  but the **Service Worker** leaked the real, unpatched
  `HeadlessChrome/150.0.0.0` UA. Stealth's UA-override evasion never reaches
  the Service Worker realm.
- `context_cores_mismatch` (−20): main thread `hardwareConcurrency` was spoofed
  to `4`, but the Worker and Service Worker both reported the real `10`.
- `context_webgl_mismatch` (−20): main thread WebGL was spoofed to a generic
  `Intel Iris OpenGL Engine` / `Intel Inc.`, but the Worker's independent
  OffscreenCanvas WebGL read leaked the real host GPU, `ANGLE (Apple, ANGLE
  Metal Renderer: Apple M5, …)`.

This is exactly this tool's core design thesis — "the strongest checks are the
cross-layer/cross-context consistency ones," per `botcheck.go`'s own package
doc — validated against a real, current, actively-maintained adversarial tool.
The six checks specifically built to catch stealth's *signature* all missed;
the checks built to catch stealth's *incompleteness* caught it anyway. Good
news for the architecture, bad news for those six specific checks, which need
their own follow-up (see [next-steps.md](next-steps.md)) since stealth has
evidently moved past what they detect.

**Raw-CDP finding — the actual remaining gap, worse than initially scoped.**
Score 40/100 "bot" against a hand-rolled CDP client with no `--enable-automation`
and no stealth patching at all — but nearly the entire deduction (−60 of the
non-soft total) came from one crude signal: the literal substring
`"headlesschrome"` in the default Chromium UA. Every architectural check
(webdriver, frameworkGlobals, all three CDP checks) read clean, correctly,
since nothing was patched or hidden — there was simply nothing automation-shaped
about this session except the word "Headless" in its User-Agent. **A custom
client that also normalizes its UA (trivial — one line) would very likely score
close to 100/human against everything exercised in this audit.** This is the
same shape of gap the very first manual check in this audit found against
Claude's own in-app browser tool: a careful, internally-consistent, non-stealth
client currently has almost nothing standing in its way. Not a code bug to
patch — a structural limitation of what client-side JS can detect about a
disciplined custom automation client that doesn't announce itself. Documented
here rather than "fixed" because there's no honest fix for it at this layer;
see [next-steps.md](next-steps.md) for what a next layer of defense would need.

**`chrome_runtime_tamper` — investigated, a promising fix reverted.** The
stealth-evasion finding above prompted tightening `chromeRuntimeOK()` to flag
`window.chrome` existing while totally lacking `runtime` (stealth's chrome
evasion adds `app`/`csi` but skips `runtime` entirely). Verified this closed
the stealth gap (score dropped 25 → 5 with the fix applied). But before
shipping it, checked whether it would false-positive on real users — and found
the official **"Chrome for Testing" binary itself lacks `chrome.runtime`
entirely**, headless AND headful, even with `--enable-automation` stripped from
launch args and `navigator.webdriver` patched to `undefined` (about as close to
"non-automated" as that binary can be made to look). So the absence is a
property of that Chrome *distribution*, not proof of automation — and this
audit's sandbox has no genuine consumer-Chrome binary to check whether regular
Chrome behaves differently. Reverted rather than ship an unverified rule that
could score real human visitors as tampered. Full reasoning is inline at
the `chromeRuntimeOK()` comment in [botcheck.js](../../../../shared/static/js/botcheck.js) and in
[`../../report.go`](../../report.go)'s `chrome_runtime_tamper` explanation.
This is the single most valuable open item in [next-steps.md](next-steps.md)
— it's a real, closeable gap, just not closeable without a genuine consumer
Chrome sample.

## 2026-07-19 — docs reorganized

This findings log, the harness architecture, and the next-steps list used to
be one 299-line `TESTING.md`, itself a sibling to a 386-line `README.md` and a
464-line `ROADMAP.md`. Split by topic into `docs/testing/`, `docs/roadmap/`,
and standalone reference files — see the top-level
[docs index](../README.md). No content was dropped, only relocated.
