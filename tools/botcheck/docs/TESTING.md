# Bot check — automation test architecture & false-negative roadmap

Companion to [`RESEARCH.md`](RESEARCH.md) (how competitor services work) and
[`ROADMAP.md`](ROADMAP.md) (feature/signal gap audit). This doc is narrower:
**does botcheck actually catch real, off-the-shelf automation tools**, verified
by running them for real rather than reasoning about them — plus what that
testing found broken and what's left to fix.

Started 2026-07-19, after a manual review (via Claude's own in-app/CDP-driven
browser) found the CDP-detection checks reading "ok" against a session that is
in fact CDP-driven. That review is written up in the session that produced this
doc; the summary worth keeping is below.

## Why this needed real browsers, not more reasoning

`go test ./... -race` (CLAUDE.md rule #6) never exercises
[`shared/static/js/botcheck.js`](../../../shared/static/js/botcheck.js) — the Go
tests construct `Signals` directly and feed them to `Evaluate`. That's correct
for testing the *scorer*, but it means a bug in the *collector* (wrong value,
thrown exception, wrong DOM read) is structurally invisible to the existing test
suite forever. The `webglGPU()` bug below shipped and passed every Go test and
every prior E2E pass, because nobody had a harness that could catch a client-side
`ReferenceError` swallowed by `safe()`.

## Test architecture

A gitignored, npm-based harness lives outside the Go module at
**`/verify-cdp/`** (repo root, sibling to `tools/`) — **not** part of the shipped
product, **not** committed (see `.gitignore`: `/verify-cdp/`). This is a
deliberate, scoped exception to CLAUDE.md rule #3 ("No Node/npm. Ever."): the
rule protects the *shipped binary and its frontend* from a JS toolchain
dependency; it says nothing about disposable local verification tooling that
never ships. If that changes (the repo decides to track these tests for real),
un-gitignore the folder and promote it properly — flagged here rather than
decided unilaterally.

```
verify-cdp/
  .puppeteerrc.cjs          # keeps the downloaded Chromium local to this folder
  .chromium-cache/          # ~550MB, shared across every Puppeteer-based test below
  cdp-trap.test.mjs         # node:test — isolated cdpTrap() probe, no network
  full-sweep.mjs            # full check-breakdown dump against a live instance,
                             # headless vs. headful, with a diff
  frameworks/
    playwright/             # one subfolder per automation framework under test
    selenium/
    puppeteer-extra-stealth/
    raw-cdp/
    nightmare/
```

**Target:** point every test at a **local dev instance**
(`APP_ENV=dev go run .` from repo root, served at `http://botcheck.localhost:8080/`
— Chromium resolves `*.localhost` to loopback natively, no `/etc/hosts` edit
needed), not production. Two reasons: it exercises whatever fix is currently
uncommitted in the working tree, and it doesn't add synthetic noise to the real
Mongo request log / fingerprint corpus. Hit the real
`https://botcheck.corpberry.com/` only when specifically validating deployed
behavior.

**Adding a new framework:** make a new `frameworks/<name>/` subfolder, `npm init
-y`, install only what that framework needs, keep any downloaded browser binary
local to the subfolder (mirror `.puppeteerrc.cjs`'s pattern — e.g.
`PLAYWRIGHT_BROWSERS_PATH` for Playwright), and reuse `full-sweep.mjs`'s
DOM-extraction approach for reading the score/verdict/check-list/raw-fingerprint
out of the rendered `#result` fragment. Report at minimum: `navigator.webdriver`,
`frameworkGlobals`, `cdpMainThread`/`cdpWorker`, and whether the live score
matched expectations.

**Known gap in this harness:** it proves a signal fires or doesn't against
*today's* Chromium build. It says nothing about older Chromium/Firefox/Safari,
and nothing about detection evasion tools not distributed over npm (Python's
`nodriver`/`undetected-chromedriver`, Go-based CDP libraries, browser
extensions). Treat every "confirmed dead" finding below as "dead against modern
Chromium via npm-distributed tooling," not "dead everywhere, forever."

## Findings log

### 2026-07-19 — CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)

`cdpTrap()` ([botcheck.js:52](../../../shared/static/js/botcheck.js:52)) —
backing `cdp_both`/`cdp_main_only`/`cdp_sw_only` — defines a getter on an
`Error`'s `.stack` and calls `console.debug()` on it, expecting a CDP client
with `Runtime.enable` active to invoke the getter while building an object
preview. Tested against **five** genuinely CDP-driven sessions and it fired
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

### 2026-07-19 — `webdriver_sw`: confirmed across 3 frameworks, left as-is (documentation fix only)

Playwright, Selenium/chromedriver, and the original Puppeteer session all show
the same pattern: main thread `webdriver: true` and iframe `iframeWebdriver:
true` correctly, but the Service Worker `swWebdriver: false` — for the *same*
automated session, three separate frameworks, not a fluke. The SW script itself
is written correctly ([handler.go:60](../handler.go:60),
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

### 2026-07-19 — `webglGPU()` bug: FIXED

[botcheck.js:474](../../../shared/static/js/botcheck.js:474) referenced an
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
bug was invisible to it — see "why this needed real browsers" above). This had
been silently neutering three rules for every visitor since it shipped:
`software_renderer` (40 pts, hard), `webgl_vendor_mismatch` (20 pts),
`gpu_os_mismatch` (25 pts) — 85 points of scoring logic that had never
evaluated a single real fingerprint.

**Not yet deployed** — this is a local source fix, uncommitted, verified only
in this working tree and against the local dev server. It needs review + a
commit + a push to reach `https://botcheck.corpberry.com/` (deploy is
CI/CD-driven off pushes to the deploy branch — not something to do
autonomously).

### 2026-07-19 — multi-framework matrix results

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
most important result of the whole audit. The six checks the codebase's own
comments specifically name as targeting this exact plugin —
`tostring_proxy`, `native_descriptor_tamper`, `native_callnew_tamper`,
`navigator_proto_tamper`, `chrome_runtime_tamper`, `chrome_late_injection` —
**were evaded, all six, cleanly.** `navigator.webdriver` itself was hidden
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
their own follow-up (see Roadmap) since stealth has evidently moved past what
they detect.

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
see Roadmap for what a next layer of defense would need.

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
[botcheck.js:238](../../../shared/static/js/botcheck.js:238) and in
[report.go](../report.go)'s `chrome_runtime_tamper` explanation. This is the
single most valuable open item in the roadmap below — it's a real, closeable
gap, just not closeable tonight without a genuine consumer Chrome sample.

## Roadmap (prioritized)

1. **Land the fixes already made** — `webglGPU()` bug fix, and the CDP-trio
   re-tier/re-weight/re-documentation — by reviewing the diff and pushing (deploy
   is CI/CD-driven off pushes; not done autonomously). Nothing here is
   deployed yet; `https://botcheck.corpberry.com/` still runs the old code.
2. **Resolve `chrome_runtime_tamper` for real** — get one real, unmodified
   consumer Google Chrome (not "Chrome for Testing") to check whether
   `chrome.runtime` is reliably present there. If yes, ship the tightened
   version from tonight (already written and verified against the stealth
   case, just reverted for lack of this one data point) — it would close a
   confirmed stealth-evasion gap. If no, this check may need retiring instead.
3. **The stealth-specific G04/G22 probes need their own follow-up.**
   `tostring_proxy`, `native_descriptor_tamper`, `native_callnew_tamper`,
   `navigator_proto_tamper` were all built explicitly to catch
   `puppeteer-extra-plugin-stealth` and none of them do anymore against the
   current version (2.11.2) — the plugin evidently evolved past them. Worth a
   focused pass reading the current stealth-plugin source (it's open source)
   to see exactly what changed and whether a sharper probe is feasible, rather
   than assuming the cross-context checks alone are enough going forward (they
   worked this time; that's not a guarantee).
4. **The raw-CDP / custom-harness gap is the real remaining hole** and doesn't
   have a client-side JS fix: a disciplined custom automation client that (a)
   doesn't include "Headless" in its UA, (b) doesn't trip `navigator.webdriver`
   or does so consistently across every context (unlike stealth's inconsistent
   patching), and (c) injects no framework markers currently evades nearly
   everything in this tool. The honest options are architectural, not
   check-level: lean harder on IP/network reputation and the fingerprint-reuse
   corpus (orthogonal signals, already built), consider a behavioral layer
   (mouse/keyboard trajectory, already noted as a non-goal in `ROADMAP.md`'s
   G52 for good reason), or accept this as a known, documented limit of a
   client-fingerprint-only, no-ML detector. Don't let a future contributor
   "fix" this with another single clever trap without reading this section
   first — that's exactly how the CDP trap ended up here.
5. **Revisit `ROADMAP.md`'s G16** (DevTools-open / debugger-timing detection),
   previously shelved as "skip, redundant with the CDP trap." That reasoning
   assumed the CDP trap works; it doesn't. Note, though: G16 detects a human
   with DevTools open, not automation — Puppeteer/Playwright/Selenium don't
   open a visible DevTools panel by default, so G16 wouldn't actually have
   caught anything in this audit's matrix either. Re-evaluate what it's
   actually good for before building it.
6. **Non-npm evasion tools stay untested by this harness** — Python's
   `undetected-chromedriver`/`nodriver`, browser extensions, and anything not
   on npm are a known blind spot of this specific test setup, not confirmed
   safe. Worth a separate pass if this matters enough (would need a Python
   environment, out of scope for the npm-based harness described here).
