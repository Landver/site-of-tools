# Bot check — automation-test findings log

*(part of [botcheck docs index](../README.md), see [README.md](README.md)
for harness architecture)* — this is index; each dated finding lives in own
file under [`findings/`](findings/) so reader (human or AI) opens only entry
relevant to their question. See [next-steps.md](next-steps.md) for
prioritized to-do list these findings produced.

This log is the **chronological, how-we-found-out** record — what was run,
when, against what. For **current per-check status** (which checks are
verified, evaded, fixed, or still untested, as of now rather than as of a
given date), see [checks/](checks/README.md) instead — it's built from the
findings below plus every check `scoring.go` defines, kept current rather
than dated.

## 2026-07-19

Several 2026-07-19 findings below have been fully absorbed into their
check's file and removed as standalone files (their row here now links
straight to the check) — see
[Per-check test-status docs added](findings/2026-07-19-checks-folder-added.md)
for why. Rows still linking under `findings/` are the ones with content
that doesn't reduce to a single check (a cross-framework audit, a shared
root-cause investigation) or that this log is the primary record of (docs
reorganizations).

| Finding | What it found |
|---|---|
| [CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)](checks/cdp_both.md) | `cdp_both`/`cdp_main_only`/`cdp_sw_only` fired zero times across 6 genuine CDP-driven sessions — technique dead on current Chromium, not evaded by one browser. Re-tiered hard/consistency → soft. |
| [`webdriver_sw`: confirmed across 3 frameworks, left as-is](checks/webdriver_sw.md) | Service Worker's `navigator.webdriver` reads `false` for real automation across Playwright, Selenium, and Puppeteer — structural blind spot, not patchable bug. Docs fixed, tier unchanged. |
| [`webglGPU()` bug: FIXED](findings/2026-07-19-webglgpu-bug-fixed.md) | Undefined-variable bug zeroed `webglVendor`/`webglRenderer` for every visitor since launch, neutering 85 points of scoring logic (`software_renderer`, `webgl_vendor_mismatch`, `gpu_os_mismatch`). Fixed and deployed same day. |
| [Multi-framework matrix results](findings/2026-07-19-multi-framework-matrix-results.md) | Headline audit: 5 frameworks scored live. `puppeteer-extra-plugin-stealth` evaded all 6 purpose-built stealth checks but caught by cross-context consistency checks (25/100). Raw CDP with no automation flags scored 40/100 on UA string alone. |
| [Docs reorganized](findings/2026-07-19-docs-reorganized.md) | Findings log (plus harness architecture and next-steps list) split out of one 299-line `TESTING.md`, itself split from 386-line `README.md` and 464-line `ROADMAP.md`. No content dropped, only relocated. |
| [Read `puppeteer-extra-plugin-stealth`'s source](findings/2026-07-19-puppeteer-extra-stealth-source-read.md) | Traced why several evaded checks stopped working, via plugin's shared `_utils/index.js` helpers. One untested idea for sharper proxy-trap probe. |
| [`tz_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)](checks/tz_mismatch.md) | 50/100 "Suspicious" reading on genuine human visit traced to Claude in Chrome sandbox's own network topology, not false-positive risk. Confirmed clean on ordinary Chrome session. Closed. |
| [`tostring_proxy` FIXED: V8's stack-frame format outran both stealth's stripper and our detector](checks/tostring_proxy.md) | Single illegal call already leaked stealth's raw `newHandler` proxy-trap frame, since current V8 formats it as bracket alias (`[as apply]`) matching neither `stripProxyFromErrors`' anchor search nor our old regex — two independent bugs, same V8 format-drift root cause. Verified live: stealth's score dropped 25→0, other three frameworks unchanged. |
| [`chrome_runtime_tamper`: evaded, fix drafted and reverted, deprioritized](checks/chrome_runtime_tamper.md) | The most heavily investigated open item: tightened `chromeRuntimeOK()` closed the stealth gap but was reverted after "Chrome for Testing" (and, less conclusively, a real consumer Chrome sample) turned out to lack `chrome.runtime` too. Deprioritized once stealth's own source showed presence-checking was never sound against it regardless. |
| [Per-check test-status docs added](findings/2026-07-19-checks-folder-added.md) | "Status of tests per check" wasn't answerable without grepping three files and merging by rule ID by hand. Added `checks/` — one file per implemented rule, current test status + Go test coverage, `next-steps.md` trimmed to only what isn't check-specific. |

## Adding a new finding

Add new dated file under [`findings/`](findings/) (name it
`YYYY-MM-DD-short-slug.md`), give one-line summary row in table above under
right date heading (add new `## YYYY-MM-DD` heading for new date), link back
to this index like existing files do.
