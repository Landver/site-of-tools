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

Several 2026-07-19 findings absorbed into their check's file, dropped as
standalone files — row links straight to check instead. Rows still under
`findings/` = content that don't reduce to one check (cross-framework audit,
shared root-cause dig).

| Finding | What it found |
|---|---|
| [CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)](checks/cdp_both.md) | `cdp_both`/`cdp_main_only`/`cdp_sw_only` fired zero times across 6 genuine CDP-driven sessions — technique dead on current Chromium, not evaded by one browser. Re-tiered hard/consistency → soft. |
| [`webdriver_sw`: confirmed across 3 frameworks, left as-is](checks/webdriver_sw.md) | Service Worker's `navigator.webdriver` reads `false` for real automation across Playwright, Selenium, and Puppeteer — structural blind spot, not patchable bug. Docs fixed, tier unchanged. |
| [`webglGPU()` bug: FIXED](findings/2026-07-19-webglgpu-bug-fixed.md) | Undefined-variable bug zeroed `webglVendor`/`webglRenderer` for every visitor since launch, neutering 85 points of scoring logic (`software_renderer`, `webgl_vendor_mismatch`, `gpu_os_mismatch`). Fixed and deployed same day. |
| [Multi-framework matrix results](findings/2026-07-19-multi-framework-matrix-results.md) | Headline audit: 5 frameworks scored live. `puppeteer-extra-plugin-stealth` evaded all 6 purpose-built stealth checks but caught by cross-context consistency checks (25/100). Raw CDP with no automation flags scored 40/100 on UA string alone. |
| [Raw-CDP/custom-harness gap: accepted as known architectural limit (CLOSED)](findings/2026-07-19-raw-cdp-gap-accepted.md) | Disciplined custom automation client (normal UA, consistent webdriver behavior, no framework markers) evades nearly everything — no client-side fix exists. Weighed IP-reputation/fingerprint-reuse build-out and a behavioral layer against accepting the gap; chose accept. |
| [Read `puppeteer-extra-plugin-stealth`'s source](findings/2026-07-19-puppeteer-extra-stealth-source-read.md) | Traced why several evaded checks stopped working, via plugin's shared `_utils/index.js` helpers. One untested idea for sharper proxy-trap probe. |
| [`tz_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)](checks/tz_mismatch.md) | 50/100 "Suspicious" reading on genuine human visit traced to Claude in Chrome sandbox's own network topology, not false-positive risk. Confirmed clean on ordinary Chrome session. Closed. |
| [`tostring_proxy` FIXED: V8's stack-frame format outran both stealth's stripper and our detector](checks/tostring_proxy.md) | Single illegal call already leaked stealth's raw `newHandler` proxy-trap frame, since current V8 formats it as bracket alias (`[as apply]`) matching neither `stripProxyFromErrors`' anchor search nor our old regex — two independent bugs, same V8 format-drift root cause. Verified live: stealth's score dropped 25→0, other three frameworks unchanged. |
| [`chrome_runtime_tamper`: evaded, fix drafted and reverted, deprioritized](checks/chrome_runtime_tamper.md) | The most heavily investigated open item: tightened `chromeRuntimeOK()` closed the stealth gap but was reverted after "Chrome for Testing" (and, less conclusively, a real consumer Chrome sample) turned out to lack `chrome.runtime` too. Deprioritized once stealth's own source showed presence-checking was never sound against it regardless. |
| [Remaining 43 checks: real-automation + fire-branch sweep (41 VERIFIED, 2 blocked by local dataset)](findings/2026-07-19-remaining-43-checks-sweep.md) | Every check that sat "not yet tested" now has a real-automation or constructed-fire-branch data point: header curls, a live-Mongo-corpus `fingerprint_reuse` test, two new Puppeteer probe scripts (`ua-mismatch-probe.mjs`, `fire-branch-probe.mjs`) exercising 28 checks through the real collector, plus stock automation naturally tripping `default_geometry`/`impossible_window`. Zero botcheck rule bugs found. One real (non-botcheck) bug found and fixed: `shared/templates/partials/head.html`'s theme-detector called unguarded `matchMedia()`. `datacenter_ip`/`proxy_ip` stay unconfirmed — local IP2Proxy LITE snapshot doesn't classify any tried IP as a proxy. Genuine-human baseline (Claude's in-app browser, and the user's real Chrome via Claude-in-Chrome) confirmed clean except one real `zero_outer_height` false positive, safely absorbed by its soft-cluster tier. |

## 2026-07-21

| Finding | What it found |
|---|---|
| [Five deep-tamper internals probes downgraded consistency → soft](findings/2026-07-21-internals-tamper-downgraded-to-soft.md) | Follow-through on the 2026-07-19 audit: `native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`, `chrome_runtime_tamper`, `chrome_late_injection` moved consistency → soft. Evaded by current stealth, false-positive-prone against privacy extensions (two firing dropped a real human to 50/"suspicious"), redundant against naive bots — so cluster-only now, not standalone deductions. Same precedent as the CDP-trap trio. Added `TestEveryRuleCanFire` fire-path completeness guard in the same pass. |

## Adding a new finding

Add new dated file under [`findings/`](findings/) (name it
`YYYY-MM-DD-short-slug.md`), give one-line summary row in table above under
right date heading (add new `## YYYY-MM-DD` heading for new date), link back
to this index like existing files do.
