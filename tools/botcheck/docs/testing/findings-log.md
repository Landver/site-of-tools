# Bot check — automation-test findings log

*(part of [botcheck docs index](../README.md), see [README.md](README.md)
for harness architecture)* — this is index; each dated finding lives in own
file under [`findings/`](findings/) so reader (human or AI) opens only entry
relevant to their question. See [next-steps.md](next-steps.md) for
prioritized to-do list these findings produced.

## 2026-07-19

| Finding | What it found |
|---|---|
| [CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)](findings/2026-07-19-cdp-trap-family-confirmed-dead.md) | `cdp_both`/`cdp_main_only`/`cdp_sw_only` fired zero times across 6 genuine CDP-driven sessions — technique dead on current Chromium, not evaded by one browser. Re-tiered hard/consistency → soft. |
| [`webdriver_sw`: confirmed across 3 frameworks, left as-is](findings/2026-07-19-webdriver-sw-confirmed-across-frameworks.md) | Service Worker's `navigator.webdriver` reads `false` for real automation across Playwright, Selenium, and Puppeteer — structural blind spot, not patchable bug. Docs fixed, tier unchanged. |
| [`webglGPU()` bug: FIXED](findings/2026-07-19-webglgpu-bug-fixed.md) | Undefined-variable bug zeroed `webglVendor`/`webglRenderer` for every visitor since launch, neutering 85 points of scoring logic (`software_renderer`, `webgl_vendor_mismatch`, `gpu_os_mismatch`). Fixed and deployed same day. |
| [Multi-framework matrix results](findings/2026-07-19-multi-framework-matrix-results.md) | Headline audit: 5 frameworks scored live. `puppeteer-extra-plugin-stealth` evaded all 6 purpose-built stealth checks but caught by cross-context consistency checks (25/100). Raw CDP with no automation flags scored 40/100 on UA string alone. `chrome_runtime_tamper` fix investigated, then reverted. |
| [Docs reorganized](findings/2026-07-19-docs-reorganized.md) | Findings log (plus harness architecture and next-steps list) split out of one 299-line `TESTING.md`, itself split from 386-line `README.md` and 464-line `ROADMAP.md`. No content dropped, only relocated. |
| [Real-Chrome baseline via Claude in Chrome](findings/2026-07-19-chrome-runtime-real-chrome-baseline.md) | Second, still-confounded data point: genuine consumer Chrome 149 also lacks `window.chrome.runtime`. Extension-controlled, so not fully organic sample `chrome_runtime_tamper` question still needs. |
| [Read `puppeteer-extra-plugin-stealth`'s source](findings/2026-07-19-puppeteer-extra-stealth-source-read.md) | Traced why 4 of 6 evaded checks stopped working, via plugin's shared `_utils/index.js` helpers. One untested idea for sharper proxy-trap probe. |
| [`timezone_ip_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)](findings/2026-07-19-timezone-webrtc-ip-mismatch-closed.md) | 50/100 "Suspicious" reading on genuine human visit traced to Claude in Chrome sandbox's own network topology, not false-positive risk. Confirmed clean on ordinary Chrome session. Closed. |
| [`tostring_proxy` FIXED: V8's stack-frame format outran both stealth's stripper and our detector](findings/2026-07-19-tostring-proxy-alias-frame-fix.md) | Nested-double-throw idea from next-steps item 3 wasn't even needed — single illegal call already leaked stealth's raw `newHandler` proxy-trap frame, since current V8 formats it as bracket alias (`[as apply]`) matching neither `stripProxyFromErrors`' anchor search nor our regex. Broadened detector's pattern; verified live: stealth's score dropped 25→0, other three frameworks (Playwright, real-Chrome-binary Selenium, raw CDP) unchanged. |
| [`chrome_runtime_tamper` (item 2): deprioritized, not closed](findings/2026-07-19-chrome-runtime-tamper-deprioritized.md) | Neither browser tool available this session can supply genuine-consumer-Chrome sample this item's waited on — in-app Browser pane turned out Electron embed, not Chrome. Recommend deprioritizing regardless: stealth's chrome.runtime evasion already shown to matter only against naive (non-stealth) bots, so even clean organic sample wouldn't make tightened check worth shipping. |

## Adding a new finding

Add new dated file under [`findings/`](findings/) (name it
`YYYY-MM-DD-short-slug.md`), give one-line summary row in table above under
right date heading (add new `## YYYY-MM-DD` heading for new date), link back
to this index like existing files do.
