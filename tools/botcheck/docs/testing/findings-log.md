# Bot check — automation-test findings log

*(part of the [botcheck docs index](../README.md), see [README.md](README.md)
for the harness architecture)* — this is an index; each dated finding lives in
its own file under [`findings/`](findings/) so a reader (human or AI) opens
only the entry relevant to their question. See [next-steps.md](next-steps.md)
for the prioritized to-do list these findings produced.

## 2026-07-19

| Finding | What it found |
|---|---|
| [CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)](findings/2026-07-19-cdp-trap-family-confirmed-dead.md) | `cdp_both`/`cdp_main_only`/`cdp_sw_only` fired zero times across 6 genuinely CDP-driven sessions — the technique is dead on current Chromium, not evaded by any one browser. Re-tiered from hard/consistency to soft. |
| [`webdriver_sw`: confirmed across 3 frameworks, left as-is](findings/2026-07-19-webdriver-sw-confirmed-across-frameworks.md) | The Service Worker's `navigator.webdriver` reads `false` for real automation across Playwright, Selenium, and Puppeteer — a structural blind spot, not a patchable bug. Documentation fixed, tier unchanged. |
| [`webglGPU()` bug: FIXED](findings/2026-07-19-webglgpu-bug-fixed.md) | An undefined-variable bug zeroed `webglVendor`/`webglRenderer` for every visitor since launch, neutering 85 points of scoring logic (`software_renderer`, `webgl_vendor_mismatch`, `gpu_os_mismatch`). Fixed and deployed same day. |
| [Multi-framework matrix results](findings/2026-07-19-multi-framework-matrix-results.md) | The headline audit: 5 frameworks scored live. `puppeteer-extra-plugin-stealth` evaded all 6 purpose-built stealth checks but was still caught by cross-context consistency checks (25/100). Raw CDP with no automation flags scored 40/100 on UA string alone. `chrome_runtime_tamper` fix investigated, then reverted. |
| [Docs reorganized](findings/2026-07-19-docs-reorganized.md) | This findings log (plus the harness architecture and next-steps list) split out of one 299-line `TESTING.md`, itself split from a 386-line `README.md` and a 464-line `ROADMAP.md`. No content dropped, only relocated. |
| [Real-Chrome baseline via Claude in Chrome](findings/2026-07-19-chrome-runtime-real-chrome-baseline.md) | A second, still-confounded data point: genuine consumer Chrome 149 also lacks `window.chrome.runtime`. Extension-controlled, so not the fully organic sample the `chrome_runtime_tamper` question still needs. |
| [Read `puppeteer-extra-plugin-stealth`'s source](findings/2026-07-19-puppeteer-extra-stealth-source-read.md) | Traced exactly why 4 of the 6 evaded checks stopped working, via the plugin's shared `_utils/index.js` helpers. One untested idea for a sharper proxy-trap probe. |
| [`timezone_ip_mismatch` + `webrtc_ip_mismatch`: sandbox artifact, confirmed non-issue (CLOSED)](findings/2026-07-19-timezone-webrtc-ip-mismatch-closed.md) | A 50/100 "Suspicious" reading on a genuine human visit traced to the Claude in Chrome sandbox's own network topology, not a false-positive risk. Confirmed clean on an ordinary Chrome session. Closed. |

## Adding a new finding

Add a new dated file under [`findings/`](findings/) (name it
`YYYY-MM-DD-short-slug.md`), give it a one-line summary row in the table above
under the right date heading (add a new `## YYYY-MM-DD` heading for a new
date), and link back to this index the way the existing files do.
