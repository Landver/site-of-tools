# `software_renderer` — WebGL uses a software renderer (headless tell)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 40 · **Reads client signal:** yes

## What it checks

WebGL renderer = software rasteriser (SwiftShader, llvmpipe, …) — what headless browser without GPU reports. Also appears on real machines inside VMs or w/ disabled GPU drivers, so strong but not absolute proof.

## Origin & history

Original day-1 rule (software WebGL renderer — SwiftShader/llvmpipe/Mesa — classic headless tell). Silently neutered its entire lifetime by `webglGPU()` collector bug until 2026-07-19 audit found & fixed it — see test status above.

## Test status: Fixed

**Was completely dead for every visitor, then fixed.** `webglGPU()`'s undefined-variable bug threw `ReferenceError` on every request (swallowed by `safe()`), so `webglVendor`/`webglRenderer` came back empty for bot & human alike since launch — this rule never evaluated a single real fingerprint. Fixed same day (2026-07-19) & confirmed live: Playwright's SwiftShader software renderer correctly fired `-40` in post-fix multi-framework audit.

See findings: [1](../findings/2026-07-19-webglgpu-bug-fixed.md), [2](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["software_renderer"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
