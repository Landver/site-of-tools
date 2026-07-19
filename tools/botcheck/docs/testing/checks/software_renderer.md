# `software_renderer` — WebGL uses a software renderer (headless tell)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 40 · **Reads client signal:** yes

## What it checks

The WebGL renderer is a software rasteriser (SwiftShader, llvmpipe, …) — what a headless browser without a GPU reports. It also appears on real machines inside VMs or with disabled GPU drivers, so it is strong but not absolute proof.

## Origin & history

Original day-1 rule (a software WebGL renderer — SwiftShader/llvmpipe/Mesa — is a classic headless tell). Silently neutered for its entire lifetime by the `webglGPU()` collector bug until the 2026-07-19 audit found and fixed it — see the test status above.

## Test status: Fixed

**Was completely dead for every visitor, then fixed.** `webglGPU()`'s undefined-variable bug threw a `ReferenceError` on every request (swallowed by `safe()`), so `webglVendor`/`webglRenderer` came back empty for bot and human alike since launch — this rule never evaluated a single real fingerprint. Fixed same day (2026-07-19) and confirmed live: Playwright's SwiftShader software renderer correctly fired `-40` in the post-fix multi-framework audit.

See findings: [1](../findings/2026-07-19-webglgpu-bug-fixed.md), [2](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["software_renderer"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
