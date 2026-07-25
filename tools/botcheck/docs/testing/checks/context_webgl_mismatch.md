# `context_webgl_mismatch` — Worker WebGL renderer ≠ main-thread WebGL renderer

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 20 · **Reads client signal:** yes

## What it checks

WebGL renderer read inside Web Worker differs from main thread's — same browser, same GPU, so strings should match. Fires only when both reads succeed; OffscreenCanvas WebGL often unsupported, which leaves nothing to compare.

## Origin & history

**G03/G08**, shipped 2026-07-18 ("worker-vs-main WebGL diff half shipped with G03"): Worker's independent OffscreenCanvas WebGL read diffed against main thread's. Check that caught stealth's spoofed WebGL renderer via Worker leaking real GPU string — see test status above.

## Test status: Verified — fires correctly

Caught `puppeteer-extra-plugin-stealth`: main-thread WebGL spoofed to generic `Intel Iris OpenGL Engine`, but Worker's independent OffscreenCanvas WebGL read leaked real host GPU (`ANGLE (Apple, ANGLE Metal Renderer: Apple M5, ...)`- ). Fired `-20`, one of three cross-context checks that caught stealth.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextAbsentDataNeverFires`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_webgl_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
