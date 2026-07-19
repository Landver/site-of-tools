# `context_webgl_mismatch` — Worker WebGL renderer ≠ main-thread WebGL renderer

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 20 · **Reads client signal:** yes

## What it checks

The WebGL renderer read inside a Web Worker differs from the main thread's — same browser, same GPU, so the strings should match. Fires only when both reads succeed; OffscreenCanvas WebGL is often unsupported, which just leaves nothing to compare.

## Origin & history

**G03/G08**, shipped 2026-07-18 ("worker-vs-main WebGL diff half shipped with G03"): Worker's independent OffscreenCanvas WebGL read diffed against the main thread's. This is the check that caught stealth's spoofed WebGL renderer via the Worker leaking the real GPU string — see the test status above.

## Test status: Verified — fires correctly

Caught `puppeteer-extra-plugin-stealth`: main-thread WebGL was spoofed to a generic `Intel Iris OpenGL Engine`, but the Worker's independent OffscreenCanvas WebGL read leaked the real host GPU (`ANGLE (Apple, ANGLE Metal Renderer: Apple M5, ...)`- ). Fired `-20`, one of three cross-context checks that caught stealth.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextAbsentDataNeverFires`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_webgl_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
