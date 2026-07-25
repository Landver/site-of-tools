# `webgl_vendor_mismatch` — WebGL vendor and renderer disagree

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 20 · **Reads client signal:** yes

## What it checks

Unmasked WebGL vendor & renderer both come from same GPU driver, so real browser never reports them in different vendor families (e.g. vendor Apple, renderer NVIDIA). Unparseable strings (VMs, masked values) count as no signal, never mismatch.

## Origin & history

**G07**, shipped 2026-07-17: collector extended to also report WebGL vendor string (previously only renderer read); rule fires when vendor & renderer parse to different confident GPU families (e.g. vendor Apple, renderer NVIDIA). Verified vs real reporting styles (ANGLE shim pairs, Safari's generalised "Apple Inc."/"Apple GPU", Firefox driver strings) specifically so no real browser contradicts itself. **2026-07-19 note:** silently never fired for anyone, bot or human, until `webglGPU()` collector bug fixed — see test status above.

## Test status: Fixed

Neutered by same `webglGPU()` bug as `software_renderer` (undefined-variable `ReferenceError`, swallowed silently) — `webglVendor`/`webglRenderer` came back empty for every visitor since launch, so rule never had real data to compare. Fixed 2026-07-19. Not yet observed firing vs real automation framework post-fix (none of five audited frameworks produced vendor/renderer mismatch).

See [finding](../findings/2026-07-19-webglgpu-bug-fixed.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestServerOnlySkipsClientChecks`, `TestWebGLVendorMismatch`, `TestGPUOSMismatch`; `tests/handler_test.go`: `TestCheckGPUCoherenceThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webgl_vendor_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
