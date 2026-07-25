# `gpu_os_mismatch` — WebGL GPU impossible on the claimed OS

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

GPU family impossible on OS the UA claims (Apple GPU on Windows, desktop NVIDIA on phone OS, …): UA rewritten but WebGL still names real hardware. Fires only on enumerated impossible pairs; plausible-but-unusual combos (AMD in Intel Mac, Adreno on Snapdragon laptop) stay silent by design.

## Origin & history

**G08**, shipped 2026-07-17: fires only on enumerated impossible GPU-family/OS pairs (Apple GPU on Windows/Linux/Android, desktop NVIDIA/AMD on iOS/Android, Adreno/Mali on macOS/iOS); deliberately silent on plausible-but-unusual combos real hardware produces (AMD + macOS on Intel Macs, Adreno + Windows on Snapdragon ARM laptops, Intel + Android on old Atom phones). Worker-vs-main-thread half of GPU coherence shipped alongside G03 as `context_webgl_mismatch`. Same `webglGPU()` collector-bug history as `webgl_vendor_mismatch` applies — see test status above.

## Test status: Fixed

Neutered by same `webglGPU()` bug as `software_renderer` & `webgl_vendor_mismatch` — fixed 2026-07-19. Not yet observed firing against real automation framework post-fix.

See [finding](../findings/2026-07-19-webglgpu-bug-fixed.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestServerOnlySkipsClientChecks`, `TestGPUOSMismatch`; `tests/handler_test.go`: `TestCheckGPUCoherenceThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["gpu_os_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
