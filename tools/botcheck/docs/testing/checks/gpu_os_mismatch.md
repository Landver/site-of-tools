# `gpu_os_mismatch` — WebGL GPU impossible on the claimed OS

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The GPU family is impossible on the OS the User-Agent claims (an Apple GPU on Windows, a desktop NVIDIA on a phone OS, …): the UA was rewritten but WebGL still names the real hardware. It fires only on enumerated impossible pairs — plausible-but-unusual combinations (AMD in an Intel Mac, Adreno on a Snapdragon laptop) stay silent by design.

## Origin & history

**G08**, shipped 2026-07-17: fires only on an enumerated list of impossible GPU-family/OS pairs (an Apple GPU on Windows/Linux/Android, a desktop NVIDIA/AMD on iOS/Android, Adreno/Mali on macOS/iOS) — deliberately silent on plausible-but-unusual combinations real hardware produces (AMD + macOS on Intel Macs, Adreno + Windows on Snapdragon ARM laptops, Intel + Android on old Atom phones). The Worker-vs-main-thread half of GPU coherence shipped alongside G03 as `context_webgl_mismatch`. Same `webglGPU()` collector-bug history as `webgl_vendor_mismatch` applies — see the test status above.

## Test status: Fixed

Neutered by the same `webglGPU()` bug as `software_renderer` and `webgl_vendor_mismatch` — fixed 2026-07-19. Not yet observed firing against a real automation framework post-fix.

See [finding](../findings/2026-07-19-webglgpu-bug-fixed.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestServerOnlySkipsClientChecks`, `TestGPUOSMismatch`; `tests/handler_test.go`: `TestCheckGPUCoherenceThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["gpu_os_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
