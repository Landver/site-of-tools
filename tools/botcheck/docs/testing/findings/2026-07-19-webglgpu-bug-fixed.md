# 2026-07-19 — `webglGPU()` bug: the case study for why this harness exists

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

The reason this whole npm-based harness got built, not just one fixed bug:
`webglGPU()` in [botcheck.js](../../../../../shared/static/js/botcheck.js)
referenced an undefined variable `c` instead of creating its own canvas
(unlike `canvasProbe()`/`detectFonts()`, which each make their own) —
throws `ReferenceError: c is not defined` on every real page, silently
swallowed by `safe()`. `go test ./... -race` stayed green the entire time,
because the Go suite constructs `Signals` directly and never executes this
file at all (see [README.md](../README.md)'s "why this needed real
browsers" and [`../go-test-suite.md`](../../go-test-suite.md)'s structural
limitation note) — a bug in the *collector* is structurally invisible to a
test suite that only exercises the *scorer*. Reproduced and confirmed via a
live Puppeteer run's raw fingerprint dump (headless and headful): top-level
`webglVendor`/`webglRenderer` empty in both, while the Worker's independent
OffscreenCanvas WebGL probe correctly read the real GPU string in both —
proof it was the bug, not absent hardware, zeroing the top-level fields.

Fixed same day, deployed, confirmed live via CI/CD. Which three rules this
had been silently neutering since launch, and their post-fix verification:
[checks/software_renderer.md](../checks/software_renderer.md),
[checks/webgl_vendor_mismatch.md](../checks/webgl_vendor_mismatch.md),
[checks/gpu_os_mismatch.md](../checks/gpu_os_mismatch.md).
