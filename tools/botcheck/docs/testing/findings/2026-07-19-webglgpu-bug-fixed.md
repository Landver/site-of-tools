# 2026-07-19 — `webglGPU()` bug: FIXED

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

`webglGPU()` in [botcheck.js](../../../../../shared/static/js/botcheck.js)
referenced an undefined variable `c` instead of creating its own canvas
(unlike `canvasProbe()`/`detectFonts()`, which each make their own).
Reproduced directly in a real page: throws `ReferenceError: c is not
defined`, silently swallowed by `safe()`, so `webglVendor`/`webglRenderer`
came back `""` on **every** request — bot or human, headless or headful —
since this code shipped. Confirmed via raw fingerprint dump in both a
headless and headful live Puppeteer run: top-level fields were empty in
both, while Worker's independent OffscreenCanvas WebGL read
(separately-written probe) correctly got real GPU string (`ANGLE (Apple,
ANGLE Metal Renderer: Apple M5, …)`) in both — proving real GPU was
available and bug, not absence of hardware, zeroed top-level fields.

**Fixed:** added `const c = document.createElement("canvas");` at top of
`webglGPU()`. Verified fix directly (same reproduction, now returns real
vendor/renderer instead of throwing). `go test ./... -race` still green
(bug was invisible to it — see [README.md](../README.md)'s "why this needed
real browsers"). Had been silently neutering three rules for every visitor
since it shipped: `software_renderer` (40 pts, hard),
`webgl_vendor_mismatch` (20 pts), `gpu_os_mismatch` (25 pts) — 85 points of
scoring logic that had never evaluated a single real fingerprint.

**Deployed 2026-07-19** (same day, after review) — merged to `master`,
confirmed live on `https://botcheck.corpberry.com/` via CI/CD.
