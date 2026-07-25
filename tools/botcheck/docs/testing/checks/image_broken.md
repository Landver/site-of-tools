# `image_broken` — A guaranteed-loadable image failed (images stripped)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Deliberately broken image reports dimensions that don't match what claimed browser/engine produces — engine tell spoofed environments rarely reproduce faithfully.

## Origin & history

**G10**, shipped 2026-07-18 (broken-image probe only, of G10 batch — battery/hairline-offset probes skipped as dated legacy PhantomJS-era tells; CSS-system-color probe, CreepJS's `hasKnownBgColor`, built then **dropped before shipping** after ground-truthing found real headed Chrome 150 on macOS already computes `ActiveText` to exactly `rgb(255,0,0)` — "headless default" this probe would have looked for is now what every real Chrome reports, tell that's simply dated): guaranteed-loadable 1×1 data-URI image that must load in any real browser — `naturalWidth == 0` or error event means environment strips images.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `naturalWidth` to always read 0 → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["image_broken"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
