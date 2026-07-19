# `image_broken` — A guaranteed-loadable image failed (images stripped)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

A deliberately broken image reports dimensions that don't match what the claimed browser/engine produces — an engine tell spoofed environments rarely reproduce faithfully.

## Origin & history

**G10**, shipped 2026-07-18 (broken-image probe only, of the G10 batch — battery/hairline-offset probes skipped as dated legacy PhantomJS-era tells; a CSS-system-color probe, CreepJS's `hasKnownBgColor`, was built then **dropped before shipping** after ground-truthing found real headed Chrome 150 on macOS already computes `ActiveText` to exactly `rgb(255,0,0)` — the "headless default" this probe would have looked for is now what every real Chrome reports, a tell that's simply dated): a guaranteed-loadable 1×1 data-URI image that must load in any real browser — `naturalWidth == 0` or an error event means the environment strips images.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/fire-branch-probe.mjs`): overrode `HTMLImageElement.prototype.naturalWidth` to always read 0. Fired through the real collector's guaranteed-loadable-image probe; genuine automation with images intact stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["image_broken"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
