# `matchmedia_missing` — Browser User-Agent but window.matchMedia is missing

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.matchMedia is part of every real browser's CSS support, desktop and mobile alike, so a browser-claimed User-Agent without it is a stripped JavaScript environment (jsdom-style) wearing a browser UA. An exotic embedded webview could conceivably lack it too, which is why this only counts inside a soft cluster.

## Origin & history

**G15**, shipped 2026-07-18 (wave-2 probes batch, collector payload bumped to `v: 4` with an additive `env` section): a browser-claimed UA missing `window.matchMedia` entirely is a stripped JavaScript environment (jsdom-style) wearing a browser UA. A devicePixelRatio-vs-screen consistency rule from the same G15 batch was **deliberately not built**: zoom legitimately changes DPR and inner-window sizes while `screen.*` stays zoom-invariant in Chrome, so a zoomed-out real window would false-fire it. CSS system colors were also dropped from this batch (see `image_broken`'s G10 note — same dated-tell problem).

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV4Signals`, `TestMatchMediaMissing`; `tests/handler_test.go`: `TestCheckV4SignalsThroughHandler`, `TestCheckStaleV3PayloadSkipsV4Rules`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["matchmedia_missing"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
