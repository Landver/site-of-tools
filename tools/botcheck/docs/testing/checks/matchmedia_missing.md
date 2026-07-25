# `matchmedia_missing` — Browser User-Agent but window.matchMedia is missing

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.matchMedia part of every real browser's CSS support, desktop & mobile alike -> browser-claimed UA w/o it = stripped JS env (jsdom-style) wearing browser UA. Exotic embedded webview could lack it too -> only counts inside soft cluster.

## Origin & history

**G15**, shipped 2026-07-18 (wave-2 probes batch, collector payload bumped to `v: 4` w/ additive `env` section): browser-claimed UA missing `window.matchMedia` entirely = stripped JS env (jsdom-style) wearing browser UA. devicePixelRatio-vs-screen consistency rule from same G15 batch **deliberately not built**: zoom legitimately changes DPR & inner-window sizes while `screen.*` stays zoom-invariant in Chrome -> zoomed-out real window would false-fire it. CSS system colors also dropped from this batch (see `image_broken`'s G10 note — same dated-tell problem).

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): deleted `window.matchMedia` → fired. Side effect: uncovered real bug in `shared/templates/partials/head.html`'s unguarded theme-detector, fixed same session. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV4Signals`, `TestMatchMediaMissing`; `tests/handler_test.go`: `TestCheckV4SignalsThroughHandler`, `TestCheckStaleV3PayloadSkipsV4Rules`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["matchmedia_missing"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
