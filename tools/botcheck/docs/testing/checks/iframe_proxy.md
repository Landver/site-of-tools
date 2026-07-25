# `iframe_proxy` — iframe contentWindow is proxied (stealth iframe patch)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 30 · **Reads client signal:** yes

## What it checks

JS Proxy constructor re-checked inside iframe's separate realm: runtimes that instrument only main window disagree w/ themselves there.

## Origin & history

**G11**, shipped 2026-07-18, alongside `iframe_webdriver`: builds fresh `srcdoc` iframe, checks whether its `contentWindow` is itself a Proxy — CreepJS's `hasIframeProxy` = direct mechanical reference. Stealth's own contentWindow-proxy patch verifiably throws when this fresh frame's window is read, which probe catches.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): patched `iframe.contentWindow` to throw (mimicking stealth's own patch) → fired. Genuine automation, stealth included, leaves it alone, stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["iframe_proxy"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
