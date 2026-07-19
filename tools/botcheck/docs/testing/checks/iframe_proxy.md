# `iframe_proxy` — iframe contentWindow is proxied (stealth iframe patch)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 30 · **Reads client signal:** yes

## What it checks

The JavaScript Proxy constructor re-checked inside an iframe's separate realm: runtimes that instrument only the main window disagree with themselves there.

## Origin & history

**G11**, shipped 2026-07-18, alongside `iframe_webdriver`: builds a fresh `srcdoc` iframe and checks whether its `contentWindow` is itself a Proxy — CreepJS's `hasIframeProxy` is the direct mechanical reference. Stealth's own contentWindow-proxy patch verifiably throws when this fresh frame's window is read, which is what the probe catches.

## Test status: Not yet tested against real automation

Not one of the six checks the 2026-07-19 stealth deep-dive specifically targeted, so no real-automation data point either way yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["iframe_proxy"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
