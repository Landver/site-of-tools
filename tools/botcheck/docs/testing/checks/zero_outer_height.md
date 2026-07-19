# `zero_outer_height` — window.outerHeight is zero

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.outerHeight is exactly 0 — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Origin & history

Internal-backlog item, shipped 2026-07-18 (v3-gated, guarded so stale pre-v3 payloads skip rather than false-fire): `window.outerHeight` exactly `0` while `innerHeight` is positive — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Test status: Verified — fires correctly

Confirmed three ways: constructed override, stock headless Puppeteer (no window-size flag), and a real false positive on the user's genuine Chrome under Claude-in-Chrome automation — safely absorbed by the soft-cluster design. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["zero_outer_height"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
