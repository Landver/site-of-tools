# `zero_outer_height` — window.outerHeight is zero

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.outerHeight is exactly 0 — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Origin & history

Internal-backlog item, shipped 2026-07-18 (v3-gated, guarded so stale pre-v3 payloads skip rather than false-fire): `window.outerHeight` exactly `0` while `innerHeight` is positive — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Test status: Not yet tested against real automation

No dedicated finding, but fired once as an incidental data point: the same confounded Claude-in-Chrome sandbox session from the `tz_mismatch`/`webrtc_ip_mismatch` investigation also tripped this rule — it stayed a no-op (below the soft cluster's 3-signal threshold) and wasn't investigated further since that session was already known to be an unrepresentative sandbox — see [`tz_mismatch`](tz_mismatch.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["zero_outer_height"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
