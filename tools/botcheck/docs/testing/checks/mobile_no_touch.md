# `mobile_no_touch` — Mobile User-Agent reports zero touch points

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 20 · **Reads client signal:** yes

## What it checks

A mobile (Android/iOS) User-Agent with no touch support, though every real phone browser reports touch points — a desktop spoofing a mobile UA usually forgets the touch surface. Desktop-mode edge cases are why it isn't a hard tell.

## Origin & history

**G12**, shipped 2026-07-18: an Android/iOS UA reporting zero `maxTouchPoints`, which no real phone browser does. The reverse direction (desktop UA plus touch support) was deliberately never built as a rule — touch-screen Windows laptops would false-fire it constantly.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3GateSkipsStalePayload`, `TestMobileNoTouch`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["mobile_no_touch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
