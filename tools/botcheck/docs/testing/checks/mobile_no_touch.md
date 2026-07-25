# `mobile_no_touch` — Mobile User-Agent reports zero touch points

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 20 · **Reads client signal:** yes

## What it checks

Mobile (Android/iOS) UA w/ no touch support, though every real phone browser reports touch points — desktop spoofing mobile UA usually forgets touch surface. Desktop-mode edge cases -> not a hard tell.

## Origin & history

**G12**, shipped 2026-07-18: Android/iOS UA reporting zero `maxTouchPoints`, which no real phone browser does. Reverse direction (desktop UA + touch support) deliberately never built as rule — touch-screen Windows laptops would false-fire it constantly.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): Android UA + real desktop `maxTouchPoints: 0` → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3GateSkipsStalePayload`, `TestMobileNoTouch`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["mobile_no_touch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
