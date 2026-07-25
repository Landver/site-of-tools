# `jsengine_ua_mismatch` — Feature-detected JS engine ≠ engine the User-Agent claims

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** yes

## What it checks

JS engine behaviour (error formats & other V8/SpiderMonkey/JavaScriptCore quirks) disagrees w/ engine family the User-Agent claims — UA lies about browser, JS VM underneath can't.

## Origin & history

**G23**, shipped 2026-07-18 (error-stack half only; Math-result & window/HTMLElement key-set fingerprinting stay deferred, need per-engine reference tables): fingerprints JS engine from `Error` stack format (V8 ` at ` frames, SpiderMonkey proprietary `fileName`/`lineNumber` plus `fn@url` frames, JSC otherwise), compared vs engine UA claims via same `engineFromUA` mapping `engine_ua_mismatch` & `productsub_mismatch` use.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): UA claimed Firefox, real JS engine stayed V8 → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestJSEngineUAMismatch`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["jsengine_ua_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
