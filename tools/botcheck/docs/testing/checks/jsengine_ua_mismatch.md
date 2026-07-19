# `jsengine_ua_mismatch` — Feature-detected JS engine ≠ engine the User-Agent claims

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** yes

## What it checks

JavaScript engine behaviour (error formats and other V8/SpiderMonkey/JavaScriptCore quirks) disagrees with the engine family the User-Agent claims — the UA lies about the browser, but the JS VM underneath can't.

## Origin & history

**G23**, shipped 2026-07-18 (error-stack half only; Math-result and window/HTMLElement key-set fingerprinting stay deferred, needing per-engine reference tables): fingerprints the JS engine from `Error` stack format (V8's ` at ` frames, SpiderMonkey's proprietary `fileName`/`lineNumber` plus `fn@url` frames, JSC otherwise), compared against the engine the UA claims via the same `engineFromUA` mapping `engine_ua_mismatch` and `productsub_mismatch` use.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/ua-mismatch-probe.mjs`): overrode `navigator.userAgent` to claim Firefox while the real JS engine underneath stayed V8. Fired `JS engine v8 vs UA implies spidermonkey` through the real collector's error-stack-format probe. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestJSEngineUAMismatch`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["jsengine_ua_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
