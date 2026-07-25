# `context_platform_mismatch` — Worker/iframe/Service-Worker platform ≠ main-thread platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 25 · **Reads client signal:** yes

## What it checks

userAgentData.platform re-read in worker, iframe, or Service Worker disagrees w/ top frame — platform spoof that didn't reach every JS context. Empty values (unsupported API, probe timeout) never treated as mismatch.

## Origin & history

**G03**, shipped 2026-07-18, same four-rule batch: diffs `userAgentData.platform` across contexts. Empty values (unsupported API, probe timeout) never treated as mismatch.

## Test status: Verified — fires correctly

Fired as bonus of `ch_platform_mismatch` probe scenario — Worker's separate realm still reported real platform. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextSignalsDoNotFalsePositive`, `TestCrossContextAbsentDataNeverFires`, `TestBrightDataStyleWorkerSpoof`; `tests/handler_test.go`: `TestCheckCrossContextSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_platform_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
