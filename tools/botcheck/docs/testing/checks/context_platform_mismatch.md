# `context_platform_mismatch` — Worker/iframe/Service-Worker platform ≠ main-thread platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 25 · **Reads client signal:** yes

## What it checks

userAgentData.platform re-read in a worker, iframe, or Service Worker disagrees with the top frame — a platform spoof that didn't reach every JavaScript context. Empty values (unsupported API, probe timeout) are never treated as a mismatch.

## Origin & history

**G03**, shipped 2026-07-18, same four-rule batch: diffs `userAgentData.platform` across contexts. Empty values (unsupported API, probe timeout) are never treated as a mismatch.

## Test status: Verified — fires correctly

Fired as an incidental bonus of the `ch_platform_mismatch` scenario in `automation-harness/ua-mismatch-probe.mjs`: patching `userAgentData` on the main thread doesn't reach a dedicated Worker's separate realm, so the Worker still reported the real platform — tripped `service worker platform macOS vs main Windows` through the real collector. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextSignalsDoNotFalsePositive`, `TestCrossContextAbsentDataNeverFires`, `TestBrightDataStyleWorkerSpoof`; `tests/handler_test.go`: `TestCheckCrossContextSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_platform_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
