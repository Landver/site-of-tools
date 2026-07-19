# `context_cores_mismatch` — Worker/iframe/Service-Worker hardwareConcurrency ≠ main thread

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 20 · **Reads client signal:** yes

## What it checks

hardwareConcurrency re-read in a secondary context disagrees with the main thread. Real anti-fingerprint throttling (Firefox resistFingerprinting, Brave's farbling) caps the value globally, so only a spoof that patched one context and forgot the others fires this.

## Origin & history

**G03**, shipped 2026-07-18, same four-rule batch as `context_language_mismatch`: diffs `hardwareConcurrency` across contexts. Real anti-fingerprint throttling (Firefox `resistFingerprinting`, Brave's farbling) caps the value globally, so only a spoof that patched one context and forgot the others fires this — which is exactly what caught `puppeteer-extra-plugin-stealth` in the 2026-07-19 audit (see test status above).

## Test status: Verified — fires correctly

Caught `puppeteer-extra-plugin-stealth`: main thread `hardwareConcurrency` was spoofed to `4`, but the Worker and Service Worker both leaked the real value (`10`). Fired `-20`, one of three cross-context checks that caught stealth after its six purpose-built detectors missed.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextAbsentDataNeverFires`, `TestBrightDataStyleWorkerSpoof`; `tests/handler_test.go`: `TestCheckCrossContextSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_cores_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
