# `context_ua_mismatch` — Worker/iframe/Service-Worker User-Agent ≠ main-thread User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 35 · **Reads client signal:** yes

## What it checks

Anti-detect tools overwhelmingly patch only top frame's navigator, so User-Agent re-read inside Web Worker, iframe, or Service Worker leaks real one. Compares only when both contexts answer — unsupported API or probe timeout never treated as evidence.

## Origin & history

**G03**, shipped 2026-07-17: original cross-context idea, recomputing `navigator.userAgent` inside Web Worker & iframe, diffing against main thread — anti-detect tools overwhelmingly patch only top frame. Extended 2026-07-18 w/ Service Worker side of same check (served via `/botcheck-sw.js`). Single check that caught `puppeteer-extra-plugin-stealth` in 2026-07-19 audit — see test status above.

## Test status: Verified — fires correctly

**The check that caught `puppeteer-extra-plugin-stealth`.** Stealth patches User-Agent cleanly in main thread & iframe (`Chrome/150.0.0.0`, no "Headless" token) but patch never reaches Service Worker realm, which kept leaking real `HeadlessChrome/150.0.0.0` string. Fired `-35`, one of three cross-context checks that caught stealth after all six purpose-built stealth detectors missed it.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextAbsentDataNeverFires`, `TestBrightDataStyleWorkerSpoof`; `tests/handler_test.go`: `TestCheckCrossContextSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_ua_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
