# `context_ua_mismatch` — Worker/iframe/Service-Worker User-Agent ≠ main-thread User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 35 · **Reads client signal:** yes

## What it checks

Anti-detect tools overwhelmingly patch only the top frame's navigator, so the User-Agent re-read inside a Web Worker, iframe, or Service Worker leaks the real one. It only compares when both contexts answer — an unsupported API or probe timeout is never treated as evidence.

## Origin & history

**G03**, shipped 2026-07-17: the original cross-context idea, recomputing `navigator.userAgent` inside a Web Worker and iframe and diffing against the main thread — anti-detect tools overwhelmingly patch only the top frame. Extended 2026-07-18 with a Service Worker side of the same check (served via `/botcheck-sw.js`). Turned out to be the single check that caught `puppeteer-extra-plugin-stealth` in the 2026-07-19 audit — see the test status above.

## Test status: Verified — fires correctly

**The check that actually caught `puppeteer-extra-plugin-stealth`.** Stealth patches the User-Agent cleanly in the main thread and iframe (`Chrome/150.0.0.0`, no "Headless" token) but its patch never reaches the Service Worker realm, which kept leaking the real `HeadlessChrome/150.0.0.0` string. Fired `-35` and was one of three cross-context checks that caught stealth after all six purpose-built stealth detectors missed it.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextAbsentDataNeverFires`, `TestBrightDataStyleWorkerSpoof`; `tests/handler_test.go`: `TestCheckCrossContextSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_ua_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
