# `productsub_mismatch` — navigator.productSub not the engine's constant

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

navigator.productSub is a fixed per-engine constant — '20030107' on every WebKit/Blink browser, '20100101' on Gecko. A value that doesn't match the engine the UA claims is a spoof or patched-runtime tell; an empty value is treated as no signal.

## Origin & history

**G02** (client-signals.md), shipped 2026-07-17, also tracked as an internal-backlog Layer 1 item: `navigator.productSub` is a fixed per-engine constant (`20030107` WebKit/Blink, `20100101` Gecko); the expected value is derived via the same `engineFromUA` helper `engine_ua_mismatch` uses, so iOS browsers (WebKit under an `FxiOS`/`CriOS` token) are correctly treated as WebKit rather than false-firing. `oscpu`/`buildID`/`pdfViewerEnabled` (the rest of G02) were tried and dropped — `pdfViewerEnabled` fires on ordinary desktop Chrome with the "Download PDFs" setting or the `AlwaysOpenPdfExternally` enterprise policy, a user preference rather than a headless tell, and correlates with `empty_plugins`, eroding the soft-cluster margin for a low-value catch.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/ua-mismatch-probe.mjs`), two ways: a dedicated override of `navigator.productSub` to `"99999999"` fired `productSub 99999999, expected 20030107`; separately, the `engine_ua_mismatch` scenario's UA-claims-Firefox override made the real (unmodified) `"20030107"` productSub disagree with the now Firefox-implied `"20100101"`, firing this rule too. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["productsub_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
