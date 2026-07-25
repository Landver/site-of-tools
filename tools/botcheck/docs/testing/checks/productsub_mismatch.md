# `productsub_mismatch` — navigator.productSub not the engine's constant

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

navigator.productSub = fixed per-engine constant — '20030107' every WebKit/Blink, '20100101' Gecko. Value not matching engine UA claims -> spoof or patched-runtime tell; empty value = no signal.

## Origin & history

**G02** (client-signals.md), shipped 2026-07-17, also tracked as internal-backlog Layer 1 item: `navigator.productSub` fixed per-engine constant (`20030107` WebKit/Blink, `20100101` Gecko); expected value derived via same `engineFromUA` helper `engine_ua_mismatch` uses, so iOS browsers (WebKit under `FxiOS`/`CriOS` token) correctly treated as WebKit, no false-fire. `oscpu`/`buildID`/`pdfViewerEnabled` (rest of G02) tried & dropped — `pdfViewerEnabled` fires on ordinary desktop Chrome w/ "Download PDFs" setting or `AlwaysOpenPdfExternally` enterprise policy (user pref, not headless tell), & correlates w/ `empty_plugins`, eroding soft-cluster margin for low-value catch.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`), two ways: direct `productSub` override, & incidentally via `engine_ua_mismatch`'s Firefox-UA scenario. Both fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["productsub_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
