# `iframe_webdriver` — navigator.webdriver is true inside the iframe

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver re-read inside fresh same-origin iframe — automation often deletes flag from top frame but forgets new browsing contexts, so clean top frame w/ webdriver still true in iframe = tell.

## Origin & history

**G11**, shipped 2026-07-18, alongside `iframe_proxy`: fresh same-origin iframe has own `Navigator.prototype`, so re-reading `navigator.webdriver` there catches automation that only patched top frame. Shipped as hard tell — deviceandbrowserinfo.com's `hasWebdriverInFrameTrue` = direct reference. Later found evaded by stealth (hidden in iframe too, not just top frame) — see test status above.

## Test status: Verified — mixed result

Fires alongside `webdriver` against genuine Playwright/Selenium automation (`-60`, same audit row). Evaded by `puppeteer-extra-plugin-stealth`, which hides `navigator.webdriver` in iframe realm too, not just main thread — more thorough hide than naive delete-only patch.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["iframe_webdriver"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
