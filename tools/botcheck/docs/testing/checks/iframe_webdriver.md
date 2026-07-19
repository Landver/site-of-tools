# `iframe_webdriver` — navigator.webdriver is true inside the iframe

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver re-read inside a fresh same-origin iframe — automation often deletes the flag from the top frame but forgets new browsing contexts, so a clean top frame with webdriver still true in the iframe is the tell.

## Origin & history

**G11**, shipped 2026-07-18, alongside `iframe_proxy`: a fresh same-origin iframe has its own `Navigator.prototype`, so re-reading `navigator.webdriver` there catches automation that only patched the top frame. Shipped as a hard tell — deviceandbrowserinfo.com's `hasWebdriverInFrameTrue` is the direct reference. Later found evaded by stealth (hidden in the iframe too, not just the top frame) — see the test status above.

## Test status: Verified — mixed result

Fires alongside `webdriver` against genuine Playwright/Selenium automation (`-60`, same audit row). Evaded by `puppeteer-extra-plugin-stealth`, which hides `navigator.webdriver` in the iframe realm too, not just the main thread — a more thorough hide than a naive delete-only patch.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["iframe_webdriver"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
