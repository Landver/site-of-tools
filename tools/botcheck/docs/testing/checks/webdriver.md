# `webdriver` — navigator.webdriver is true

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver = W3C-standard flag browser sets when driven by automation (Selenium, Puppeteer, Playwright). Human's browser never sets it, but well-patched bot can delete property -> clean value proves nothing.

## Origin & history

Original rule, predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — mixed result

Fires reliably vs genuine, unpatched automation: Playwright headless & Selenium/chromedriver both scored `-60` in 2026-07-19 five-framework audit. Evaded by `puppeteer-extra-plugin-stealth` 2.11.2, which deletes flag consistently across main thread, iframe, & Service Worker — caught instead by cross-context checks (`context_ua_mismatch`, `context_cores_mismatch`, `context_webgl_mismatch`).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`, `TestServerOnlySkipsClientChecks`; `tests/handler_test.go`: `TestCheckJSONFlagsWebdriver`, `TestIndexCurlGetsServerOnlyScore`, `TestCheckDatacenterPlusHeadlessIsBot`, `TestServiceWorkerScriptServed`; `tests/report_test.go`: `TestSubgroup`, `TestExplanation`, `TestResultTemplateShowsNewSections`, `TestCheckFragmentShowsReportingSections`, `TestResultTemplateWithoutPayloadHidesNewSections`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webdriver"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
