# `webdriver` — navigator.webdriver is true

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver is the W3C-standard flag a browser sets when it is driven by automation (Selenium, Puppeteer, Playwright). A human's browser never sets it — but a well-patched bot can delete the property, so a clean value proves nothing.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — mixed result

Fires reliably against genuine, unpatched automation: Playwright headless and Selenium/chromedriver both scored `-60` on it in the 2026-07-19 five-framework audit. Evaded by `puppeteer-extra-plugin-stealth` 2.11.2, which deletes the flag consistently across main thread, iframe, and Service Worker — caught instead by the cross-context checks (`context_ua_mismatch`, `context_cores_mismatch`, `context_webgl_mismatch`).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`, `TestServerOnlySkipsClientChecks`; `tests/handler_test.go`: `TestCheckJSONFlagsWebdriver`, `TestIndexCurlGetsServerOnlyScore`, `TestCheckDatacenterPlusHeadlessIsBot`, `TestServiceWorkerScriptServed`; `tests/report_test.go`: `TestTierScore`, `TestSubgroup`, `TestExplanation`, `TestResultTemplateShowsNewSections`, `TestCheckFragmentShowsReportingSections`, `TestResultTemplateWithoutPayloadHidesNewSections`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webdriver"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
