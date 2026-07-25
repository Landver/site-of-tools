# `webdriver_sw` — navigator.webdriver is true in the Service Worker

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver re-read inside Service Worker. In practice rarely fires even vs confirmed automation (Puppeteer, Playwright, Selenium/chromedriver all tested clean here 2026-07-19 despite reading true elsewhere in same session) — Chromium's Service Worker scope appears not to inherit automation flag at all, patched or not. Left in as hard tell on rare chance it does fire, but don't read clean value as reassurance.

## Origin & history

**G14**, shipped 2026-07-18: `/botcheck-sw.js` re-reports `navigator.webdriver` from Service Worker context, same idea as `iframe_webdriver` applied to third JavaScript realm — bot.incolumitas's `inconsistentServiceWorkerNavigatorPropery` is direct reference. Shipped as hard tell (paired w/ `cdp_sw_only` in same context). Confirmed 2026-07-19 to never read true for genuine automation regardless — see test status above, which also corrected original 2026-07-18 explanation text (had implied clean reading here was reassuring).

## Test status: Confirmed structural blind spot

**Structural blind spot, confirmed across three frameworks.** Playwright, Selenium/chromedriver, & Puppeteer all show same pattern for *same* automated session: main thread & iframe correctly read `webdriver: true`, but Service Worker reads `false`. Chromium's `ServiceWorkerGlobalScope` appears not to carry automation flag into that context at all, patched or not — not fluke, not gap in stealth's patching. Left running at hard tier (genuine positive there would still be strong evidence), but clean reading in Service Worker context proves nothing; only `report.go`'s explanation text was corrected (previously implied miss here was reassuring).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webdriver_sw"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
