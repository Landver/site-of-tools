# `webdriver_sw` — navigator.webdriver is true in the Service Worker

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

navigator.webdriver re-read inside the Service Worker. In practice this rarely fires even against confirmed automation (Puppeteer, Playwright, Selenium/chromedriver all tested clean here on 2026-07-19 despite reading true elsewhere in the same session) — Chromium's Service Worker scope appears not to inherit the automation flag at all, patched or not. Left in as a hard tell on the rare chance it does fire, but don't read a clean value as reassurance.

## Origin & history

**G14**, shipped 2026-07-18: `/botcheck-sw.js` re-reports `navigator.webdriver` from the Service Worker context, the same idea as `iframe_webdriver` applied to a third JavaScript realm — bot.incolumitas's `inconsistentServiceWorkerNavigatorPropery` is the direct reference. Shipped as a hard tell (paired with `cdp_sw_only` in the same context). Confirmed 2026-07-19 to never read true for genuine automation regardless — see the test status above, which also corrected the original 2026-07-18 explanation text (it had implied a clean reading here was reassuring).

## Test status: Confirmed structural blind spot

**Structural blind spot, confirmed across three frameworks.** Playwright, Selenium/chromedriver, and Puppeteer all show the same pattern for the *same* automated session: main thread and iframe correctly read `webdriver: true`, but the Service Worker reads `false`. Chromium's `ServiceWorkerGlobalScope` appears not to carry the automation flag into that context at all, patched or not — not a fluke, not a gap in stealth's patching. Left running at hard tier (a genuine positive there would still be strong evidence), but a clean reading in the Service Worker context proves nothing; only `report.go`'s explanation text was corrected (previously implied a miss here was reassuring).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["webdriver_sw"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
