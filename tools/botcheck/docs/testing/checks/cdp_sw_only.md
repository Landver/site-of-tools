# `cdp_sw_only` — CDP automation detected in the Service Worker only

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The same CDP-preview trap as cdp_both, tripped only in the Service Worker context. Same 2026-07-19 finding applies — not shown reliable against real automation, kept only because it's free when silent.

## Origin & history

Original day-1 rule (`cdpTrap()` — `Error.stack` getter tripped by a CDP client's object-preview generation), extended by **G14** (shipped 2026-07-18) with a Service Worker side (`cdp_sw_only`, run from `/botcheck-sw.js`), originally at consistency tier. Confirmed dead against six genuine CDP-driven sessions on 2026-07-19 and re-tiered to soft — see the test status above.

## Test status: Fixed

**Confirmed dead against six genuine CDP-driven sessions, re-tiered down.** `cdpTrap()` expects a CDP client with `Runtime.enable` active to invoke an `Error.stack` getter while building a console object preview. Tested against Claude's own in-app CDP browser, unstealthed Puppeteer (headless and headful), Playwright, Selenium+chromedriver (real "Chrome for Testing" binary), a hand-rolled raw CDP client with no `--enable-automation` flag, and `puppeteer-extra-stealth` — fired **zero times** in all six. The technique's premise (CDP preview generation invokes property getters) doesn't hold on current Chromium at all, automation or not. Moved from hard/consistency tier down to soft (weight 8, only bites as part of a >=3 cluster like every other soft signal) rather than deleted outright — free when silent, might still catch a future Chromium regression or an older engine.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestCDPSWOnlyDoesNotDoubleCount`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["cdp_sw_only"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
