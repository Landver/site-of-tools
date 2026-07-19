# `cdp_both` — CDP automation detected in main thread and Worker

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

A Chrome DevTools Protocol client was detected reading an Error's stack getter in both the main thread and a Web Worker while it was being logged — the classic 'CDP builds an object preview, which touches getters' tell. Downgraded to soft on 2026-07-19: tested against five genuinely CDP-driven sessions (Puppeteer, Playwright, Selenium/chromedriver, a hand-rolled Runtime.enable CDP client, puppeteer-extra-stealth) and it fired zero times — the technique doesn't appear to work on current Chromium at all, automation or not, so a clean value here proves very little either way.

## Origin & history

Original day-1 rule (`cdpTrap()` — `Error.stack` getter tripped by a CDP client's object-preview generation), extended by **G14** (shipped 2026-07-18) with a Service Worker side (`cdp_sw_only`, run from `/botcheck-sw.js`), originally at consistency tier. Confirmed dead against six genuine CDP-driven sessions on 2026-07-19 and re-tiered to soft — see the test status above.

## Test status: Fixed

**Confirmed dead against six genuine CDP-driven sessions, re-tiered down.** `cdpTrap()` expects a CDP client with `Runtime.enable` active to invoke an `Error.stack` getter while building a console object preview. Tested against Claude's own in-app CDP browser, unstealthed Puppeteer (headless and headful), Playwright, Selenium+chromedriver (real "Chrome for Testing" binary), a hand-rolled raw CDP client with no `--enable-automation` flag, and `puppeteer-extra-stealth` — fired **zero times** in all six. The technique's premise (CDP preview generation invokes property getters) doesn't hold on current Chromium at all, automation or not. Moved from hard/consistency tier down to soft (weight 8, only bites as part of a >=3 cluster like every other soft signal) rather than deleted outright — free when silent, might still catch a future Chromium regression or an older engine.

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`, `TestCDPSWOnlyDoesNotDoubleCount`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["cdp_both"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
