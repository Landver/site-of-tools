# `cdp_both` — CDP automation detected in main thread and Worker

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

CDP (Chrome DevTools Protocol) client detected reading Error's stack getter in both main thread & Web Worker while being logged — classic 'CDP builds object preview, which touches getters' tell. Downgraded to soft 2026-07-19: tested against five genuinely CDP-driven sessions (Puppeteer, Playwright, Selenium/chromedriver, hand-rolled Runtime.enable CDP client, puppeteer-extra-stealth), fired zero times — technique doesn't appear to work on current Chromium at all, automation or not, so clean value here proves very little either way.

## Origin & history

Original day-1 rule (`cdpTrap()` — `Error.stack` getter tripped by CDP client's object-preview generation), extended by **G14** (shipped 2026-07-18) w/ Service Worker side (`cdp_sw_only`, run from `/botcheck-sw.js`), originally at consistency tier. Confirmed dead against six genuine CDP-driven sessions 2026-07-19, re-tiered to soft — see test status above.

## Test status: Fixed

**Confirmed dead against six genuine CDP-driven sessions, re-tiered down.** `cdpTrap()` expects CDP client w/ `Runtime.enable` active to invoke `Error.stack` getter while building console object preview. Tested against Claude's own in-app CDP browser, unstealthed Puppeteer (headless & headful), Playwright, Selenium+chromedriver (real "Chrome for Testing" binary), hand-rolled raw CDP client w/ no `--enable-automation` flag, & `puppeteer-extra-stealth` — fired **zero times** in all six. Technique's premise (CDP preview generation invokes property getters) doesn't hold on current Chromium at all, automation or not. Moved from hard/consistency tier down to soft (weight 8, only bites as part of >=3 cluster like every other soft signal) rather than deleted outright — free when silent, might still catch future Chromium regression or older engine.

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeadlessChromeScoresBot`, `TestCDPSWOnlyDoesNotDoubleCount`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["cdp_both"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
