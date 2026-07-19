# `default_geometry` — Default 800×600 screen

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The screen is exactly 800×600, the default of headless images and fresh VMs. Real displays that size are rare but exist (old machines, embedded panels), so it's a soft hint only.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

No construction needed: fired on stock, unmodified Selenium/chromedriver, plain headless Puppeteer, and raw-CDP runs alike — headless Chromium's real screen default is 800×600 unless a window-size/screen-emulation flag overrides it. Strongest evidence tier here: genuine off-the-shelf automation, not a synthetic probe. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestTwoSoftSignalsStayHuman`; `tests/report_test.go`: `TestTierScore`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["default_geometry"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
