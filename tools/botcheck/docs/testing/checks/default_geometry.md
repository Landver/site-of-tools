# `default_geometry` — Default 800×600 screen

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The screen is exactly 800×600, the default of headless images and fresh VMs. Real displays that size are rare but exist (old machines, embedded panels), so it's a soft hint only.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Fired on stock, unmodified Selenium/Puppeteer/raw-CDP — headless Chromium's real screen default, no override needed. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestTwoSoftSignalsStayHuman`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["default_geometry"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
