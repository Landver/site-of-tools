# `impossible_window` — Outer window smaller than inner (impossible)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.outerWidth smaller than innerWidth — geometrically impossible for a real window, classic math slip in a spoofed environment. Fires only when both values present.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Fired on stock headless Puppeteer w/ no window-size flag set — genuine automation artifact, no override needed. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["impossible_window"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
