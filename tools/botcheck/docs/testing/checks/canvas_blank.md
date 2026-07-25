# `canvas_blank` — Canvas renders blank (blocked / headless)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Canvas draw produced fully transparent, empty image — canvas API blocked or environment renders nothing. Some privacy tools block canvas reads openly, so soft signal.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): patched `getImageData` to return all-zero buffer -> fired. Genuine automation w/ working canvas stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["canvas_blank"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
