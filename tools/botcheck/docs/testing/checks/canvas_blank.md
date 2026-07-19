# `canvas_blank` — Canvas renders blank (blocked / headless)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

A canvas draw produced a fully transparent, empty image — the canvas API is blocked or the environment renders nothing. Some privacy tools block canvas reads openly, so it's a soft signal.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["canvas_blank"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
