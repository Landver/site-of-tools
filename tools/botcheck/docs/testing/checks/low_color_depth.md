# `low_color_depth` — Unusually low screen colour depth

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The screen reports a colour depth below 16 bits. No real modern display looks like that; minimal headless or VM environments sometimes do.

## Origin & history

Internal-backlog Layer 1 item, shipped: `screen.colorDepth` below 16 bits — no real modern display reports that.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["low_color_depth"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
