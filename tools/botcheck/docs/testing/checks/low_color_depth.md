# `low_color_depth` — Unusually low screen colour depth

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Screen reports colour depth below 16 bits. No real modern display looks like that; minimal headless or VM environments sometimes do.

## Origin & history

Internal-backlog Layer 1 item, shipped: `screen.colorDepth` below 16 bits — no real modern display reports that.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `screen.colorDepth` to `8` → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["low_color_depth"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
