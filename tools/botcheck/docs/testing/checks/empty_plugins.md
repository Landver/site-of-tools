# `empty_plugins` — No browser plugins

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.plugins empty — typical of headless builds, but also of modern desktop browsers that report empty list anyway. That ambiguity is why this only counts as part of a cluster.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `navigator.plugins` to `[]` -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestTwoSoftSignalsStayHuman`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["empty_plugins"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
