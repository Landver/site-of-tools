# `implausible_hardware` — Implausible hardwareConcurrency / deviceMemory

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

hardwareConcurrency or deviceMemory outside any plausible range (negative, or above 128). Such values come from careless spoofing, not real hardware.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `hardwareConcurrency` to `999` → fired (plus bonus `context_cores_mismatch`, override only reaching main thread). See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["implausible_hardware"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
