# `empty_languages` — navigator.languages is empty

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.languages is an empty array. Real browsers always carry at least one language, though some hardened setups empty it on purpose — weak alone, it only counts with other signals.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/fire-branch-probe.mjs`): overrode `navigator.languages` to `[]`. Fired through the real collector; genuine automation frameworks that report a real language list stay `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["empty_languages"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
