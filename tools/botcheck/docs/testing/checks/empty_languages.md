# `empty_languages` — navigator.languages is empty

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.languages is empty array. Real browsers always carry >=1 language, though some hardened setups empty it on purpose — weak alone, only counts w/ other signals.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `navigator.languages` to `[]` -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["empty_languages"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
