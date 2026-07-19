# `lang_mismatch` — navigator.languages ≠ Accept-Language

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 15 · **Reads client signal:** yes

## What it checks

navigator.languages and the Accept-Language header are set from the same browser preference, so a spoofed locale that changed only one side disagrees here. Either side missing counts as 'can't tell'.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Not yet tested against real automation

No real-automation-harness finding and no dedicated Go test references this rule ID directly.

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["lang_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
