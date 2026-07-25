# `lang_mismatch` — navigator.languages ≠ Accept-Language

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 15 · **Reads client signal:** yes

## What it checks

navigator.languages & Accept-Language header set from same browser preference, so spoofed locale that changed only one side disagrees here. Either side missing = 'can't tell'.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): overrode `navigator.languages`, real `Accept-Language` header untouched → fired (plus bonus `language_primary_mismatch`/`context_language_mismatch`). See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["lang_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
