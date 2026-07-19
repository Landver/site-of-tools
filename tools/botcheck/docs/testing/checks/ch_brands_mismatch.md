# `ch_brands_mismatch` — Sec-CH-UA header brands ≠ userAgentData.brands

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

The brand list in the Sec-CH-UA header disagrees with navigator.userAgentData.brands — two views of the same value that a UA spoofer must keep in sync. The GREASE decoy brand is ignored, and stripped or absent client hints simply skip the check.

## Origin & history

Internal-backlog Layer 2 item, shipped: parses the `Sec-CH-UA` header's brand list and compares it to JS `navigator.userAgentData.brands` (the GREASE decoy brand ignored on both sides).

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ch_brands_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
