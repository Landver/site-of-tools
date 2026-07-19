# `implausible_hardware` — Implausible hardwareConcurrency / deviceMemory

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

hardwareConcurrency or deviceMemory sits outside any plausible range (negative, or above 128). Values like that come from careless spoofing, not from real hardware.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["implausible_hardware"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
