# `plugins_mimetypes_incoherent` — Plugins present but no mimeTypes (incoherent fake)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

navigator.plugins and navigator.mimeTypes must cross-reference each other; a spoofed plugin list that isn't wired both ways is internally incoherent.

## Origin & history

Internal-backlog item, shipped 2026-07-18 (v3-gated): `navigator.plugins` and `navigator.mimeTypes` must cross-reference each other in a real browser; a spoofed plugin list that isn't wired both ways is internally incoherent.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/fire-branch-probe.mjs`): left `navigator.plugins` at its real non-zero value, overrode `navigator.mimeTypes` to `[]`. Fired through the real collector; genuine automation's real plugins/mimeTypes stay cross-referenced and `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["plugins_mimetypes_incoherent"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
