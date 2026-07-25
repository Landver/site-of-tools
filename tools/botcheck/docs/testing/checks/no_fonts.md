# `no_fonts` — No system fonts detectable

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

No probe fonts detectable at all — neutralised font-enumeration surface or font-less headless/VM environment. Aggressive anti-fingerprint settings suppress fonts too, so soft cluster signal.

## Origin & history

Internal-backlog Layer 2 item, shipped: zero probe fonts detectable via `measureText` width technique — neutralised font-enumeration surface or genuinely font-less headless/VM environment. Aggressive anti-fingerprint settings suppress fonts too, kept soft for that reason.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): patched `measureText` so every probe font matches baseline → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["no_fonts"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
