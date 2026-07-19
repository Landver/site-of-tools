# `no_fonts` — No system fonts detectable

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

No probe fonts could be detected at all — a neutralised font-enumeration surface or a font-less headless/VM environment. Aggressive anti-fingerprint settings suppress fonts too, so it's a soft cluster signal.

## Origin & history

Internal-backlog Layer 2 item, shipped: zero probe fonts detectable via the `measureText` width technique — a neutralised font-enumeration surface or a genuinely font-less headless/VM environment. Aggressive anti-fingerprint settings suppress fonts too, kept soft for that reason.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): patched `measureText` so every probe font matches baseline → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`; `tests/report_test.go`: `TestTierScore`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["no_fonts"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
