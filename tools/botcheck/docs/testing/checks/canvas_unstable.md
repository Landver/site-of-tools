# `canvas_unstable` — Canvas output is randomised between draws

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 15 · **Reads client signal:** yes

## What it checks

Two identical canvas draws produced different hashes — image output randomised between reads, exactly what noise-injecting anti-fingerprint tools & stealth plugins do. Some privacy browsers do this openly, so consistency signal, not bot proof.

## Origin & history

Internal-backlog Layer 2 item, shipped: two identical canvas draws hashing differently = image output randomised between reads — what noise-injecting anti-fingerprint tools & stealth plugins do on purpose.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): patched `toDataURL` to vary each call -> fired. Genuine automation reports stable draws, stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["canvas_unstable"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
