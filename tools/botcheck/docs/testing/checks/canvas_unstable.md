# `canvas_unstable` — Canvas output is randomised between draws

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 15 · **Reads client signal:** yes

## What it checks

Two identical canvas draws produced different hashes — the image output is being randomised between reads, exactly what noise-injecting anti-fingerprint tools and stealth plugins do. Some privacy browsers do this openly, so it is a consistency signal, not a bot proof.

## Origin & history

Internal-backlog Layer 2 item, shipped: two identical canvas draws hashing differently means the image output is being randomised between reads — what noise-injecting anti-fingerprint tools and stealth plugins do on purpose.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/fire-branch-probe.mjs`): patched `HTMLCanvasElement.prototype.toDataURL` to return a different value each call. Fired through the real collector; genuine automation (Selenium, raw-cdp, stealth) reports stable draws and stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["canvas_unstable"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
