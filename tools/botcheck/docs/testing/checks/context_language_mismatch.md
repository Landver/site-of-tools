# `context_language_mismatch` — Worker/iframe/Service-Worker language ≠ main-thread language

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 20 · **Reads client signal:** yes

## What it checks

The cross-context idea applied to navigator.languages: a worker, iframe, or Service Worker reporting a different primary language than the top frame means one context was patched. Privacy browsers that clamp the language list do it in every context, so they stay consistent and silent.

## Origin & history

**G03**, shipped 2026-07-18 as part of a four-rule batch (with `context_cores_mismatch`, `context_platform_mismatch`, `context_webgl_mismatch`) that broadened the original UA-only cross-context idea to also diff `navigator.languages` across Worker, Service Worker, and iframe. Deliberately silent when either side is empty/unreadable — privacy browsers that clamp the language list do it in every context, so they stay consistent and don't false-fire.

## Test status: Not yet tested against real automation

Same cross-context family as `context_ua_mismatch`/`context_cores_mismatch`/`context_webgl_mismatch`, which did catch stealth in the audit, but this specific field wasn't called out as firing (or not) against any of the five tested frameworks.

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextSignalsDoNotFalsePositive`, `TestCrossContextAbsentDataNeverFires`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_language_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
