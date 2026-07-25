# `context_language_mismatch` — Worker/iframe/Service-Worker language ≠ main-thread language

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** context · **Weight:** 20 · **Reads client signal:** yes

## What it checks

Cross-context idea applied to navigator.languages: worker, iframe, or Service Worker reporting different primary language than top frame -> one context patched. Privacy browsers clamp language list in every context, so stay consistent & silent.

## Origin & history

**G03**, shipped 2026-07-18 in four-rule batch (w/ `context_cores_mismatch`, `context_platform_mismatch`, `context_webgl_mismatch`) broadening original UA-only cross-context idea to also diff `navigator.languages` across Worker, Service Worker, iframe. Silent when either side empty/unreadable — privacy browsers clamp language list in every context, so stay consistent, don't false-fire.

## Test status: Verified — fires correctly

Fired as bonus of `lang_mismatch` probe scenario — main-thread-only override left Worker's real language in place. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestCrossContextSignals`, `TestCrossContextSignalsDoNotFalsePositive`, `TestCrossContextAbsentDataNeverFires`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["context_language_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
