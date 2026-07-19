# `language_primary_mismatch` — navigator.language ≠ navigator.languages[0]

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 15 · **Reads client signal:** yes

## What it checks

navigator.language must equal navigator.languages[0] — the same preference exposed twice. Spoofers that patch the single field but not the array disagree here.

## Origin & history

Internal-backlog Layer 1 item, shipped: `navigator.language` must equal `navigator.languages[0]` — the same preference exposed twice; spoofers that patch the single field but not the array disagree here.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestAppVersionAndLanguageMismatchFlag`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["language_primary_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
