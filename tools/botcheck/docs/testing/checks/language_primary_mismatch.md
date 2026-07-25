# `language_primary_mismatch` — navigator.language ≠ navigator.languages[0]

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 15 · **Reads client signal:** yes

## What it checks

navigator.language must equal navigator.languages[0] — same preference exposed twice. Spoofers that patch single field but not array disagree here.

## Origin & history

Internal-backlog Layer 1 item, shipped: `navigator.language` must equal `navigator.languages[0]` — same preference exposed twice; spoofers that patch single field but not array disagree here.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): overrode `navigator.language` alone, `languages[0]` stayed real → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestAppVersionAndLanguageMismatchFlag`.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["language_primary_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
