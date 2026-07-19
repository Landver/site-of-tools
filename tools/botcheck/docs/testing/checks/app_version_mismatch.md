# `app_version_mismatch` — navigator.appVersion inconsistent with User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 15 · **Reads client signal:** yes

## What it checks

navigator.appVersion is always the User-Agent minus its 'Mozilla/' prefix on every mainstream browser. A hand-built spoof that sets the two values independently usually forgets this coupling.

## Origin & history

Internal-backlog Layer 1 item, shipped: `navigator.appVersion` is always the UA string minus its `Mozilla/` prefix on every mainstream browser; a hand-built spoof that sets the two independently usually forgets the coupling.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): overrode `navigator.appVersion` alone → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestAppVersionAndLanguageMismatchFlag`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["app_version_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
