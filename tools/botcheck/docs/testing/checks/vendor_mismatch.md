# `vendor_mismatch` — Chromium User-Agent but navigator.vendor ≠ \"Google Inc.\"

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

A Chromium-family User-Agent whose navigator.vendor isn't 'Google Inc.' — real Chrome, Edge, and Opera all report it. Only fires when a vendor string is present and wrong; forks that drop the field entirely yield no signal.

## Origin & history

Internal-backlog Layer 1 item, shipped: a Chromium-family UA whose `navigator.vendor` isn't `"Google Inc."` — real Chrome, Edge, and Opera all report it; forks that drop the field entirely yield no signal rather than a false mismatch.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/ua-mismatch-probe.mjs`): overrode `navigator.vendor` to `"Evil Corp"` on a Chrome-claiming UA. Fired `vendor=Evil Corp` through the real collector — a dedicated positive to go with the prior incidental sandbox trip noted below. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestVendorMismatchFlags`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["vendor_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
