# `vendor_mismatch` — Chromium User-Agent but navigator.vendor ≠ \"Google Inc.\"

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

Chromium-family User-Agent whose navigator.vendor isn't 'Google Inc.' — real Chrome, Edge, Opera all report it. Fires only when vendor string present & wrong; forks that drop field entirely yield no signal.

## Origin & history

Internal-backlog Layer 1 item, shipped: Chromium-family UA whose `navigator.vendor` isn't `"Google Inc."` — real Chrome, Edge, Opera all report it; forks that drop field entirely yield no signal rather than false mismatch.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): overrode `navigator.vendor` on Chrome-claiming UA -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestVendorMismatchFlags`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["vendor_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
