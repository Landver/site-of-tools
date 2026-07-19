# `ua_header_mismatch` — JS User-Agent ≠ HTTP User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 35 · **Reads client signal:** yes

## What it checks

navigator.userAgent and the HTTP User-Agent header are the same string in a real browser — page JavaScript cannot change the header. A difference means one side was rewritten by an anti-detect tool or a proxy; rare privacy setups that rewrite headers can also trip this.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`automation-harness/ua-mismatch-probe.mjs`): kept the real HTTP `User-Agent` header, overrode `navigator.userAgent` afterward via `evaluateOnNewDocument` so only the JS side diverges. Fired `navigator vs header differ` through the real collector. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`; `tests/report_test.go`: `TestSubgroup`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_header_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
