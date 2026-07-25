# `ua_header_mismatch` — JS User-Agent ≠ HTTP User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 35 · **Reads client signal:** yes

## What it checks

navigator.userAgent & HTTP User-Agent header are same string in real browser — page JS cannot change header. Difference means one side rewritten by anti-detect tool or proxy; rare privacy setups that rewrite headers can also trip this.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): kept real HTTP header, overrode `navigator.userAgent` alone -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`; `tests/report_test.go`: `TestSubgroup`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_header_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
