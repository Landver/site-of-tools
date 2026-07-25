# `ua_os_mismatch` — OS in User-Agent ≠ userAgentData.platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

OS named in User-Agent string disagrees w/ userAgentData.platform — classic sign of hand-edited UA. Either side unreadable (unusual UA, non-Chromium browser) counts as 'can't tell', not mismatch.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Curl `POST /check`: client JSON claiming Windows UA vs `uaData.platform: macOS` -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestPlatformSpoofScoresSuspicious`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_os_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
