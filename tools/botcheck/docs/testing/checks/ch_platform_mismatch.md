# `ch_platform_mismatch` — Sec-CH-UA-Platform ≠ navigator.userAgentData.platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

Sec-CH-UA-Platform request header & navigator.userAgentData.platform come from same source in real Chromium browser, so a spoof editing one & forgetting other disagrees here. Non-Chromium browsers send neither & skip the check.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Curl `POST /check`: `Sec-CH-UA-Platform: Windows` header vs client JSON body claiming `macOS` → fired. Same harness quirk as `ch_brands_mismatch` — see [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ch_platform_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
