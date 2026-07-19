# `ch_platform_mismatch` — Sec-CH-UA-Platform ≠ navigator.userAgentData.platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

The Sec-CH-UA-Platform request header and navigator.userAgentData.platform come from the same source in a real Chromium browser, so a spoof that edits one and forgets the other disagrees here. Non-Chromium browsers send neither and simply skip the check.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Curl `POST /check`: `Sec-CH-UA-Platform: Windows` header vs a client JSON body claiming `macOS` → fired. Same harness quirk as `ch_brands_mismatch` — see [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ch_platform_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
