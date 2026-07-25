# `ch_brands_mismatch` — Sec-CH-UA header brands ≠ userAgentData.brands

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

Brand list in Sec-CH-UA header disagrees w/ navigator.userAgentData.brands — two views of same value a UA spoofer must keep in sync. GREASE decoy brand ignored; stripped or absent client hints skip the check.

## Origin & history

Internal-backlog Layer 2 item, shipped: parses `Sec-CH-UA` header's brand list, compares to JS `navigator.userAgentData.brands` (GREASE decoy brand ignored both sides).

## Test status: Verified — fires correctly

Curl `POST /check`: real `Sec-CH-UA` header vs client JSON body claiming different brand → fired. (Browser-probe route hit harness quirk instead — see [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).)

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ch_brands_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
