# `ch_brands_mismatch` — Sec-CH-UA header brands ≠ userAgentData.brands

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 20 · **Reads client signal:** yes

## What it checks

The brand list in the Sec-CH-UA header disagrees with navigator.userAgentData.brands — two views of the same value that a UA spoofer must keep in sync. The GREASE decoy brand is ignored, and stripped or absent client hints simply skip the check.

## Origin & history

Internal-backlog Layer 2 item, shipped: parses the `Sec-CH-UA` header's brand list and compares it to JS `navigator.userAgentData.brands` (the GREASE decoy brand ignored on both sides).

## Test status: Verified — fires correctly

Curl `POST /check`: real `Sec-CH-UA` header (Chromium + Google Chrome brands) against a client JSON body claiming `brands: ["Opera"]`. Fired with `header and JS brand lists differ`. (The browser-probe route hit a harness quirk — the root `puppeteer` package's plain launch reports empty `userAgentData.brands` on this origin even unmodified, unlike raw-cdp/selenium — so this was closed via direct header+payload instead; see [finding](../findings/2026-07-19-remaining-43-checks-sweep.md) for the harness caveat.)

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ch_brands_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
