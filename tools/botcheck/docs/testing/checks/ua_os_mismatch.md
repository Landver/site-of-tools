# `ua_os_mismatch` — OS in User-Agent ≠ userAgentData.platform

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

The OS named in the User-Agent string disagrees with userAgentData.platform — the classic sign of a hand-edited UA. Either side being unreadable (an unusual UA, a non-Chromium browser) counts as 'can't tell', not as a mismatch.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Curl `POST /check`: client JSON body with `navMainUA` claiming Windows against `uaData.platform: "macOS"`. Fired `UA Windows vs platform macOS`. (Both sides are client-JSON fields; closed via direct payload rather than the browser probe for the same reason as `ua_chrome_version_mismatch` — see [finding](../findings/2026-07-19-remaining-43-checks-sweep.md) for the harness caveat.)

## Go scorer coverage

`tests/botcheck_test.go`: `TestPlatformSpoofScoresSuspicious`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_os_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
