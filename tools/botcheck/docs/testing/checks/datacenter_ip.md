# `datacenter_ip` — Egress IP is a datacenter / Tor address

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 30 · **Reads client signal:** no (server-only)

## What it checks

The egress IP belongs to a datacenter/hosting range or is a Tor exit — where automation lives, not where humans usually browse from. Verified good crawlers are expected to trip this, and a human on a cloud-routed work VPN can too.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Investigated — local dataset can't confirm

Tried ~30 known datacenter/hosting/VPN/Tor egress IPs (curl + spoofed `CF-Connecting-IP`) against the local IP2Proxy LITE PX12 snapshot — none flagged as proxy, including `8.8.8.8`/`1.1.1.1` (cited elsewhere as `DCH`-flagged in the paid, non-LITE database). Read as a LITE-tier coverage gap in this snapshot, not a rule bug: the eval itself is a straight passthrough of `IsDatacenter`, already exercised by Go fixtures. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`; `tests/handler_test.go`: `TestIndexCurlGetsServerOnlyScore`; `tests/report_test.go`: `TestSubgroup`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["datacenter_ip"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
