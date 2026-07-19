# `datacenter_ip` — Egress IP is a datacenter / Tor address

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 30 · **Reads client signal:** no (server-only)

## What it checks

The egress IP belongs to a datacenter/hosting range or is a Tor exit — where automation lives, not where humans usually browse from. Verified good crawlers are expected to trip this, and a human on a cloud-routed work VPN can too.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Not yet tested against real automation

No framework in the 2026-07-19 audit ran from a datacenter/Tor egress, so this rule had nothing to react to either way; untested by the harness so far.

## Go scorer coverage

`tests/botcheck_test.go`: `TestStealthSpoofScoresBot`; `tests/handler_test.go`: `TestIndexCurlGetsServerOnlyScore`; `tests/report_test.go`: `TestSubgroup`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["datacenter_ip"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
