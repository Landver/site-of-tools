# `proxy_ip` — Egress IP is a proxy / VPN

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 20 · **Reads client signal:** no (server-only)

## What it checks

The egress IP is a known VPN or public proxy. Plenty of privacy-conscious people use one, so this is transparency about the connection rather than an accusation — it only weighs in alongside other evidence, and never for an address the datacenter/Tor check already caught.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Not yet tested against real automation

No real-automation-harness finding and no dedicated Go test references this rule ID directly.

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["proxy_ip"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
