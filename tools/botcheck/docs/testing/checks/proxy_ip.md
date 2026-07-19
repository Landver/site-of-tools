# `proxy_ip` — Egress IP is a proxy / VPN

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 20 · **Reads client signal:** no (server-only)

## What it checks

The egress IP is a known VPN or public proxy. Plenty of privacy-conscious people use one, so this is transparency about the connection rather than an accusation — it only weighs in alongside other evidence, and never for an address the datacenter/Tor check already caught.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Investigated — local dataset can't confirm

Same investigation and same conclusion as [`datacenter_ip`](datacenter_ip.md): ~30 known VPN/hosting/Tor egress IPs against the local IP2Proxy LITE PX12 snapshot, none flagged. LITE-tier coverage gap, not a rule bug — the eval is a straight passthrough of `IsVPN`/`IsProxy`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["proxy_ip"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
