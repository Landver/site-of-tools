# `proxy_ip` — Egress IP is a proxy / VPN

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 20 · **Reads client signal:** no (server-only)

## What it checks

Egress IP is known VPN or public proxy. Plenty of privacy-conscious people use one, so this = transparency about connection, not accusation — only weighs in alongside other evidence, never for address datacenter/Tor check already caught.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story here; part of first working scorer.

## Test status: Investigated — local dataset can't confirm

Same investigation & conclusion as [`datacenter_ip`](datacenter_ip.md): ~30 known VPN/hosting/Tor egress IPs against local IP2Proxy LITE PX12 snapshot, none flagged. LITE-tier coverage gap, not rule bug — eval = straight passthrough of `IsVPN`/`IsProxy`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["proxy_ip"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
