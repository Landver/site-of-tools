# `ip_blocklisted` — Egress IP is on a threat / abuse blocklist

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** no (server-observed)

## What it checks

The egress IP appears on a shared threat/abuse blocklist — the ipsum feed, which aggregates 30+ public lists, plus any ban another service recorded. An ipsum-only listing only fires once at least three of those feeds agree (the project's own auto-ban grade); a deliberate ban from another source is trusted directly. Recycled residential addresses and shared NATs can carry a stale reputation, so it weighs in alongside other evidence, and verified good bots are exempt.

## Origin & history

**G37**, shipped 2026-07-21. The blocklist depth item that had sat as "Not built" — competitors (bot.incolumitas, BrowserScan, Pixelscan, whoer) look up the egress IP against blocklists/DNSBLs for an abuse-reputation signal beyond the datacenter/VPN/Tor *type* classification IP2Proxy PX12 already gives us. Backed by a new **shared** Mongo collection, `ip_blocklist` (see [storage.md](../../storage.md)), which any service/script/workflow can write flagged IPs into — botcheck is the first reader, not the owner. A daily background sync ([`iptools/ipsum.go`](../../../../iptools/ipsum.go)) downloads the [stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed (Unlicense / public domain) and upserts every listed IP under source `ipsum`, preserving the occurrence count (how many of the 30+ feeds list it) as the record's `count`. On `POST /check` (and the server-only `GET /` JSON path) the handler calls `iptools.BlockList.Check(ip)` and fills `Signals.IPBlocklistSources` / `IPBlocklistCount` / `IPBlocklistDeliberate`.

Fire logic (domain-pure, [`scoring.go`](../../../scoring.go)):

- **not listed / corpus off** → empty sources → silent (never evidence, same contract as the fingerprint-corpus rules).
- **ipsum-only** → fires only when `count ≥ ipsumBlocklistFloor` (3), matching ipsum's own README recommendation for an auto-ban list. Below that a single feed's take is too weak to dock a real human on a recycled residential address.
- **deliberate ban** (any source other than the automatic `ipsum` feed) → fires regardless of count.

Consistency-tier (weight 25), because it is server-observed and not client-spoofable, the same class as `datacenter_ip` / `proxy_ip`. Suppressed for verified good bots via `suppressedForGoodBot` — a verified crawler's egress can legitimately land on an abuse list (shared cloud ranges, recycled addresses), so the deduction is recorded, not counted, exactly like its datacenter/proxy hits. Roadmap item G37 (see [ip-reputation.md](../../roadmap/ip-reputation.md)); storage + sync detail: [storage.md](../../storage.md).

## Test status: Server-side corpus rule — no browser-observable trigger

`ip_blocklisted` fires from a corpus lookup keyed on the egress IP, not from anything a browser emits, so the real-automation harness doesn't apply (there is no client-side condition to construct). It is covered by Go domain fixtures for the floor logic, the deliberate-source bypass, the verified-good-bot suppression, and the server-only fire path, plus a live-Mongo integration round-trip on the corpus itself (upsert / created-at immutability / multi-source independence / `LastSync`) and an offline parse test of the ipsum feed format.

## Go scorer coverage

`tests/botcheck_test.go`: `TestIPBlocklistedRule`, `TestIPBlocklistedSuppressedForVerifiedGoodBot`, `TestEveryRuleCanFire`; `tools/iptools/tests/blocklist_test.go`: `TestNewBlockListDisabled`, `TestNilBlockListIsSafe`, `TestBlockListLiveRoundTrip`; `tools/iptools/ipsum_internal_test.go`: `TestParseIPsum`, `TestParseIPsumNoHeaderTime`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ip_blocklisted"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
