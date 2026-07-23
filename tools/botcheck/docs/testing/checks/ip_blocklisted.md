# `ip_blocklisted` — Egress IP is on a threat / abuse blocklist

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** no (server-observed)

## What it checks

The egress IP appears on a shared threat/abuse blocklist — the ipsum feed, which aggregates 30+ public lists, or Spamhaus's DROP list of hijacked/leased netblocks, plus any ban another service recorded. An ipsum-only listing only fires once at least three of those feeds agree (the project's own auto-ban grade); a deliberate ban or a DROP netblock match is trusted directly. Recycled residential addresses and shared NATs can carry a stale reputation, so it weighs in alongside other evidence, and verified good bots are exempt.

## Origin & history

**G37**, shipped 2026-07-21 (ipsum), extended same day (Spamhaus DROP). The blocklist depth item that had sat as "Not built" — competitors (bot.incolumitas, BrowserScan, Pixelscan, whoer) look up the egress IP against blocklists/DNSBLs for an abuse-reputation signal beyond the datacenter/VPN/Tor *type* classification IP2Proxy PX12 already gives us. Backed by a new **shared** Mongo collection, `ip_blocklist` (see [storage.md](../../storage.md)), which any service/script/workflow can write flagged IPs into — botcheck is a reader, not the owner. On `POST /check` (and the server-only `GET /` JSON path) the handler calls `iptools.BlockList.Check(ip)` and fills `Signals.IPBlocklistSources` / `IPBlocklistCount` / `IPBlocklistDeliberate`.

Two daily background syncs feed the corpus, sharing one staleness guard (`BlockList.ShouldSync`):

- [`iptools/ipsum.go`](../../../../iptools/ipsum.go) downloads the [stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed (Unlicense / public domain) and upserts every listed IP under source `ipsum`, preserving the occurrence count (how many of the 30+ feeds list it) as the record's `count`.
- [`iptools/spamhaus.go`](../../../../iptools/spamhaus.go) downloads Spamhaus's **DROP** list (`drop_v4.json`, confirmed free for all use including commercial) and upserts every listed **netblock** under source `spamhaus-drop`. DROP is whole IPv4 CIDR ranges, not individual IPs — its ~1,669 blocks cover ~15 million addresses — so entries carry `RangeStart`/`RangeEnd` bounds (via the package-internal `ipv4RangeBounds` helper) instead of one document per address, and `BlockList.Check`'s Mongo query matches either an exact IP or containment inside a stored range. DROP carries no count (binary presence on an already-high-confidence, human-curated list). Spamhaus's condition for use — credit them, keep their copyright notice + date with the data — is met by stamping their copyright/timestamp/terms into every ingested record's `meta`, plus a site-footer credit (see [storage.md](../../storage.md)).

Fire logic (domain-pure, [`scoring.go`](../../../scoring.go)):

- **not listed / corpus off** → empty sources → silent (never evidence, same contract as the fingerprint-corpus rules).
- **ipsum-only** → fires only when `count ≥ ipsumBlocklistFloor` (3), matching ipsum's own README recommendation for an auto-ban list. Below that a single feed's take is too weak to dock a real human on a recycled residential address.
- **deliberate ban** (any source other than the automatic `ipsum` feed — including `spamhaus-drop`) → fires regardless of count.

Consistency-tier (weight 25), because it is server-observed and not client-spoofable, the same class as `datacenter_ip` / `proxy_ip`. Suppressed for verified good bots via `suppressedForGoodBot` — a verified crawler's egress can legitimately land on an abuse list (shared cloud ranges, recycled addresses), so the deduction is recorded, not counted, exactly like its datacenter/proxy hits. Roadmap item G37 (see [ip-reputation.md](../../roadmap/ip-reputation.md)); storage + sync detail: [storage.md](../../storage.md).

## Test status: Server-side corpus rule — no browser-observable trigger

`ip_blocklisted` fires from a corpus lookup keyed on the egress IP, not from anything a browser emits, so the real-automation harness doesn't apply (there is no client-side condition to construct). It is covered by Go domain fixtures for the floor logic, the deliberate-source bypass, the verified-good-bot suppression, and the server-only fire path, plus live-Mongo integration round-trips on the corpus itself (upsert / created-at immutability / multi-source independence / `LastSync` / range containment) and offline parse tests of both feed formats.

## Go scorer coverage

`tests/botcheck_test.go`: `TestIPBlocklistedRule`, `TestIPBlocklistedSuppressedForVerifiedGoodBot`, `TestEveryRuleCanFire`; `tools/iptools/tests/blocklist_test.go`: `TestNewBlockListDisabled`, `TestNilBlockListIsSafe`, `TestBlockListLiveRoundTrip`, `TestBlockListLiveRangeContainment`, `TestSyncSpamhausDROPNilRepo`, `TestSyncSpamhausDROPSkipsWhenFresh`; `tools/iptools/ipsum_internal_test.go`: `TestParseIPsum`, `TestParseIPsumNoHeaderTime`; `tools/iptools/spamhaus_internal_test.go`: `TestParseDROP`, `TestParseDROPNoMetadata`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ip_blocklisted"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
