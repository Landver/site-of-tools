# `ip_blocklisted` — Egress IP is on a threat / abuse blocklist

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** no (server-observed)

## What it checks

Egress IP on shared threat/abuse blocklist — ipsum feed (aggregates 30+ public lists), or Spamhaus DROP list of hijacked/leased netblocks, plus any ban another service recorded. ipsum-only listing fires only once ≥3 feeds agree (project's auto-ban grade); deliberate ban or DROP netblock match trusted directly. Recycled residential addresses & shared NATs can carry stale reputation, so weighs in alongside other evidence; verified good bots exempt.

## Origin & history

**G37**, shipped 2026-07-21 (ipsum), extended same day (Spamhaus DROP). Blocklist depth item that sat "Not built" — competitors (bot.incolumitas, BrowserScan, Pixelscan, whoer) look up egress IP vs blocklists/DNSBLs for abuse-reputation signal beyond datacenter/VPN/Tor *type* classification IP2Proxy PX12 gives us. Backed by new **shared** Mongo collection `ip_blocklist` (see [storage.md](../../storage.md)), which any service/script/workflow can write flagged IPs into — botcheck reads, doesn't own. On `POST /check` (& server-only `GET /` JSON path) handler calls `iptools.BlockList.Check(ip)`, fills `Signals.IPBlocklistSources` / `IPBlocklistCount` / `IPBlocklistDeliberate`.

Two daily background syncs feed corpus, sharing one staleness guard (`BlockList.ShouldSync`):

- [`iptools/ipsum.go`](../../../../iptools/ipsum.go) downloads [stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed (Unlicense / public domain), upserts every listed IP under source `ipsum`, preserving occurrence count (how many of 30+ feeds list it) as record `count`.
- [`iptools/spamhaus.go`](../../../../iptools/spamhaus.go) downloads Spamhaus **DROP** list (`drop_v4.json`, confirmed free for all use incl commercial), upserts every listed **netblock** under source `spamhaus-drop`. DROP = whole IPv4 CIDR ranges, not individual IPs — ~1,669 blocks cover ~15 million addresses — so entries carry `RangeStart`/`RangeEnd` bounds (via package-internal `ipv4RangeBounds` helper) instead of one doc per address; `BlockList.Check` Mongo query matches exact IP or containment inside stored range. DROP carries no count (binary presence on already-high-confidence, human-curated list). Spamhaus use condition — credit them, keep copyright notice + date w/ data — met by stamping copyright/timestamp/terms into every ingested record `meta`, plus site-footer credit (see [storage.md](../../storage.md)).

Fire logic (domain-pure, [`scoring.go`](../../../scoring.go)):

- **not listed / corpus off** → empty sources → silent (never evidence, same contract as fingerprint-corpus rules).
- **ipsum-only** → fires only when `count ≥ ipsumBlocklistFloor` (3), matching ipsum README recommendation for auto-ban list. Below that, single feed's take too weak to dock a real human on recycled residential address.
- **deliberate ban** (any source other than automatic `ipsum` feed — incl `spamhaus-drop`) → fires regardless of count.

Consistency-tier (weight 25): server-observed, not client-spoofable, same class as `datacenter_ip` / `proxy_ip`. Suppressed for verified good bots via `suppressedForGoodBot` — verified crawler egress can legitimately land on abuse list (shared cloud ranges, recycled addresses), so deduction recorded, not counted, exactly like its datacenter/proxy hits. Roadmap item G37 (see [ip-reputation.md](../../roadmap/ip-reputation.md)); storage + sync detail: [storage.md](../../storage.md).

## Test status: Server-side corpus rule — no browser-observable trigger

`ip_blocklisted` fires from corpus lookup keyed on egress IP, not from anything a browser emits, so real-automation harness doesn't apply (no client-side condition to construct). Covered by Go domain fixtures for floor logic, deliberate-source bypass, verified-good-bot suppression, server-only fire path, plus live-Mongo integration round-trips on corpus itself (upsert / created-at immutability / multi-source independence / `LastSync` / range containment) & offline parse tests of both feed formats.

## Go scorer coverage

`tests/botcheck_test.go`: `TestIPBlocklistedRule`, `TestIPBlocklistedSuppressedForVerifiedGoodBot`, `TestEveryRuleCanFire`; `tools/iptools/tests/blocklist_test.go`: `TestNewBlockListDisabled`, `TestNilBlockListIsSafe`, `TestBlockListLiveRoundTrip`, `TestBlockListLiveRangeContainment`, `TestSyncSpamhausDROPNilRepo`, `TestSyncSpamhausDROPSkipsWhenFresh`; `tools/iptools/ipsum_internal_test.go`: `TestParseIPsum`, `TestParseIPsumNoHeaderTime`; `tools/iptools/spamhaus_internal_test.go`: `TestParseDROP`, `TestParseDROPNoMetadata`.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["ip_blocklisted"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
