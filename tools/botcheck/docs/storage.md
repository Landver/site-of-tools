# Bot check — storage: fingerprint corpus + shared IP blocklist

*(part of the [botcheck docs index](README.md))*

Botcheck reads two Mongo collections in the shared `site-of-tools` database: its
own **fingerprint corpus** (`botcheck_fingerprints`, below) and a **shared IP
blocklist** (`ip_blocklist`, [next section](#the-shared-ip-blocklist-g37)) it
consumes but does not own.

## The fingerprint corpus (G41/G42 reuse + G43 churn)

A rolling corpus of fingerprint sightings in MongoDB (`botcheck_fingerprints`
collection in shared `site-of-tools` database).
On every `POST /check` handler hashes POSTed fingerprint's stable client fields
— `Signals.FingerprintHash()`, sha256 over UA, languages, userAgentData.platform,
cores, memory, screen + colour depth, timezone, WebGL vendor/renderer,
productSub, engine, font count — records `(hash, IP, ts)`. That one
`(hash, IP, ts)` collection feeds **two** rules, the spatial and temporal reads
of the same data:

- **Reuse (G41/G42, `fingerprint_reuse`, consistency −25):** counts how many
  **distinct IPs** presented that exact hash. Five or more trips the rule — the
  scraping-farm catch (farm locks one browser fingerprint, rotates its proxy
  pool, the incolumitas ScrapingBee case), while one person roaming networks
  never reaches five IPs in a month. Verified crawler fleets share one
  fingerprint by design, so the rule is suppressed for them (G36 — see
  [roadmap/ip-reputation.md](roadmap/ip-reputation.md)).
- **Churn (G43, `ip_fingerprint_churn`, soft 8):** the inverse read — counts how
  many **distinct fingerprints** one IP presented within a short rolling window
  (`churnWindow`, 10 min), via `Corpus.DistinctHashesByIP`. Eight or more is a
  fingerprint-randomising client (or a busy shared egress). Soft, so a corporate
  NAT legitimately showing many browsers never docks a lone visitor — it only
  bites in a ≥3 soft cluster.

Corpus deliberately minimal and self-pruning: `ts` TTL index expires every
sighting after 30 days, hash is one-way (raw fingerprint never stored), and —
exactly like iptools history — disabled Mongo (empty `MONGODB_URI`) turns whole
thing into no-op: `FingerprintIPs`/`FingerprintChurn` stay 0, both rules stay
silent, score unchanged. Domain scorer itself stays pure: both counts arrive as
plain `Signals` fields, so `Evaluate` still needs no DB, its tests still
construct `Signals` directly.

## The shared IP blocklist (G37)

The `ip_blocklist` collection (also in `site-of-tools`) backs the
`ip_blocklisted` rule and is **shared, not botcheck-owned**: any
service/script/workflow can write flagged IPs into it, and any consumer can
read. Its repository lives in iptools (the IP-reputation home) as
[`iptools.BlockList`](../../iptools/blocklist.go), since botcheck already reuses
the iptools IP layer.

**Schema** (the corpus's public contract — external writers match these field
names, snake_case bson):

| field | meaning |
|---|---|
| `ip` | the flagged address for a single-IP entry, or the CIDR string itself for a netblock entry (Spamhaus DROP) — the CIDR is that record's identity |
| `source` | what flagged it — `"ipsum"`, `"spamhaus-drop"`, `"rate-limiter"`, `"manual"`, … |
| `reason` | free-text why (optional) |
| `count` | optional confidence/occurrence count (ipsum: how many of its 30+ feeds list the IP); 0 = source carries none (true for Spamhaus DROP, which is binary presence, not a count) |
| `range_start` / `range_end` | inclusive IPv4 bounds (see the package-internal `ipv4RangeBounds` helper in [`cidr.go`](../../iptools/cidr.go)) for a netblock entry — one document covers a whole CIDR instead of one row per address. Omitted for a plain single-IP entry |
| `meta` | any source-specific extras, so nothing a richer feed carried is lost (ipsum stashes its feed timestamp + URL; Spamhaus DROP stashes its copyright notice + timestamp + terms URL + per-record sblid/rir) |
| `created_at` | set once, on first insert (immutable — written via `$setOnInsert`) |
| `updated_at` | refreshed on every touch; drives the TTL |

**Indexes:** a **TTL** on `updated_at` (60 days — the owner's spec: an entry not
refreshed within two months self-prunes, so reputation decays once an IP falls
off every feed), a **unique `(ip, source)`** compound, and a **sparse
`(range_start, range_end)`** compound (only netblock entries carry those
fields, so sparse keeps the ~100k-plus single-IP rows out of it). The unique
compound is the "don't lose data" guarantee — each source keeps its *own*
record per IP/CIDR, so the daily feed syncs never clobber a manual/other-service
ban and vice versa; its `ip`-prefix also serves `Check`'s exact-match branch.
External writers must also use `$setOnInsert` for `created_at` to keep it
set-once.

**Feeding it — two daily syncs, one shared staleness guard**
(`BlockList.ShouldSync`, since both feeds want the identical 24-hour cadence —
threshold is the interval *minus* an hour of slack, not the bare interval,
because a sync's completion write always lands slightly after the tick that
triggered it):

- **ipsum** ([`iptools/ipsum.go`](../../iptools/ipsum.go), `RunIPsumSync`
  started in `main.go`) downloads the
  [stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed — a
  public-domain (Unlicense) `IP<TAB>count` list built from 30+ blocklists — and
  bulk-upserts every IP under source `ipsum`, preserving the occurrence count.
- **Spamhaus DROP** ([`iptools/spamhaus.go`](../../iptools/spamhaus.go),
  `RunSpamhausDROPSync`) downloads `drop_v4.json` — Spamhaus confirmed this is
  free for all use including commercial, on condition of crediting them and
  keeping their copyright notice + date "with the file and data." DROP lists
  ~1,669 human-curated, high-confidence hijacked/leased **netblocks**, not
  individual IPs — those blocks cover ~15 million addresses, so one document
  per address isn't an option. Each CIDR record is stored as one document with
  `range_start`/`range_end` bounds instead, and its own `meta` carries the
  feed's copyright/timestamp/terms plus its own `sblid`/`rir` — literally
  satisfying "the date and copy text remain with the file and data." IPv6
  (`drop_v6.json`) is a deliberate non-goal: a 128-bit range representation
  isn't worth the complexity right now. The site footer also credits Spamhaus
  with the © mark they asked for
  ([`shared/templates/partials/footer.html`](../../../shared/templates/partials/footer.html)),
  gated on the same `.Attribution` flag as the IP2Location credit.

Both syncs advance the touched entries' `updated_at` on every refresh, keeping
still-listed IPs/netblocks alive against the TTL; an entry that drops off its
feed stops being refreshed and ages out after the 60-day window. A non-200
download is an error that aborts the sync (retried next tick), so an outage can
never parse as an empty feed.

**Reading it — botcheck + the IP tool.** botcheck reads it on `POST /check`;
the IP tool ([`iptools`](../../iptools/handler.go)) also reads it, keyed on the
looked-up IP (any address, not just the egress), and renders it in the "proxy /
blocklist / network" result card + the JSON `blocklist` field. Either way,
`BlockList.Check(ip)` matches an exact single-IP entry OR (for a parseable
IPv4 address) containment inside a stored netblock range, via one Mongo query
with an `$or` — callers never need to know which kind of entry matched.
botcheck's handler fills three server-observed `Signals` fields
(`IPBlocklistSources`, `IPBlocklistCount`, `IPBlocklistDeliberate`). Same
nil-safety as the fingerprint corpus: disabled Mongo → nil `BlockList` → `Check`
returns empty → the rule is silent → the pure `Evaluate` still needs no DB. See
[checks/ip_blocklisted.md](testing/checks/ip_blocklisted.md) for the fire logic
and [roadmap/ip-reputation.md](roadmap/ip-reputation.md) (G37) for the
data-source research behind picking ipsum and Spamhaus DROP.
