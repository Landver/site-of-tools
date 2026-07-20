# Bot check — storage: the fingerprint corpus (G41/G42 reuse + G43 churn)

*(part of the [botcheck docs index](README.md))*

Botcheck stores exactly one thing: rolling corpus of fingerprint sightings in
MongoDB (`botcheck_fingerprints` collection in shared `site-of-tools` database).
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
