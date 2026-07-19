# Bot check — storage: the fingerprint corpus (G41/G42)

*(part of the [botcheck docs index](README.md))*

Botcheck stores exactly one thing: rolling corpus of fingerprint sightings in
MongoDB (`botcheck_fingerprints` collection in shared `site-of-tools` database).
On every `POST /check` handler hashes POSTed fingerprint's stable client fields
— `Signals.FingerprintHash()`, sha256 over UA, languages, userAgentData.platform,
cores, memory, screen + colour depth, timezone, WebGL vendor/renderer,
productSub, engine, font count — records `(hash, IP, ts)`, counts how many
**distinct IPs** presented that exact hash. Five or more trips
`fingerprint_reuse` consistency rule (−25): scraping-farm catch (farm locks one
browser fingerprint, rotates its proxy pool — the incolumitas ScrapingBee case),
while one person roaming networks never reaches five IPs in a month. Verified
crawler fleets share one fingerprint by design, so rule suppressed for them
(G36 — see [roadmap/ip-reputation.md](roadmap/ip-reputation.md)).

Corpus deliberately minimal and self-pruning: `ts` TTL index expires every
sighting after 30 days, hash is one-way (raw fingerprint never stored), and —
exactly like iptools history — disabled Mongo (empty `MONGODB_URI`) turns whole
thing into no-op: `FingerprintIPs` stays 0, rule stays silent, score unchanged.
Domain scorer itself stays pure: count arrives as plain `Signals` field, so
`Evaluate` still needs no DB, its tests still construct `Signals` directly.
