# Bot check — storage: the fingerprint corpus (G41/G42)

*(part of the [botcheck docs index](README.md))*

Botcheck stores exactly one thing: a rolling corpus of fingerprint sightings in
MongoDB (the `botcheck_fingerprints` collection in the shared `site-of-tools`
database). On every `POST /check` the handler hashes the POSTed fingerprint's
stable client fields — `Signals.FingerprintHash()`, sha256 over UA, languages,
userAgentData.platform, cores, memory, screen + colour depth, timezone, WebGL
vendor/renderer, productSub, engine, font count — records `(hash, IP, ts)`, and
counts how many **distinct IPs** presented that exact hash. Five or more trips
the `fingerprint_reuse` consistency rule (−25): the scraping-farm catch (a farm
locks one browser fingerprint and rotates its proxy pool — the incolumitas
ScrapingBee case), while one person roaming networks never reaches five IPs in a
month. Verified crawler fleets share one fingerprint by design, so the rule is
suppressed for them (G36 — see [roadmap/ip-reputation.md](roadmap/ip-reputation.md)).

The corpus is deliberately minimal and self-pruning: a `ts` TTL index expires
every sighting after 30 days, the hash is one-way (the raw fingerprint is never
stored), and — exactly like the iptools history — a disabled Mongo (empty
`MONGODB_URI`) turns the whole thing into a no-op: `FingerprintIPs` stays 0, the
rule stays silent, and the score is unchanged. The domain scorer itself stays
pure: the count arrives as a plain `Signals` field, so `Evaluate` still needs no
DB and its tests still construct `Signals` directly.
