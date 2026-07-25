# `ip_fingerprint_churn` — This IP presented many different fingerprints in a short window

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Same egress IP presented many different browser fingerprints within a few minutes — shape of a client rotating fingerprint to evade tracking, temporal opposite of fingerprint-reuse check. Kept soft: large shared network (corporate NAT) can legitimately show many browsers, so only counts alongside other signals.

## Origin & history

**G43**, shipped 2026-07-21: temporal companion to `fingerprint_reuse`, backed by same rolling Mongo fingerprint corpus ([`corpus.go`](../../../corpus.go), `botcheck_fingerprints` collection). Reuse = *one fingerprint from many IPs* (farm locking one identity across proxy pool); churn = *many fingerprints from one IP* (client randomising fingerprint per request). `Corpus.DistinctHashesByIP(ip, window)` counts distinct fingerprint hashes recorded for connecting IP within `churnWindow` (10 minutes); handler feeds count into `Signals.FingerprintChurn` on `POST /check`; rule fires at `fingerprintChurnMinHashes` (8) or more. Soft, not consistency: corporate/shared NAT can legitimately present many browsers from one address, so lone visitor never docked — only bites as part of soft cluster of ≥3. Roadmap item G43 (see [ip-reputation.md](../../roadmap/ip-reputation.md)); storage detail: [storage.md](../../storage.md).

## Test status: Server-side corpus rule — no browser-observable trigger

`ip_fingerprint_churn` fires from corpus count, not from anything a browser emits, so real-automation harness doesn't apply the way it does to client checks (no client-side condition to construct). Covered instead by Go domain fixtures (floor behaviour, soft-tier, server-only skip) & live-Mongo integration round-trip (distinct counting per IP, IP isolation, rolling-window enforcement, end-to-end handler wiring). Corpus query & handler wiring mirror already-verified `fingerprint_reuse` path.

## Go scorer coverage

`tests/corpus_test.go`: `TestFingerprintChurnRule`, `TestNilCorpusIsSafe`, `TestCheckNilCorpusLeavesRuleSilent`, `TestCorpusChurnLiveRoundTrip`, `TestCorpusChurnLiveViaHandler`; `tests/botcheck_test.go`: `TestEveryRuleCanFire`.

---

"What it checks" sourced from [`report.go`](../../../report.go) `ruleExplanations["ip_fingerprint_churn"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
