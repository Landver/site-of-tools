# `ip_fingerprint_churn` — This IP presented many different fingerprints in a short window

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The same egress IP presented many different browser fingerprints within a few minutes — the shape of a client rotating its fingerprint to evade tracking, the temporal opposite of the fingerprint-reuse check. Kept soft because a large shared network (a corporate NAT) can legitimately show many browsers, so it only counts alongside other signals.

## Origin & history

**G43**, shipped 2026-07-21: the temporal companion to `fingerprint_reuse`, backed by the same rolling Mongo fingerprint corpus ([`corpus.go`](../../../corpus.go), `botcheck_fingerprints` collection). Where reuse is *one fingerprint from many IPs* (a farm locking one identity across a proxy pool), churn is *many fingerprints from one IP* (a client randomising its fingerprint per request). `Corpus.DistinctHashesByIP(ip, window)` counts the distinct fingerprint hashes recorded for the connecting IP within `churnWindow` (10 minutes); the handler feeds that count into `Signals.FingerprintChurn` on `POST /check`, and the rule fires at `fingerprintChurnMinHashes` (8) or more. Soft, not consistency: a corporate/shared NAT can legitimately present many browsers from one address, so a lone visitor is never docked — it only bites as part of a soft cluster of ≥3. Roadmap item G43 (see [ip-reputation.md](../../roadmap/ip-reputation.md)); storage detail: [storage.md](../../storage.md).

## Test status: Server-side corpus rule — no browser-observable trigger

`ip_fingerprint_churn` fires from a corpus count, not from anything a browser emits, so the real-automation harness doesn't apply the way it does to client checks (there is no client-side condition to construct). It is covered instead by Go domain fixtures (floor behaviour, soft-tier, server-only skip) and a live-Mongo integration round-trip (distinct counting per IP, IP isolation, rolling-window enforcement, and the end-to-end handler wiring). The corpus query and the handler wiring mirror the already-verified `fingerprint_reuse` path.

## Go scorer coverage

`tests/corpus_test.go`: `TestFingerprintChurnRule`, `TestNilCorpusIsSafe`, `TestCheckNilCorpusLeavesRuleSilent`, `TestCorpusChurnLiveRoundTrip`, `TestCorpusChurnLiveViaHandler`; `tests/botcheck_test.go`: `TestEveryRuleCanFire`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ip_fingerprint_churn"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
