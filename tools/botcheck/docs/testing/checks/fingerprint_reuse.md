# `fingerprint_reuse` — This exact fingerprint was seen from many IP addresses

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The same stable browser fingerprint (User-Agent, screen, GPU, timezone, …) arrived from many distinct IP addresses within the rolling 30-day corpus — the shape of a scraping farm that locks one fingerprint and rotates its proxy pool. One person roaming across networks accumulates a couple of IPs honestly, which is why this only counts from five; verified crawler fleets share one fingerprint by design and are exempt.

## Origin & history

**G41/G42**, shipped 2026-07-18: backed by the rolling 30-day Mongo fingerprint corpus ([`corpus.go`](../../../corpus.go), `botcheck_fingerprints` collection) — `Signals.FingerprintHash()` (sha256 over UA, languages, platform, cores, memory, screen, timezone, WebGL vendor/renderer, productSub, engine, font count) is the exact fingerprint ID; this rule fires at five or more distinct IPs presenting the same hash in the window, the scraping-farm catch (one person roaming networks never reaches five in a month). Suppressed for verified crawler fleets (**G36**), which legitimately share one fingerprint by design. Full storage detail: [storage.md](../../storage.md).

## Test status: Verified — fires correctly

Closed despite the longitudinal-corpus caveat above: `POST /check` with an identical synthetic fingerprint from 6 distinct spoofed `CF-Connecting-IP` values (trusted unconditionally in dev — see `platform/app.go`'s `cfIPExtractor`). Fired at exactly the 5th distinct IP (`fingerprintReuseMinIPs`), silent at 4; repeat hits from one IP never inflated the count — confirms real dedup against the live Mongo corpus, not just a hit counter. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/corpus_test.go`: `TestFingerprintReuseRule`, `TestFingerprintReuseSuppressedForGoodBot`, `TestCheckNilCorpusLeavesRuleSilent`, `TestCorpusLiveViaHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["fingerprint_reuse"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
