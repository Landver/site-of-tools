# `fingerprint_reuse` — This exact fingerprint was seen from many IP addresses

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** network · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Same stable browser fingerprint (UA, screen, GPU, timezone, …) arrived from many distinct IPs within rolling 30-day corpus — shape of scraping farm that locks one fingerprint & rotates its proxy pool. One person roaming across networks accumulates a couple IPs honestly -> this only counts from five; verified crawler fleets share one fingerprint by design & are exempt.

## Origin & history

**G41/G42**, shipped 2026-07-18: backed by rolling 30-day Mongo fingerprint corpus ([`corpus.go`](../../../corpus.go), `botcheck_fingerprints` collection) — `Signals.FingerprintHash()` (sha256 over UA, languages, platform, cores, memory, screen, timezone, WebGL vendor/renderer, productSub, engine, font count) is exact fingerprint ID; rule fires at >=5 distinct IPs presenting same hash in window, the scraping-farm catch (one person roaming networks never reaches five in a month). Suppressed for verified crawler fleets (**G36**), which legitimately share one fingerprint by design. Full storage detail: [storage.md](../../storage.md).

## Test status: Verified — fires correctly

`POST /check` w/ identical fingerprint from 6 spoofed `CF-Connecting-IP` values: fired at exactly 5 distinct IPs (`fingerprintReuseMinIPs`), silent at 4; same-IP repeats never inflated count. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/corpus_test.go`: `TestFingerprintReuseRule`, `TestFingerprintReuseSuppressedForGoodBot`, `TestCheckNilCorpusLeavesRuleSilent`, `TestCorpusLiveViaHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["fingerprint_reuse"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
