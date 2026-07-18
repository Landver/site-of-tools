# botcheck — wave-2 continuation (handoff)

Written 2026-07-18 so a fresh session can pick up the work without the original
conversation. Read this first, then [ROADMAP.md](ROADMAP.md) (the source of truth
for feature rows) and [README.md](README.md) (current design).

## Where things stand

- **master @ `570bc7f`** contains wave 1, merged from `feat/botcheck-next`:
  - **Detection batch** (branch `feat/botcheck-a`): 13 new rules (50 → **63**),
    collector payload `v: 3` (gate const `collectorVTamperV3`), G09 WebRTC leak,
    G10 broken-image, G11 iframe webdriver+proxy, G12 mobile-no-touch, G13 wider
    automation markers, G14 SW webdriver+CDP, G17 navigator-proto walk, G22
    chrome.runtime + late-injection, G23 JS-engine cross-check, plus backlog softs
    (plugins/mimeTypes, zero outerHeight). `system_color_headless` was built then
    deliberately dropped — real Chrome computes ActiveText to the old headless
    value, so it false-fires everywhere (verified via kimi-webbridge).
  - **Reporting batch** (branch `feat/botcheck-b`): G54 raw fingerprint dump
    (`Report.ClientPayload` + `Signals.RawJSON()`, data attrs on the verdict
    card), G55 per-signal "why" explanations (`tools/botcheck/report.go`),
    G56 detected-environment line, G50 per-tier sub-scores, G38/G44 conn-card
    surface (`platform/conn.go`: `ConnNetwork`, `WithNetwork`, `ProxyKindLabel`).
- Verified on master: `go vet ./...` + `go test ./... -race` green; prod-mode
  smoke (embed FS): browser GET 200, curl GET → server-only JSON score, POST
  /check → 63 checks + `clientPayload` echo, `/botcheck-sw.js` 200.
- **This branch (`feat/botcheck-c`) is the continuation point** — it currently
  equals master. Worktrees `botcheck-a`/`botcheck-b` are merged and can be
  removed; `botcheck-next` is the integration branch.

## Wave-2 scope (not started)

### C — MongoDB fingerprint corpus (G41/G42) + G38/G44 wiring

Design contract (already decided — follow it):

- `func (s Signals) FingerprintHash() string` in `botcheck.go` — sha256 over a
  canonical subset of stable client fields (UA, languages, uaData.platform,
  cores, memory, screen+colorDepth, tz, WebGL vendor+renderer, productSub,
  engine, fontCount). Pure, deterministic, testable.
- New `tools/botcheck/corpus.go` — nil-safe repository mirroring
  `tools/iptools/history.go` + its wiring at `main.go:45`:
  `NewCorpus(db *mongo.Database)`, `EnsureIndexes` via
  `platform.EnsureTTLIndex(coll, "ts", 30*24h)`, `Record(ctx, hash, ip)`,
  `DistinctIPs(ctx, hash) (int, error)`.
- Handler: on POST /check with ClientCollected — record, then count →
  `sig.FingerprintIPs int json:"-"`.
- Rule `fingerprint_reuse` (consistency, 25): fires at ≥5 distinct IPs ("this
  exact fingerprint seen from N IPs" — the ScrapingBee-farm catch). Add its ID
  to `suppressedForGoodBot` (verified crawler fleets legitimately share one
  fingerprint across many IPs).
- Surface: `Report.FingerprintIPs` + one line in the raw-fingerprint card;
  explanation entry in `report.go` (**never use the word "flagged"** — see
  gotchas).
- G38/G44 wiring: the surface exists (conn partial renders ASN/proxy rows when
  enriched); remaining step is calling `.WithNetwork(...)` in botcheck's handler
  `index`, populated from the iptools lookup result.
- Copy honesty: `index.html` says "Nothing is stored" twice (intro + G53
  disclosure) — rewrite to describe the rolling 30-day fingerprint corpus.
- `main.go`: `botcheck.Register(botApp, geo, corpus)` (mirror iptools).
- Tests: rule fires ≥5 / silent <5 / suppressed for verified good bot; hash
  determinism; nil-corpus no-op; handler wiring; Mongo integration test skipped
  when `MONGODB_URI` is empty (iptools-history pattern).
- Docs: ROADMAP rows G41/G42 (+G38/G44 → full "Shipped"), README 63 → 64 rules
  + storage section.

### D — G46 returning-visitor history (localStorage only, no server state)

- `shared/static/js/botcheck.js`: after the result swap, read
  `[data-score]`/`[data-verdict]` from the swapped-in DOM (attrs already exist
  on the verdict card), append `{ts, score, verdict}` to localStorage key
  `botcheck:history`, cap 20.
- `tools/botcheck/templates/index.html`: a "your recent checks" card, hidden
  when empty; copy states the list lives only in the browser. (C also edits
  index.html — different region; if parallel, separate branches then merge.)
- ROADMAP row G46.

### Wave 3 — final verification & merge

- `go vet ./...` + `go test ./... -race`.
- Real-Chrome E2E via kimi-webbridge on the dev server: 100/human, zero false
  fires across all rules; new UI renders (raw dump, why-expanders, environment
  line, sub-scores, history card after two runs, conn-card ASN/proxy rows when
  the BINs are present).
- ROADMAP "Build status" header: add the wave-1+2 batch paragraph (63 rules →
  final count); reconcile counts.
- Merge the integration branch into master — **ask the user first** (no git
  mutations without explicit approval).

## Conventions & gotchas (learned the hard way)

- Workflow: one worktree per wave agent branched off `feat/botcheck-next`,
  strictly disjoint file ownership, merge back, master last.
- `TestCheckFullBrowserHeadersFlagNone` counts the word "flagged" verbatim in
  the rendered fragment — keep it out of all new UI copy and explanations.
- Damning-when-false fields: fail-to-pass in the collector + a `CollectorV`
  gate (the `collectorVTamperV3` pattern) so a stale cached collector never
  reads as tampered.
- Both-sides-present guard: empty/0 means "not supplied", never evidence.
- New network-side deductions that a genuine crawler fleet is expected to trip
  belong in `suppressedForGoodBot`.
- Tests are black-box in `tools/botcheck/tests/` (white-box exception beside the
  code, e.g. `report_internal_test.go`).
- Prod smoke recipe: `APP_ENV=prod BASE_DOMAIN=corpberry.com LISTEN_ADDR=:18081
  ./site-of-tools`, then `curl -H "Host: botcheck.corpberry.com" ...` (a plain
  curl GET correctly returns the server-only JSON score, not HTML).
