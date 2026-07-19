# Bot check — Go test suite (black-box, `botcheck/tests/`)

*(part of the [botcheck docs index](README.md))* — for separate npm-based
harness testing against real automation frameworks, see
[testing/README.md](testing/README.md); this page covers Go unit/handler tests
only.

- **Domain (`botcheck_test.go`)** — construct canned `Signals` (no HTTP, no BINs),
  assert `Score`/`Verdict`/`Checks`, table-driven: clean Chrome on residential IP
  → `human`; headless Chrome (webdriver + SwiftShader + CDP both contexts) →
  `bot`; stealth spoof (UA mismatch + TZ mismatch + datacenter IP) →
  `bot`/`suspicious`; Electron catch (UA OS ≠ `userAgentData.platform`) →
  `suspicious`; privacy-conscious human (couple soft quirks, nothing else) →
  still `human` (proves ≥3-soft-cluster rule doesn't false-positive). `go-cmp` on
  `Checks` slice locks in *which* signals fired, not just the number.
- **Handler (`handler_test.go`)** — `httptest`: `POST /check` a JSON fingerprint,
  assert negotiated output (JSON for `Accept: */*`, `botcheck/result` fragment
  for `Accept: text/html`), with fake `iptools.Looker` (no PX12 BIN in CI) whose
  zero value returns nil result, so IP signals absent and only client half of
  fingerprint scored.
- **Corpus (`corpus_test.go`)** — `FingerprintHash` determinism (server-observed
  fields never leak in), `fingerprint_reuse` floor (fires at ≥5, silent below) +
  good-bot suppression, and nil-safe disabled store. Live Mongo round-trip +
  end-to-end handler wiring run only when `MONGODB_TEST_URI` set, skip cleanly
  otherwise (iptools-history pattern).
- **Report (`report_test.go`)** — `Subgroup` filtering, rule `Explanation`
  lookups, `Environment` browser/engine display line, plus their rendering
  through `result.html`.

White-box test beside code, `tools/botcheck/report_internal_test.go` (package
`botcheck`, CLAUDE.md-documented exception for tests needing unexported
symbols), enforces two structural invariants over unexported
`rules`/`ruleExplanations`: every consistency-tier rule has a subgroup, every
rule ID — all 66 currently implemented, plus 1 remaining reserved ID,
`system_color_headless` — has a `ruleExplanations` entry (G55 coverage guard).
For which specific Go tests exercise which rule ID today, see
[testing/checks/](testing/checks/README.md) — each of the 66 per-check files
lists its own scorer-test coverage instead of this page trying to enumerate
all 66 (a few, e.g. `framework_globals` and `ch_platform_mismatch`, currently
have none beyond the blanket explanation-presence guard above).

**Structural limitation worth knowing:** suite constructs `Signals` directly,
never exercises `shared/static/js/botcheck.js` — actual browser collector — at
all. Bug in collector (wrong value, thrown exception silently swallowed by its
`safe()` wrapper, wrong DOM read) invisible to `go test` by design, since it
tests the *scorer*, not the *collector*. Exactly what let real bug in
`webglGPU()` ship and survive every Go test run — see
[testing/findings/2026-07-19-webglgpu-bug-fixed.md](testing/findings/2026-07-19-webglgpu-bug-fixed.md)
for incident and why npm-based [testing/](testing/README.md) harness exists to
cover that gap.
