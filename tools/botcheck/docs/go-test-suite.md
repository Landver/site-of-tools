# Bot check — Go test suite (black-box, `botcheck/tests/`)

*(part of the [botcheck docs index](README.md))* — for the separate npm-based
harness that tests against real automation frameworks, see
[testing/README.md](testing/README.md); this page is about the Go unit/handler
tests only.

- **Domain (`botcheck_test.go`)** — construct canned `Signals` (no HTTP, no BINs)
  and assert `Score`/`Verdict`/`Checks`, table-driven: clean Chrome on a
  residential IP → `human`; headless Chrome (webdriver + SwiftShader + CDP both
  contexts) → `bot`; stealth spoof (UA mismatch + TZ mismatch + datacenter IP) →
  `bot`/`suspicious`; the Electron catch (UA OS ≠ `userAgentData.platform`) →
  `suspicious`; privacy-conscious human (a couple of soft quirks, nothing else) →
  still `human` (proves the ≥3-soft-cluster rule doesn't false-positive). `go-cmp`
  on the `Checks` slice locks in *which* signals fired, not just the number.
- **Handler (`handler_test.go`)** — `httptest`: `POST /check` a JSON fingerprint
  and assert the negotiated output (JSON for `Accept: */*`, the `botcheck/result`
  fragment for `Accept: text/html`), with a fake `iptools.Looker` (no PX12 BIN in
  CI) and a nil service (IP signals absent, still scores the client half).
- **Corpus (`corpus_test.go`)** — `FingerprintHash` determinism (server-observed
  fields never leak in), the `fingerprint_reuse` floor (fires at ≥5, silent
  below) + good-bot suppression, and the nil-safe disabled store. Live Mongo
  round-trip + end-to-end handler wiring run only when `MONGODB_TEST_URI` is
  set, skipping cleanly otherwise (the iptools-history pattern).

**A structural limitation worth knowing:** this suite constructs `Signals`
directly and never exercises `shared/static/js/botcheck.js` — the actual
browser collector — at all. A bug in the collector (wrong value, a thrown
exception silently swallowed by its `safe()` wrapper, a wrong DOM read) is
invisible to `go test` by design, since it tests the *scorer*, not the
*collector*. This is exactly what let a real bug in `webglGPU()` ship and
survive every Go test run — see
[testing/findings-log.md](testing/findings-log.md#2026-07-19--webglgpu-bug-fixed)
for the incident and why the npm-based [testing/](testing/README.md) harness
exists to cover that gap.
