# `native_callnew_tamper` — Native function misses its call/new TypeError traps

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Genuine native functions throw specific TypeErrors when called or constructed the wrong way; JavaScript overrides typically miss those traps. Same caveat as the descriptor probe — a privacy extension's override can also fail the traps, so it isn't a hard tell.

## Origin & history

**G04**, shipped 2026-07-17, same batch: verifies native functions throw the correct `TypeError`s when called or constructed the wrong way — a JavaScript override typically misses those traps. Later found evaded by stealth's `stripProxyFromErrors` helper, which defeats stack-trace-based Proxy detection generally — see the test status above.

## Test status: Verified — evaded (open gap)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly (shares its code-comment section with `native_descriptor_tamper`). Root cause: stealth's `stripProxyFromErrors` helper wraps every Proxy trap in try/catch and rewrites the thrown error's stack, defeating stack-trace-based Proxy detection generally. **Still open**, same as `native_descriptor_tamper` — no concrete probe idea yet (see [next-steps.md item 3](../next-steps.md)).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestStealthPatchedBrowserScoresBot`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_callnew_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
