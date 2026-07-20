# `native_callnew_tamper` — Native function misses its call/new TypeError traps

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Genuine native functions throw specific TypeErrors when called or constructed the wrong way; a naive JavaScript override misses those traps. Soft, cluster-only since 2026-07-21 for the same reason as the descriptor probe — evaded by current stealth, and a privacy extension's override can also miss the traps, so it isn't standalone evidence.

## Origin & history

**G04**, shipped 2026-07-17, same batch: verifies native functions throw the correct `TypeError`s when called or constructed the wrong way — a JavaScript override typically misses those traps. Later found evaded by stealth's `stripProxyFromErrors` helper, which defeats stack-trace-based Proxy detection generally — see the test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause: stealth's `stripProxyFromErrors` helper wraps every Proxy trap in try/catch and rewrites the thrown error's stack, defeating stack-trace-based Proxy detection generally.

**Resolution (2026-07-21): downgraded consistency/25 → soft/8**, together with `native_descriptor_tamper` and the three other deep-tamper probes — evaded by real stealth, real false-positive risk against a privacy extension's DOM-API override, so it only corroborates as part of a soft cluster now. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestStealthCaughtByCrossContextChecks`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_callnew_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
