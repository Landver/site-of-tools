# `native_callnew_tamper` — Native function misses its call/new TypeError traps

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Genuine native fns throw specific TypeErrors when called/constructed wrong way; naive JS override misses those traps. Soft, cluster-only since 2026-07-21 for same reason as descriptor probe — evaded by current stealth, & privacy extension's override can also miss traps -> not standalone evidence.

## Origin & history

**G04**, shipped 2026-07-17, same batch: verifies native fns throw correct `TypeError`s when called/constructed wrong way — JS override typically misses those traps. Later found evaded by stealth's `stripProxyFromErrors` helper, which defeats stack-trace-based Proxy detection generally — see test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause: stealth's `stripProxyFromErrors` helper wraps every Proxy trap in try/catch & rewrites thrown error's stack, defeating stack-trace-based Proxy detection generally.

**Resolution (2026-07-21): downgraded consistency/25 → soft/8**, together w/ `native_descriptor_tamper` & three other deep-tamper probes — evaded by real stealth, real false-positive risk against privacy extension's DOM-API override -> only corroborates as part of soft cluster now. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestStealthCaughtByCrossContextChecks`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_callnew_tamper"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
