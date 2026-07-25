# `tostring_proxy` — Function.prototype.toString is proxied or replaced (stealth hallmark)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 45 · **Reads client signal:** yes

## What it checks

Proxying Function.prototype.toString exists for one reason: making patched functions look native — hallmark of puppeteer-extra-style stealth plugins. No legitimate software does it. Can't see patches installed by other means, e.g. modified browser build.

## Origin & history

**G04**, shipped 2026-07-17 (batch w/ `native_descriptor_tamper` & `native_callnew_tamper`): the `Function.prototype.toString` Proxy probe — shape differential against a control native plus error-stack apply-frame inspection, the specific hallmark of `puppeteer-extra`-style stealth plugins. Shipped as hard tell. Collector payload versioned `v: 2` at same time so stale cached collector skips these damning-when-false rules instead of reading as tampered. Later evaded & re-fixed — see test status above.

## Test status: Fixed

**Evaded, then fixed, then re-verified — two independent bugs, same root cause.** Originally one of six checks `puppeteer-extra-plugin-stealth` 2.11.2 evaded cleanly (score unaffected). A single illegal call (`Function.prototype.toString.call(null)`) against live stealth 2.11.2 produced this raw, completely unstripped stack:

```
TypeError: Cannot read properties of null (reading 'toString')
    at newHandler.<computed> [as apply] (eval at <anonymous> (:4:65), <anonymous>:18:30)
```

Root cause: stealth's `stripProxyFromErrors` helper finds its strip anchor by searching for literal prefix `at Object.newHandler.<computed> [as ` — but current V8 (Chrome 150) renders frame as `at newHandler.<computed> [as apply]`, w/ **no `Object.` prefix**, so stealth's own anchor search comes up empty & its "strip" = silent no-op. Separately, this rule's own old regex (`/at\s+\S*apply\b|\bapply@/`) also failed to match same frame, since `apply` sits inside V8's `[as apply]` bracket-alias annotation, not as own contiguous token right after `at`. Two independent bugs on two different projects' code, both dated to same V8 stack-frame format change. Fixed by adding `TRAP_ALIAS_RE` matching V8's `[as <trapname>]` alias annotation for any of 13 canonical Proxy trap names — structural tell (genuine native illegal-invocation `TypeError` never routes through differently-named object-literal trap handler) rather than signature match on `puppeteer-extra`'s specific `newHandler` variable name, so should survive future stealth rename. Verified live: stealth's score dropped `25 -> 0`; Playwright, Selenium, & raw-CDP scores unchanged (rule correctly stays quiet — no false positive on three independent unpatched engines, incl. this session's own Electron-based browser).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestStealthCaughtByCrossContextChecks` (asserts stays clean against current stealth), `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["tostring_proxy"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
