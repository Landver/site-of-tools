# `chrome_late_injection` — window.chrome was injected late (stealth bolt-on)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.chrome appears among last window keys, as if bolted on after startup rather than created during page setup — old CreepJS hasHighChromeIndex tell for a late-injected fake. Soft, cluster-only since 2026-07-21: current stealth fakes chrome.runtime in place instead of late-injecting, so this only catches naive bolt-on.

## Origin & history

**G22**, shipped 2026-07-18, same batch as `chrome_runtime_tamper`: flags `'chrome'` appearing among last ~50 keys of both enumerable window keys & own property names — stealth patches inject `window.chrome` late, after page setup, rather than present from start. Gated on Chrome UA. Also evaded by current stealth — see test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Current stealth fakes `chrome.runtime` in place rather than late-injecting a fake `window.chrome`, so "high chrome index" premise no longer catches it.

**Resolution (2026-07-21): downgraded consistency/15 → soft/8**, w/ other four deep-tamper probes — catches only naive bolt-on, so corroborates as part of soft cluster now rather than docking on its own. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestChromeRulesNeedAChromeUA`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["chrome_late_injection"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
