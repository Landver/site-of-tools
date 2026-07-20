# `chrome_late_injection` — window.chrome was injected late (stealth bolt-on)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.chrome appears among the last window keys, as if bolted on after startup rather than created during page setup — the old CreepJS hasHighChromeIndex tell for a late-injected fake. Soft, cluster-only since 2026-07-21: current stealth fakes chrome.runtime in place instead of late-injecting, so this only catches a naive bolt-on.

## Origin & history

**G22**, shipped 2026-07-18, same batch as `chrome_runtime_tamper`: flags `'chrome'` appearing among the last ~50 keys of both the enumerable window keys and the own property names — stealth patches inject `window.chrome` late, after page setup, rather than having it present from the start. Gated on a Chrome UA. Also evaded by current stealth — see the test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Current stealth fakes `chrome.runtime` in place rather than late-injecting a fake `window.chrome`, so the "high chrome index" premise no longer catches it.

**Resolution (2026-07-21): downgraded consistency/15 → soft/8**, with the other four deep-tamper probes — able to catch only a naive bolt-on, so it corroborates as part of a soft cluster now rather than docking on its own. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestChromeRulesNeedAChromeUA`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["chrome_late_injection"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
