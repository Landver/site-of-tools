# `native_descriptor_tamper` — Native function has an impossible property descriptor

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

A native function's property descriptor doesn't match the spec — a naive monkey-patch gets enumerability or writability wrong. Downgraded to a soft, cluster-only signal on 2026-07-21: current puppeteer-extra-stealth evades it (it spreads the original descriptor), while a legitimate privacy extension patching DOM APIs can trip it, so on its own it says little either way.

## Origin & history

**G04**, shipped 2026-07-17, same batch as `tostring_proxy`: property-descriptor/own-property sanity on native functions, per-spec enumerability (WebIDL operations are `enumerable: true`, ECMA-262 built-ins are not). A same-day real-Chrome end-to-end pass caught and fixed a false positive before deploy: an initial blanket-`enumerable: false` assertion false-fired on every real browser, since WebIDL operations are enumerable by spec — the probe now asserts enumerability per target family instead. Later found evaded by stealth's `replaceProperty` helper, which always spreads the original descriptor — see the test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause (read from the plugin's source): its `replaceProperty` helper always spreads the *original* property descriptor before applying overrides, preserving `enumerable`/`configurable`/`writable` faithfully. No concrete sharpening idea (this doesn't route through a JS Proxy trap the way `tostring_proxy` does).

**Resolution (2026-07-21): downgraded consistency/25 → soft/8.** Since it adds nothing against the stealth adversary it targeted, and the only thing that trips it is a naive patch or a legitimate privacy extension (a real human, whom two of these firing at 25 each dropped to 50/"suspicious"), it was moved to the cluster-only soft tier — it can no longer dock a human on its own, and only corroborates when three or more soft signals fire together. Same handling and precedent as the CDP-trap trio. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestStealthCaughtByCrossContextChecks`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_descriptor_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
