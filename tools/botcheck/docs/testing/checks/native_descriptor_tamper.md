# `native_descriptor_tamper` — Native function has an impossible property descriptor

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Native fn's property descriptor doesn't match spec — naive monkey-patch gets enumerability/writability wrong. Downgraded to soft, cluster-only signal on 2026-07-21: current puppeteer-extra-stealth evades it (spreads original descriptor), while legit privacy extension patching DOM APIs can trip it -> on its own says little either way.

## Origin & history

**G04**, shipped 2026-07-17, same batch as `tostring_proxy`: property-descriptor/own-property sanity on native fns, per-spec enumerability (WebIDL operations `enumerable: true`, ECMA-262 built-ins not). Same-day real-Chrome end-to-end pass caught & fixed false positive before deploy: initial blanket-`enumerable: false` assertion false-fired on every real browser, since WebIDL operations enumerable by spec — probe now asserts enumerability per target family instead. Later found evaded by stealth's `replaceProperty` helper, which always spreads original descriptor — see test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause (read from plugin's source): its `replaceProperty` helper always spreads *original* property descriptor before applying overrides, preserving `enumerable`/`configurable`/`writable` faithfully. No concrete sharpening idea (doesn't route through JS Proxy trap the way `tostring_proxy` does).

**Resolution (2026-07-21): downgraded consistency/25 → soft/8.** Since it adds nothing against stealth adversary it targeted, & only thing that trips it is naive patch or legit privacy extension (real human, whom two of these firing at 25 each dropped to 50/"suspicious"), moved to cluster-only soft tier — can no longer dock a human on its own, only corroborates when 3+ soft signals fire together. Same handling & precedent as CDP-trap trio. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestStealthCaughtByCrossContextChecks`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_descriptor_tamper"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
