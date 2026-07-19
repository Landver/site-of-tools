# `native_descriptor_tamper` — Native function has an impossible property descriptor

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

A native function's property descriptor doesn't match the spec — patched-in fakes usually get enumerability or writability wrong. A privacy extension patching DOM APIs can leave the same trace, so this is a consistency hit, not standalone bot proof.

## Origin & history

**G04**, shipped 2026-07-17, same batch as `tostring_proxy`: property-descriptor/own-property sanity on native functions, per-spec enumerability (WebIDL operations are `enumerable: true`, ECMA-262 built-ins are not). A same-day real-Chrome end-to-end pass caught and fixed a false positive before deploy: an initial blanket-`enumerable: false` assertion false-fired on every real browser, since WebIDL operations are enumerable by spec — the probe now asserts enumerability per target family instead. Later found evaded by stealth's `replaceProperty` helper, which always spreads the original descriptor — see the test status above.

## Test status: Verified — evaded (open gap)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause (read from the plugin's source): its `replaceProperty` helper always spreads the *original* property descriptor before applying overrides, preserving `enumerable`/`configurable`/`writable` faithfully. **Still open** — genuinely harder problem than `tostring_proxy`'s alias-frame fix, since this doesn't route through a JS Proxy trap at all; no concrete probe idea yet (see [next-steps.md item 3](../next-steps.md)).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestDeepTamperSignals`, `TestDeepTamperSkipsStalePayload`, `TestStealthPatchedBrowserScoresBot`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_descriptor_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
