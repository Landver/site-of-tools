# `navigator_proto_tamper` — Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The Navigator prototype chain was modified — replaced getters or unexpected own properties, the way a hand-rolled 'undeletable' webdriver patch is installed. Soft, cluster-only since 2026-07-21: modern stealth hides webdriver with a launch flag and never touches the prototype, so this catches only a naive patch or a legitimate extension — tamper evidence, not a verdict.

## Origin & history

**G17**, shipped 2026-07-18: per WebIDL, `webdriver`/`plugins`/`languages` must be native, getter-only, enumerable+configurable accessors living on `Navigator.prototype`, never own data properties on the instance — how "undeletable" webdriver patches get installed. Only confident anomalies fire; any probe failure reads as a pass, not evidence. Later found evaded: post-Chrome-89, `puppeteer-extra-plugin-stealth` needs no JS patch here at all (its `beforeLaunch` hook appends a launch flag instead) — see the test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause (read from the plugin's source): post-Chrome-89, `navigator.webdriver` needs no JS patch at all — the plugin's `beforeLaunch` hook just appends `--disable-blink-features=AutomationControlled` to the launch args, before the page (and this probe) ever runs.

**Resolution (2026-07-21): downgraded consistency/25 → soft/8.** With the whole prototype-patch angle bypassed by modern stealth, this only catches a naive hand-patch or a privacy extension, so it moved to the cluster-only soft tier alongside the other deep-tamper probes. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["navigator_proto_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
