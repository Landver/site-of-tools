# `navigator_proto_tamper` — Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Navigator prototype chain modified — replaced getters or unexpected own properties, way hand-rolled 'undeletable' webdriver patch installed. Soft, cluster-only since 2026-07-21: modern stealth hides webdriver w/ launch flag, never touches prototype -> catches only naive patch or legit extension — tamper evidence, not verdict.

## Origin & history

**G17**, shipped 2026-07-18: per WebIDL, `webdriver`/`plugins`/`languages` must be native, getter-only, enumerable+configurable accessors on `Navigator.prototype`, never own data properties on instance — how "undeletable" webdriver patches installed. Only confident anomalies fire; any probe failure = pass, not evidence. Later found evaded: post-Chrome-89, `puppeteer-extra-plugin-stealth` needs no JS patch here (its `beforeLaunch` hook appends launch flag instead) — see test status above.

## Test status: Verified — evaded → downgraded to soft (2026-07-21)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it. Root cause (from plugin source): post-Chrome-89, `navigator.webdriver` needs no JS patch — plugin's `beforeLaunch` hook appends `--disable-blink-features=AutomationControlled` to launch args, before page (& this probe) runs.

**Resolution (2026-07-21): downgraded consistency/25 → soft/8.** Whole prototype-patch angle bypassed by modern stealth -> only catches naive hand-patch or privacy extension, so moved to cluster-only soft tier alongside other deep-tamper probes. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["navigator_proto_tamper"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
