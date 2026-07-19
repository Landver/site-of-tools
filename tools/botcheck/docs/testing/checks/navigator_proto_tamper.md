# `navigator_proto_tamper` — Navigator.prototype accessor descriptor anomaly (webdriver/plugins/languages)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The Navigator prototype chain was modified — replaced getters or unexpected own properties, which is how 'undeletable' webdriver patches are installed. Legitimate extensions can touch it too, so it reads as tamper evidence, not a verdict.

## Origin & history

**G17**, shipped 2026-07-18: per WebIDL, `webdriver`/`plugins`/`languages` must be native, getter-only, enumerable+configurable accessors living on `Navigator.prototype`, never own data properties on the instance — how "undeletable" webdriver patches get installed. Only confident anomalies fire; any probe failure reads as a pass, not evidence. Later found evaded: post-Chrome-89, `puppeteer-extra-plugin-stealth` needs no JS patch here at all (its `beforeLaunch` hook appends a launch flag instead) — see the test status above.

## Test status: Verified — evaded (open gap)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Root cause (read from the plugin's source): post-Chrome-89, `navigator.webdriver` needs no JS patch at all — the plugin's `beforeLaunch` hook just appends `--disable-blink-features=AutomationControlled` to the launch args, before the page (and this probe) ever runs. **Still open** — genuinely separate, harder problem; no concrete probe idea yet (see [next-steps.md item 3](../next-steps.md)).

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["navigator_proto_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
