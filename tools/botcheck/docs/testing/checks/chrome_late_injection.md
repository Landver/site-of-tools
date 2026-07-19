# `chrome_late_injection` — window.chrome was injected late (stealth bolt-on)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 15 · **Reads client signal:** yes

## What it checks

Traces of scripts injected into the page after load (the way CDP's Page.addScriptToEvaluateOnNewDocument installs automation shims) were observed — real browsers don't inject scripts into their own startup.

## Origin & history

**G22**, shipped 2026-07-18, same batch as `chrome_runtime_tamper`: flags `'chrome'` appearing among the last ~50 keys of both the enumerable window keys and the own property names — stealth patches inject `window.chrome` late, after page setup, rather than having it present from the start. Gated on a Chrome UA. Also evaded by current stealth — see the test status above.

## Test status: Verified — evaded (open gap)

**Evaded by `puppeteer-extra-plugin-stealth` 2.11.2**, one of six checks purpose-built for this class of stealth patch that missed it cleanly. Describes the general stealth-patch shape without a named root cause the way the other five got (no dedicated source-read finding for this one specifically). Open, no follow-up investigation yet — see [next-steps.md item 3](../next-steps.md).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestChromeRulesNeedAChromeUA`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["chrome_late_injection"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
