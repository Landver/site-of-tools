# `chrome_runtime_tamper` — window.chrome.runtime fails the integrity probe

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.chrome and its runtime sub-object don't have the shape real Chrome ships — a naive fake built to pass hasChromeObject-style checks usually misses properties or prototypes. Downgraded to soft, cluster-only on 2026-07-21: puppeteer-extra-plugin-stealth 2.11.2 fakes chrome.runtime perfectly (evading it), AND the official Chrome for Testing binary lacks chrome.runtime entirely (so tightening it risked flagging real visitors) — leaving it able to catch only a naive fake, which is not worth an individual deduction.

## Origin & history

**G22**, shipped 2026-07-18: genuine `chrome.runtime.sendMessage`/`connect` are native non-constructors (no own `prototype`, `new fn()` throws a `TypeError`) — a stealth-bolted fake usually gets the shape or error constructor wrong. Gated on a Chrome UA. The single most heavily investigated check in the 2026-07-19 audit (evaded, a tightened fix drafted and reverted, then deprioritized) — full story in the test status above.

## Test status: Known gap → downgraded to soft (2026-07-21)

**Resolution (2026-07-21): downgraded consistency/20 → soft/8.** The investigation below already concluded this check can, at best, catch only *naive* bots (stealth fakes it perfectly, and tightening it risked flagging real Chrome-for-Testing visitors). A signal that catches only what other checks already catch, at the cost of a real false-positive risk, does not belong in the load-bearing consistency tier — it moved to the cluster-only soft tier alongside the other deep-tamper probes. The "more promising open angle" below (the alias-frame stack-leak fix, needs an HTTPS target to verify) remains a valid future sharpening; if it lands and proves out against real stealth, this can be re-promoted. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

### Prior investigation (why it was a known gap)

**The most heavily investigated open item in the whole audit — evaded, a fix drafted, then deliberately reverted.** Evaded cleanly by `puppeteer-extra-plugin-stealth` 2.11.2 (one of six stealth-targeted checks missed). A tightened version (flag `window.chrome` existing with `runtime` totally absent) was verified to close the stealth gap (score `25 -> 5`), but before shipping it, the official "Chrome for Testing" binary itself was found to lack `chrome.runtime` too — headless and headful, even with automation flags stripped — so the tightened rule risked scoring real human visitors as tampered. Reverted. A second, extension-controlled consumer-Chrome-149 sample (via Claude in Chrome) showed the same absence, still not a clean organic baseline. **Deprioritized 2026-07-19**, not because the data point is unobtainable, but because reading stealth's own source shows `chrome.runtime`'s evasion only activates when the real thing is *already* missing — meaning even a clean organic-Chrome answer would only ever justify catching *naive* bots (already caught several other ways), never a stealth-equipped one. Left exactly as shipped (lenient, absence-tolerant). **More promising open angle, untested:** `chromeRuntimeOK()`'s call/construct traps share `tostring_proxy`'s old shape (check `e instanceof TypeError`, never `e.stack`) — plausibly the same alias-frame stack-leak fix would catch stealth's fake regardless of the real-Chrome-baseline question, but stealth's `chrome.runtime` evasion only activates on a secure (HTTPS) origin, and this harness's target is plain HTTP `localhost` — needs an HTTPS target to verify, deliberately not tried against production.

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`, `TestChromeRulesNeedAChromeUA`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["chrome_runtime_tamper"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
