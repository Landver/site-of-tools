# `chrome_runtime_tamper` — window.chrome.runtime fails the integrity probe

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft (downgraded from consistency/internals 2026-07-21) · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.chrome & its runtime sub-object lack the shape real Chrome ships — naive fake built to pass hasChromeObject-style checks usually misses properties or prototypes. Downgraded to soft, cluster-only 2026-07-21: puppeteer-extra-plugin-stealth 2.11.2 fakes chrome.runtime perfectly (evading it), AND official Chrome for Testing binary lacks chrome.runtime entirely (so tightening risked flagging real visitors) — leaving it able to catch only naive fake, not worth individual deduction.

## Origin & history

**G22**, shipped 2026-07-18: genuine `chrome.runtime.sendMessage`/`connect` are native non-constructors (no own `prototype`, `new fn()` throws `TypeError`) — stealth-bolted fake usually gets shape or error constructor wrong. Gated on Chrome UA. Single most heavily investigated check in 2026-07-19 audit (evaded, tightened fix drafted & reverted, then deprioritized) — full story in test status above.

## Test status: Known gap → downgraded to soft (2026-07-21)

**Resolution (2026-07-21): downgraded consistency/20 → soft/8.** Investigation below already concluded this check can at best catch only *naive* bots (stealth fakes it perfectly, & tightening risked flagging real Chrome-for-Testing visitors). A signal catching only what other checks already catch, at cost of real false-positive risk, doesn't belong in load-bearing consistency tier — moved to cluster-only soft tier alongside other deep-tamper probes. "More promising open angle" below (alias-frame stack-leak fix, needs HTTPS target to verify) remains valid future sharpening; if it lands & proves out vs real stealth, can be re-promoted. Full rationale: [the downgrade finding](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

### Prior investigation (why it was a known gap)

**Most heavily investigated open item in whole audit — evaded, fix drafted, then deliberately reverted.** Evaded cleanly by `puppeteer-extra-plugin-stealth` 2.11.2 (one of six stealth-targeted checks missed). A tightened version (flag `window.chrome` existing w/ `runtime` totally absent) verified to close stealth gap (score `25 -> 5`), but before shipping, official "Chrome for Testing" binary itself found to lack `chrome.runtime` too — headless & headful, even w/ automation flags stripped — so tightened rule risked scoring real human visitors as tampered. Reverted. A second, extension-controlled consumer-Chrome-149 sample (via Claude in Chrome) showed same absence, still not a clean organic baseline. **Deprioritized 2026-07-19**, not because data point unobtainable, but because reading stealth's own source shows `chrome.runtime`'s evasion only activates when real thing *already* missing — so even a clean organic-Chrome answer would only ever justify catching *naive* bots (already caught several other ways), never a stealth-equipped one. Left exactly as shipped (lenient, absence-tolerant). **More promising open angle, untested:** `chromeRuntimeOK()`'s call/construct traps share `tostring_proxy`'s old shape (check `e instanceof TypeError`, never `e.stack`) — plausibly same alias-frame stack-leak fix would catch stealth's fake regardless of real-Chrome-baseline question, but stealth's `chrome.runtime` evasion only activates on secure (HTTPS) origin, & this harness's target is plain HTTP `localhost` — needs HTTPS target to verify, deliberately not tried vs production.

See findings: [1](../findings/2026-07-19-multi-framework-matrix-results.md), [2](../findings/2026-07-19-puppeteer-extra-stealth-source-read.md), [3](../findings/2026-07-21-internals-tamper-downgraded-to-soft.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`, `TestChromeRulesNeedAChromeUA`, `TestInternalsTamperDowngradedToSoft`, `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckV3SignalsThroughHandler`, `TestCheckStaleV2PayloadScores100ThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["chrome_runtime_tamper"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
