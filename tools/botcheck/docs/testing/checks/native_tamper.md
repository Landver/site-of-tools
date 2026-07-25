# `native_tamper` — A native function was monkey-patched (toString)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 45 · **Reads client signal:** yes

## What it checks

Built-in JS fns stringify as '[native code]'; automation stealth patches that replace them (usually to hide webdriver) often fail this check. Only catches shallow patches — Proxy-based replacement fakes the string, which is what toString-proxy probe is for.

## Origin & history

Original day-1 rule — shallow `[native code]` `toString()` check on handful of natives. **G04** (shipped 2026-07-17) added deeper probes that became `tostring_proxy`, `native_descriptor_tamper`, & `native_callnew_tamper` as separate rules, specifically because this shallow check alone doesn't catch Proxy-based replacement that fakes native string.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): crude non-Proxy `Function.prototype.toString` replacement → fired, confirming shallow/deep split vs `tostring_proxy` (which catches Proxy-based version stealth actually uses). See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestEveryRuleCanFire`; `tests/handler_test.go`: `TestCheckDeepTamperSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["native_tamper"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
