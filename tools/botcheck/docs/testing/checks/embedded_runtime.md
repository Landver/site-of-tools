# `embedded_runtime` — User-Agent is an embedded app runtime (Electron/CEF)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** no (server-only)

## What it checks

UA belongs to embedded runtime (Electron, CEF, QtWebEngine, NW.js): real Chromium engine wrapped in desktop app. Legit for app, but unusual for browsing arbitrary sites, & standard shell for custom automation -> reads suspicious, not definitive.

## Origin & history

Day-1 rule, scope clarified by **G13** (2026-07-18): CefSharp/Awesomium/CEF deliberately excluded from `framework_globals`'s hard-60 automation-marker list because this rule already covers that class of legit desktop app embedding Chromium engine — division of labor between the two rules, not oversight.

## Test status: Verified — fires correctly

Real-browser probe set Electron-flavored UA -> fired. Reconfirmed live: this session's own in-app browser genuinely is Electron-embedded, scored 75/100 w/ this as only deduction. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestElectronUAIsSuspiciousNotHardBot`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["embedded_runtime"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
