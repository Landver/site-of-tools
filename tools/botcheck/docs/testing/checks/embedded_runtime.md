# `embedded_runtime` — User-Agent is an embedded app runtime (Electron/CEF)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** no (server-only)

## What it checks

The User-Agent belongs to an embedded runtime (Electron, CEF, QtWebEngine, NW.js): a real Chromium engine wrapped in a desktop app. Legitimate for an app, but unusual for browsing arbitrary sites — and the standard shell for custom automation — so it reads as suspicious, not definitive.

## Origin & history

Original day-1 rule, its scope clarified by **G13** (2026-07-18): CefSharp/Awesomium/CEF are deliberately excluded from `framework_globals`'s hard-60 automation-marker list specifically because this rule already covers that class of legitimate desktop app embedding a Chromium engine — a division of labor between the two rules, not an oversight.

## Test status: Verified — fires correctly

Real-browser probe set an Electron-flavored UA → fired. Reconfirmed live: this session's own in-app browser genuinely is Electron-embedded, scored 75/100 with this as the only deduction. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestElectronUAIsSuspiciousNotHardBot`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["embedded_runtime"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
