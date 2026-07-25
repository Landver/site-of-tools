# `framework_globals` — Automation framework globals present

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** yes

## What it checks

Automation frameworks leave own global variables on page (phantom, nightmare, __webdriver_evaluate, …), which no real site defines. List only catches frameworks that leak globals; custom or fully patched tooling won't appear here.

## Origin & history

Day-1 rule, broadened twice: **G13** (shipped 2026-07-18) extended `WINDOW_MARKERS` w/ Playwright binding hooks (`__pwInitScripts`, `__playwright__binding__`), wider Selenium/Watir canon, & Sequentum's `window.external` — CefSharp/Awesomium/CEF deliberately excluded from this hard-60 list since legit desktop apps embed those runtimes (`embedded_runtime` already covers that class). **G17** (2026-07-18) folded its suspect-name own-property sweep into this rule, extending from `document` to also cover `window`. **2026-07-19 finding:** Playwright's binding-hook markers don't fire against stock launch w/ no bindings exposed (see [checks/framework_globals.md](framework_globals.md) test status above) — see [roadmap/client-signals.md G13](../../roadmap/client-signals.md).

## Test status: Verified — mixed result

Caught all 7 of classic chromedriver's `$cdc_...` markers in audit (`-60`) — "works great against classic Selenium." No dedicated Go unit test asserts this rule directly (see below); only verification so far is the one real-Selenium data point.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["framework_globals"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
