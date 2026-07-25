# `ua_chrome_version_mismatch` — User-Agent Chrome version ≠ userAgentData version

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Chrome major version in UA string must equal Chromium version userAgentData reports — even forks like Opera/Vivaldi expose true engine version there. Mismatch means UA hand-edited or frozen, as anti-detect & older Electron setups do.

## Origin & history

**G01**, shipped 2026-07-17, trimmed same day: compares UA's `Chrome/NNN` major version against `Chromium` entry of `navigator.userAgentData.getHighEntropyValues(['fullVersionList'])` (not fork's own branded entry — comparing against Opera's/Vivaldi's own version would false-positive real users of those browsers). Same-day review fixed exactly that false positive (Opera/Vivaldi/Yandex/Samsung scoring "suspicious") by re-anchoring on `Chromium` entry specifically. `platformVersion`/`uaFullVersion`/`architecture`/`bitness`/`model` requested briefly then dropped as unused (YAGNI) — no rule needed them.

## Test status: Verified — fires correctly

Curl `POST /check`: client JSON claiming `Chrome/999` vs `uaData` claiming real Chromium `125` -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_chrome_version_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
