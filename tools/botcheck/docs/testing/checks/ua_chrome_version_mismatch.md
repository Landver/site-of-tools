# `ua_chrome_version_mismatch` — User-Agent Chrome version ≠ userAgentData version

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The Chrome major version in the UA string must equal the Chromium version userAgentData reports — even forks like Opera or Vivaldi expose the true engine version there. A mismatch means the UA was hand-edited or frozen, as anti-detect and older Electron setups do.

## Origin & history

**G01**, shipped 2026-07-17, trimmed same day: compares the UA's `Chrome/NNN` major version against the `Chromium` entry of `navigator.userAgentData.getHighEntropyValues(['fullVersionList'])` (not the fork's own branded entry — comparing against Opera's/Vivaldi's own version would false-positive real users of those browsers). A same-day review fixed exactly that false positive (Opera/Vivaldi/Yandex/Samsung scoring "suspicious") by re-anchoring on the `Chromium` entry specifically. `platformVersion`/`uaFullVersion`/`architecture`/`bitness`/`model` were requested briefly then dropped as unused (YAGNI) — no rule ended up needing them.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["ua_chrome_version_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
