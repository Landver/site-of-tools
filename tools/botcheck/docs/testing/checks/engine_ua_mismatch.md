# `engine_ua_mismatch` — Feature-detected engine ≠ engine the User-Agent claims

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

Page feature-detects real rendering engine (Blink/Gecko/WebKit) & compares to engine UA claims — UA string cannot change what engine actually supports. Only confident disagreement fires; engine that can't be identified is no signal.

## Origin & history

**G05**, shipped 2026-07-17: `engineFamily()` feature-detects real rendering engine independent of UA string (`-moz-appearance` ⇒ Gecko, `GestureEvent` ⇒ WebKit, `-webkit-app-region`/`webkitRequestFileSystem` ⇒ Blink), compared against engine `engineFromUA` infers from claimed UA — robust against spoofed UA string a parse would otherwise trust.

## Test status: Verified — fires correctly

Real-browser probe (`ua-mismatch-probe.mjs`): UA claimed Firefox, real engine stayed Blink -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["engine_ua_mismatch"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
