# `engine_ua_mismatch` — Feature-detected engine ≠ engine the User-Agent claims

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** ua · **Weight:** 30 · **Reads client signal:** yes

## What it checks

The page feature-detects the real rendering engine (Blink/Gecko/WebKit) and compares it to the engine the User-Agent claims — a UA string cannot change what the engine actually supports. Only a confident disagreement fires; an engine that can't be identified is no signal.

## Origin & history

**G05**, shipped 2026-07-17: `engineFamily()` feature-detects the real rendering engine independent of the UA string (`-moz-appearance` ⇒ Gecko, `GestureEvent` ⇒ WebKit, `-webkit-app-region`/`webkitRequestFileSystem` ⇒ Blink), compared against the engine `engineFromUA` infers from the claimed User-Agent — robust against a spoofed UA string a parse would otherwise trust.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`; `tests/handler_test.go`: `TestCheckQuickWinSignalsThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["engine_ua_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
