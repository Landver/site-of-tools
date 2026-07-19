# `zero_outer_height` — window.outerHeight is zero

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

window.outerHeight is exactly 0 — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Origin & history

Internal-backlog item, shipped 2026-07-18 (v3-gated, guarded so stale pre-v3 payloads skip rather than false-fire): `window.outerHeight` exactly `0` while `innerHeight` is positive — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.

## Test status: Verified — fires correctly

Confirmed three ways. Constructed: real-browser probe (`automation-harness/fire-branch-probe.mjs`) overrode `window.outerHeight` to `0`, fired through the real collector. Genuine off-the-shelf automation: plain headless Puppeteer with no window-size flag set reports a real `outerHeight: 0` on its own, no override needed. Genuine human, no automation at all: the user's actual Chrome 149/macOS (via the Claude-in-Chrome connector) scored 100/100 "Looks human" but this one line read **flagged** — `window.outerHeight` genuinely read 0 under that extension-driven browsing session. All three land safely: this is exactly why the rule is soft-tier and only bites inside a ≥3-signal cluster — the real false-positive case cost nothing. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestQuickWinSignals`, `TestV3Signals`, `TestV3GateSkipsStalePayload`; `tests/handler_test.go`: `TestCheckStaleV2PayloadScores100ThroughHandler`; `tests/report_test.go`: `TestExplanation`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["zero_outer_height"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
