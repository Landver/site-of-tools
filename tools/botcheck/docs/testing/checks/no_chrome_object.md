# `no_chrome_object` — window.chrome missing on a Chrome User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Chrome User-Agent but no window.chrome object, which real desktop Chrome always exposes. Some Chromium forks drop it honestly, so counts only in a cluster.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): `window.chrome = undefined` → fired. (`delete`/`defineProperty` throws on this build — plain assignment works.) See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["no_chrome_object"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
