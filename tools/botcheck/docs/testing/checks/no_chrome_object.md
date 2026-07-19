# `no_chrome_object` — window.chrome missing on a Chrome User-Agent

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

A Chrome User-Agent but no window.chrome object, which real desktop Chrome always exposes. Some Chromium forks drop it honestly, so it only counts in a cluster.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): `window.chrome = undefined` → fired. (`delete`/`defineProperty` throws on this build — plain assignment works.) See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["no_chrome_object"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
