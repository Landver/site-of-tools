# `screen_avail_impossible` — Available screen area larger than the physical screen

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

The available screen area is reported larger than the physical screen — impossible on a real display, and the sign of a spoofed screen object that doesn't model taskbar/menu-bar math.

## Origin & history

Internal-backlog Layer 1 item, shipped: `availWidth`/`availHeight` larger than the physical screen — impossible on a real display, the sign of a spoofed screen object that doesn't model taskbar/menu-bar math.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `screen.availWidth` to `99999` → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["screen_avail_impossible"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
