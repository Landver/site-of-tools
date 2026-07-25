# `screen_avail_impossible` — Available screen area larger than the physical screen

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** yes

## What it checks

Available screen area reported larger than physical screen — impossible on real display, sign of spoofed screen object not modeling taskbar/menu-bar math.

## Origin & history

Internal-backlog Layer 1 item, shipped: `availWidth`/`availHeight` larger than physical screen — impossible on real display, sign of spoofed screen object not modeling taskbar/menu-bar math.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `screen.availWidth` to `99999` → fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["screen_avail_impossible"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
