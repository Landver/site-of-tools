# `permission_impossible` — Impossible permission state (prompt while denied)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Permissions API says notifications would 'prompt' while Notification.permission is 'denied' — combination a genuine browser never shows. Historically caught automation that mocked Permissions API without keeping Notification mirror in sync.

## Origin & history

Original rule — predates 2026-07-17 competitor-gap audit (G01+), so no G-item shipment story to move here; part of first working scorer.

## Test status: Verified — fires correctly

Fired against genuine Playwright automation in audit (`-25`) — incidental catch (Playwright's default profile apparently leaves Permissions API in a state this rule flags), not deeply investigated beyond the one table row. No dedicated Go test references this rule ID directly either.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, incidental to broader table-driven test, not a dedicated assertion.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["permission_impossible"]` — same text live result page shows under this check's "why" expander. Update both together if check's behavior changes.
