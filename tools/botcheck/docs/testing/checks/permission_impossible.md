# `permission_impossible` — Impossible permission state (prompt while denied)

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The Permissions API says notifications would 'prompt' while Notification.permission is 'denied' — a combination a genuine browser never shows. It historically caught automation that mocked the Permissions API without keeping the Notification mirror in sync.

## Origin & history

Original rule — predates the 2026-07-17 competitor-gap audit (G01+), so there's no G-item shipment story to move here; it was part of the first working scorer.

## Test status: Verified — fires correctly

Fired against genuine Playwright automation in the audit (`-25`) — an incidental catch (Playwright's default profile apparently leaves the Permissions API in a state this rule flags), not deeply investigated beyond the one table row. No dedicated Go test references this rule ID directly either.

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

No test references this rule ID directly — coverage, if any, is incidental to a broader table-driven test, not a dedicated assertion.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["permission_impossible"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
