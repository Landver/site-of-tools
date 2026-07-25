# `tz_self_inconsistent` — Timezone name disagrees with getTimezoneOffset()

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

Browser IANA timezone name implies different UTC offset than Date().getTimezoneOffset() reports — spoofers commonly change one & forget other. Needs no IP lookup; genuinely misconfigured machine could trip it -> weighs less than a hard tell.

## Origin & history

Internal-backlog Layer 2 item, shipped: compares `Intl.DateTimeFormat().resolvedOptions().timeZone` (IANA name) against `getTimezoneOffset()` — Go resolves zone w/ `time.LoadLocation` (embedding `time/tzdata`) at request time, threaded in as `Signals.Now` to keep `Evaluate` pure. IP-independent, unlike `tz_mismatch`.

## Test status: Verified — fires correctly

Real-browser probe (`fire-branch-probe.mjs`): overrode `getTimezoneOffset()`, real IANA zone name untouched -> fired. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["tz_self_inconsistent"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
