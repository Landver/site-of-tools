# `tz_self_inconsistent` — Timezone name disagrees with getTimezoneOffset()

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** consistency · **Subgroup:** internals · **Weight:** 25 · **Reads client signal:** yes

## What it checks

The browser's IANA timezone name implies a different UTC offset than Date().getTimezoneOffset() reports — spoofers commonly change one and forget the other. Needs no IP lookup at all; a genuinely misconfigured machine could trip it, which is why it weighs less than a hard tell.

## Origin & history

Internal-backlog Layer 2 item, shipped: compares `Intl.DateTimeFormat().resolvedOptions().timeZone` (IANA name) against `getTimezoneOffset()` — Go resolves the zone with `time.LoadLocation` (embedding `time/tzdata`) at request time, threaded in as `Signals.Now` to keep `Evaluate` pure. IP-independent, unlike `tz_mismatch`.

## Test status: Not yet tested against real automation

No real-automation-harness finding yet.

## Go scorer coverage

`tests/botcheck_test.go`: `TestLayer2Signals`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["tz_self_inconsistent"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
