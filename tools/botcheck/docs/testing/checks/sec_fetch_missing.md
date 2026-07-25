# `sec_fetch_missing` — Browser User-Agent but no Sec-Fetch-* headers

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-only)

## What it checks

Browser-claimed User-Agent but no Sec-Fetch-* headers, which real browsers send on every navigation & fetch. Scripted clients usually don't bother — but proxy in path can strip headers too, caveat that keeps this soft.

## Origin & history

Internal-backlog Layer 1 item, shipped: browser-claimed UA sending no `Sec-Fetch-*` headers, which real browsers send on every navigation/fetch. Kept soft not hard for same reason as **G06** header rules — proxy in path can strip headers too.

## Test status: Verified — fires correctly

Curl-verified both directions vs local dev: fires w/ browser UA + no `Sec-Fetch-Mode`, stays `ok` w/ header present or non-browser UA. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestSecFetchMissingFlagsScriptedBrowserUA`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["sec_fetch_missing"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
