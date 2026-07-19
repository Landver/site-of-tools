# `sec_fetch_missing` — Browser User-Agent but no Sec-Fetch-* headers

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-only)

## What it checks

A browser-claimed User-Agent but no Sec-Fetch-* headers, which real browsers send on every navigation and fetch. Scripted clients usually don't bother — but a proxy in the path can strip headers too, the caveat that keeps this soft.

## Origin & history

Internal-backlog Layer 1 item, shipped: a browser-claimed UA sending no `Sec-Fetch-*` headers, which real browsers send on every navigation/fetch. Kept soft rather than hard for the same reason as the **G06** header rules — a proxy in the path can strip headers too.

## Test status: Verified — fires correctly

Curl-verified both directions against local dev: browser UA + no `Sec-Fetch-Mode` fires; header present stays `ok`; non-browser UA never fires (gated by `looksLikeBrowser`). Confirmed clean on a real `POST /check` mimicking the collector's own `fetch` headers too. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestSecFetchMissingFlagsScriptedBrowserUA`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["sec_fetch_missing"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
