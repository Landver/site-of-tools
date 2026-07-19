# `accept_language_missing` — Browser User-Agent but no Accept-Language header

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-only)

## What it checks

Every real browser sends Accept-Language. Its total absence suggests a scripted client; kept soft because a proxy can strip the header in transit.

## Origin & history

**G06**, shipped 2026-07-17, same batch as `accept_encoding_missing`: total absence of `Accept-Language` on a browser-claimed UA, kept soft for the same proxy-stripping caveat.

## Test status: Verified — fires correctly

Curl-verified both directions vs local dev: fires w/ browser UA + no header, stays `ok` w/ header present or non-browser UA. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeaderPresenceSignals`; `tests/handler_test.go`: `TestCheckHeaderClusterThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["accept_language_missing"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
