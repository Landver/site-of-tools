# `accept_encoding_missing` — Browser User-Agent but no Accept-Encoding header

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-only)

## What it checks

Every real browser sends Accept-Encoding (they all support at least gzip); its absence means a scripted client that didn't bother, or a proxy that rewrote it — the caveat that keeps this soft.

## Origin & history

**G06**, shipped 2026-07-17, one of three soft header-presence rules (with `accept_language_missing`, `accept_nav_mismatch`), keyed on `looksLikeBrowser(UA)`. Every real browser sends `Accept-Encoding` (all support at least gzip); kept soft, not hard, specifically because a proxy in the path can strip or rewrite it. `Upgrade-Insecure-Requests` was captured but deliberately left unused: Safari never sends it, so any rule requiring it would false-positive real Safari.

## Test status: Verified — fires correctly

Curl-verified both directions vs local dev: fires w/ browser UA + no header, stays `ok` w/ header present or non-browser UA. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeaderPresenceSignals`, `TestSingleHeaderSoftSignalStaysHuman`; `tests/handler_test.go`: `TestCheckHeaderClusterThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["accept_encoding_missing"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
