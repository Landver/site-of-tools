# `accept_nav_mismatch` — Browser User-Agent but Accept doesn't include text/html

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** soft · **Weight:** 8 · **Reads client signal:** no (server-only)

## What it checks

A real browser's navigation/fetch Accept includes text/html; bare API clients send */* or application/json. Legitimate JSON consumers of this tool trip it too — harmless, because one soft signal alone never moves the score.

## Origin & history

**G06**, shipped 2026-07-17, same batch: a browser-claimed UA whose navigation/fetch `Accept` doesn't include `text/html` — bare API clients send `*/*` or `application/json` instead. Legitimate JSON consumers of this tool trip it too, harmless since one soft signal alone never moves the score.

## Test status: Verified — fires correctly

Curl-verified both directions: `Accept: application/json` (curl's own default when requesting JSON) fires, exactly as the doc comment expects for a JSON API caller. A real `POST /check` mimicking the collector's own `fetch` call (`Accept: text/html`, per `botcheck.js`) stays `ok`. See [finding](../findings/2026-07-19-remaining-43-checks-sweep.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestHeaderPresenceSignals`; `tests/handler_test.go`: `TestCheckHeaderClusterThroughHandler`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["accept_nav_mismatch"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
