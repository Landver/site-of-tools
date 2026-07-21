# Bot check — architecture: package layout, request flow, routes

*(part of the [botcheck docs index](README.md))*

## Package layout (`botcheck/`, mirrors `iptools/`)

- `botcheck.go` — **pure domain**: `Signals`, `Check`, `Report`, `Evaluate`, signal
  helpers. No `echo`, no `iptools` import — tests construct `Signals` directly, no
  HTTP, no databases.
- `scoring.go` — ordered weighted rule set (68 rules: hard tells → consistency
  cross-checks → soft heuristics) and soft-signal combination rule. See
  [scoring-model.md](scoring-model.md).
- `corpus.go` — Mongo fingerprint corpus (G41/G42 reuse + G43 churn): nil-safe repository (mirrors
  `iptools/history.go`) recording fingerprint sightings, counting distinct IPs per
  hash (reuse) and distinct fingerprints per IP within a short window (churn).
  Disabled Mongo turns it into a no-op. See [storage.md](storage.md).
- `handler.go` — transport: parses client payload, gathers server signals off
  `*echo.Context`, maps shared `iptools.Service` result into plain `Signals`
  fields, folds fingerprint into Mongo corpus (G41/G42), serves the
  `/botcheck-sw.js` Service Worker script, calls `Evaluate`, content-negotiates
  the response.
- `report.go` — presentation helpers: rule explanations (`Explanation`/
  `ruleExplanations`), browser/engine display line (`Environment`).
- `goodbots.go` — verified-crawler classifier: `BotIdentity`, good-bot allowlist,
  `classifyGoodBot` (called from `Evaluate` to suppress expected deductions).
- `templates/` — `botcheck/index` (page) + `botcheck/result` (fragment).
- `tests/` — black-box domain + handler tests. See [go-test-suite.md](go-test-suite.md).
- collector: `shared/static/js/botcheck.js` (hand-vendored, no npm). See
  [signals-client.md](signals-client.md) and
  [collector-provenance.md](collector-provenance.md).

**Layering (the important part).** `botcheck.go` is pure function of a plain
`Signals` struct — imports neither `echo` nor `iptools`, tests need no BIN
databases (build `Signals` directly, same trick `iptools` uses with its `Looker`
interface). **Handler** does all impure work: bind client JSON, read headers off
`*echo.Context`, call `iptools.Service.Lookup(...)` for IP facts, *map*
`*iptools.Result` into `Signals` fields, call `Evaluate`, then `platform.Respond`.
Reusing `iptools.Looker` means handler test injects a fake IP service (no 1.7 GB
PX12 BIN in CI), nil service degrades gracefully exactly as it does for IP tool.
Straight application of
[ARCHITECTURE.md §4](../../../docs/ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this).

## Request flow

```
Browser                          Go (botcheck.corpberry.com app)
  │  GET /  ───────────────────▶ handler.index
  │                               renders page shell + server "your request" card
  │  ◀── HTML page + <script src="/static/js/botcheck.js">
  │
  │  (collector runs: navigator/canvas/webgl/worker/iframe/CDP/… )
  │  POST /check  {fingerprint JSON}  ─▶ handler.check
  │      Accept: text/html                 1. c.Bind(&payload)   (parse client JSON)
  │                                        2. gather server signals from *echo.Context
  │                                        3. iptools.Service.Lookup(c.RealIP())  (IP rep/geo/tz)
  │                                        4. build botcheck.Signals{client + server}
  │                                        5. fold into the Mongo corpus (Record) and read back
  │                                           the distinct-IP count (DistinctIPs) → FingerprintIPs
  │                                           (G41/G42; no-ops on a disabled/nil corpus)
  │                                        6. report := botcheck.Evaluate(signals)   ← pure domain
  │                                        7. respond: HTML fragment | JSON
  │  ◀── results-table fragment (browser)  or  JSON (curl/API)
  └── collector injects fragment into #result
```

**Verdict is server-only.** POSTed fingerprint trivially forgeable, so client just
collects, never scores. API/CLI caller can skip browser entirely — `POST /check`
with JSON body (no `text/html` in `Accept`) returns `Report` as JSON, client
fields it can't supply simply absent (scorer treats absent client signals as
non-triggering, so bare server-only call still returns IP-based partial score).

## Routes & content negotiation

| Route | Browser | curl / API (JSON) |
|---|---|---|
| `GET /` | Full page; collector then POSTs `/check` | Server-only score (headers + IP, no JS signals) |
| `POST /check` | HTML results fragment | Full JSON `Report` |
| `GET /botcheck-sw.js` | Service Worker script (`application/javascript`) | same |

```sh
# server-only score of your request (no JS signals)
curl https://botcheck.corpberry.com
# score a fingerprint you collected yourself
curl -X POST https://botcheck.corpberry.com/check \
  -H 'Content-Type: application/json' -d '{"webdriver":true}'
```

## Client-Hints opt-in (an Echo v5 detail)

Chromium sends low-entropy hints (`Sec-CH-UA`, `Sec-CH-UA-Mobile`,
`Sec-CH-UA-Platform`) by default on secure origins. `GET /` explicitly opts in to
`Sec-CH-UA-Platform` anyway, so it reliably appears on subsequent `POST /check`
for the `ch_platform_mismatch` cross-check:

```go
c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform")
```

Only `Accept-CH`/`Critical-CH` header server sends — no opt-in for high-entropy
hints (`platformVersion`, `fullVersionList`, `architecture`). `fullVersionList`
instead comes purely from client-side
`navigator.userAgentData.getHighEntropyValues(["fullVersionList"])` call in
collector; header opt-in only strengthens *server-observed* side of platform
comparison (point is spoofing client keeps the two out of sync).
