# Bot check — architecture: package layout, request flow, routes

*(part of the [botcheck docs index](README.md))*

## Package layout (`botcheck/`, mirrors `iptools/`)

- `botcheck.go` — **pure domain**: `Signals`, `Check`, `Report`, `Evaluate`, and
  the signal helpers. No `echo`, no `iptools` import — so its tests construct
  `Signals` directly, with no HTTP and no databases.
- `scoring.go` — the ordered weighted rule set (66 rules: hard tells → consistency
  cross-checks → soft heuristics) and the soft-signal combination rule. See
  [scoring-model.md](scoring-model.md).
- `corpus.go` — the Mongo fingerprint corpus (G41/G42): a nil-safe repository
  (mirrors `iptools/history.go`) recording fingerprint sightings and counting
  distinct IPs per hash. A disabled Mongo turns it into a no-op. See
  [storage.md](storage.md).
- `handler.go` — transport: parses the client payload, gathers server signals off
  `*echo.Context`, maps the shared `iptools.Service` result into plain `Signals`
  fields, calls `Evaluate`, and content-negotiates the response.
- `templates/` — `botcheck/index` (page) + `botcheck/result` (fragment).
- `tests/` — black-box domain + handler tests. See [go-test-suite.md](go-test-suite.md).
- collector: `shared/static/js/botcheck.js` (hand-vendored, no npm). See
  [signals-client.md](signals-client.md) and
  [collector-provenance.md](collector-provenance.md).

**Layering (the important part).** `botcheck.go` is a pure function of a plain
`Signals` struct — it imports neither `echo` nor `iptools`, so its tests need no
BIN databases (they build `Signals` directly, the same trick `iptools` uses with
its `Looker` interface). The **handler** does all the impure work: bind the client
JSON, read headers off `*echo.Context`, call `iptools.Service.Lookup(...)` for IP
facts, *map* the `*iptools.Result` into `Signals` fields, call `Evaluate`, then
`platform.Respond`. Reusing `iptools.Looker` means the handler test injects a fake
IP service (no 1.7 GB PX12 BIN in CI), and a nil service degrades gracefully
exactly as it does for the IP tool. This is a straight application of
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
  │                                        5. report := botcheck.Evaluate(signals)   ← pure domain
  │                                        6. respond: HTML fragment | JSON
  │  ◀── results-table fragment (browser)  or  JSON (curl/API)
  └── collector injects fragment into #result
```

**The verdict is server-only.** The POSTed fingerprint is trivially forgeable, so
the client just collects; it never scores. An API/CLI caller can skip the browser
entirely — `POST /check` with a JSON body (no `text/html` in `Accept`) returns the
`Report` as JSON, and the client fields it can't supply are simply absent (the
scorer treats absent client signals as non-triggering, so a bare server-only call
still returns an IP-based partial score).

## Routes & content negotiation

| Route | Browser | curl / API (JSON) |
|---|---|---|
| `GET /` | Full page; the collector then POSTs `/check` | Server-only score (headers + IP, no JS signals) |
| `POST /check` | HTML results fragment | Full JSON `Report` |

```sh
# server-only score of your request (no JS signals)
curl https://botcheck.corpberry.com
# score a fingerprint you collected yourself
curl -X POST https://botcheck.corpberry.com/check \
  -H 'Content-Type: application/json' -d '{"webdriver":true}'
```

## Client-Hints opt-in (an Echo v5 detail)

Chromium sends the low-entropy hints (`Sec-CH-UA`, `Sec-CH-UA-Mobile`,
`Sec-CH-UA-Platform`) by default on secure origins, but the high-entropy ones
(`platformVersion`, `fullVersionList`, `architecture`) only arrive if the server
asks. `GET /` sets the opt-in response headers so they appear on the subsequent
`POST /check`:

```go
c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Arch")
c.Response().Header().Set("Critical-CH", "Sec-CH-UA-Platform-Version")
```

Even without this we still have the JS `getHighEntropyValues()` copy; the header
opt-in gives us the *server-observed* side of the comparison (the point is that a
spoofing client keeps the two out of sync).
