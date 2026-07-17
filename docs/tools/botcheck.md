# Bot check (`botcheck.corpberry.com`)

A live score of how much the visitor's browser looks like a human vs. an
automated bot. It fuses **client-side
signals** (collected by a vendored JS collector) with **server-observed signals**
(HTTP headers + IP reputation) and cross-checks the two — the disagreements are
what give automation away. Output is a 0–100 authenticity score, a verdict band
(`human` / `suspicious` / `bot`), and a transparent per-signal breakdown.

This tool is the practical follow-up to the research in
[botornot/](botornot/) (how the major public bot-detection services work) and its
design doc [botornot/building-our-own.md](botornot/building-our-own.md).

> **Naming:** the tool is **Bot check** (display name) / `botcheck` (the Go
> package, routes, and the `botcheck.corpberry.com` subdomain). "Bot-or-not"
> refers only to the competitor research in [botornot/](botornot/), never to this
> tool.

## Package layout (`botcheck/`, mirrors `iptools/`)

- `botcheck.go` — **pure domain**: `Signals`, `Check`, `Report`, `Evaluate`, and
  the signal helpers. No `echo`, no `iptools` import — so its tests construct
  `Signals` directly, with no HTTP and no databases.
- `scoring.go` — the ordered weighted rule set (hard tells → consistency
  cross-checks → soft heuristics) and the soft-signal combination rule.
- `handler.go` — transport: parses the client payload, gathers server signals off
  `*echo.Context`, maps the shared `iptools.Service` result into plain `Signals`
  fields, calls `Evaluate`, and content-negotiates the response.
- `templates/` — `botcheck/index` (page) + `botcheck/result` (fragment).
- `tests/` — black-box domain + handler tests.
- collector: `shared/static/js/botcheck.js` (hand-vendored, no npm).

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

## Scoring model (no ML, deterministic)

Start at **100** and subtract each triggered rule's weight; clamp at 0; map to a
band: `≥80 human`, `≥50 suspicious`, else `bot`. Rules are tiered:

- **Hard tells** (≈40–60): `navigator.webdriver`, automation-framework globals,
  bot/HTTP-client User-Agent, monkey-patched natives, software WebGL renderer, CDP
  in both main thread + Worker.
- **Consistency** (≈15–35): JS UA ≠ HTTP UA; Worker/iframe UA ≠ main UA;
  `Sec-CH-UA-Platform` ≠ `userAgentData.platform`; UA OS ≠ platform; embedded
  runtime (Electron/CEF); browser TZ offset ≠ IP TZ offset; datacenter/Tor IP;
  proxy/VPN IP; impossible permission state; `navigator.languages` ≠
  `Accept-Language`; CDP main-thread only; `navigator.vendor` ≠ `"Google Inc."`
  on a Chromium UA; `navigator.appVersion` ≠ UA; `navigator.language` ≠
  `languages[0]`; IANA zone ≠ `getTimezoneOffset()` (self-consistency); canvas
  randomised between draws; `Sec-CH-UA` header brands ≠ `userAgentData.brands`.
- **Soft** (8 each): no plugins, empty languages, default 800×600, impossible
  window geometry, missing `window.chrome`, implausible hardware, available
  screen larger than physical, low colour depth, browser UA without `Sec-Fetch-*`,
  canvas renders blank, no H.264/AAC codecs, no detectable fonts. Soft signals
  **only bite as a cluster of ≥3** (one 25-point deduction), so a single quirk
  never false-positives a real human.

Every rule appears in the response `checks` list as flagged / clean /
`not collected` (a client rule on a server-only request is skipped, never counted
as a pass) — the breakdown is the point. In the HTML view the checks are grouped
by tier (automation tells / consistency cross-checks / environment heuristics).

## Known gaps (documented, not bugs)

TLS/JA3 + HTTP/2 fingerprinting (nginx terminates TLS upstream) and behavioral
biometrics need infra/ML we don't have. Crowd/rarity scoring needs a persistence
layer, and **MongoDB is now available** (a shared server, the `site-of-tools`
database, and the `platform/mongo.go` client) — but botcheck **does not use it
yet** and stays a pure, deterministic, in-request scorer. The DB-backed models
(crowd/rarity, request velocity, returning-visitor history) can build on that
client when we add them, sitting below the domain scorer per rule #5. See the
design doc for the full rationale and future paths. The tool is a
**self-test/inspection page, not an inline WAF** — it scores the current visitor
and blocks nothing.
