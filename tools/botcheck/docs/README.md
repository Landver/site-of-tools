# Bot check (`botcheck.corpberry.com`)

A live score of how much the visitor's browser looks like a human vs. an
automated bot. It fuses **client-side signals** (collected by a vendored JS
collector) with **server-observed signals** (HTTP headers + IP reputation) and
cross-checks the two — the disagreements are what give automation away. Output is
a 0–100 authenticity score, a verdict band (`human` / `suspicious` / `bot`), and
a transparent per-signal breakdown.

**The thesis:** client signals are all spoofable, so the detection power lives in
the server cross-checking what the browser *claims* against what the connection
*actually shows*. The tool reuses the entire server-observed IP layer from
[`iptools`](../../iptools/docs/README.md) (IP2Proxy PX12 + IP2Location) for free, so it is
essentially "a JS collector + a deterministic server scorer."

This doc is the tool's **design + reference**. Its two companions in this folder
are [RESEARCH.md](RESEARCH.md) — how the major public bot-detection services work,
and how our own test browser scored against all of them — and
[ROADMAP.md](ROADMAP.md) — the competitor-gap audit plus the backlog of what to
build next and why. The raw per-service writeups live in [reports/](reports/).

> **Naming:** the tool is **Bot check** (display name) / `botcheck` (the Go
> package, routes, and the `botcheck.corpberry.com` subdomain). "Bot-or-not"
> refers only to the competitor research ([RESEARCH.md](RESEARCH.md) +
> [reports/](reports/)), never to this tool.

## Scope & non-goals

`GET /` renders a page shell (a short explainer, a "your request" server card
like the iptools connection inspector, and the vendored collector script); the
collector gathers client signals and POSTs them to `POST /check`, which fuses them
with the server signals, runs the scorer, and returns an HTML fragment (browser)
or JSON (API/CLI) by content negotiation.

**Non-goals:** this is a self-test/inspection tool, **not an inline WAF**. It does
not block requests, set a verdict cookie, or protect other endpoints — it returns
a score for *the person looking at the page*. (An "enforcement mode" other tools
could call is a possible later bolt-on — see [ROADMAP.md](ROADMAP.md).)

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

## Signal inventory

Split by *where the signal physically comes from* — the whole game is that server
signals can't be forged by the client and client signals can, so the scorer's job
is to make the two disagree and weight the disagreement.

### Server-side (Go computes these off `*echo.Context` — unforgeable by the client)

| Signal | Source in Go | What it tells us |
|---|---|---|
| **IP reputation** — datacenter / hosting / VPN / proxy / Tor + ASN | `iptools.Service.Lookup(ip).Proxy` (IP2Proxy **PX12**) | Hosting/proxy IPs are the strongest cheap bot tell (`IsProxy`, `ProxyType` VPN/TOR/DCH/…, `UsageType`, `Threat`) |
| **IP geolocation → country + timezone** | `iptools.Service.Lookup(ip)` → `.Country`, `.Timezone` (IP2Location DB11) | Anchor for the two best cross-checks: browser-TZ vs IP-TZ, and languages vs IP-country |
| **Raw HTTP `User-Agent`** | `c.Request().UserAgent()` | Cross-checked vs the JS `navigator.userAgent`; parsed for `HeadlessChrome`, `python-requests`, `Go-http-client`, `curl`, empty UA |
| **`Sec-CH-UA*` client-hint headers** | `c.Request().Header.Get("Sec-CH-UA" / …-Platform / …-Mobile)` | Cross-checked vs the JS `navigator.userAgentData` — spoofers routinely forget to keep header + JS hints in sync |
| **`Accept-Language`** | `c.Request().Header.Get("Accept-Language")` | vs `navigator.languages` (JS) and vs IP-country. Empty/`*` is a weak tell |
| **Header presence / plausibility** | `c.Request().Header` | Missing `Accept`/`Accept-Encoding`, or a Chrome UA with no `Sec-CH-UA` on a secure connection |
| **Connection metadata** | shared `platform.Conn(c)` — resolved IP, how derived (Cloudflare/XFF/direct), scheme, host | Shown in the "your request" card; also feeds the IP lookup |

We deliberately **cannot** read HTTP header order/casing, TLS JA3/JA4, HTTP/2
frame fingerprints, or the TCP/IP SYN fingerprint — nginx terminates TLS,
normalizes headers, and downgrades to HTTP/1.1 before Go sees the request, and
`crypto/tls` never hands the raw ClientHello to a handler. This is a documented
gap (see [ROADMAP.md](ROADMAP.md)), not a bug.

### Client-side (vendored collector gathers, POSTs as JSON — spoofable, used in cross-checks)

Plain HTML can't read `navigator`/`canvas`/`WebGL`, so a JS collector is justified
under CLAUDE.md golden rule #4. The collector builds one JSON object and POSTs it.

- **Hard automation tells** — `navigator.webdriver`; automation-framework globals
  (`$cdc_*`/`$wdc_*`, `__selenium*`/`__webdriver*`, `__playwright`/`__pw_*`,
  `_phantom`/`callPhantom`, `__nightmare`, Sequentum in `window.external`); the
  **CDP probe** (`Error.stack` getter + `console.log` serialization trick that
  fires when a DevTools-Protocol client sent `Runtime.enable` — the dominant modern
  tell, run in both the main thread and a Worker).
- **Lie / tamper detection** — `Function.prototype.toString()` `[native code]`
  check on key natives (catches monkey-patched getters); error-stack Proxy probes.
- **Cross-context consistency** — recompute `navigator.{userAgent, platform,
  languages, hardwareConcurrency}` + WebGL renderer inside a Web Worker and an
  iframe; POST all copies so Go can diff them (top-frame-only spoofs collapse here).
- **Classic headless tells** — impossible permission state (`prompt` while
  `denied`); `window.chrome`/`chrome.runtime` presence; empty
  `plugins`/`mimeTypes`/`languages`; software WebGL renderer (SwiftShader/Mesa);
  default `800x600` / `screen == avail` / `outerWidth < innerWidth`;
  implausible `hardwareConcurrency`/`deviceMemory`.
- **Fingerprint surfaces (for consistency, not raw entropy)** — canvas 2D hash,
  WebGL vendor/renderer + params, AudioContext hash, font list — used for
  GPU-vs-claimed-OS coherence and spoof/noise-stability, not a uniqueness score.
- **The cross-check most free tools skip (our differentiator)** —
  `navigator.userAgentData.getHighEntropyValues([...])` for the **full** set
  (`platform`, `platformVersion`, `uaFullVersion`, `fullVersionList`,
  `architecture`, `bitness`, `model`), triangulated against both the legacy UA
  string *and* the `Sec-CH-UA` request headers. The browser version reported here
  must match the UA's `Chrome/NNN` major (this is exactly where CreepJS caught the
  Electron UA spoof: UA said macOS 10_15_7, `userAgentData` said 26.5.1).
- **Real-engine feature detection** — probe capabilities unique to one engine
  (`-moz-appearance` ⇒ Gecko, `GestureEvent` ⇒ WebKit, `-webkit-app-region` /
  `webkitRequestFileSystem` ⇒ Blink) and cross-check the detected engine against
  the one the UA claims — robust against a spoofed UA string a parse would trust.
- **Engine constants** — `navigator.productSub` is a fixed per-engine value
  (`20030107` on WebKit/Blink, `20100101` on Gecko); a value that disagrees with
  the claimed engine is a patched-runtime tell. `navigator.pdfViewerEnabled` is a
  soft desktop-Chromium headless tell.
- **Timezone** — `Intl.DateTimeFormat().resolvedOptions().timeZone` +
  `getTimezoneOffset()`, compared to the IP timezone from IP2Location.

## Scoring model (no ML, deterministic)

Start at **100** and subtract each triggered rule's weight; clamp at 0; map to a
band: `≥80 human`, `≥50 suspicious`, else `bot`. `Evaluate` is a pure function of
`Signals` — no DB, no ML, no globals — so it is trivially testable and race-free.
Rules are tiered:

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
  randomised between draws; `Sec-CH-UA` header brands ≠ `userAgentData.brands`;
  feature-detected engine ≠ engine the UA claims; UA `Chrome/NNN` major ≠
  `userAgentData` version; `navigator.productSub` ≠ the engine's constant.
- **Soft** (8 each): no plugins, empty languages, default 800×600, impossible
  window geometry, missing `window.chrome`, implausible hardware, available
  screen larger than physical, low colour depth, browser UA without `Sec-Fetch-*`,
  canvas renders blank, no H.264/AAC codecs, no detectable fonts, desktop Chrome
  with the PDF viewer disabled. Soft signals **only bite as a cluster of ≥3** (one
  25-point deduction), so a single quirk never false-positives a real human.

The load-bearing rules are the **cross-checks** — combinations that should not
co-occur — because a rule engine beats a checklist here: JS `navigator.userAgent`
vs the HTTP header; `Sec-CH-UA-Platform` (header) vs `userAgentData.platform`
(JS); `Intl` timezone vs IP2Location timezone (a datacenter IP **and** a TZ
mismatch is worse than either alone — they pair, not double-count); UA-claimed OS
vs `userAgentData.platform` vs the GPU renderer's implied platform; main-thread
navigator vs Worker vs iframe. Any single hard tell (≥40) drops a clean 100 below
80 on its own, so a real automation flag never reads "human."

Every rule appears in the response `checks` list as flagged / clean /
`not collected` (a client rule on a server-only request is skipped, never counted
as a pass) — the breakdown is the point. In the HTML view the checks are grouped
by tier (automation tells / consistency cross-checks / environment heuristics),
with the number + verdict at the top and the per-signal table below.

### Client-Hints opt-in (an Echo v5 detail)

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

## Collector provenance (vendored by hand, no npm)

Per golden rule #3 there is **no npm and no `node_modules`** — the collector is
vendored by hand into `shared/static/js/botcheck.js`, the same way `htmx.min.js`
and `alpine.min.js` are. We read the following for technique and port specific
probes; we do **not** add them as dependencies or a build step:

| Project | License | What we take |
|---|---|---|
| **BotD** | MIT | Self-contained OSS bot detector — the collector base |
| **CreepJS** | MIT (client only) | Lie/tamper detection + cross-context recompute probes (name kept off anything public — trademarked) |
| **fp-collect / fp-scanner** | MIT | Collection checklist + per-test consistency verdicts (reference for our `Check` rows) |
| **FingerprintJS (OSS)** | MIT | Canvas/WebGL/audio/font collection |
| **MixVisit `@mix-visit/lite`** | MIT | Engine-vs-UA consistency reference (the engine behind iphey.com) + WebRTC leak |

Collection-surface references (uniqueness tools, not bot detectors — we don't copy
their scoring): **AmIUnique** and **EFF Cover Your Tracks** (the latter is AGPLv3,
so read-only, never vendored). The server scorer is our own — none of these ship
one we'd want.

## Testing (black-box, `botcheck/tests/`)

- **Domain (`botcheck_test.go`)** — construct canned `Signals` (no HTTP, no BINs)
  and assert `Score`/`Verdict`/`Checks`, table-driven: clean Chrome on a
  residential IP → `human`; headless Chrome (webdriver + SwiftShader + CDP both
  contexts) → `bot`; stealth spoof (UA mismatch + TZ mismatch + datacenter IP) →
  `bot`/`suspicious`; the Electron catch (UA OS ≠ `userAgentData.platform`) →
  `suspicious`; privacy-conscious human (a couple of soft quirks, nothing else) →
  still `human` (proves the ≥3-soft-cluster rule doesn't false-positive). `go-cmp`
  on the `Checks` slice locks in *which* signals fired, not just the number.
- **Handler (`handler_test.go`)** — `httptest`: `POST /check` a JSON fingerprint
  and assert the negotiated output (JSON for `Accept: */*`, the `botcheck/result`
  fragment for `Accept: text/html`), with a fake `iptools.Looker` (no PX12 BIN in
  CI) and a nil service (IP signals absent, still scores the client half).

## Known gaps (documented, not bugs)

TLS/JA3 + HTTP/2 fingerprinting (nginx terminates TLS upstream) and behavioral
biometrics need infra/ML we don't have. Crowd/rarity scoring needs a persistence
layer, and **MongoDB is now available** (a shared server, the `site-of-tools`
database, and the `platform/mongo.go` client) — but botcheck **does not use it
yet** and stays a pure, deterministic, in-request scorer. The DB-backed models
(crowd/rarity, request velocity, returning-visitor history) can build on that
client when we add them, sitting below the domain scorer per rule #5. The full
list of deferred items — with severity, effort, and the cheap approximation we do
instead — lives in [ROADMAP.md](ROADMAP.md). The tool is a
**self-test/inspection page, not an inline WAF** — it scores the current visitor
and blocks nothing.
