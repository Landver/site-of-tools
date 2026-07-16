# Building our own "bot-or-not" service (`botcheck.corpberry.com`)

A concrete design for a new tool subdomain that scores a visitor's browser as
**human / suspicious / bot** and shows a per-signal breakdown — the same core job
BrowserScan, Pixelscan, iphey, whoer and deviceandbrowserinfo do, minus the two
categories we structurally can't reach yet (network-layer TLS fingerprinting and
behavioral/crowd ML).

This is a **design doc, not built yet.** It is the synthesis of the 11-service
research in this folder (see `../botornot/*.md` and the cross-service
`synthesis.md`) mapped onto this repo's constraints: one Go 1.26 binary, Echo v5,
content-negotiated HTML+JSON, layered domain package, vendored JS (no npm),
stateless (no DB yet). Read [ARCHITECTURE.md §4](../../ARCHITECTURE.md#4-request-layering-the-core-pattern--read-this)
first — this tool is a straight application of that pattern, and
[`iptools.md`](../iptools.md) is the sibling tool it borrows the most from.

**The one-sentence thesis:** client signals are all spoofable, so the detection
power lives in the server cross-checking what the browser *claims* against what
the connection *actually shows*. We already have the entire server-observed IP
layer for free (`iptools` bundles IP2Proxy PX12 + IP2Location), so the MVP is
mostly "add a JS collector + a deterministic scorer."

---

## 1. Scope & MVP goal

**MVP deliverable:** a page at `botcheck.corpberry.com` plus a JSON API that
returns a bot/trust score (0..100) and a verdict band for the current visitor,
with a transparent per-signal table showing which checks passed, failed, or were
inconsistent.

- `GET /` — the page shell: a short explainer, a "your request" server card (like
  the iptools connection inspector), and the vendored collector script. On load
  the collector gathers client signals and POSTs them.
- `POST /check` — accepts the collected fingerprint JSON, fuses it with
  server-observed signals (HTTP headers + IP reputation/geo via the existing
  `iptools` databases), runs the deterministic scorer, and returns either an HTML
  results fragment (browser) or JSON (API/CLI) by content negotiation.

**In scope for v1:** client fingerprint collection, HTTP header + Client-Hints
cross-checks, IP reputation/geo/timezone cross-checks, and a no-ML weighted
deduction scorer with a per-signal table.

**Explicitly deferred (see §6):** TLS/JA3/JA4 + HTTP/2 frame fingerprinting
(blocked by our nginx topology), behavioral biometrics, and crowd-blending/rarity
(both need the future MongoDB and/or ML).

**Non-goals:** this is a self-test/inspection tool, not an inline WAF. It does not
block requests, set a verdict cookie, or protect other endpoints. It returns a
score for *the person looking at the page*. (An "enforcement mode" that other
tools could call is a later bolt-on, noted in §6.)

---

## 2. Signal inventory

Split by *where the signal physically comes from*. This split is the whole game:
the server signals can't be forged by the client, the client signals can — so the
scorer's job (§4) is to make the two disagree and weight the disagreement.

### 2a. Server-side signals (Go computes these, no JS required)

These come straight off `*echo.Context` in the handler — the request is already in
hand. No collection round-trip needed; they're known the instant the POST (or even
the initial GET) arrives.

| Signal | Source in Go | What it tells us |
|---|---|---|
| **IP reputation** — datacenter / hosting / VPN / proxy / Tor + ASN | `iptools.Service.Lookup(ip).Proxy` (IP2Proxy **PX12**, already bundled) | Hosting/proxy IPs are the single strongest cheap bot tell. `Proxy.IsProxy`, `Proxy.ProxyType` (VPN/TOR/DCH/PUB/WEB/SES/RES), `Proxy.UsageType`, `Proxy.Threat` |
| **IP geolocation → country + timezone** | `iptools.Service.Lookup(ip)` → `.Country`, `.Timezone` (IP2Location DB11) | The anchor for the two best cross-checks: browser-TZ vs IP-TZ, and `Accept-Language`/`navigator.languages` vs IP-country |
| **Raw HTTP `User-Agent`** | `c.Request().UserAgent()` | Cross-checked against the JS `navigator.userAgent` (they must match) and parsed for `HeadlessChrome`, `python-requests`, `Go-http-client`, `curl`, empty UA |
| **`Sec-CH-UA*` client-hint headers** | `c.Request().Header.Get("Sec-CH-UA" / "Sec-CH-UA-Platform" / "Sec-CH-UA-Mobile")` | Cross-checked against the JS `navigator.userAgentData` — anti-detect browsers routinely forget to keep header + JS hints in sync (see §3e for the `Accept-CH` opt-in needed for the high-entropy ones) |
| **`Accept-Language`** | `c.Request().Header.Get("Accept-Language")` | vs `navigator.languages` (JS) and vs IP-country. Empty/`*` is a weak bot tell |
| **Header presence / plausibility** | `c.Request().Header` | Missing `Accept`, missing `Accept-Encoding`, or a UA claiming Chrome with no `Sec-CH-UA` on a secure connection = mismatch |
| **Connection metadata** | reuse `iptools`' `conn(c)` pattern — resolved IP, how derived (Cloudflare/XFF/direct), scheme, host | Shown in the "your request" card; also feeds the IP lookup |

We deliberately **cannot** read HTTP header *order/casing*, TLS JA3/JA4, HTTP/2
frame fingerprints, or the TCP/IP SYN fingerprint — nginx terminates TLS,
normalizes headers, and downgrades to HTTP/1.1 before the request reaches Go, and
Go's `crypto/tls` never hands the raw ClientHello to a handler anyway. This is a
known, documented gap (§6), not a bug.

### 2b. Client-side signals (vendored JS collector gathers, POSTs as JSON)

Plain HTML genuinely cannot read `navigator`/`canvas`/`WebGL`, so a JS collector is
justified under CLAUDE.md golden rule #4. This is the "must-collect" list from the
synthesis, trimmed to what a no-ML scorer can actually use. The collector builds
one JSON object and POSTs it to `/check`.

**Hard automation tells (each is close to a standalone verdict):**
- `navigator.webdriver === true`.
- Automation-framework globals: `$cdc_*` / `$wdc_*` (Selenium/ChromeDriver),
  `__selenium*` / `__webdriver*`, `__playwright` / `__pw_*` / `__pwInitScripts`,
  `_phantom` / `callPhantom` (PhantomJS), `__nightmare`, Sequentum markers in
  `window.external`.
- **CDP probe** — the `Error.stack` getter + `console.log` serialization trick that
  fires when a DevTools-Protocol client sent `Runtime.enable` (Puppeteer/Playwright/
  Selenium 4). This is the *dominant modern tell* and is exactly what flagged the
  in-app Electron browser during recon (`isAutomatedWithCDP: true`). **Caveat:** it
  also fires when a human has DevTools open, and was partially neutralized in 2024 —
  so it's strong-but-not-durable; weight it high but not as an instant-kill on its
  own, and run it in a Worker too (below).

**Lie / tamper detection (the category the weak tools miss):**
- `Function.prototype.toString()` `[native code]` check on key natives, to catch
  monkey-patched getters (puppeteer-extra-stealth, anti-detect browsers).
- Proxy detection via error-stack frames.

**Cross-context consistency (catches top-frame-only spoofs):**
- Recompute `navigator.{userAgent, platform, languages, hardwareConcurrency}` and
  the WebGL renderer **inside a Web Worker and an iframe**; POST all three copies so
  Go can diff them. (Worker/iframe mismatch unmasked Bright Data on incolumitas and
  our own Electron browser failed `HEADCHR_IFRAME` / worker-navigator checks.)

**Classic headless tells:**
- `Permissions.query({name:'notifications'})` returning `prompt` while
  `Notification.permission === 'denied'` (the canonical impossible state).
- `window.chrome` / `chrome.runtime` presence + integrity (for Chrome UAs).
- Empty `navigator.plugins` / `mimeTypes` / `languages`.
- WebGL `UNMASKED_RENDERER_WEBGL` = `SwiftShader` / `Mesa OffScreen` (software
  renderer ⇒ headless on a desktop UA).
- Screen/window geometry: default `800x600`, `screen == avail`, impossible
  `outerWidth < innerWidth`.
- `hardwareConcurrency` / `deviceMemory` implausibility.

**Fingerprint/entropy surfaces (for consistency, not raw entropy):**
- Canvas 2D hash, WebGL vendor/renderer + params, AudioContext hash, font list.
  We use these for GPU-vs-claimed-OS consistency and spoof/noise-stability, not for
  a uniqueness score (that's the AmIUnique/EFF job, not a bot verdict).

**The cross-check most free tools skip (our differentiator):**
- `navigator.userAgentData.getHighEntropyValues(['platform','platformVersion',
  'architecture','fullVersionList'])` — POST it so Go can triangulate it against
  both the legacy UA string *and* the `Sec-CH-UA` request headers. CreepJS caught
  the Electron UA spoof exactly here (UA said macOS 10_15_7, `userAgentData` said
  26.5.1).

**Timezone (for the headline cross-check):**
- `Intl.DateTimeFormat().resolvedOptions().timeZone` + `getTimezoneOffset()` — Go
  compares this to the IP timezone from IP2Location. Browser-TZ ≠ IP-TZ is the
  most-cited cross-layer signal (VPN users trip it; so do lazy bots).

---

## 3. Architecture

The canonical shape from the synthesis (§3, "collector → POST → server scorer" —
what incolumitas, BrowserScan, iphey, Fingerprint all do) maps one-to-one onto this
repo's layered pattern. **The verdict is computed server-side and never trusted
from the client** (the POSTed fingerprint is trivially forgeable — this is why
CYT's client-scored design is useless adversarially).

### 3a. Request flow

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

An API/CLI caller skips the browser entirely: `POST /check` with a JSON body and no
`text/html` in `Accept` gets the `Report` as JSON. The client fields it can't
supply are simply absent and score as "unknown" (the scorer treats absent client
signals as non-triggering, so a bare server-only call still returns an IP-based
partial score).

### 3b. Go layout (per CLAUDE.md — one folder = one package, code co-located with templates)

New self-contained package `botcheck/`, mirroring `iptools/`:

```
botcheck/
  botcheck.go     domain: Signals, Report, Check, Evaluate(Signals) Report   ← PURE Go, no echo, no iptools
  scoring.go      the weighted rules table + verdict bands (still pure)
  handler.go      transport: parse → gather server signals → enrich → Evaluate → respond
  embed.go        //go:embed templates  → var Templates embed.FS
  templates/
    index.html    {{define "botcheck/index"}}   full page shell + collector <script>
    result.html   {{define "botcheck/result"}}  the per-signal results table (fragment)
    nav.html      {{define "botcheck/nav"}}      (only if we add sub-pages later)
  tests/
    botcheck_test.go   black-box: canned Signals → assert Score/Verdict/Checks
    handler_test.go    httptest: POST a fingerprint body → assert negotiated output

shared/static/js/
  botcheck.js     vendored collector (hand-written or trimmed BotD), served at /static/js/botcheck.js
```

**Layering (the important part):**

- `botcheck.go` is **pure domain** — it imports neither `echo` nor `iptools`. Its
  input `Signals` is a plain struct bundling *already-collected* client values and
  *already-looked-up* server values (IP country/timezone, is-datacenter, is-proxy,
  etc.) as plain fields. Its output is `Report`. This is the layer that lets one
  feature serve HTML + JSON + fragment with zero duplication.
- The **handler** does the impure work: `c.Bind` the client JSON, read headers off
  `*echo.Context`, call `iptools.Service.Lookup(...)` to get IP facts, *map* the
  `*iptools.Result` into `botcheck.Signals` plain fields, call
  `botcheck.Evaluate`, then `platform.Respond` / branch on content negotiation.

Keeping `botcheck.go` free of an `iptools` import (the handler bridges the two) is
deliberate: the domain scorer stays a pure function of a plain struct, so its tests
need no BIN databases (they construct `Signals` directly) — same trick `iptools`
uses with its `Looker` interface.

```go
// botcheck/botcheck.go — pure domain, no HTTP, no iptools import.
package botcheck

// Signals is everything the scorer needs: client-collected + server-observed,
// already flattened to plain fields so this package imports nothing but stdlib.
type Signals struct {
    // ── client-collected (from the POSTed JSON; zero value = "not supplied") ──
    Webdriver        bool
    FrameworkGlobals []string // e.g. ["$cdc_", "__playwright"]
    CDPMainThread    bool
    CDPWorker        bool
    NativeToStringOK bool     // false = a key native was monkey-patched
    NavMainUA        string
    NavWorkerUA      string   // recomputed in a Web Worker
    NavIframeUA      string
    Languages        []string // navigator.languages
    Permissions      string   // "prompt"/"granted"/"denied" for notifications
    NotificationPerm string
    HasChromeObject  bool
    WebGLRenderer    string   // UNMASKED_RENDERER_WEBGL
    Plugins          int
    ScreenW, ScreenH int
    OuterW, InnerW   int
    HardwareCores    int
    DeviceMemory     float64
    BrowserTZ        string   // Intl timezone
    UAData           UAData   // userAgentData.getHighEntropyValues()

    // ── server-observed (filled by the handler from *echo.Context + iptools) ──
    HTTPUserAgent   string
    SecCHUA         string
    SecCHUAPlatform string
    AcceptLanguage  string
    IPCountry       string
    IPTimezone      string
    IsDatacenter    bool
    IsProxy         bool
    IsVPN           bool
    IsTor           bool
    ASN             string
}

type UAData struct{ Platform, PlatformVersion, Architecture string }

// Check is one row in the transparent breakdown table.
type Check struct {
    ID       string `json:"id"`       // e.g. "webdriver", "tz_mismatch"
    Label    string `json:"label"`    // human text for the HTML table
    Tier     string `json:"tier"`     // "hard" | "consistency" | "soft"
    Weight   int    `json:"weight"`   // points deducted when Triggered
    Triggered bool  `json:"triggered"`
    Detail   string `json:"detail,omitempty"` // "browser=Europe/Moscow ip=Europe/Istanbul"
}

// Report is the content-negotiated result the transport layer renders.
type Report struct {
    Score   int     `json:"score"`   // 0..100 authenticity; 100 = looks human
    Verdict string  `json:"verdict"` // "human" | "suspicious" | "bot"
    Checks  []Check `json:"checks"`
}

// Evaluate is the whole scorer: a pure function of the current request. No DB,
// no ML, no globals — so it's trivially testable and race-free.
func Evaluate(in Signals) Report { /* see §4 */ }
```

```go
// botcheck/handler.go — transport only (Echo v5 signatures).
func Register(e *echo.Echo, svc iptools.Looker) {
    h := &handler{svc: svc}
    e.GET("/", h.index)
    e.POST("/check", h.check)
}

func (h *handler) check(c *echo.Context) error {
    var client clientPayload        // the JSON shape the collector POSTs
    if err := c.Bind(&client); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"error": "bad fingerprint payload"})
    }
    sig := client.toSignals()                       // client half
    r := c.Request()
    sig.HTTPUserAgent = r.UserAgent()               // server half: headers
    sig.SecCHUA = r.Header.Get("Sec-CH-UA")
    sig.SecCHUAPlatform = r.Header.Get("Sec-CH-UA-Platform")
    sig.AcceptLanguage = r.Header.Get("Accept-Language")
    if res, err := h.svc.Lookup(c.RealIP()); err == nil { // server half: IP rep/geo
        sig.IPCountry, sig.IPTimezone, sig.ASN = res.Country, res.Timezone, res.ASN
        if p := res.Proxy; p != nil {
            sig.IsProxy = p.IsProxy
            sig.IsDatacenter = p.ProxyType == "DCH"
            sig.IsVPN = p.ProxyType == "VPN"
            sig.IsTor = p.ProxyType == "TOR"
        }
    }
    report := botcheck.Evaluate(sig)                // ← pure domain call

    if platform.WantsJSON(c) {                      // API/CLI → JSON
        return c.JSON(http.StatusOK, report)
    }
    return c.Render(http.StatusOK, "botcheck/result", report) // browser → fragment
}
```

Reusing `iptools.Looker` (its existing one-method interface `Lookup(string)
(*Result, error)`) means the handler test injects a fake IP service — no 1.7 GB
PX12 BIN needed in CI, and a nil service degrades gracefully exactly as it does for
the IP tool.

### 3c. What stays client-only vs server-only

| Client-only (must be JS) | Server-only (must be Go) |
|---|---|
| `navigator.*`, `webdriver`, framework globals | Raw HTTP `User-Agent` header, header set/plausibility |
| canvas / WebGL / audio / font hashes | `Sec-CH-UA*` request headers |
| CDP `Error.stack` probe, `toString` tamper check | IP reputation (datacenter/VPN/proxy/Tor) + ASN — IP2Proxy |
| Web Worker / iframe recompute | IP country + timezone — IP2Location |
| `Intl` timezone, screen/window geometry | the resolved client IP + how it was derived |
| `userAgentData.getHighEntropyValues()` | (blocked: TLS JA3/JA4, HTTP/2 frames, header order, TCP SYN — see §6) |

**The verdict is server-only.** The client just collects; it never scores.

### 3d. Wiring (main.go, config, nav — all tiny additions)

No new config keys: the tool reuses the same `*iptools.Service` (same BIN paths
already in `Config`). In `main.go`, alongside the existing `ipApp`:

```go
botApp := platform.NewApp(renderer, staticFS, cfg.IsDev())
botcheck.Register(botApp, geo)  // reuse the same *iptools.Service already opened

hosts := map[string]*echo.Echo{
    cfg.VHost(""):         apex,
    cfg.VHost("ip"):       ipApp,
    cfg.VHost("botcheck"): botApp,   // dev: botcheck.localhost:8080
}
```

Add the `botcheck.Templates` source to `platform.NewRenderer(...)`, and add one
entry to `site.Tools(cfg)` (`URL: cfg.URL("botcheck")`) so it shows in the apex
tools index and the header dropdown. `/static/js/botcheck.js` is served by every
app's `StaticFS` (from `shared.Static`), so it's reachable on the botcheck host
without extra plumbing.

### 3e. Client-Hints opt-in (a real Echo v5 detail)

Chromium sends the *low-entropy* hints (`Sec-CH-UA`, `Sec-CH-UA-Mobile`,
`Sec-CH-UA-Platform`) by default on secure origins, but the *high-entropy* ones
(`platformVersion`, `fullVersionList`, `architecture`) only arrive if the server
asks. So on `GET /` set the opt-in response headers:

```go
c.Response().Header().Set("Accept-CH", "Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Arch")
c.Response().Header().Set("Critical-CH", "Sec-CH-UA-Platform-Version")
```

The high-entropy hints then appear on the subsequent `POST /check`. Even without
this we still have the JS `getHighEntropyValues()` copy to cross-check; the header
opt-in just gives us the *server-observed* side of that comparison (the whole point
is that a spoofing client keeps the two out of sync).

---

## 4. Scoring model (no ML, deterministic, no DB)

Model: **weighted additive deduction from a 100 "authenticity" baseline**, exactly
the BrowserScan/whoer UX fused with Fingerprint's Suspect-Score idea (sum of
triggered signal weights) and the sannysoft/deviceandbrowserinfo transparent
checklist. Start at 100, subtract each triggered signal's weight, clamp at 0, map
the remainder to a verdict band. `Evaluate` is a pure function of `Signals`.

### Signal tiers & example weights

Weights are a **starting proposal** to tune against the fixtures in §7, not gospel.

| Tier | Signal (triggered when…) | Weight |
|---|---|---|
| **Hard tell** | `Webdriver == true` | 60 |
| **Hard tell** | any `FrameworkGlobals` present | 60 |
| **Hard tell** | UA contains `HeadlessChrome` / `python-requests` / `Go-http-client` / `curl` | 60 |
| **Hard tell** | `NativeToStringOK == false` (monkey-patched native) | 45 |
| **Hard tell** | `WebGLRenderer` is SwiftShader/Mesa on a desktop UA | 40 |
| **Hard tell** | CDP probe fires in **both** main thread and Worker | 40 |
| **Consistency** | `HTTPUserAgent` ≠ `NavMainUA` | 35 |
| **Consistency** | `NavWorkerUA`/`NavIframeUA` ≠ `NavMainUA` | 35 |
| **Consistency** | `SecCHUAPlatform` ≠ `UAData.Platform` | 30 |
| **Consistency** | UA-claimed OS ≠ `UAData.Platform` (the CreepJS/Electron catch) | 30 |
| **Consistency** | `BrowserTZ` ≠ `IPTimezone` | 25 |
| **Consistency** | `IsDatacenter` \|\| `IsTor` | 30 |
| **Consistency** | `IsProxy` \|\| `IsVPN` | 20 |
| **Consistency** | permissions impossible state (`prompt` while `denied`) | 25 |
| **Consistency** | `AcceptLanguage`/`Languages` disagree, or neither matches `IPCountry` | 15 |
| **Consistency** | CDP probe fires in main thread only | 15 |
| **Soft** | empty `Plugins` (Chrome UA) | 8 |
| **Soft** | default `800x600` / `ScreenW==avail` geometry | 8 |
| **Soft** | `OuterW < InnerW` (impossible) | 8 |
| **Soft** | empty `Languages` | 8 |
| **Soft** | implausible `HardwareCores` / `DeviceMemory` | 8 |

**Weak-signal combination rule** (borrowed from deviceandbrowserinfo): no single
soft signal should ever produce a false positive, so a soft hit only counts once
**≥3 soft signals fire together** — at which point the cluster promotes to a single
medium deduction (e.g. 25) instead of summing the individual 8s. A lone soft
anomaly (privacy browser, unusual monitor) stays harmless.

### The cross-checks (client-claimed vs server-observed)

These are where a rule engine beats a checklist. Each is "a combination that should
not co-occur":

- **UA vs header UA:** JS `navigator.userAgent` must equal the HTTP `User-Agent`.
- **Client Hints vs `userAgentData`:** `Sec-CH-UA-Platform` (header) must match
  `UAData.Platform` (JS).
- **Browser TZ vs IP TZ:** `Intl` timezone vs IP2Location timezone (VPN/proxy trips
  this — which is *why* it pairs with the IP-reputation signal, not double-counts
  it: a datacenter IP **and** a TZ mismatch is worse than either alone).
- **UA OS vs everything:** the OS in the UA string vs `UAData.Platform` vs the GPU
  renderer's implied platform.
- **Cross-context:** main-thread navigator vs Worker vs iframe.

### Verdict bands

```go
switch {
case score >= 80: verdict = "human"
case score >= 50: verdict = "suspicious"
default:           verdict = "bot"
}
```

Any single hard tell (weight ≥40) drops a clean 100 below 80 on its own, so a
real automation flag never reads "human." Bands are just thresholds — tune with the
fixtures. Presentation follows the universal pattern: **the number + verdict at the
top, the per-signal `Checks` table below** (each row pass/fail with its `Detail`),
which is what makes these pages trustworthy and debuggable.

**No database, no ML, no persistence** — everything is a pure function of the one
request, so it slots under CLAUDE.md rules #1 and #5 with room for the DB-backed
models to sit *below* the domain service later.

---

## 5. Open-source to borrow / study (and the vendoring caveat)

We are not writing the collector from scratch if we can help it — but **no npm, no
`node_modules`, ever** (golden rule #3). That means we **vendor the built/authored
JS by hand** into `shared/static/js/botcheck.js`, the same way `htmx.min.js` and
`alpine.min.js` are already vendored. We read these repos for technique and lift
the built artifact or port the specific probes; we do **not** add them as npm deps
or a build step.

| Project | License | What to take | Repo |
|---|---|---|---|
| **BotD** | MIT | Closest to a drop-in OSS bot detector (Selenium/Playwright/Puppeteer/PhantomJS/headless). Best candidate to vendor as the collector base — self-contained built file | github.com/fingerprintjs/BotD |
| **CreepJS** | MIT (client only; crowd backend not published) | The lie/tamper detection (`src/lies`), headless rating (`src/headless`), and cross-context recompute — port these probes | github.com/abrahamjuliot/creepjs |
| **fp-collect** | MIT | Collection module (webdriver, phantom, selenium, sequentum, permissions, resOverflow) — the checklist that powers bot.sannysoft.com | github.com/antoinevastel/fp-collect |
| **fp-scanner** | MIT | Per-test consistency verdicts over an fp-collect object — a reference for our `Check` rows | github.com/antoinevastel/fpscanner |
| **FingerprintJS (OSS)** | MIT | Canvas/WebGL/audio/font collection; note OSS accuracy is much lower than their Pro engine | github.com/fingerprintjs/fingerprintjs |
| **MixVisit `@mix-visit/lite`** | MIT | The engine behind iphey.com — strong reference for **engine-vs-UA consistency** (feature-detects real Blink/Gecko/WebKit and compares to the claimed UA) + WebRTC leak | github.com/mixvisit-service/mixvisit |

Collection-surface references (not bot detectors — they measure uniqueness, don't
copy their scoring): **AmIUnique** (defines the "what to collect" checklist) and
**EFF Cover Your Tracks** (entropy framing) — the latter is **AGPLv3**, so do not
vendor its code; read it only.

**Recommended path:** vendor **BotD** as the collector base (MIT, self-contained,
ships as one file with no build), then hand-port the CreepJS lie/tamper +
cross-context probes and the `userAgentData` high-entropy grab (BotD doesn't do the
Client-Hints cross-check — our differentiator). Keep the CreepJS name off anything
public (trademarked). Write our own server scorer (§4) — none of these ship one we'd
want.

---

## 6. Out of scope (without ML / at our scale) + cheap approximations

Honest gaps, each with the reason and the cheap thing we do instead:

- **TLS JA3/JA4 + HTTP/2 frame fingerprinting.** Blocked by topology: Cloudflare/
  nginx terminate TLS, normalize headers, and downgrade to HTTP/1.1 before Go sees
  the request; `crypto/tls` doesn't expose the raw ClientHello to handlers anyway.
  Only DataDome/BrowserScan/incolumitas do this, and they own the edge. *Cheap
  approximation:* the UA/Client-Hints/IP cross-checks catch the same casual
  offenders (default `python-requests`/`Go-http-client`/`curl`, undetected-
  chromedriver, stealth plugins). *Future path if ever wanted:* extract JA3 at the
  edge with an OpenResty/nginx JA3 module and forward it as an `X-JA3` header for Go
  to score, **or** terminate TLS directly in Go on this subdomain with a custom
  `net.Listener` that peeks the ClientHello bytes. Both are real work — defer.
- **Behavioral biometrics** (incolumitas' 30+ classifier mouse/keystroke ensemble,
  DataDome's behavior models). Needs event-stream capture + a trained model. Out
  without ML. *Cheap approximation:* none needed for v1 — the fingerprint + IP
  layers already classify the casual/scraper threat. Slots in later *below* the
  domain service (rule #5) once we have somewhere to stream events.
- **Crowd-blending / rarity scoring** (CreepJS grades, AmIUnique uniqueness). Needs
  a population database. *Cheap approximation:* rule-based consistency (§4) instead
  of statistical rarity. Lands naturally when the planned **MongoDB** arrives —
  store each `Signals`+`Report`, then add a rarity signal as one more `Check`.
- **Active challenge / CAPTCHA / proof-of-work** (DataDome Picasso, incolumitas
  form challenge). Out of scope and off-brand — we never solve or issue CAPTCHAs.
  Not needed for a self-test tool.
- **Enterprise edge ML** (DataDome's 1,000+ models, sub-2ms edge decisions). Not our
  scale and not our shape (we're a self-test page, not an inline WAF).

If we later want an **enforcement mode** (other tools asking "is this visitor a
bot?"), that's the DB era: persist `Report`s keyed by a signed request token
(Fingerprint's `requestId` / DataDome's signed cookie pattern) and expose a
server-verified lookup — but *never* trust a score the client computed or replays.

---

## 7. Phased build plan & testing

Small, shippable increments. Each phase ends green under `make test`
(`go test ./... -race`) and the `.githooks/pre-push` gate.

- **Phase 0 — skeleton.** Create `botcheck/` (domain + handler + embed + templates),
  wire `botcheck.corpberry.com` into `main.go`, add the nav entry. `GET /` renders a
  static page; `POST /check` returns a hardcoded `Report`. Proves routing + content
  negotiation end to end.
- **Phase 1 — server-only scorer.** Implement `Evaluate` against **server signals
  only** (UA parse, header plausibility, IP reputation/geo/timezone via the reused
  `iptools.Service`). A `curl` with no client body already gets a partial IP-based
  score. This is the highest-value-per-effort slice — it reuses code we already
  have.
- **Phase 2 — vendored collector.** Add `shared/static/js/botcheck.js` (BotD base +
  ported probes), collect the §2b client signals, POST them, wire `clientPayload.
  toSignals()`, add the client-side rules to `Evaluate`. Re-init Alpine on the
  injected fragment (CLAUDE.md gotcha).
- **Phase 3 — cross-checks + weak-signal combo.** Add the client-vs-server
  cross-checks (§4) and the ≥3-soft-signals promotion rule. Tune weights/bands
  against the fixtures below.
- **Phase 4 — polish.** `Accept-CH` opt-in (§3e), the "your request" server card,
  the results-table UX, IP2Location attribution footer (reuse the `.Attribution`
  view-model flag — this tool uses the LITE databases, so the credit is required,
  exactly as in `iptools`).

**Testing (per CLAUDE.md rule #6 — black-box in `botcheck/tests/`):**

- **Domain (`botcheck_test.go`)** — the core. Construct canned `Signals` structs (no
  HTTP, no BINs) and assert `Score`/`Verdict`/`Checks`. Table-driven fixtures, each a
  named scenario:
  - *clean Chrome on a residential IP* → high score, `human`.
  - *headless Chrome* (`Webdriver`+SwiftShader+CDP both contexts) → near 0, `bot`.
  - *stealth spoof* (`HTTPUserAgent` ≠ `NavMainUA`; `BrowserTZ` ≠ `IPTimezone`;
    datacenter IP) → low, `bot`/`suspicious`.
  - *the Electron/anti-detect catch* (UA OS ≠ `UAData.Platform`) → `suspicious`.
  - *privacy-conscious human* (empty plugins + default-ish geometry, nothing else)
    → still `human` (proves the weak-signal combo rule doesn't false-positive).
  - `go-cmp` on the `Checks` slice to lock in *which* signals fired, not just the
    number.
- **Handler (`handler_test.go`)** — `httptest`: `POST /check` with a JSON fingerprint
  body and assert the negotiated output (JSON when `Accept: */*`, the
  `botcheck/result` fragment HTML when `Accept: text/html`). Inject a fake
  `iptools.Looker` (reuse the pattern from `iptools/tests`) so no PX12 BIN is
  required; also assert graceful behavior with a **nil** service (IP signals absent,
  still scores the client half). DB-independent by construction, so it runs in CI.

**Bottom line:** Phases 0–1 alone (server-only, reusing `iptools`) already ship a
credible IP-reputation + header-consistency scorer; Phases 2–3 bring it up to parity
with the free client-side self-test pages. TLS/network fingerprinting and
behavioral/crowd ML stay documented gaps, not blockers.
