# Client-side port scanner — implementation plan (DRAFT v1, pre-review)

> New page on `ip.corpberry.com`, scans **visitor's own machine** for
> listening ports **entirely in browser**. Go server serves page +
> port catalog, **never emits single scan packet** — whole
> point & marketing hook.

**Status:** draft for DRY / KISS / YAGNI / no-paranoia review pass. Don't
build yet. Grounded in ten research reports in
[`../reports/`](../reports/) — start w/
[`00-landscape-and-ideas.md`](../reports/00-landscape-and-ideas.md),
[`browser-constraints-2026.md`](../reports/browser-constraints-2026.md), and
[`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md).

---

## 1. Goal & scope

Add fourth IP-tool page: **"Port scan"** (`/ports`). Visitor clicks
button; browser JS probes curated list of well-known ports on
`http://127.0.0.1:<port>`, reports per-port honest **inferred** state
(responding / refused / no-response). Server's only jobs: serve
page & expose port catalog as JSON.

**Why client-side (core requirement):** server-side scanner (GRC
ShieldsUP!, YouGetSignal, online Nmap frontends) sends outbound/inbound scan
traffic *from operator's IP* — why those tools all bolt on
captchas, per-IP caps, "payment as identification," & authorization
checkboxes to avoid blocklisting (see
[`online-nmap-frontends.md`](../reports/online-nmap-frontends.md)). Scanning
in visitor's browser inverts that: packets originate from
*their* connection, corpberry's IP reputation never at stake, need
none of that abuse machinery.

### Non-goals (explicit)
- **Not** general internet port scanner. Scanning arbitrary public IPs from
  browser unreliable & looks abusive; don't do it.
- **Not** firewall/"stealth" tester. Requires *inbound* probe from
  external host (ShieldsUP!'s model) — opposite direction from browser's
  outbound-only connections. Link to ShieldsUP! for that instead.
- **No** raw TCP/SYN/UDP, **no** banner/version detection — impossible in
  browser (CORS makes every cross-origin response opaque).
- **No** server-side scanning fallback. If browser can't, we explain
  why; never "helpfully" scan from server.

## 2. Feasibility — what the browser actually allows (the honest boundary)

From [`browser-constraints-2026.md`](../reports/browser-constraints-2026.md).
Four gates stack; probe must clear all.

| Gate | Effect on us |
|---|---|
| **Mixed content** (HTTPS page → `http://`) | Blocked in general, **but loopback (`127.0.0.1`, `localhost`, `*.localhost`) exempt** in Chrome & Firefox — "potentially trustworthy" secure context. **Safari blocks even loopback** → Safari probes nothing. |
| **Local Network Access** (Chrome 142, shipped ~Oct 2025) | Permission prompt gates public→loopback/private requests. Triggered by user gesture (scan button). Set `targetAddressSpace: "loopback"` on request. **Must verify at build time** whether loopback needs click in current Chrome, or only LAN does. |
| **Bad-ports list** (`ERR_UNSAFE_PORT`, WHATWG Fetch) | Browsers flatly refuse ~dozens of ports (22 SSH, 25 SMTP, 53 DNS, 110/143, 137/139, 389, 5060, 6000, 6665-6669…). **Can never be probed** — catalog must exclude them or they error & confuse users. `445` SMB *not* on list; `80/443/3000/3306/5432/6379/8080/9200/27017` *not* blocked. |
| **WebRTC mDNS obfuscation** | Since Chrome M73 real LAN IP hidden behind `<uuid>.local` candidate. So **cannot** auto-discover subnet for LAN sweep — if we ever do LAN, user types subnet. |

**What we can honestly deliver:** best-effort reachability of visitor's own
loopback over HTTP, non-blocked ports, reading only connect/timing signal.
Genuinely useful — detects running Postgres, Redis, Mongo, Docker daemon,
dev server, etc. Nothing more, & we say so plainly.

**Result states** — inferred from `fetch` promise outcome + timing, never real
socket, so we borrow Nmap's honest vocabulary
([`nmap-concepts.md`](../reports/nmap-concepts.md)) & never guess "open":

| State | Signal | Meaning shown to user |
|---|---|---|
| **open** | promise resolves / errors *after* connecting, fast | "responding — something is listening and speaking HTTP" |
| **closed** | promise rejects *fast* (`ECONNREFUSED`) | "refused — nothing listening on that port" |
| **filtered** | hangs to our timeout | "no response — filtered, or open but not HTTP (e.g. a database/SSH). Can't tell which from a browser." |

## 3. Architecture fit

Follows existing layered pattern, w/ one honest caveat that has
**direct precedent in this very tool**: IPv6 check already documented as
*"the one genuinely client-side piece… isn't in JSON — by nature, not
omission"* ([`../README.md`](../README.md)). Port scanner is same shape,
larger.

- **Server-side domain (pure Go):** **port catalog** — list of ports we
  probe, each w/ service label + category. Single source of
  truth. Feeds both server-rendered table & JSON endpoint.
- **Transport (handler):** one new route, content-negotiated like
  rest of tool (`platform.Respond` / `WantsJSON` / `IsHTMX`).
- **Client-side (vendored JS):** scan **engine** — part that literally
  cannot run on server. Mirrors `botcheck.js` precedent (hand-written,
  no npm, `shared/static/js/`, loaded via `{{asset …}}`).

**Golden-rule #2 ("every feature speaks HTML + JSON"):** honored genuinely, not
performatively. *Catalog* speaks both — HTML page for browsers, JSON for
CLI (`curl` gets list of ports + service names this tool knows). *Scan
results* browser-only by nature (same as IPv6 check). We do **not**
invent fake server-side scan just to have JSON result. → *flagged for
YAGNI reviewer: is JSON catalog worth it, or ceremony?*

### Endpoint contract
| Request | Response |
|---|---|
| `GET /ports` (browser) | Full scanner page: intro + trust line + "Scan my machine" button + server-rendered port table (all rows start `pending`) + browser-support notice. |
| `GET /ports` (JSON, e.g. `curl`) | `{"note":"scan runs in your browser; this is the catalog it probes","ports":[{"port":5432,"service":"PostgreSQL","category":"database"}, …]}` |
| htmx | Not used. Scan is pure Alpine/JS (CLAUDE.md rule #4: htmx only when plain HTML can't); no fragment swap needed. |

## 4. Server-side changes (Go)

All in `tools/iptools/` (self-contained, per CLAUDE.md layout).

1. **`ports.go`** — new domain file. Pure Go, no HTTP:
   ```go
   type Port struct {
       Number   int    `json:"port"`
       Service  string `json:"service"`
       Category string `json:"category"` // "web" | "database" | "cache" | "infra" | …
       Note     string `json:"note,omitempty"`
   }
   // PortCatalog returns the curated, hand-maintained list of browser-probeable
   // ports. Deliberately excludes every WHATWG bad port (they can't be probed).
   func PortCatalog() []Port { … }
   ```
   ~20-30 entries: dev servers (3000, 5173, 8000, 8080, 4200…), databases (3306,
   5432, 27017, 1433…), caches/brokers (6379, 11211, 5672…), infra (2375 Docker,
   9200 Elasticsearch, 8500 Consul…), plus 80/443/445. **Zero bad ports.**
2. **`handler.go`** — add `e.GET("/ports", h.ports)` in `Register`, &:
   ```go
   func (h *handler) ports(c *echo.Context) error {
       cat := PortCatalog()
       if platform.WantsJSON(c) {
           return c.JSON(http.StatusOK, map[string]any{"note": …, "ports": cat})
       }
       return c.Render(http.StatusOK, "ip/ports", map[string]any{
           "Title": "Port scan", "Active": "ports", "Ports": cat, "Attribution": false,
       })
   }
   ```
   Note `Attribution: false` — page uses no IP2Location data, so LITE
   credit clause doesn't apply (same logic as `/cidr`).
3. **`nav.html`** — add fourth segmented-control link, `.Active "ports"`.
4. **`templates/ports.html`** — new `{{define "ip/ports"}}` page (see §6).

## 5. Client-side engine — `shared/static/js/portscan.js`

Hand-written, vendored, no npm (rule #3). Driven by small Alpine component so
results table is reactive, matching `ipv6probe` idiom already in
`index.html`. Registered on `alpine:init`; `<script src="{{asset
"js/portscan.js"}}">` tag lives in `ports.html`.

**Probe primitive** (from
[`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md) —
`no-cors fetch()` cleanest signal, least calibration, works from HTTPS
because loopback trustworthy):

```js
async function probe(port, timeoutMs) {
  const t0 = performance.now();
  try {
    await fetch(`http://127.0.0.1:${port}/`, {
      mode: "no-cors",
      signal: AbortSignal.timeout(timeoutMs),
      // declare intent + clear mixed-content/LNA in current Chrome
      targetAddressSpace: "loopback",
    });
    return { state: "open", ms: performance.now() - t0 };   // resolved → listening HTTP
  } catch (e) {
    const ms = performance.now() - t0;
    if (e.name === "TimeoutError" || ms >= timeoutMs * 0.9)
      return { state: "filtered", ms }; // hung → filtered or open-non-HTTP
    return { state: "closed", ms };      // fast reject → refused
  }
}
```

Engine responsibilities:
- **Calibration first.** Probe port we expect closed (random high port) to
  learn "fast reject" baseline, since `performance.now()` coarsened
  (~100µs) & absolute timings drift. Show brief "calibrating…" step so
  numbers read as principled.
- **Bounded concurrency.** Small batches (≈6-8 in flight) — Chrome throttles
  socket pool; flood makes timing "weird and inconsistent." Stream each
  result into table as it lands (progressive render, GRC/BrowserLeaks style).
- **Browser gating.** Feature-detect up front:
  - Safari (no loopback mixed content) → don't scan; show "why your browser
    blocks this" explainer (turn limit into teaching moment).
  - Chrome 142+ → scan button is user gesture; if LNA prompt
    appears, inline "click Allow to let *your* browser probe *your* machine"
    note explains it. If denied, everything reads `filtered` — detect
    all-filtered pattern & hint permission likely denied.
  - Firefox → works for loopback; note partial LAN support.
- **Bad-port guard for custom input** (Phase 2): `BAD_PORTS` Set in JS; if
  user types one, show "browsers can't probe port N (protocol-safety block)"
  instead of misleading `filtered`. Go catalog needs no such guard — it's
  curated clean. (Single browser-side concern → single home; not duplicated.)

## 6. UI / UX (`ports.html`)

Reuse existing idioms: `.card`, `.eyebrow`, `dl.spec`, `.btn-primary`,
`.field`, `text-ok` / `text-danger` / `text-faint`, `.alert-error`. Tailwind sees
only literal class strings (never build class names in Go).

Layout, top to bottom:
1. `ip/nav` w/ **Port scan** active.
2. **H1 + one-paragraph intro** stating scope: "Finds services listening on your
   own computer (localhost). Runs entirely in your browser."
3. **Trust line, prominent:** *"This scan runs in your browser, from your own
   connection. corpberry never sends the packets and never sees the results."*
   No server-side competitor can say this — the differentiator.
4. **Scan controls:** preset selector (MVP: just "Common dev ports"; Phase 2
   adds "Databases", "Remote access") + big **"Scan my machine"** button. Scan
   **never auto-fires on page load** (see §7).
5. **Headline verdict banner** after run: "6 of 24 ports responding" w/
   green/amber styling — GRC's TruStealth-banner idea, restated honestly.
6. **Results table** — `PORT · SERVICE · STATE`, color-coded rows, service
   labels from catalog, each row a clickable "what is this?" note (cheap
   education, GRC idea). Rows start `pending`, fill in as probes complete.
7. **Copy results** button (text/JSON) — professional, near-zero cost.
8. **Browser-support notice** + short **"How this works / Background"** details
   block (technique, why states inferred, link to ShieldsUP! for external
   firewall testing). SEO + expectation-setting, like CanYouSeeMe's on-page
   explainer.

Result copy **first-person & plain** (CanYouSeeMe idea), surfaces
*reason* (refused vs no-response), never fear-mongers.

## 7. Ethics & the eBay lesson (product correctness, not paranoia)

This exact technique caused 2020 eBay/ThreatMetrix backlash (Schneier, The
Register, BleepingComputer) — sites scanned visitors' localhost
**silently, on page load, without consent**
([`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md)).
Our tool is opposite by design; these are baseline product choices, not
defensive gold-plating:
- **Opt-in only** — button click starts it; nothing scans on load.
- **Unmistakably "your own machine"** — copy, `127.0.0.1` target, &
  trust line all say so.
- **No exfiltration** — results stay in browser (MVP writes nothing to
  server; see history caveat in §9).

Deliberately **absent** (would be paranoia / YAGNI for client-side tool):
rate limiting, captcha, per-IP caps, identity walls, heavy legal disclaimers.
Server has no scan-abuse surface, so needs no scan-abuse defenses. → *for
no-paranoia reviewer: confirm we haven't smuggled in server-side-tool
defenses that make no sense here.*

## 8. Testing (CLAUDE.md rule #6)

Go side (black-box, in `tools/iptools/tests/`):
- `PortCatalog()` non-empty, every entry has service label, & **no entry
  is a WHATWG bad port** (assert against bad-port set — the test that
  actually matters).
- `/ports` handler: JSON request → catalog JSON w/ right shape; browser
  request → renders `ip/ports`; nav `Active` = "ports".

JS side: no npm/node test harness in this repo (consistent w/
`botcheck.js` being untested JS). Verification **manual & documented**: run
local service on known port (`python -m http.server 8000`, `redis-server`),
load `/ports`, confirm state. Document manual steps in `../README.md`.
→ *is untested JS acceptable here, or do we need minimal harness? flag for
review.*

## 9. Phasing

**Phase 1 — MVP (build first):** loopback scan, curated catalog, `no-cors fetch`
engine w/ calibration + bounded concurrency, three honest states, browser
gating (Safari explainer), results table + headline banner + trust line, copy
button, Go catalog + JSON endpoint, Go tests, docs.

**Phase 2 — later:** custom port input (w/ bad-port guard), more presets
("databases", fun ~14-port eBay "remote-access" replica), WebSocket
connect-timing mode for non-HTTP ports (RDP/VNC) w/ concurrency caps.

**Phase 3 — optional / speculative:** LAN scan (user types subnet, Chrome LNA
prompt); WebRTC subnet *hint* (flagged unreliable — mDNS); InternetDB enrichment
of resolved public IP (verify CORS; proxy would re-introduce server
traffic → probably don't); own-scan history + "re-run & diff" reusing
existing Mongo lookup-history pattern — **but** persisting a list of what's
running on user's machine is a privacy step-down from "results never leave the
browser," so needs deliberate decision, not a default.

## 10. Open questions / decisions needed
1. **Does current Chrome show LNA prompt for *loopback*, or only LAN?** Must
   verify empirically before shipping — changes first-run UX copy.
2. **Is JSON catalog endpoint worth it** (rule #2) or ceremony (YAGNI)?
3. **Untested JS** — acceptable (matches `botcheck.js`), or add minimal
   harness?
4. **Nav label** — "Port scan" vs "Open ports" vs "Local ports"?
5. **Re-verify bad-ports list against WHATWG spec at build time** — it
   moves; newly-blocked port in catalog would silently misreport.

## 11. Files touched (MVP)
- `tools/iptools/ports.go` — **new** (domain: `Port`, `PortCatalog`).
- `tools/iptools/handler.go` — add route + `ports` handler.
- `tools/iptools/templates/ports.html` — **new** (`ip/ports` page).
- `tools/iptools/templates/nav.html` — add 4th tab.
- `shared/static/js/portscan.js` — **new** (scan engine).
- `tools/iptools/tests/ports_test.go` — **new** (catalog + handler tests).
- `tools/iptools/docs/README.md` — document the page + manual JS verification.

## 12. References
All ten research reports in [`../reports/`](../reports/). Most load-bearing:
- [`00-landscape-and-ideas.md`](../reports/00-landscape-and-ideas.md) — synthesis, comparison table, ideas-to-steal, feasibility verdict.
- [`browser-constraints-2026.md`](../reports/browser-constraints-2026.md) — the four gates, bad-ports list, LNA, Safari stop.
- [`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md) — probe primitives, calibration, eBay case, ethics.
- [`nmap-concepts.md`](../reports/nmap-concepts.md) — honest port-state vocabulary.
- [`grc-shieldsup.md`](../reports/grc-shieldsup.md), [`browserleaks.md`](../reports/browserleaks.md), [`canyouseeme.md`](../reports/canyouseeme.md), [`yougetsignal.md`](../reports/yougetsignal.md), [`online-nmap-frontends.md`](../reports/online-nmap-frontends.md), [`shodan-censys.md`](../reports/shodan-censys.md), [`privacy-leak-test-suites.md`](../reports/privacy-leak-test-suites.md) — UX / result-presentation / business ideas.
