# Client-side port scanner — implementation plan (DRAFT v1, pre-review)

> A new page on `ip.corpberry.com` that scans **the visitor's own machine** for
> listening ports **entirely in their browser**. The Go server serves the page +
> a port catalog and **never emits a single scan packet** — that's the whole
> point, and the marketing hook.

**Status:** draft for the DRY / KISS / YAGNI / no-paranoia review pass. Do not
build yet. Grounded in the ten research reports in
[`../reports/`](../reports/) — start with
[`00-landscape-and-ideas.md`](../reports/00-landscape-and-ideas.md),
[`browser-constraints-2026.md`](../reports/browser-constraints-2026.md), and
[`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md).

---

## 1. Goal & scope

Add a fourth IP-tool page: **"Port scan"** (`/ports`). The visitor clicks a
button; JavaScript in their browser probes a curated list of well-known ports on
`http://127.0.0.1:<port>` and reports, per port, an honest **inferred** state
(responding / refused / no-response). The server's only jobs are to serve the
page and expose the port catalog as JSON.

**Why client-side (the core requirement):** a server-side scanner (GRC
ShieldsUP!, YouGetSignal, the online Nmap frontends) sends outbound/inbound scan
traffic *from the operator's IP* — which is why those tools all bolt on
captchas, per-IP caps, "payment as identification," and authorization
checkboxes to avoid getting blocklisted (see
[`online-nmap-frontends.md`](../reports/online-nmap-frontends.md)). Doing the
scan in the visitor's browser inverts that entirely: the packets originate from
*their* connection, corpberry's IP reputation is never at stake, and we need
none of that abuse machinery.

### Non-goals (explicit)
- **Not** a general internet port scanner. Scanning arbitrary public IPs from a
  browser is unreliable and looks abusive; we don't do it.
- **Not** a firewall/"stealth" tester. That requires an *inbound* probe from an
  external host (ShieldsUP!'s model) — the opposite direction from a browser's
  outbound-only connections. We'll link to ShieldsUP! for that instead.
- **No** raw TCP/SYN/UDP, **no** banner/version detection — impossible in a
  browser (CORS makes every cross-origin response opaque).
- **No** server-side scanning fallback. If the browser can't do it, we explain
  why; we never "helpfully" scan from the server.

## 2. Feasibility — what the browser actually allows (the honest boundary)

From [`browser-constraints-2026.md`](../reports/browser-constraints-2026.md).
Four gates stack; a probe must clear all of them.

| Gate | Effect on us |
|---|---|
| **Mixed content** (HTTPS page → `http://`) | Blocked in general, **but loopback (`127.0.0.1`, `localhost`, `*.localhost`) is exempt** in Chrome & Firefox because it's a "potentially trustworthy" secure context. **Safari blocks even loopback** → Safari can probe nothing. |
| **Local Network Access** (Chrome 142, shipped ~Oct 2025) | A permission prompt gates public→loopback/private requests. Triggered by a user gesture (our scan button). Set `targetAddressSpace: "loopback"` on the request. **Must be verified at build time** whether loopback needs the click in current Chrome, or only the LAN does. |
| **Bad-ports list** (`ERR_UNSAFE_PORT`, WHATWG Fetch) | Browsers flatly refuse ~dozens of ports (22 SSH, 25 SMTP, 53 DNS, 110/143, 137/139, 389, 5060, 6000, 6665-6669…). These **can never be probed** — our catalog must exclude them or they error and confuse users. `445` SMB is *not* on the list; `80/443/3000/3306/5432/6379/8080/9200/27017` are *not* blocked. |
| **WebRTC mDNS obfuscation** | Since Chrome M73 the real LAN IP is hidden behind a `<uuid>.local` candidate. So we **cannot** auto-discover the subnet for a LAN sweep — if we ever do LAN, the user types their subnet. |

**What we can honestly deliver:** best-effort reachability of the visitor's own
loopback over HTTP, on non-blocked ports, reading only connect/timing signal.
Genuinely useful — it detects a running Postgres, Redis, Mongo, Docker daemon,
dev server, etc. Nothing more, and we say so plainly.

**Result states** — inferred from `fetch` promise outcome + timing, never a real
socket, so we borrow Nmap's honest vocabulary
([`nmap-concepts.md`](../reports/nmap-concepts.md)) and never guess "open":

| State | Signal | Meaning shown to user |
|---|---|---|
| **open** | promise resolves / errors *after* connecting, fast | "responding — something is listening and speaking HTTP" |
| **closed** | promise rejects *fast* (`ECONNREFUSED`) | "refused — nothing listening on that port" |
| **filtered** | hangs to our timeout | "no response — filtered, or open but not HTTP (e.g. a database/SSH). Can't tell which from a browser." |

## 3. Architecture fit

This follows the existing layered pattern, with one honest caveat that has
**direct precedent in this very tool**: the IPv6 check is already documented as
*"the one genuinely client-side piece… isn't in JSON — by nature, not
omission"* ([`../README.md`](../README.md)). The port scanner is the same shape,
larger.

- **Server-side domain (pure Go):** the **port catalog** — the list of ports we
  probe, each with a service label + category. This is the single source of
  truth. It feeds both the server-rendered table and the JSON endpoint.
- **Transport (handler):** one new route, content-negotiated exactly like the
  rest of the tool (`platform.Respond` / `WantsJSON` / `IsHTMX`).
- **Client-side (vendored JS):** the scan **engine** — the part that literally
  cannot run on the server. Mirrors the `botcheck.js` precedent (hand-written,
  no npm, `shared/static/js/`, loaded via `{{asset …}}`).

**Golden-rule #2 ("every feature speaks HTML + JSON"):** honored genuinely, not
performatively. The *catalog* speaks both — HTML page for browsers, JSON for
CLI (`curl` gets the list of ports + service names this tool knows about). The
*scan results* are browser-only by nature (same as the IPv6 check). We do **not**
invent a fake server-side scan just to have a JSON result. → *flagged for the
YAGNI reviewer: is the JSON catalog worth it, or ceremony?*

### Endpoint contract
| Request | Response |
|---|---|
| `GET /ports` (browser) | Full scanner page: intro + trust line + "Scan my machine" button + server-rendered port table (all rows start `pending`) + browser-support notice. |
| `GET /ports` (JSON, e.g. `curl`) | `{"note":"scan runs in your browser; this is the catalog it probes","ports":[{"port":5432,"service":"PostgreSQL","category":"database"}, …]}` |
| htmx | Not used here. The scan is pure Alpine/JS (CLAUDE.md rule #4: htmx only when plain HTML can't); no fragment swap needed. |

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
2. **`handler.go`** — add `e.GET("/ports", h.ports)` in `Register`, and:
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
   Note `Attribution: false` — this page uses no IP2Location data, so the LITE
   credit clause doesn't apply (same logic as `/cidr`).
3. **`nav.html`** — add a fourth segmented-control link, `.Active "ports"`.
4. **`templates/ports.html`** — new `{{define "ip/ports"}}` page (see §6).

## 5. Client-side engine — `shared/static/js/portscan.js`

Hand-written, vendored, no npm (rule #3). Driven by a small Alpine component so
the results table is reactive, matching the `ipv6probe` idiom already in
`index.html`. Registered on `alpine:init`; the `<script src="{{asset
"js/portscan.js"}}">` tag lives in `ports.html`.

**Probe primitive** (from
[`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md) —
`no-cors fetch()` is the cleanest signal, least calibration, works from HTTPS
because loopback is trustworthy):

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
- **Calibration first.** Probe a port we expect closed (a random high port) to
  learn the "fast reject" baseline, since `performance.now()` is coarsened
  (~100µs) and absolute timings drift. Show a brief "calibrating…" step so the
  numbers read as principled.
- **Bounded concurrency.** Small batches (≈6-8 in flight) — Chrome throttles the
  socket pool; a flood makes timing "weird and inconsistent." Stream each
  result into the table as it lands (progressive render, GRC/BrowserLeaks style).
- **Browser gating.** Feature-detect up front:
  - Safari (no loopback mixed content) → don't scan; show the "why your browser
    blocks this" explainer (turn the limit into a teaching moment).
  - Chrome 142+ → the scan button is the user gesture; if the LNA prompt
    appears, an inline "click Allow to let *your* browser probe *your* machine"
    note explains it. If denied, everything reads `filtered` — detect the
    all-filtered pattern and hint that the permission was likely denied.
  - Firefox → works for loopback; note partial LAN support.
- **Bad-port guard for custom input** (Phase 2): a `BAD_PORTS` Set in JS; if the
  user types one, show "browsers can't probe port N (protocol-safety block)"
  instead of a misleading `filtered`. The Go catalog needs no such guard — it's
  curated clean. (Single browser-side concern → single home; not duplicated.)

## 6. UI / UX (`ports.html`)

Reuse existing idioms: `.card`, `.eyebrow`, `dl.spec`, `.btn-primary`,
`.field`, `text-ok` / `text-danger` / `text-faint`, `.alert-error`. Tailwind sees
only literal class strings (never build class names in Go).

Layout, top to bottom:
1. `ip/nav` with **Port scan** active.
2. **H1 + one-paragraph intro** stating scope: "Finds services listening on your
   own computer (localhost). Runs entirely in your browser."
3. **Trust line, prominent:** *"This scan runs in your browser, from your own
   connection. corpberry never sends the packets and never sees the results."*
   None of the server-side competitors can say this — it's the differentiator.
4. **Scan controls:** a preset selector (MVP: just "Common dev ports"; Phase 2
   adds "Databases", "Remote access") + a big **"Scan my machine"** button. The
   scan **never auto-fires on page load** (see §7).
5. **Headline verdict banner** after a run: "6 of 24 ports responding" with
   green/amber styling — GRC's TruStealth-banner idea, restated honestly.
6. **Results table** — `PORT · SERVICE · STATE`, color-coded rows, service
   labels from the catalog, each row a clickable "what is this?" note (cheap
   education, GRC idea). Rows start `pending`, fill in as probes complete.
7. **Copy results** button (text/JSON) — professional, near-zero cost.
8. **Browser-support notice** + a short **"How this works / Background"** details
   block (technique, why states are inferred, link to ShieldsUP! for external
   firewall testing). SEO + expectation-setting, like CanYouSeeMe's on-page
   explainer.

Result copy is **first-person and plain** (CanYouSeeMe idea), surfaces the
*reason* (refused vs no-response), and never fear-mongers.

## 7. Ethics & the eBay lesson (product correctness, not paranoia)

This exact technique caused the 2020 eBay/ThreatMetrix backlash (Schneier, The
Register, BleepingComputer) because sites scanned visitors' localhost
**silently, on page load, without consent**
([`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md)).
Our tool is the opposite by design, and these are baseline product choices, not
defensive gold-plating:
- **Opt-in only** — a button click starts it; nothing scans on load.
- **Unmistakably "your own machine"** — the copy, the `127.0.0.1` target, and
  the trust line all say so.
- **No exfiltration** — results stay in the browser (MVP writes nothing to the
  server; see history caveat in §9).

Deliberately **absent** (would be paranoia / YAGNI for a client-side tool):
rate limiting, captcha, per-IP caps, identity walls, heavy legal disclaimers.
The server has no scan-abuse surface, so it needs no scan-abuse defenses. → *for
the no-paranoia reviewer: confirm we haven't smuggled in server-side-tool
defenses that make no sense here.*

## 8. Testing (CLAUDE.md rule #6)

Go side (black-box, in `tools/iptools/tests/`):
- `PortCatalog()` is non-empty, every entry has a service label, and **no entry
  is a WHATWG bad port** (assert against the bad-port set — this is the test that
  actually matters).
- `/ports` handler: JSON request → catalog JSON with the right shape; browser
  request → renders `ip/ports`; nav `Active` = "ports".

JS side: no npm/node test harness exists in this repo (consistent with
`botcheck.js` being untested JS). Verification is **manual and documented**: run
a local service on a known port (`python -m http.server 8000`, `redis-server`),
load `/ports`, confirm the state. Document the manual steps in `../README.md`.
→ *is untested JS acceptable here, or do we need a minimal harness? flag for
review.*

## 9. Phasing

**Phase 1 — MVP (build first):** loopback scan, curated catalog, `no-cors fetch`
engine with calibration + bounded concurrency, three honest states, browser
gating (Safari explainer), results table + headline banner + trust line, copy
button, Go catalog + JSON endpoint, Go tests, docs.

**Phase 2 — later:** custom port input (with bad-port guard), more presets
("databases", the fun ~14-port eBay "remote-access" replica), WebSocket
connect-timing mode for non-HTTP ports (RDP/VNC) with concurrency caps.

**Phase 3 — optional / speculative:** LAN scan (user types subnet, Chrome LNA
prompt); WebRTC subnet *hint* (flagged unreliable — mDNS); InternetDB enrichment
of the resolved public IP (verify CORS; a proxy would re-introduce server
traffic → probably don't); own-scan history + "re-run & diff" reusing the
existing Mongo lookup-history pattern — **but** persisting a list of what's
running on a user's machine is a privacy step-down from "results never leave the
browser," so this needs a deliberate decision, not a default.

## 10. Open questions / decisions needed
1. **Does current Chrome show the LNA prompt for *loopback*, or only LAN?** Must
   be verified empirically before shipping — changes the first-run UX copy.
2. **Is the JSON catalog endpoint worth it** (rule #2) or ceremony (YAGNI)?
3. **Untested JS** — acceptable (matches `botcheck.js`), or add a minimal
   harness?
4. **Nav label** — "Port scan" vs "Open ports" vs "Local ports"?
5. **Re-verify the bad-ports list against the WHATWG spec at build time** — it
   moves; a newly-blocked port in our catalog would silently misreport.

## 11. Files touched (MVP)
- `tools/iptools/ports.go` — **new** (domain: `Port`, `PortCatalog`).
- `tools/iptools/handler.go` — add route + `ports` handler.
- `tools/iptools/templates/ports.html` — **new** (`ip/ports` page).
- `tools/iptools/templates/nav.html` — add 4th tab.
- `shared/static/js/portscan.js` — **new** (scan engine).
- `tools/iptools/tests/ports_test.go` — **new** (catalog + handler tests).
- `tools/iptools/docs/README.md` — document the page + manual JS verification.

## 12. References
All ten research reports live in [`../reports/`](../reports/). Most load-bearing:
- [`00-landscape-and-ideas.md`](../reports/00-landscape-and-ideas.md) — synthesis, comparison table, ideas-to-steal, feasibility verdict.
- [`browser-constraints-2026.md`](../reports/browser-constraints-2026.md) — the four gates, bad-ports list, LNA, Safari stop.
- [`client-side-scan-techniques.md`](../reports/client-side-scan-techniques.md) — probe primitives, calibration, eBay case, ethics.
- [`nmap-concepts.md`](../reports/nmap-concepts.md) — honest port-state vocabulary.
- [`grc-shieldsup.md`](../reports/grc-shieldsup.md), [`browserleaks.md`](../reports/browserleaks.md), [`canyouseeme.md`](../reports/canyouseeme.md), [`yougetsignal.md`](../reports/yougetsignal.md), [`online-nmap-frontends.md`](../reports/online-nmap-frontends.md), [`shodan-censys.md`](../reports/shodan-censys.md), [`privacy-leak-test-suites.md`](../reports/privacy-leak-test-suites.md) — UX / result-presentation / business ideas.
