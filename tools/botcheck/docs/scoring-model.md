# Bot check — scoring model (no ML, deterministic)

*(part of the [botcheck docs index](README.md))*

Start at **100** and subtract each triggered rule's weight; clamp at 0; map to a
band: `≥80 human`, `≥50 suspicious`, else `bot`. `Evaluate` is a pure function of
`Signals` — no DB, no ML, no globals — so it is trivially testable and race-free.
Rules are tiered:

> **Good-bot override (G36).** A recognised crawler / AI agent (see
> [`goodbots.go`](../goodbots.go)) is *named* on the report. If the egress ASN
> **number** is the operator's single-tenant crawler AS — one an outsider can't
> originate from (matched by number, not owner name, since the name also covers the
> operator's rentable public cloud) — the verdict is overridden to `good-bot` and its
> expected deductions (`bot_user_agent`, `datacenter_ip`, `proxy_ip`,
> `fingerprint_reuse`) are recorded as
> "expected", not counted. Recognition alone never lowers the score: a merely
> *declared* Googlebot (or any UA copy) stays a fully-penalised `bot`, so there is no
> spoof path to leniency. Every other tell (webdriver, CDP, tamper) still counts.

- **Hard tells** (≈40–60): `navigator.webdriver`, automation-framework globals,
  bot/HTTP-client User-Agent, monkey-patched natives, a proxied/replaced
  `Function.prototype.toString` (stealth hallmark), software WebGL renderer,
  `navigator.webdriver` true inside the iframe or the Service Worker.
- **Consistency** (≈15–35): JS UA ≠ HTTP UA; Worker/iframe/Service-Worker UA ≠
  main UA; `Sec-CH-UA-Platform` ≠ `userAgentData.platform`; UA OS ≠ platform;
  embedded runtime (Electron/CEF); browser TZ offset ≠ IP TZ offset;
  datacenter/Tor IP; proxy/VPN IP; impossible permission state;
  `navigator.languages` ≠ `Accept-Language`; `navigator.vendor` ≠ `"Google Inc."`
  on a Chromium UA; `navigator.appVersion` ≠ UA; `navigator.language` ≠
  `languages[0]`; IANA zone ≠ `getTimezoneOffset()` (self-consistency); canvas
  randomised between draws; `Sec-CH-UA` header brands ≠ `userAgentData.brands`;
  feature-detected engine ≠ engine the UA claims; UA `Chrome/NNN` major ≠ the
  `Chromium` `fullVersionList` entry; `navigator.productSub` ≠ the engine's
  constant; WebGL unmasked vendor ≠ renderer family; GPU family impossible on
  the UA-claimed OS; context (worker/iframe/SW) language, core count, or
  platform ≠ main thread; worker WebGL renderer ≠ main-thread renderer; native
  function with an impossible property descriptor or missing its call/new
  `TypeError` traps; iframe `contentWindow` proxied; mobile UA with zero touch
  points; Navigator.prototype accessor-descriptor anomaly; `chrome.runtime`
  integrity failure; `window.chrome` injected late; Error-stack JS engine ≠
  engine the UA claims; public WebRTC candidate IP ≠ egress IP; this exact
  fingerprint seen from ≥5 distinct IPs in the rolling 30-day corpus.
- **Soft** (8 each): no plugins, empty languages, default 800×600, impossible
  window geometry, missing `window.chrome`, implausible hardware, available
  screen larger than physical, low colour depth, browser UA without `Sec-Fetch-*`,
  canvas renders blank, no H.264/AAC codecs, no detectable fonts, browser UA
  without `Accept-Encoding`, without `Accept-Language`, or with an `Accept`
  lacking `text/html`, a guaranteed-loadable image failing, plugins without
  `mimeTypes`, zero `outerHeight`, browser UA without `window.matchMedia`,
  `navigator.connection` effectiveType contradicting its own rtt/downlink, and
  (as of 2026-07-19) the three CDP-preview checks (`cdp_both`/`cdp_main_only`/
  `cdp_sw_only`) — downgraded from hard/consistency after an audit found they
  never fire against real CDP-driven automation; see
  [the CDP-trap finding](testing/findings/2026-07-19-cdp-trap-family-confirmed-dead.md). Soft signals **only bite
  as a cluster of ≥3** (one 25-point deduction), so a single quirk never
  false-positives a real human.

The load-bearing rules are the **cross-checks** — combinations that should not
co-occur — because a rule engine beats a checklist here: JS `navigator.userAgent`
vs the HTTP header; `Sec-CH-UA-Platform` (header) vs `userAgentData.platform`
(JS); `Intl` timezone vs IP2Location timezone (a datacenter IP **and** a TZ
mismatch is worse than either alone — they pair, not double-count); UA-claimed OS
vs `userAgentData.platform` vs the GPU renderer's implied platform; main-thread
navigator vs Worker vs iframe. Any single hard tell (≥40) drops a clean 100 below
80 on its own, so a real automation flag never reads "human." (2026-07-19 caveat:
this held up well in practice — see the `puppeteer-extra-plugin-stealth` test in
[the multi-framework matrix results](testing/findings/2026-07-19-multi-framework-matrix-results.md), where the cross-context
checks caught what six purpose-built stealth-detection rules missed.)

Every rule appears in the response `checks` list as flagged / clean /
`not collected` (a client rule on a server-only request is skipped, never counted
as a pass) — the breakdown is the point. In the HTML view the checks are grouped
by tier (automation tells / consistency cross-checks / environment heuristics),
with the number + verdict at the top and the per-signal table below.

For the full list of 66 rules with IDs, weights, and current tier, read
[`../scoring.go`](../scoring.go) directly — it's the ordered, authoritative
source; this doc is a summary, not a mirror.
