# Bot check — scoring model (no ML, deterministic)

*(part of the [botcheck docs index](README.md))*

Start at **100**, subtract each triggered rule's weight; clamp at 0; map to band:
`≥80 human`, `≥50 suspicious`, else `bot`. `Evaluate` is pure function of
`Signals` — no DB, no ML, no globals — trivially testable and race-free. Rules
tiered:

> **Good-bot override (G36).** Recognised crawler / AI agent (see
> [`goodbots.go`](../goodbots.go)) is *named* on report. If egress ASN **number**
> is operator's single-tenant crawler AS — one outsider can't originate from
> (matched by number, not owner name, since name also covers operator's rentable
> public cloud) — verdict overridden to `good-bot`, expected deductions
> (`bot_user_agent`, `datacenter_ip`, `proxy_ip`, `fingerprint_reuse`) recorded as
> "expected," not counted. Recognition alone never lowers score: merely
> *declared* Googlebot (or any UA copy) stays fully-penalised `bot`, no spoof
> path to leniency. Every other tell (webdriver, CDP, tamper) still counts.

- **Hard tells** (≈40–60): `navigator.webdriver`, automation-framework globals,
  bot/HTTP-client User-Agent, monkey-patched natives, proxied/replaced
  `Function.prototype.toString` (stealth hallmark), software WebGL renderer,
  `navigator.webdriver` true inside iframe or Service Worker.
- **Consistency** (≈15–35): JS UA ≠ HTTP UA; Worker/iframe/Service-Worker UA ≠
  main UA; `Sec-CH-UA-Platform` ≠ `userAgentData.platform`; UA OS ≠ platform;
  embedded runtime (Electron/CEF); browser TZ offset ≠ IP TZ offset;
  datacenter/Tor IP; proxy/VPN IP; impossible permission state;
  `navigator.languages` ≠ `Accept-Language`; `navigator.vendor` ≠ `"Google Inc."`
  on Chromium UA; `navigator.appVersion` ≠ UA; `navigator.language` ≠
  `languages[0]`; IANA zone ≠ `getTimezoneOffset()` (self-consistency); canvas
  randomised between draws; `Sec-CH-UA` header brands ≠ `userAgentData.brands`;
  feature-detected engine ≠ engine UA claims; UA `Chrome/NNN` major ≠
  `Chromium` `fullVersionList` entry; `navigator.productSub` ≠ engine's constant;
  WebGL unmasked vendor ≠ renderer family; GPU family impossible on
  UA-claimed OS; context (worker/iframe/SW) language, core count, or platform ≠
  main thread; worker WebGL renderer ≠ main-thread renderer;
  iframe `contentWindow` proxied; mobile UA with zero touch points; Error-stack
  JS engine ≠ engine UA claims; public WebRTC candidate IP ≠ egress IP; this
  exact fingerprint seen from ≥5 distinct IPs in rolling 30-day corpus.
- **Soft** (8 each): no plugins, empty languages, default 800×600, impossible
  window geometry, missing `window.chrome`, implausible hardware, available
  screen larger than physical, low colour depth, browser UA without
  `Sec-Fetch-*`, canvas renders blank, no H.264/AAC codecs, no detectable fonts,
  browser UA without `Accept-Encoding`, without `Accept-Language`, or with
  `Accept` lacking `text/html`, guaranteed-loadable image failing, plugins
  without `mimeTypes`, zero `outerHeight`, browser UA without
  `window.matchMedia`, `navigator.connection` effectiveType contradicting its
  own rtt/downlink, one egress IP presenting ≥8 distinct fingerprints in a
  10-min window (`ip_fingerprint_churn`, the corpus fingerprint-rotation tell —
  G43, the temporal inverse of the `fingerprint_reuse` consistency rule),
  three CDP-preview checks
  (`cdp_both`/`cdp_main_only`/`cdp_sw_only`) — downgraded from hard/consistency
  2026-07-19 after audit found they never fire against real CDP-driven
  automation; see [the CDP-trap check status](testing/checks/cdp_both.md) — and
  (as of 2026-07-21) five deep-tamper probes: native function with impossible
  property descriptor or missing call/new `TypeError` traps
  (`native_descriptor_tamper`/`native_callnew_tamper`), Navigator.prototype
  accessor-descriptor anomaly (`navigator_proto_tamper`), `chrome.runtime`
  integrity failure (`chrome_runtime_tamper`), `window.chrome` injected late
  (`chrome_late_injection`) — downgraded from consistency/internals after the
  audit found current stealth evades all five while a privacy extension can trip
  them; see [the downgrade finding](testing/findings/2026-07-21-internals-tamper-downgraded-to-soft.md).
  Soft signals **only bite as cluster of ≥3** (one 25-point deduction), single
  quirk never false-positives a real human.

Load-bearing rules are the **cross-checks** — combos that shouldn't co-occur —
rule engine beats checklist here: JS `navigator.userAgent` vs HTTP header;
`Sec-CH-UA-Platform` (header) vs `userAgentData.platform` (JS); `Intl` timezone
vs IP2Location timezone (datacenter IP **and** TZ mismatch worse than either
alone — they pair, not double-count); UA-claimed OS vs `userAgentData.platform`
vs GPU renderer's implied platform; main-thread navigator vs Worker vs iframe.
Any single hard tell (≥40) drops clean 100 below 80 on its own, real automation
flag never reads "human." (2026-07-19 caveat: held up well in practice — see
`puppeteer-extra-plugin-stealth` test in
[the multi-framework matrix results](testing/findings/2026-07-19-multi-framework-matrix-results.md),
where cross-context checks caught what six purpose-built stealth-detection
rules missed.)

Every rule appears in response `checks` list as flagged / clean /
`not collected` (client rule on server-only request skipped, never counted as
pass) — breakdown is the point. In HTML view checks grouped by tier (automation
tells / consistency cross-checks / environment heuristics), number + verdict at
top, per-signal table below.

For full list of 67 rules with IDs, weights, current tier, read
[`../scoring.go`](../scoring.go) directly — ordered, authoritative source; this
doc is summary, not mirror.
