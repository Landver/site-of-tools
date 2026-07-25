# Remaining 43 checks: real-automation + fire-branch sweep

*(part of [findings-log.md](../findings-log.md), see [testing index](../README.md))*

Closes out every check that sat at "Not yet tested against real automation" in
[checks/](../checks/README.md) — 43 of them. Per-check outcome in each check's
own file; this = how-we-found-out record.

## Method

Local dev (`APP_ENV=dev`, already running, `botcheck.localhost:8080`), same
target discipline as prior findings here.

1. **Header-only soft checks** (`accept_encoding_missing`,
   `accept_language_missing`, `accept_nav_mismatch`, `sec_fetch_missing`) —
   plain `curl` against `GET /` (JSON mode) & `POST /check` (mimics real
   collector's `Accept: text/html` fetch), toggling each header present/absent,
   browser UA vs non-browser UA. All four fire & stay silent exactly per
   `looksLikeBrowser(UA)` gating in [`botcheck.go`](../../../botcheck.go).

2. **`fingerprint_reuse`** — `POST /check` w/ identical synthetic fingerprint
   JSON body from 6 distinct spoofed `CF-Connecting-IP` values (header
   `platform/app.go`'s `cfIPExtractor()` trusts unconditionally — safe only
   because dev has no nginx in front to strip it, see that file's comment).
   Fired at exactly 5th distinct IP (`fingerprintReuseMinIPs` floor), not 4th;
   repeat hits from one IP never inflated count. Full pass against live Mongo
   corpus, both edges.

3. **UA/engine/platform-mismatch family** — new
   [`automation-harness/ua-mismatch-probe.mjs`](../../../../../automation-harness/ua-mismatch-probe.mjs):
   one Puppeteer scenario per check, each patching exactly one side of
   comparison (`navigator.userAgent`, `.vendor`, `.appVersion`, `.productSub`,
   `.language`, `.languages`, `.userAgentData`) via `evaluateOnNewDocument`,
   through real `botcheck.js` collector, not Go-side `Signals{}` literal.
   Every scenario fired exactly the check(s) it targeted:
   `ua_header_mismatch`, `engine_ua_mismatch`, `jsengine_ua_mismatch`,
   `vendor_mismatch`, `app_version_mismatch`, `productsub_mismatch`,
   `language_primary_mismatch`, `lang_mismatch` (bonus:
   `context_language_mismatch` fired alongside it), `embedded_runtime`,
   `mobile_no_touch`. `ch_platform_mismatch` scenario instead fired
   `context_platform_mismatch` — see caveat below.

   **Caveat found:** root `automation-harness`'s plain `puppeteer.launch()` (no
   CDP metadata override) reports EMPTY
   `navigator.userAgentData.platform`/`.brands` & empty
   `getHighEntropyValues(["fullVersionList"])` on this origin, even
   unmodified — confirmed `isSecureContext: true`, so not that. `raw-cdp` &
   `selenium` (real "Chrome for Testing" launched w/o Puppeteer's launcher)
   both report full, real Client Hints on same origin, so this is specific to
   how root `puppeteer` package's default launch talks to this browser build,
   not a property of the origin or of Chrome-for-Testing generally. Never
   chased further (out of scope) — worked around instead (next point).

4. **`ch_platform_mismatch`, `ch_brands_mismatch`, `ua_chrome_version_mismatch`,
   `ua_os_mismatch`** — closed w/ direct `curl POST /check`, a
   `Sec-CH-UA-Platform`/`Sec-CH-UA` header plus synthetic client JSON body
   carrying deliberately different `uaData`/`brands`/`navMainUA`. All four
   comparisons are server-observed-header vs. client-JSON or client-JSON vs.
   client-JSON — no browser Client Hints support required to exercise Go
   comparison end to end through live handler. All four fired w/ exact expected
   `detail` string.

5. **DOM/API-override family** — new
   [`automation-harness/fire-branch-probe.mjs`](../../../../../automation-harness/fire-branch-probe.mjs):
   18 more scenarios, each patching one native (`Function.prototype.toString`,
   `CanvasRenderingContext2D.prototype.{measureText,getImageData}`,
   `HTMLCanvasElement.prototype.toDataURL`, `HTMLImageElement.prototype.
   naturalWidth`, `HTMLVideoElement`/`HTMLAudioElement.prototype.canPlayType`,
   `HTMLIFrameElement.prototype.contentWindow`, `Navigator.prototype.
   {languages,plugins,mimeTypes,hardwareConcurrency,connection}`,
   `Screen.prototype.{colorDepth,availWidth}`, `window.{outerHeight,chrome,
   matchMedia}`, `Date.prototype.getTimezoneOffset`) to construct exact
   condition each rule targets. All 18 fired correctly:
   `native_tamper`, `empty_languages`, `empty_plugins`,
   `plugins_mimetypes_incoherent`, `implausible_hardware`, `low_color_depth`,
   `screen_avail_impossible`, `zero_outer_height`, `no_chrome_object`,
   `matchmedia_missing`, `missing_proprietary_codecs`, `no_fonts`,
   `image_broken`, `iframe_proxy`, `canvas_blank`, `canvas_unstable`,
   `netinfo_incoherent`, `tz_self_inconsistent`.

   Two setup snags, both harness technique, not botcheck bugs: `window.chrome`
   is a non-configurable-but-**writable** own property on this Chromium build —
   `delete`/`Object.defineProperty` throws "Cannot redefine property," plain
   `window.chrome = undefined` works. And deleting `window.matchMedia`
   correctly tripped `matchmedia_missing`, but also threw a *separate*, real
   bug — see below.

6. **`default_geometry`, `impossible_window`** — needed no construction: fired
   on stock, unmodified headless automation (Selenium's real 800×600 screen
   default; plain headless Puppeteer's `outerHeight: 0` w/ no window-size flag
   set). Strongest evidence tier — genuine off-the-shelf automation, not
   synthetic probe.

7. **Genuine-human baseline** — Claude's own in-app browser (Electron
   42.5.1-embedded Chromium — correctly fires only `embedded_runtime`,
   75/100 "Suspicious," matching existing `chrome_runtime_tamper` finding's
   incidental note about this same sandbox) and, separately, user's actual
   Chrome 149/macOS via Claude-in-Chrome connector — **100/100 "Looks human,"
   one exception**: `zero_outer_height` read **flagged**, not `ok`. Real,
   unmodified Chrome window, under Claude-in-Chrome's own extension-driven
   automation, reported `window.outerHeight === 0` — false positive existing
   entirely independent of any spoofing. No fix warranted: precisely why
   `zero_outer_height` is soft-tier & only bites inside a ≥3-signal cluster
   (see `Evaluate` in [`botcheck.go`](../../../botcheck.go)) — the one real
   occurrence here cost nothing, exactly as designed.

## Bug found and fixed (not a scoring rule — a shared partial)

`shared/templates/partials/head.html`'s inline theme-detector called bare
`matchMedia(...)` w/ no guard. Harmless on every real browser (always
present) — but it's the *exact* condition `matchmedia_missing` targets, & this
session constructed it. Unguarded call throws before `window.toggleTheme` is
even defined, breaking theme toggle **site-wide** for that visitor (not scoped
to botcheck). Fixed w/ a `typeof matchMedia === "function"` guard, same file.
Found as side effect of testing `matchmedia_missing`, not itself a botcheck
rule — noted here because that's where it surfaced.

## Left open (environment/tooling, not rule bugs)

- **`datacenter_ip`, `proxy_ip`** — tried ~30 known datacenter/hosting/VPN/Tor
  egress IPs (Google, Cloudflare, AWS, DigitalOcean, Hetzner, OVH, Scaleway,
  Akamai/Linode/Vultr, a commonly-cited Tor exit) against local IP2Proxy LITE
  PX12 snapshot via `curl` + spoofed `CF-Connecting-IP`. Zero flagged as
  proxy — including `8.8.8.8`/`1.1.1.1`, which public IP2Proxy documentation
  cites as `DCH`-flagged in the (paid, non-LITE) database. Concluded a
  LITE-tier coverage gap in this local snapshot, not a rule bug — the rule
  itself (`scoring.go`'s `datacenter_ip`/`proxy_ip` eval) is straight
  passthrough of `IsDatacenter`/`IsProxy`/`IsVPN`/`IsTor`, already exercised by
  Go fixtures. Still can't be positively confirmed against a real classified IP
  locally; revisit if a paid PX12 snapshot ever lands here.
- **`playwright/check.mjs`** — errored (`chrome-headless-shell-1228` missing
  from Playwright browser cache, needs `npx playwright install`, a real
  download). Pre-existing harness gap, not from this session. Not chased:
  Selenium, raw-cdp, puppeteer-extra-stealth, & the two new Puppeteer-based
  probe scripts already gave 5+ independent real-automation data points for
  this sweep.
- **`nightmare`** — `Error: Electron failed to install correctly`. Dead/
  unmaintained framework (Electron-based, last real updates ~2018); not
  reinstalled — other five real-automation sources already more than cover
  this sweep's need for genuine off-the-shelf tooling.
