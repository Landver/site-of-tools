# Roadmap — internal backlog by effort (non-competitor-driven)

*(part of the [roadmap index](README.md))*

The competitor-gap category files are framed against competitors. This is the
complementary view: everything we want to add **regardless of any
competitor**, ordered by complexity against our stack (one Go binary, a
vendored JS collector, no npm, MongoDB now available but used only for the
fingerprint corpus so far, and nginx/Cloudflare terminating TLS in front, so
the raw connection isn't visible to Go). Every client signal is spoofable, so
new signals should prefer the **cross-check** shape — browser claim vs. a
second context / the connection / the population — over standalone tells.
Where an item also appears in the competitor audit, its `G##` is noted and
linked.

## Layer 1 — Simple (no new deps or infra; pure-Go rules over collected fields)

**Shipped:**

| Signal | Tier | Idea |
|---|---|---|
| `vendor_mismatch` | consistency | Chromium UA but `navigator.vendor` ≠ `"Google Inc."` |
| `app_version_mismatch` | consistency | `navigator.appVersion` ≠ UA without the `Mozilla/` prefix |
| `language_primary_mismatch` | consistency | `navigator.language` ≠ `navigator.languages[0]` |
| `screen_avail_impossible` | soft | `availWidth/Height` larger than the physical screen |
| `low_color_depth` | soft | `screen.colorDepth` < 16 |
| `sec_fetch_missing` | soft | Browser UA but no `Sec-Fetch-*` request header |
| `productsub_mismatch` | consistency | `navigator.productSub` ≠ the engine's constant (`20030107` WebKit/Blink, `20100101` Gecko), engine inferred via `engineFromUA` so iOS browsers are WebKit — [client-signals.md](client-signals.md) G02, shipped 2026-07-17 |

**Remaining candidates (same shape, drop-in later):**

- ~~`maxTouchPoints` > 0 on a desktop UA, or `ontouchstart` present without touch — touch/UA mismatch.~~ — **shipped 2026-07-18** as `mobile_no_touch` (consistency, v3-gated: Android/iOS UA + zero touch). The desktop-UA-plus-touch reverse direction was deliberately skipped — touch-screen Windows laptops would false-fire it.
- ~~`navigator.plugins` vs `mimeTypes` coherence (plugins present, mimeTypes empty).~~ — **shipped 2026-07-18** as `plugins_mimetypes_incoherent` (soft, v3-gated).
- ~~Zero `outerHeight`/`innerHeight` (a headless tell).~~ — **shipped 2026-07-18** as `zero_outer_height` (soft: `outerHeight == 0` with `innerHeight > 0`, the guard that makes stale pre-v3 payloads skip).
- `Accept-Encoding` / `Accept-Language` header absent on a browser UA — **shipped 2026-07-17 via** [client-signals.md](client-signals.md) **G06** as the soft `accept_encoding_missing` / `accept_language_missing` rules (soft, not hard, exactly because proxies can strip these — the `sec_fetch_missing` caveat).
- `Accept` without `text/html` on a browser-UA request — **shipped 2026-07-17 via G06** as the soft `accept_nav_mismatch` rule.

## Layer 2 — Medium (more collection / tuning; still no new infra or deps)

**Shipped:**

| Signal | Tier | Idea |
|---|---|---|
| `tz_self_inconsistent` | consistency | `Intl….timeZone` (IANA) vs `getTimezoneOffset()` — Go resolves the zone with `time.LoadLocation` (embeds `time/tzdata`) at request time (threaded in as `Signals.Now`, keeping `Evaluate` pure). IP-independent. |
| `canvas_unstable` | consistency | Two identical canvas draws hashing differently ⇒ noise-injecting anti-fingerprint tool. |
| `canvas_blank` | soft | The drawn canvas has no non-transparent pixels ⇒ blocked / headless. |
| `ch_brands_mismatch` | consistency | Parse the `Sec-CH-UA` header brand list and compare to JS `userAgentData.brands` (GREASE decoy ignored). |
| `missing_proprietary_codecs` | soft | Browser UA but neither H.264 nor AAC (`canPlayType`) ⇒ stripped / headless build. |
| `no_fonts` | soft | Zero probe fonts detectable via the `measureText` width technique ⇒ neutralised font surface / font-less VM. |
| `ua_chrome_version_mismatch` | consistency | UA `Chrome/NNN` major ≠ the `Chromium` (or `Google Chrome`) `fullVersionList` entry — compares the engine version, so Chromium forks whose branded version diverges (Opera/Vivaldi/Samsung) don't false-positive — [client-signals.md](client-signals.md) G01, shipped 2026-07-17. |
| `engine_ua_mismatch` | consistency | Feature-detected engine (`-moz-appearance`⇒Gecko, `GestureEvent`⇒WebKit, `-webkit-app-region`/`webkitRequestFileSystem`⇒Blink) ≠ the engine the UA claims — G05, shipped 2026-07-17. |

**Remaining candidates (not yet built):**

- **Fuller media-codec / font-diversity matrices** — beyond the current H.264/AAC pair and the zero-fonts floor, score against expected per-browser codec sets and typical font-count ranges (needs careful thresholds to avoid mobile false positives).
- **JS engine tells** (G23) — `Error` stack format, `Function.prototype.toString` quirks, `Math`/number formatting differences (V8 vs SpiderMonkey vs JSC) vs the claimed browser. The Error-stack half is **shipped 2026-07-18** as `jsengine_ua_mismatch`; the Math/toString-quirk halves stay here (they need per-engine reference tables).
- **WebRTC** (G09) — collect ICE candidates: local-IP leak, presence of an mDNS `.local` candidate, and `srflx` public IP vs the server-observed IP. **Shipped 2026-07-18** as `webrtc_ip_mismatch` (public candidates only, same address family, private/link-local/ULA/CGNAT excluded).
- **Request velocity** (G43) — an in-memory per-IP counter (a `sync.Map` with TTL) to flag bursts. Introduces process state, so it bends the current stateless rule; better backed by MongoDB (now available, not yet used by botcheck), sitting below the domain service.

## Layer 3 — Hard (new infrastructure, dependencies, ML, or a stored corpus)

> MongoDB is now available (a `site-of-tools` database + a `platform/mongo.go`
> client), so the DB-backed items below are no longer *blocked* on provisioning a
> database — what remains is building the corpus/logic and wiring it below the
> domain service. botcheck uses Mongo only for the fingerprint corpus so far.

- **TLS fingerprint (JA3/JA4)** (G27) — the connection's TLS ClientHello vs the UA-implied stack. Blocked today: Cloudflare/nginx terminate TLS. Paths: an nginx/OpenResty JA3 module forwarding an `X-JA3` header, or terminating TLS in Go on this subdomain and peeking the ClientHello. Real work — infra.
- **HTTP/2 frame fingerprint (Akamai-style)** (G26) — SETTINGS / WINDOW_UPDATE / header-priority ordering. nginx downgrades to HTTP/1.1 before Go sees it; needs Go-terminated h2 or edge capture.
- **TCP/IP SYN fingerprint (p0f / zardaxt)** (G30) — OS inferred from SYN packet fields vs UA OS. Needs raw packet capture on the host.
- **Behavioral biometrics** (G34) — stream mouse/keystroke/scroll/touch events and classify (incolumitas runs a 30+ classifier ensemble). Needs an event pipeline and a trained model. ML.
- **Fingerprint rarity / crowd-blending** (G40) — store every fingerprint and score how rare the combination is. MongoDB is now available for the corpus; lands naturally as one more `Check` once storage sits below the domain service (not built yet).
- **Stable visitor ID / returning-device matching** (G47) — probabilistic identity across sessions (FingerprintJS-Pro style). Needs storage (MongoDB now available) and matching logic.
- **ML risk model** (G52) — a trained classifier (logistic / gradient-boosted) over the whole signal vector, replacing the hand-tuned weights. Needs labelled data, training, and serving.
- **Active challenge / proof-of-work / invisible CAPTCHA** (G59) — deliberately out of scope: we never issue or solve CAPTCHAs, and a self-test tool blocks nothing.
