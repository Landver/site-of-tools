# Roadmap — internal backlog by effort (non-competitor-driven)

*(part of the [roadmap index](README.md))*

The competitor-gap category files are framed against competitors. This is the
complementary view: everything we want to add **regardless of any
competitor**, ordered by complexity against our stack (one Go binary, a
vendored JS collector, no npm, MongoDB now available but used only for the
fingerprint corpus so far, and nginx/Cloudflare terminating TLS in front, so
the raw connection isn't visible to Go). Every client signal is spoofable, so
new signals should prefer the **cross-check** shape — browser claim vs a
second context / the connection / the population — over standalone tells.
Where an item also appears in the competitor audit, its `G##` is noted and
linked. Each shipped item's implementation lives in its own
[checks/](../testing/checks/README.md) file now, not restated here.

## Layer 1 — Simple (no new deps or infra; pure-Go rules over collected fields)

**All shipped** — `vendor_mismatch`, `app_version_mismatch`,
`language_primary_mismatch`, `screen_avail_impossible`, `low_color_depth`,
`sec_fetch_missing`, `productsub_mismatch` (G02), `mobile_no_touch` (G12),
`plugins_mimetypes_incoherent`, `zero_outer_height`, `accept_encoding_missing`
/ `accept_language_missing` / `accept_nav_mismatch` (G06). Nothing remains at
this complexity tier — see [checks/](../testing/checks/README.md) for any of
these.

## Layer 2 — Medium (more collection / tuning; still no new infra or deps)

**Shipped:** `tz_self_inconsistent`, `canvas_unstable`, `canvas_blank`,
`ch_brands_mismatch`, `missing_proprietary_codecs`, `no_fonts`,
`ua_chrome_version_mismatch` (G01), `engine_ua_mismatch` (G05),
`jsengine_ua_mismatch` — error-stack half only (G23), `webrtc_ip_mismatch`
(G09). See [checks/](../testing/checks/README.md) for any of these.

**Remaining candidates (not yet built):**

- **Fuller media-codec / font-diversity matrices** — beyond current H.264/AAC pair and zero-fonts floor, score against expected per-browser codec sets and typical font-count ranges (needs careful thresholds to avoid mobile false positives).
- **JS engine tells, the rest of G23** — `Math`/number-formatting differences (V8 vs SpiderMonkey vs JSC) vs claimed browser. The error-stack half already shipped as `jsengine_ua_mismatch`; this remaining half needs per-engine reference tables.
- ~~**Request velocity** (G43)~~ — **shipped 2026-07-21** as `ip_fingerprint_churn`, the fingerprint-rotation variant: `Corpus.DistinctHashesByIP(ip, 10-min window)` over the existing `botcheck_fingerprints` corpus counts distinct fingerprints per IP, firing soft at ≥8 (a corporate NAT legitimately shows many browsers, so cluster-only). Backed by MongoDB below the domain service exactly as this row anticipated — no process state. Raw request-rate-per-IP was deliberately not added (a self-test tool only sees its own traffic, and a fast-refreshing human would false-fire). See [ip-reputation.md](ip-reputation.md) G43 and [checks/ip_fingerprint_churn.md](../testing/checks/ip_fingerprint_churn.md).

## Layer 3 — Hard (new infrastructure, dependencies, ML, or a stored corpus)

> MongoDB now available (a `site-of-tools` database + a `platform/mongo.go`
> client), so DB-backed items below no longer *blocked* on provisioning a
> database — what remains is building the corpus/logic and wiring it below
> the domain service. botcheck uses Mongo only for the fingerprint corpus so
> far.

- ~~**TLS fingerprint (JA3/JA4)** (G27)~~ — **closed as a dead end, 2026-07-21.** Investigated actually building this (an nginx `ssl_preread` listener or a Go-terminated TLS sidecar for this subdomain) and killed it before touching prod: Cloudflare's proxied mode terminates the visitor's TLS at its own edge and originates a *separate* connection to origin, so whatever ClientHello ever reaches our nginx/Go is Cloudflare's own edge-to-origin handshake — identical for every visitor, not the browser's. No amount of origin-side infra changes that while Cloudflare proxy stays on (required for the client-IP trust model). Cloudflare's own edge-computed JA3/JA4 (`cf-ja3-hash`/`cf-ja4` headers) exists but is gated to Enterprise Bot Management, not worth buying for a personal tool. See [network-layer.md](network-layer.md) G27 for the full finding.
- ~~**HTTP/2 frame fingerprint (Akamai-style)** (G26)~~ — closes alongside G27, same root cause (see above).
- ~~**TCP/IP SYN fingerprint (p0f / zardaxt)** (G30)~~ — closes alongside G27: even with raw packet capture, the SYN we'd see is Cloudflare's, not the visitor's.
- **Behavioral biometrics** (G34) — stream mouse/keystroke/scroll/touch events, classify (incolumitas runs a 30+ classifier ensemble). Needs an event pipeline and a trained model. ML.
- **Fingerprint rarity / crowd-blending** (G40) — store every fingerprint, score how rare the combination is. MongoDB now available for the corpus; lands naturally as one more `Check` once storage sits below the domain service (not built yet).
- **Stable visitor ID / returning-device matching** (G47) — probabilistic identity across sessions (FingerprintJS-Pro style). Needs storage (MongoDB now available) and matching logic.
- **ML risk model** (G52) — a trained classifier (logistic / gradient-boosted) over the whole signal vector, replacing hand-tuned weights. Needs labelled data, training, and serving.
- **Active challenge / proof-of-work / invisible CAPTCHA** (G59) — deliberately out of scope: we never issue or solve CAPTCHAs, and a self-test tool blocks nothing.
