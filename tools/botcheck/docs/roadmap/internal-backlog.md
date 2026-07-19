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
- **Request velocity** (G43) — an in-memory per-IP counter (a `sync.Map` with TTL) to flag bursts. Introduces process state, bends the current stateless rule; better backed by MongoDB (already used by botcheck for the G41/G42 fingerprint corpus, but not yet for this), sitting below the domain service.

## Layer 3 — Hard (new infrastructure, dependencies, ML, or a stored corpus)

> MongoDB now available (a `site-of-tools` database + a `platform/mongo.go`
> client), so DB-backed items below no longer *blocked* on provisioning a
> database — what remains is building the corpus/logic and wiring it below
> the domain service. botcheck uses Mongo only for the fingerprint corpus so
> far.

- **TLS fingerprint (JA3/JA4)** (G27) — the connection's TLS ClientHello vs UA-implied stack. Blocked today: Cloudflare/nginx terminate TLS. Paths: an nginx/OpenResty JA3 module forwarding an `X-JA3` header, or terminating TLS in Go on this subdomain and peeking ClientHello. Real work — infra.
- **HTTP/2 frame fingerprint (Akamai-style)** (G26) — SETTINGS / WINDOW_UPDATE / header-priority ordering. nginx downgrades to HTTP/1.1 before Go sees it; needs Go-terminated h2 or edge capture.
- **TCP/IP SYN fingerprint (p0f / zardaxt)** (G30) — OS inferred from SYN packet fields vs UA OS. Needs raw packet capture on the host.
- **Behavioral biometrics** (G34) — stream mouse/keystroke/scroll/touch events, classify (incolumitas runs a 30+ classifier ensemble). Needs an event pipeline and a trained model. ML.
- **Fingerprint rarity / crowd-blending** (G40) — store every fingerprint, score how rare the combination is. MongoDB now available for the corpus; lands naturally as one more `Check` once storage sits below the domain service (not built yet).
- **Stable visitor ID / returning-device matching** (G47) — probabilistic identity across sessions (FingerprintJS-Pro style). Needs storage (MongoDB now available) and matching logic.
- **ML risk model** (G52) — a trained classifier (logistic / gradient-boosted) over the whole signal vector, replacing hand-tuned weights. Needs labelled data, training, and serving.
- **Active challenge / proof-of-work / invisible CAPTCHA** (G59) — deliberately out of scope: we never issue or solve CAPTCHAs, and a self-test tool blocks nothing.
