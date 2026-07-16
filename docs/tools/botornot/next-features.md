# botcheck — next detection features, by complexity

A backlog of additional bot/not signals for `botcheck`, split into three effort
layers. **Layer 1 (simple)** was implemented alongside this doc; Layers 2–3 are
designed but not built. Complexity is measured against our stack: one Go binary
(Echo v5), a vendored JS collector (no npm), no DB yet, and nginx/Cloudflare
terminating TLS in front (so the raw connection is not visible to Go).

Every client signal is spoofable, so the durable value is in **cross-checks** —
what the browser claims vs. what a second context / the connection / the
population shows. New signals should prefer that shape over standalone tells.

---

## Layer 1 — Simple (no new deps, no infra; pure-Go rules over collected fields)

**Implemented in this change:**

| Signal | Tier | Idea |
|---|---|---|
| `vendor_mismatch` | consistency | Chromium UA but `navigator.vendor` ≠ `"Google Inc."` |
| `app_version_mismatch` | consistency | `navigator.appVersion` ≠ UA without the `Mozilla/` prefix |
| `language_primary_mismatch` | consistency | `navigator.language` ≠ `navigator.languages[0]` |
| `screen_avail_impossible` | soft | `availWidth/Height` larger than the physical screen |
| `low_color_depth` | soft | `screen.colorDepth` < 16 |
| `sec_fetch_missing` | soft | Browser UA but no `Sec-Fetch-*` request header |

**Remaining simple candidates (same shape, drop-in later):**

- `productSub`/`product` sanity (`"20030107"` / `"Gecko"` for all mainstream browsers).
- `pdfViewerEnabled` expected `true` on desktop Chrome.
- `maxTouchPoints` > 0 on a desktop UA, or `ontouchstart` present without touch — touch/UA mismatch.
- `navigator.plugins` vs `mimeTypes` coherence (plugins present, mimeTypes empty).
- Zero `outerHeight`/`innerHeight` (a headless tell).
- `Accept-Encoding` / `Accept-Language` header absent on a browser UA (server-side; **validate against the CF/nginx path first — proxies can strip these**, which is why `sec_fetch_missing` is soft, not hard).
- `Accept: */*` on a top-level navigation (weak).

## Layer 2 — Medium (more collection / tuning; still no new infra or deps)

- **Timezone offset self-consistency** — `Intl….timeZone` (IANA) vs `getTimezoneOffset()`. Go resolves the zone with `time.LoadLocation` (embed `time/tzdata` for portability) and compares. Needs the request time threaded into `Evaluate` for DST, so it stays a pure function. IP-independent, high value. (Borderline simple/medium.)
- **Canvas / WebGL / Audio fingerprint hashing** — stable hash + a second draw: a hash that *changes* between draws ⇒ randomised (anti-fingerprint tool / stealth); an all-zero/blank hash ⇒ blocked or headless.
- **Font enumeration** — measure text widths across font stacks; headless/VM environments expose an unusually small or telltale font set.
- **Client-Hints brand cross-check** — parse the `Sec-CH-UA` header brand list and compare to JS `userAgentData.brands`; check the GREASE `"Not A;Brand"` entry is well-formed.
- **Browser version plausibility** — parse the Chrome major from the UA vs `userAgentData.fullVersionList`; flag impossible or very stale versions.
- **Media codec matrix** — `canPlayType`/`MediaSource.isTypeSupported` results vs the claimed browser.
- **JS engine tells** — `Error` stack format, `Function.prototype.toString` quirks, `Math`/number formatting differences (V8 vs SpiderMonkey vs JSC) vs the claimed browser.
- **WebRTC** — collect ICE candidates: local-IP leak, presence of an mDNS `.local` candidate, and `srflx` public IP vs the server-observed IP.
- **Request velocity** — an in-memory per-IP counter (a `sync.Map` with TTL) to flag bursts. Note: introduces process state, so it bends the current stateless rule; better once the planned MongoDB lands, sitting below the domain service.

## Layer 3 — Hard (new infrastructure, dependencies, ML, or the DB)

- **TLS fingerprint (JA3/JA4)** — the connection's TLS ClientHello vs the UA-implied stack. Blocked today: Cloudflare/nginx terminate TLS. Paths: an nginx/OpenResty JA3 module forwarding an `X-JA3` header, or terminating TLS in Go on this subdomain and peeking the ClientHello. Real work — infra.
- **HTTP/2 frame fingerprint (Akamai-style)** — SETTINGS / WINDOW_UPDATE / header-priority ordering. nginx downgrades to HTTP/1.1 before Go sees it; needs Go-terminated h2 or edge capture.
- **TCP/IP SYN fingerprint (p0f / zardaxt)** — OS inferred from SYN packet fields vs UA OS. Needs raw packet capture on the host.
- **Behavioral biometrics** — stream mouse/keystroke/scroll/touch events and classify (incolumitas runs a 30+ classifier ensemble). Needs an event pipeline and a trained model. ML.
- **Fingerprint rarity / crowd-blending** — store every fingerprint and score how rare the combination is. Needs the planned MongoDB; lands naturally as one more `Check` once storage sits below the domain service.
- **Stable visitor ID / returning-device matching** — probabilistic identity across sessions (FingerprintJS-Pro style). Needs a DB and matching logic.
- **ML risk model** — a trained classifier (logistic / gradient-boosted) over the whole signal vector, replacing the hand-tuned weights. Needs labelled data, training, and serving.
- **Active challenge / proof-of-work / invisible CAPTCHA** — deliberately out of scope: we never issue or solve CAPTCHAs, and a self-test tool blocks nothing.
