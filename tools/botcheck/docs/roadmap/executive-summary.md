# Roadmap — executive summary

*(part of the [roadmap index](README.md))*

`botcheck` already ships a credible client + server **consistency** scorer: 68
tiered rules, cross-context (worker/iframe/service-worker) UA checks, UA/Client-Hints/timezone/IP
cross-checks, and IP2Proxy datacenter/VPN/Tor classification, all fused
server-side and shown as a transparent per-signal breakdown. Gaps fall into
three clean buckets:

1. **Cheap client signals we don't collect yet — the real opportunity.** Ten
   low/trivial-effort items, all shipped as of 2026-07-17 — see
   [quick-wins.md](quick-wins.md). Most extended collectors we already had:
   richer high-entropy Client Hints, deeper native-tamper/lie detection,
   broader cross-context diffs, engine feature-detection, GPU-vs-OS coherence.
   Pure deterministic Go/JS rules that fit the existing scorer w/ no new
   infra.

2. **Structural blind spots needing infra, ML, or persistence botcheck
   doesn't fully use yet.** The network layer (TLS **JA3/JA4**, HTTP/2
   frames, TCP SYN, header order — see [network-layer.md](network-layer.md)),
   crowd **rarity/entropy**, persistent **identity**, **behavioral**
   biometrics, and an **ML** risk model (see
   [ip-reputation.md](ip-reputation.md),
   [persistent-identity.md](persistent-identity.md),
   [behavioral.md](behavioral.md), [scoring-fusion.md](scoring-fusion.md)).
   Most already documented as deferred. **Network-layer ones are a confirmed
   dead end, not an open infra backlog** — 2026-07-21 finding: Cloudflare's
   proxied mode terminates the visitor's connection at its edge and
   originates a wholly separate one to origin at every layer (TCP/TLS/HTTP2),
   so no origin-side engineering can ever see the visitor's real network
   characteristics, only Cloudflare's own edge-to-origin connection — see
   [network-layer.md](network-layer.md). DB-backed ones now *unblocked* —
   MongoDB available — but botcheck persists only the fingerprint corpus so
   far, so rest stay build-it tasks; ML ones conflict w/ no-ML rule.
   Correctly parked, not oversights.

3. **Intentional non-goals.** Enforcement/inline-WAF decisions, CAPTCHA /
   active challenges / proof-of-work, signed verdict tokens, and collector
   obfuscation (see [enforcement.md](enforcement.md) and
   [collector-architecture.md](collector-architecture.md)). Enterprise
   vendors do these; for a transparent self-test tool that blocks nothing
   they'd be the *wrong* design. Listed for completeness, flagged as
   non-goals.

## What they do well that we don't (the qualitative read)

Beyond individual signals, several services model good *practices* worth
copying:

- **Scope honesty & transparency.** deviceandbrowserinfo states plainly its
  verdict does **not** use IP reputation or behavior; incolumitas warns
  "false positives are expected" and versions its signals openly. That
  candor is what makes a checker trusted as a reference. We're transparent
  per-signal — see [reporting-ux.md](reporting-ux.md) (G53, G55).
- **Depth of lie/tamper detection.** CreepJS doesn't just check `toString`
  `[native code]` — it walks property descriptors, traps whether `call`/`new`
  throw the right `TypeError`, and detects the `Function.prototype.toString`
  Proxy stealth plugins install. See [client-signals.md](client-signals.md)
  (G04, G17, G22) — and
  [the multi-framework matrix results](../testing/findings/2026-07-19-multi-framework-matrix-results.md)
  for the 2026-07-19 finding that the current
  `puppeteer-extra-plugin-stealth` evades all of these anyway.
- **Feature-detecting the *real* engine.** iphey/MixVisit feature-detect
  Blink vs Gecko vs WebKit and compare to claimed UA, instead of trusting the
  UA string a spoofer controls ([client-signals.md](client-signals.md), G05).
- **Naming the environment back to the user.** Fingerprint says "Electron
  42.5.1" and attaches per-signal confidence; CreepJS splits `likeHeadless` /
  `headless` / `stealth` so "real engine but patched" reads differently from
  "headless build." See [reporting-ux.md](reporting-ux.md) (G56, G49, G50).
- **A raw dump for the debugging audience.** sannysoft/CreepJS show the full
  raw fingerprint; see [reporting-ux.md](reporting-ux.md) (G54).
- **Entropy framing.** AmIUnique/EFF report "one in X browsers share this" —
  a ready-made explainability and weighting model, needing a population
  corpus we don't have. See [ip-reputation.md](ip-reputation.md) (G40) and
  [reporting-ux.md](reporting-ux.md) (G58).
- **The unforgeable network layer.** The edge-owners (DataDome, BrowserScan,
  incolumitas) cross-check the TLS/TCP/HTTP2 handshake against the claimed
  browser — the one class of signal a JS spoofer can't touch, and the one we
  structurally can't see behind nginx. See
  [network-layer.md](network-layer.md) (G26–G30, G48).
- **Good-bot / AI-agent classification.** DataDome and Fingerprint separate
  verified Googlebot-style crawlers and known AI-company agents from
  malicious automation; we now separate them too (G36, shipped) — see
  [ip-reputation.md](ip-reputation.md): recognised crawlers/agents are named,
  and verified ones (ASN-corroborated) get a distinct `good-bot` verdict.
