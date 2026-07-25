# Roadmap — deferred by design & explicit non-goals (recap)

*(part of the [roadmap index](README.md))*

These items scattered across category files; grouped here so not
mistaken for oversights.

- **Confirmed dead end, not just blocked by current topology (verified
  2026-07-21):** TLS JA3/JA4 (G27), HTTP/2 frame fingerprint (G26), TCP SYN
  fingerprint (G30), HTTP header order/casing (G29), & cross-layer
  OS-coherence rule depending on them (G48). Cloudflare's proxied mode runs
  two fully independent connections at every layer (TCP, TLS, HTTP/2) —
  visitor↔edge, then separate edge↔origin connection Cloudflare itself
  originates — so no origin-side infra (custom nginx
  module, Go-terminated TLS listener, raw packet capture) would ever expose
  visitor's real network characteristics; would only capture
  Cloudflare's own edge-to-origin connection, identical for every visitor.
  Only way to see real signal is disabling Cloudflare proxy, ruled
  out separately (breaks `CF-Connecting-IP` trust model & exposes
  shared origin IP for every other project behind same nginx — see
  `docs/DEPLOYMENT.md`). Not an open backlog item to revisit w/ more infra
  investment — closed. See [network-layer.md](network-layer.md) &
  [scoring-fusion.md](scoring-fusion.md).
- **Needs stored corpus (Mongo-backed since wave 2 — fingerprint corpus
  shipped G41/G42, & request velocity/churn G43 shipped 2026-07-21 on same
  corpus):** crowd rarity & entropy (G40, G58 — deferred as *scoring* w/
  concrete reason as of 2026-07-21: rarity doesn't discriminate at self-test
  scale, see [ip-reputation.md](ip-reputation.md) G40), fuzzy/LSH hashing (
  deferred half of G42), persistent visitor ID (G47). See
  [ip-reputation.md](ip-reputation.md), [reporting-ux.md](reporting-ux.md),
  [persistent-identity.md](persistent-identity.md). (Returning-visitor history,
  G46, shipped localStorage-only instead — no corpus needed.)
- **Conflicts with no-ML / stateless:** behavioral biometrics (G34), intent
  modeling (G35), ML risk model (G52), time-staggered re-scoring (G51). See
  [behavioral.md](behavioral.md), [scoring-fusion.md](scoring-fusion.md).
- **Off-brand non-goals for self-test tool:** enforcement / inline WAF
  (G61), active challenge / CAPTCHA / Picasso-style PoW (G59), signed verdict
  tokens (G60), collector obfuscation/hardening (G62), evercookie/supercookie
  test (G45), server-side port scanning (G32). See
  [enforcement.md](enforcement.md),
  [collector-architecture.md](collector-architecture.md),
  [persistent-identity.md](persistent-identity.md),
  [network-layer.md](network-layer.md).
- **Not applicable to web page:** mobile-SDK native signals (G25),
  cross-customer threat intelligence (G39). See
  [client-signals.md](client-signals.md), [ip-reputation.md](ip-reputation.md).
