# Roadmap — deferred by design & explicit non-goals (recap)

*(part of the [roadmap index](README.md))*

These items appear scattered across category files; grouped here so they
aren't mistaken for oversights.

- **Blocked by topology (edge/TLS):** TLS JA3/JA4 (G27), HTTP/2 frame
  fingerprint (G26), TCP SYN fingerprint (G30), HTTP header order/casing
  (G29), and the cross-layer OS-coherence rule that depends on them (G48).
  See [network-layer.md](network-layer.md) and
  [scoring-fusion.md](scoring-fusion.md). All blind as long as nginx/Cloudflare
  terminate TLS in front of Go.
- **Needs a stored corpus (Mongo-backed since wave 2 — the fingerprint corpus
  shipped G41/G42):** crowd rarity & entropy (G40, G58), fuzzy/LSH hashing
  (the deferred half of G42), request velocity (G43), persistent visitor ID
  (G47). See [ip-reputation.md](ip-reputation.md),
  [reporting-ux.md](reporting-ux.md), [persistent-identity.md](persistent-identity.md).
  (Returning-visitor history, G46, shipped localStorage-only instead — no
  corpus needed.)
- **Conflicts with no-ML / stateless:** behavioral biometrics (G34), intent
  modeling (G35), ML risk model (G52), time-staggered re-scoring (G51). See
  [behavioral.md](behavioral.md), [scoring-fusion.md](scoring-fusion.md).
- **Off-brand non-goals for a self-test tool:** enforcement / inline WAF
  (G61), active challenge / CAPTCHA / Picasso-style PoW (G59), signed verdict
  tokens (G60), collector obfuscation/hardening (G62), evercookie/supercookie
  test (G45), server-side port scanning (G32). See
  [enforcement.md](enforcement.md),
  [collector-architecture.md](collector-architecture.md),
  [persistent-identity.md](persistent-identity.md),
  [network-layer.md](network-layer.md).
- **Not applicable to a web page:** mobile-SDK native signals (G25),
  cross-customer threat intelligence (G39). See
  [client-signals.md](client-signals.md), [ip-reputation.md](ip-reputation.md).
