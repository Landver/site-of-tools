# Roadmap — collector architecture (G62)

*(part of the [roadmap index](README.md))*

Ratings key: see [README.md § How to read the ratings](README.md#how-to-read-the-ratings).

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G62 | Anti-reverse-engineering / integrity hardening of the collector | DataDome, Fingerprint.com | low · high-infra · **Not built** | Protect the collection tag: obfuscation, UI/signal tag-splitting, service-worker offload, encrypted payloads, randomized first-party load path to defeat blockers and forgery. → **Deliberately off-scope and against the grain — our collector is intentionally readable and vendored; a self-test tool has no adversary to hide from.** |
