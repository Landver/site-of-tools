# Roadmap — enforcement / production-integration features (G59–G61)

*(part of the [roadmap index](README.md))*

Ratings key: see [README.md § How to read the ratings](README.md#how-to-read-the-ratings).
All three are deliberate non-goals — see [deferred-nongoals.md](deferred-nongoals.md).

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G59 | Active challenge / CAPTCHA / server-seeded canvas device-class proof-of-work | DataDome | low · medium · Deferred (documented) | DataDome's Picasso: the server sends a random seed of drawing instructions, the client renders invisibly and returns a hash; stable GPU/driver/OS rendering differences reveal the true device class, with a fresh seed defeating replay. Also CAPTCHA/invisible Device Check escalation. → **Active challenges/CAPTCHA/PoW are a deliberate non-goal (off-brand, we never issue/solve challenges). Note: our canvas check is stability/blank only, not server-seeded device-class hashing — but adding Picasso-style seeding crosses into active-challenge territory we've ruled out. Keep deferred.** |
| G60 | Signed verdict token / cookie integrity + replay protection | DataDome, Fingerprint.com | low · medium · Deferred (documented) | Emit a cryptographically signed verdict (DataDome's HMAC datadome cookie with replay checks; Fingerprint's sealed result tied to event_id fetched server-to-server) so a captured verdict can't be forged or reused. → **Only relevant if the verdict gates something downstream, which it doesn't (self-test). Deferred correctly. Our transparency (showing the full breakdown to the client) is the opposite design intent and appropriate here.** |
| G61 | Enforcement mode / inline WAF decision | DataDome, Fingerprint.com | low · high-infra · Deferred (documented) | Act on the verdict inline — allow/hard-block/challenge at the edge (DataDome), or feed a passive verdict into a customer's block decision (Fingerprint). → **Intentionally off-brand — botcheck is a self-test that blocks nothing. Keep as an explicit non-goal in the docs, not a gap to close.** |
