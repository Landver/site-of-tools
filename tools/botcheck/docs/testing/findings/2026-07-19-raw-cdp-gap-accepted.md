# 2026-07-19 — raw-CDP / custom-harness gap: accepted as known limit

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Disciplined custom automation client — skips "Headless" in UA, doesn't trip
`navigator.webdriver` (or trips it consistently everywhere, unlike stealth's
inconsistent patching), injects no framework marker — evades nearly
everything this tool checks. No client-side JS fix exists for it.

Weighed three options:

1. Lean harder on IP/network reputation + fingerprint-reuse corpus
   (orthogonal signal, already built — see [`../../storage.md`](../../storage.md)).
2. A behavioral layer (mouse/keyboard trajectory) — already a non-goal per
   [`../../roadmap/scoring-fusion.md`](../../roadmap/scoring-fusion.md)'s
   G52, for good reason (conflicts with the no-ML/stateless design).
3. Accept as a known, documented limit of a client-fingerprint-only, no-ML
   detector.

**Chose 3, accept.** Architecture already validated elsewhere in this same
audit — stealth was caught via cross-context consistency checks even where
six purpose-built checks missed entirely (see
[multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md)).
That same defense doesn't reach a disciplined custom client with no
framework signature at all, though — genuinely nothing architectural left to
check against.

Data point behind this: [checks/bot_user_agent.md](../checks/bot_user_agent.md)
— a raw CDP client, no automation flags, scored `40/100` almost entirely off
the UA string ("headlesschrome" substring), everything architectural read
clean.

Future contributor: don't "fix" this with another single clever trap without
reading this file plus [findings-log.md](../findings-log.md) first — that's
exactly how the CDP-trap check ended up needing this whole audit in the
first place.
