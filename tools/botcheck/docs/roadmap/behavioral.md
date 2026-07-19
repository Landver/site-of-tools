# Roadmap — behavioral / interaction analysis (G33–G35)

*(part of the [roadmap index](README.md))*

Ratings key: see [README.md § How to read the ratings](README.md#how-to-read-the-ratings).
All three conflict w/ no-ML / stateless design (see
[deferred-nongoals.md](deferred-nongoals.md)) and stay deferred together.

| # | Capability they provide | Who has it | Sev · Effort · Status | What they do that we don't → recommended move |
|---|---|---|---|---|
| G33 | Optional interactive challenge to elicit organic telemetry | bot.incolumitas | low · medium · **Not built** | Offer unauthenticated task (fill form, confirm dialog, edit+scrape table) engineered to generate organic mouse/keyboard/scroll trajectories for behavioral classifier. → **Only worth it if behavioral scoring ever built (itself deferred). Skip till then.** |
| G34 | Behavioral biometrics (mouse/keystroke/scroll/touch ensemble) | bot.incolumitas, deviceandbrowserinfo.com, DataDome, BrowserScan.net | low · ml-or-db · Deferred (documented) | Collect timestamped interaction stream and score w/ ensemble (bot.incolumitas: 30+ classifiers, re-scored at 1.5/4/7/10/15s; DataDome: per-customer baselines) to separate organic motion from synthetic input. → **Deferred. High cost (needs ML ensemble + training corpus), conflicts w/ our pure/deterministic/no-ML scorer, and low value for page that auto-runs on load w/ no required interaction. Keep deferred.** |
| G35 | Navigation-sequence / intent modeling (incl. LLM-agent intent) | DataDome, Fingerprint.com | low · ml-or-db · **Not built** | Model sequence of requests/navigation and infer intent vs baseline, incl newer AI-agent/LLM-crawler intent angle. → **Out of scope for single-page self-test; ML + multi-request context.** |
