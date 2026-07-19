# Bot check — collector provenance (vendored by hand, no npm)

*(part of the [botcheck docs index](README.md))*

Per golden rule #3 there is **no npm and no `node_modules`** in the shipped
product — the collector is vendored by hand into
`shared/static/js/botcheck.js`, the same way `htmx.min.js` and `alpine.min.js`
are. We read the following for technique and port specific probes; we do
**not** add them as dependencies or a build step:

| Project | License | What we take |
|---|---|---|
| **BotD** | MIT | Self-contained OSS bot detector — the collector base |
| **CreepJS** | MIT (client only) | Lie/tamper detection + cross-context recompute probes (name kept off anything public — trademarked) |
| **fp-collect / fp-scanner** | MIT | Collection checklist + per-test consistency verdicts (reference for our `Check` rows) |
| **FingerprintJS (OSS)** | MIT | Canvas/WebGL/audio/font collection |
| **MixVisit `@mix-visit/lite`** | MIT | Engine-vs-UA consistency reference (the engine behind iphey.com) + WebRTC leak |

Collection-surface references (uniqueness tools, not bot detectors — we don't copy
their scoring): **AmIUnique** and **EFF Cover Your Tracks** (the latter is AGPLv3,
so read-only, never vendored). The server scorer is our own — none of these ship
one we'd want.

> **Note:** [`/verify-cdp/`](../../../verify-cdp) is a separate thing — a
> gitignored, npm-based *test* harness (not shipped, not committed) that drives
> real automation frameworks against the live tool to check detection actually
> works. See [testing/README.md](testing/README.md). It's a deliberate, scoped
> exception to the "no npm" rule for disposable local verification tooling, not
> a contradiction of this page.
