# Bot check — collector provenance (vendored by hand, no npm)

*(part of the [botcheck docs index](README.md))*

Per golden rule #3, **no npm and no `node_modules`** in shipped product —
collector vendored by hand into `shared/static/js/botcheck.js`, same way
`htmx.min.js` and `alpine.min.js` are. We read following for technique and port
specific probes; do **not** add them as dependencies or build step:

| Project | License | What we take |
|---|---|---|
| **BotD** | MIT | Self-contained OSS bot detector — the collector base |
| **CreepJS** | MIT (client only) | Lie/tamper detection + cross-context recompute probes (name kept off anything public — trademarked) |
| **fp-collect / fp-scanner** | MIT | Collection checklist + per-test consistency verdicts (reference for our `Check` rows) |
| **FingerprintJS (OSS)** | MIT | Canvas/WebGL/audio/font collection |
| **MixVisit `@mix-visit/lite`** | MIT | Engine-vs-UA consistency reference (the engine behind iphey.com) + WebRTC leak |

Collection-surface references (uniqueness tools, not bot detectors — we don't
copy their scoring): **AmIUnique** and **EFF Cover Your Tracks** (latter AGPLv3,
so read-only, never vendored). Server scorer is our own — none of these ship one
we'd want.

> **Note:** [`/automation-harness/`](../../../automation-harness) is separate — a
> gitignored, npm-based *test* harness (not shipped, not committed) driving real
> automation frameworks against live tool to check detection actually works. See
> [testing/README.md](testing/README.md). Deliberate, scoped exception to "no
> npm" rule for disposable local verification tooling, not a contradiction of
> this page.
