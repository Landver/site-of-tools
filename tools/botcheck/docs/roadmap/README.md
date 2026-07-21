# Bot check — roadmap index

"What's next" doc set for `botcheck`, split so reader (human or AI) opens only
file relevant to question, not one 465-line monolith. Two halves:

1. **Competitor-gap audit** — every capability, signal, technique, and
   reporting feature one+ of twelve researched services provide that our own
   [`botcheck`](../README.md) tool does **not** (or weaker), each rated by
   value-to-us, effort, and status. Split by category — see table below.
2. **Internal backlog** ([internal-backlog.md](internal-backlog.md)):
   effort-layered features we want regardless of competitor.

For how tool works today and why designed this way, see
[`../README.md`](../README.md); for how competitor services work and how our
test browser scored against them, see [`../RESEARCH.md`](../RESEARCH.md).

## Start here

- **New to this audit?** Read [executive-summary.md](executive-summary.md) first — three-bucket framing of where gaps are, plus qualitative "what they do well" read.
- **Picking up work?** [quick-wins.md](quick-wins.md) fully shipped as of 2026-07-17; open work starts at medium-effort/infra/DB-backed rows in category files below.
- **Want history?** [changelog.md](changelog.md) — dated build-status entries, oldest first.
- **Checking specific `G##` row?** Use category map below.

## Category files (the gap audit, by section)

| File | Covers | IDs |
|---|---|---|
| [quick-wins.md](quick-wins.md) | Highest-value, lowest-cost items (all shipped) | — |
| [client-signals.md](client-signals.md) | Client-side detection signals | G01–G25 |
| [network-layer.md](network-layer.md) | Network-layer fingerprinting (TLS/HTTP2/TCP) | G26–G32 |
| [behavioral.md](behavioral.md) | Behavioral / interaction analysis | G33–G35 |
| [ip-reputation.md](ip-reputation.md) | IP reputation depth, crowd-blending & rarity | G36–G44 |
| [persistent-identity.md](persistent-identity.md) | Persistent identity & history | G45–G47 |
| [scoring-fusion.md](scoring-fusion.md) | Scoring model & cross-layer fusion | G48–G52 |
| [reporting-ux.md](reporting-ux.md) | Reporting, transparency & UX | G53–G58 |
| [enforcement.md](enforcement.md) | Enforcement / production-integration | G59–G61 |
| [collector-architecture.md](collector-architecture.md) | Collector architecture hardening | G62 |
| [deferred-nongoals.md](deferred-nongoals.md) | Recap: everything deferred by design or explicit non-goal | (all of the above) |
| [internal-backlog.md](internal-backlog.md) | Non-competitor-driven backlog, by effort (Layer 1/2/3) | — |

## How to read the ratings

Each row in category files carries **`Sev · Effort · Status`**:

- **Sev** (severity) = value **to our tool specifically** — stateless, no-ML
  self-test page on personal portfolio (MongoDB available but botcheck only
  uses it for fingerprint corpus so far), *not* enterprise WAF. Cheap client
  signal we forgot rates higher than DataDome-scale behavioral ML, near-
  worthless at our scale.
- **Effort** = `trivial` → `low` → `medium` → `high-infra` (needs edge/TLS/packet
  access) → `ml-or-db` (needs persistence in MongoDB or a trained model).
- **Status** = **Not built** (true blind spot) · **Partial** (weaker version) ·
  **Shipped** · **Deferred (documented)** (acknowledged gap, not oversight).

## What this is built from

- Twelve firsthand service reports in [`../reports/`](../reports/)
  (`deviceandbrowserinfo`, `incolumitas`, `sannysoft`, `creepjs`, `fingerprint`,
  `browserscan`, `pixelscan`, `iphey`, `whoer`, `amiunique`, `coveryourtracks`,
  `datadome`) — see [`../RESEARCH.md`](../RESEARCH.md) for cross-service
  summary.
- Our **shipped** implementation, read as ground truth (not design doc):
  [`../../scoring.go`](../../scoring.go) (the 68 detection rules),
  [`../../botcheck.go`](../../botcheck.go) (the `Signals` struct + scorer),
  [`../../handler.go`](../../handler.go) (server signals), and
  [`shared/static/js/botcheck.js`](../../../../shared/static/js/botcheck.js)
  (the vendored collector).

Each competitor capability compared against that code, and **every claimed gap
verified against real source** to kill false "we don't do X" entries at time
this audit was written. Snapshot has since moved on as more items shipped
(recount as of 2026-07-21, after G37 shipped): of 62 items, 31 now
**Shipped**, 18 genuine blind spots (**Not built**), 13 already acknowledged
in design docs as **Deferred** (the network-layer four, G26/G27/G29/G30 + G48,
now confirmed dead ends rather than open infra — see
[network-layer.md](network-layer.md)), 0 currently carry **Partial** status
(rows that used to be narrower-form implementations since updated to Shipped as
work landed — see [changelog.md](changelog.md)).

## Note on method & confidence

Produced by fan-out over twelve reports (one extractor each), a synthesis pass
against shipped code, and two independent verification passes: an adversarial
code-verifier that re-read `botcheck/*.go` + collector to reject any false gap
(rejected none), and a completeness critic that surfaced 13 capabilities first
pass missed (folded into category files). Severity/effort/status reflect our
stack's constraints as of this writing; re-check code before acting on any
single row, since collector and rule set evolve — see
[changelog.md](changelog.md) for what's shipped since.
