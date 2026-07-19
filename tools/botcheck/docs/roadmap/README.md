# Bot check — roadmap index

The "what's next" doc set for `botcheck`, split so a reader (human or AI) only
opens the file relevant to their question instead of one 465-line monolith.
Two halves:

1. **The competitor-gap audit** — every capability, signal, technique, and
   reporting feature that one or more of the twelve researched services provide
   and our own [`botcheck`](../README.md) tool does **not** (or does more
   weakly), each rated by value-to-us, effort, and status. Split by category —
   see the table below.
2. **The internal backlog** ([internal-backlog.md](internal-backlog.md)):
   effort-layered features we want regardless of any competitor.

For how the tool works today and why it's designed the way it is, see
[`../README.md`](../README.md); for how the competitor services work and how
our test browser scored against them, see [`../RESEARCH.md`](../RESEARCH.md).

## Start here

- **New to this audit?** Read [executive-summary.md](executive-summary.md) first — the three-bucket framing of where the gaps are, plus the qualitative "what they do well" read.
- **Picking up work?** [quick-wins.md](quick-wins.md) is fully shipped as of 2026-07-17; open work starts at medium-effort/infra/DB-backed rows in the category files below.
- **Want the history?** [changelog.md](changelog.md) — dated build-status entries, oldest first.
- **Checking a specific `G##` row?** Use the category map below.

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
| [deferred-nongoals.md](deferred-nongoals.md) | Recap: everything deferred by design or an explicit non-goal | (all of the above) |
| [internal-backlog.md](internal-backlog.md) | Non-competitor-driven backlog, by effort (Layer 1/2/3) | — |

## How to read the ratings

Each row in the category files carries **`Sev · Effort · Status`**:

- **Sev** (severity) = value **to our tool specifically** — a stateless, no-ML
  self-test page on a personal portfolio (MongoDB is available but botcheck
  only uses it for the fingerprint corpus so far), *not* an enterprise WAF. A
  cheap client signal we simply forgot rates higher than DataDome-scale
  behavioral ML, which is near-worthless at our scale.
- **Effort** = `trivial` → `low` → `medium` → `high-infra` (needs edge/TLS/packet
  access) → `ml-or-db` (needs persistence in MongoDB or a trained model).
- **Status** = **Not built** (true blind spot) · **Partial** (we do a weaker
  version) · **Shipped** · **Deferred (documented)** (an acknowledged gap, not
  an oversight).

## What this is built from

- The twelve firsthand service reports in [`../reports/`](../reports/)
  (`deviceandbrowserinfo`, `incolumitas`, `sannysoft`, `creepjs`, `fingerprint`,
  `browserscan`, `pixelscan`, `iphey`, `whoer`, `amiunique`, `coveryourtracks`,
  `datadome`) — see [`../RESEARCH.md`](../RESEARCH.md) for the cross-service
  summary.
- Our **shipped** implementation, read as ground truth (not the design doc):
  [`../../scoring.go`](../../scoring.go) (the 66 detection rules),
  [`../../botcheck.go`](../../botcheck.go) (the `Signals` struct + scorer),
  [`../../handler.go`](../../handler.go) (server signals), and
  [`shared/static/js/botcheck.js`](../../../../shared/static/js/botcheck.js)
  (the vendored collector).

Each competitor capability was compared against that code, and **every claimed
gap was verified against the real source** to remove false "we don't do X"
entries. None survived: of 62 items, 0 were things we actually already
shipped-but-uncredited, 16 are things we do in a narrower form (**Partial**), 31
are genuine blind spots (**Not built**), and 15 are already acknowledged in our
design docs as **Deferred**.

## Note on method & confidence

Produced by a fan-out over the twelve reports (one extractor each), a synthesis
pass against the shipped code, and two independent verification passes: an
adversarial code-verifier that re-read `botcheck/*.go` + the collector to
reject any false gap (it rejected none), and a completeness critic that
surfaced 13 capabilities the first pass missed (folded into the category
files). Severity/effort/status reflect our stack's constraints as of this
writing; re-check the code before acting on any single row, since the
collector and rule set evolve — see [changelog.md](changelog.md) for what's
shipped since.
