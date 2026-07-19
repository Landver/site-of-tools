# 2026-07-19 — per-check test-status docs added

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

"Status of tests per check" wasn't answerable from this folder without
grepping [findings-log.md](../findings-log.md), [next-steps.md](../next-steps.md),
and `report.go` comments and mentally merging them per rule ID — the same
scattering [docs-reorganized.md](2026-07-19-docs-reorganized.md) had already
fixed once at the file level, recurring at the rule level as more findings
landed.

Added [`checks/`](../checks/README.md): one file per rule in
[`scoring.go`](../../../scoring.go) (66 — counted by the `why` expander on
the live result page, not the 67 rule IDs `report.go` carries, since one,
`system_color_headless`, is a reserved ID with no active rule yet). Each
states the check's tier/weight, current real-automation test status pulled
from whichever findings mention it, and which Go tests in `tests/` reference
its ID directly. [next-steps.md](../next-steps.md) trimmed to only the items
that don't belong to one check (raw-CDP gap, G16, non-npm tooling) — the
rest now point into `checks/` instead of restating it. No content dropped,
same as the prior reorg: relocated and, where duplicated across three files,
merged down to one.
