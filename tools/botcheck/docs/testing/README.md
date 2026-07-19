# Bot check — automation test harness

*(part of [botcheck docs index](../README.md))*

Companion to [`../RESEARCH.md`](../RESEARCH.md) (how competitor services
work) and [`../roadmap/README.md`](../roadmap/README.md) (feature/signal gap
audit). Narrower scope: **does botcheck catch real, off-the-shelf automation
tools** — verified by running them for real, not reasoning about them. See
[findings-log.md](findings-log.md) for the dated, chronological account of
what testing found, [next-steps.md](next-steps.md) for what's left to fix
that isn't specific to one check, and **[checks/](checks/README.md) as the
single per-check reference** — one file per rule in
[`scoring.go`](../../scoring.go) covering what it checks, its origin/history,
its real-automation test status, and its Go scorer coverage, so "what does
this check do, why does it exist, and is it actually verified" all answer
from one file instead of a grep across `roadmap/`, `changelog.md`,
`findings/`, and `report.go` comments.

Started 2026-07-19, after manual review (Claude's own in-app/CDP-driven
browser) found CDP-detection checks reading "ok" against a session actually
CDP-driven.

## Why this needed real browsers, not more reasoning

`go test ./... -race` (CLAUDE.md rule #6) never exercises
[`shared/static/js/botcheck.js`](../../../../shared/static/js/botcheck.js) —
Go tests construct `Signals` directly, feed to `Evaluate`. Fine for testing
*scorer*, but bug in *collector* (wrong value, thrown exception, wrong DOM
read) stays structurally invisible to existing suite forever. The
[`webglGPU()` bug](findings/2026-07-19-webglgpu-bug-fixed.md) shipped,
passed every Go test and prior E2E pass — no harness existed to catch
client-side `ReferenceError` swallowed by `safe()`. See also
[`../go-test-suite.md`](../go-test-suite.md) for what Go suite covers.

## Test architecture

Gitignored, npm-based harness lives outside Go module at
**`/automation-harness/`** (repo root, sibling to `tools/`) — **not** part of shipped
product, **not** committed (see `.gitignore`: `/automation-harness/`). Deliberate,
scoped exception to CLAUDE.md rule #3 ("No Node/npm. Ever."): rule protects
*shipped binary and frontend* from JS toolchain dependency; says nothing
about disposable local verification tooling that never ships. If that
changes (repo decides to track these tests for real), un-gitignore folder,
promote it properly — flagged here rather than decided unilaterally. (Named
`automation-harness`, not `verify-cdp` — outgrew that name once it started
covering Playwright, Selenium, puppeteer-extra-stealth, and raw CDP, not
just CDP trap.)

```
automation-harness/
  .puppeteerrc.cjs          # keeps the downloaded Chromium local to this folder
  .chromium-cache/          # ~550MB, shared across every Puppeteer-based test below
  cdp-trap.test.mjs         # node:test — isolated cdpTrap() probe, no network
  full-sweep.mjs            # full check-breakdown dump against a live instance,
                             # headless vs. headful, with a diff
  frameworks/
    playwright/             # one subfolder per automation framework under test
    selenium/
    puppeteer-extra-stealth/
    raw-cdp/
    nightmare/
```

**Target:** point every test at **local dev instance**
(`APP_ENV=dev go run .` from repo root, served at `http://botcheck.localhost:8080/`
— Chromium resolves `*.localhost` to loopback natively, no `/etc/hosts` edit
needed), not production. Two reasons: exercises whatever fix sits
uncommitted in working tree, doesn't add synthetic noise to real Mongo
request log / fingerprint corpus. Hit real `https://botcheck.corpberry.com/`
only when specifically validating deployed behavior.

**Adding new framework:** make new `frameworks/<name>/` subfolder, `npm init
-y`, install only what framework needs, keep downloaded browser binary local
to subfolder (mirror `.puppeteerrc.cjs`'s pattern — e.g.
`PLAYWRIGHT_BROWSERS_PATH` for Playwright), reuse `full-sweep.mjs`'s
DOM-extraction approach reading score/verdict/check-list/raw-fingerprint out
of rendered `#result` fragment. Report at minimum: `navigator.webdriver`,
`frameworkGlobals`, `cdpMainThread`/`cdpWorker`, whether live score matched
expectations.

**Known gap in this harness:** proves signal fires or not against *today's*
Chromium build. Says nothing about older Chromium/Firefox/Safari, nothing
about detection evasion tools not distributed over npm (Python's
`nodriver`/`undetected-chromedriver`, Go-based CDP libraries, browser
extensions). Treat every "confirmed dead" finding in
[findings-log.md](findings-log.md) as "dead against modern Chromium via
npm-distributed tooling," not "dead everywhere, forever."
