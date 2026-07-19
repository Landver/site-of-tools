# Bot check — automation test harness

*(part of the [botcheck docs index](../README.md))*

Companion to [`../RESEARCH.md`](../RESEARCH.md) (how competitor services work)
and [`../roadmap/README.md`](../roadmap/README.md) (feature/signal gap audit).
This is narrower: **does botcheck actually catch real, off-the-shelf
automation tools**, verified by running them for real rather than reasoning
about them. See [findings-log.md](findings-log.md) for what testing found and
[next-steps.md](next-steps.md) for what's left to fix.

Started 2026-07-19, after a manual review (via Claude's own in-app/CDP-driven
browser) found the CDP-detection checks reading "ok" against a session that is
in fact CDP-driven.

## Why this needed real browsers, not more reasoning

`go test ./... -race` (CLAUDE.md rule #6) never exercises
[`shared/static/js/botcheck.js`](../../../../shared/static/js/botcheck.js) —
the Go tests construct `Signals` directly and feed them to `Evaluate`. That's
correct for testing the *scorer*, but it means a bug in the *collector* (wrong
value, thrown exception, wrong DOM read) is structurally invisible to the
existing test suite forever. The `webglGPU()` bug in
[findings-log.md](findings-log.md) shipped and passed every Go test and every
prior E2E pass, because nobody had a harness that could catch a client-side
`ReferenceError` swallowed by `safe()`. See also
[`../go-test-suite.md`](../go-test-suite.md) for what the Go suite does cover.

## Test architecture

A gitignored, npm-based harness lives outside the Go module at
**`/verify-cdp/`** (repo root, sibling to `tools/`) — **not** part of the shipped
product, **not** committed (see `.gitignore`: `/verify-cdp/`). This is a
deliberate, scoped exception to CLAUDE.md rule #3 ("No Node/npm. Ever."): the
rule protects the *shipped binary and its frontend* from a JS toolchain
dependency; it says nothing about disposable local verification tooling that
never ships. If that changes (the repo decides to track these tests for real),
un-gitignore the folder and promote it properly — flagged here rather than
decided unilaterally.

```
verify-cdp/
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

**Target:** point every test at a **local dev instance**
(`APP_ENV=dev go run .` from repo root, served at `http://botcheck.localhost:8080/`
— Chromium resolves `*.localhost` to loopback natively, no `/etc/hosts` edit
needed), not production. Two reasons: it exercises whatever fix is currently
uncommitted in the working tree, and it doesn't add synthetic noise to the real
Mongo request log / fingerprint corpus. Hit the real
`https://botcheck.corpberry.com/` only when specifically validating deployed
behavior.

**Adding a new framework:** make a new `frameworks/<name>/` subfolder, `npm init
-y`, install only what that framework needs, keep any downloaded browser binary
local to the subfolder (mirror `.puppeteerrc.cjs`'s pattern — e.g.
`PLAYWRIGHT_BROWSERS_PATH` for Playwright), and reuse `full-sweep.mjs`'s
DOM-extraction approach for reading the score/verdict/check-list/raw-fingerprint
out of the rendered `#result` fragment. Report at minimum: `navigator.webdriver`,
`frameworkGlobals`, `cdpMainThread`/`cdpWorker`, and whether the live score
matched expectations.

**Known gap in this harness:** it proves a signal fires or doesn't against
*today's* Chromium build. It says nothing about older Chromium/Firefox/Safari,
and nothing about detection evasion tools not distributed over npm (Python's
`nodriver`/`undetected-chromedriver`, Go-based CDP libraries, browser
extensions). Treat every "confirmed dead" finding in
[findings-log.md](findings-log.md) as "dead against modern Chromium via
npm-distributed tooling," not "dead everywhere, forever."
