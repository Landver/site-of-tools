# 2026-07-19 — CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

`cdpTrap()` ([botcheck.js](../../../../../shared/static/js/botcheck.js)) —
backs `cdp_both`/`cdp_main_only`/`cdp_sw_only` — defines getter on
`Error`'s `.stack`, calls `console.debug()` on it, expects CDP client with
`Runtime.enable` active to invoke getter while building object preview.
Tested against **six** genuinely CDP-driven sessions, fired **zero** times
in every one:

1. Claude's own in-app CDP-driven browser tool (original trigger for this audit).
2. Genuine, un-stealthed Puppeteer session, headless AND headful, with
   `page.on('console', …)` listener forcing console-message capture (plus
   plain-object property getter through `console.debug()` — rules out
   anything `Error.stack`-specific).
3. Playwright, headless chromium — `cdpMainThread`/`cdpWorker`/`swCDP` all `false`.
4. Selenium + chromedriver, driving real "Google Chrome for Testing" binary
   — same result, all three `false`, despite chromedriver's session genuinely
   running over CDP.
5. Hand-rolled `chrome-remote-interface` client, Chromium spawned directly,
   Page/Runtime/Network domains enabled for whole session, deliberately
   **no** `--enable-automation` flag — still all `false`.
6. `puppeteer-extra` + `puppeteer-extra-plugin-stealth` — also all `false`
   (unsurprising given #2-5, confirmed).

Net: never one browser evading it. Technique's premise — CDP preview
generation invokes property getters — doesn't hold on current Chromium
regardless of transport. **Fixed** by honest recalibration, not deletion
(kept running — free when silent, might catch future Chromium regression
or older engine): moved `cdp_both`, `cdp_main_only`, and `cdp_sw_only` from
hard (40pts) / consistency (15pts each) down into soft-heuristics section
of `scoring.go` (weight 8, only bites as part of ≥3 cluster like every
other soft signal), physically relocated to file's own "Soft heuristics"
block, rewrote their `report.go` explanations to state 2026-07-19 finding
plainly instead of old "DevTools-open false positive" framing (implied
trap works against real automation with just narrow blind spot — it
doesn't, full stop, far as this audit can tell). `go test ./... -race`
green after change — nothing in existing suite asserted specific tier for
these three IDs, only `.Triggered` booleans, so safe to change without
touching test expectations.
