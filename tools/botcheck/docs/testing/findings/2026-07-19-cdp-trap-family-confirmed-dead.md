# 2026-07-19 — CDP-trap family: confirmed dead, downgraded to soft tier (FIXED)

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

`cdpTrap()` ([botcheck.js](../../../../../shared/static/js/botcheck.js)) —
backing `cdp_both`/`cdp_main_only`/`cdp_sw_only` — defines a getter on an
`Error`'s `.stack` and calls `console.debug()` on it, expecting a CDP client
with `Runtime.enable` active to invoke the getter while building an object
preview. Tested against **six** genuinely CDP-driven sessions and it fired
**zero** times in every one:

1. Claude's own in-app CDP-driven browser tool (the original trigger for this audit).
2. A genuine, un-stealthed Puppeteer session, headless AND headful, with a
   `page.on('console', …)` listener explicitly forcing console-message capture
   (and a plain-object property getter through `console.debug()` — rules out
   anything `Error.stack`-specific).
3. Playwright, headless chromium — `cdpMainThread`/`cdpWorker`/`swCDP` all `false`.
4. Selenium + chromedriver, driving the real "Google Chrome for Testing" binary
   — same result, all three `false`, despite chromedriver's session genuinely
   running over CDP.
5. A hand-rolled `chrome-remote-interface` client, Chromium spawned directly,
   Page/Runtime/Network domains explicitly enabled for the whole session,
   deliberately with **no** `--enable-automation` flag — still all `false`.
6. `puppeteer-extra` + `puppeteer-extra-plugin-stealth` — also all `false`
   (unsurprising given #2-5, but confirmed).

Net: this was never one browser evading it. The technique's premise — CDP
preview generation invokes property getters — doesn't hold on current Chromium
regardless of transport. **Fixed** by honest recalibration rather than deletion
(kept running — it's free when silent, and might catch a future Chromium
regression or an older engine): moved `cdp_both`, `cdp_main_only`, and
`cdp_sw_only` from hard (40pts) / consistency (15pts each) down into the
soft-heuristics section of `scoring.go` (weight 8, only bites as part of a ≥3
cluster like every other soft signal), physically relocated to the file's own
"Soft heuristics" block, and rewrote their `report.go` explanations to state
the 2026-07-19 finding plainly instead of the old "DevTools-open false
positive" framing (which implied the trap works against real automation and
just has a narrow blind spot — it doesn't, full stop, as far as this audit can
tell). `go test ./... -race` green after the change — nothing in the existing
suite asserted a specific tier for these three IDs, only `.Triggered` booleans,
so this was safe to change without touching test expectations.
