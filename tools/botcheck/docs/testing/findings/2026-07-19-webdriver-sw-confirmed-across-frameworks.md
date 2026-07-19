# 2026-07-19 — `webdriver_sw`: confirmed across 3 frameworks, left as-is (documentation fix only)

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Playwright, Selenium/chromedriver, and original Puppeteer session all show
same pattern: main thread `webdriver: true` and iframe `iframeWebdriver:
true` correctly, but Service Worker `swWebdriver: false` — for *same*
automated session, three separate frameworks, not a fluke. SW script itself
written correctly (`swScript` const in [handler.go](../../../handler.go),
`navigator.webdriver===true`) — Chromium's `ServiceWorkerGlobalScope`
appears to simply not carry `--enable-automation` flag into
`navigator.webdriver` there, regardless of patching.

**Not re-tiered** (unlike CDP trio): this isn't low-precision signal that
sometimes false-positives on humans (DevTools-open problem) — it's a
signal that structurally never fires true against tested real automation.
Tier changes nothing for a check that never triggers either way, so only
substantive fix available was correcting `report.go`'s explanation text
(was: "a third JavaScript realm automation tools rarely bother to patch,"
implying it usually catches unpatched automation — opposite of what's
observed) to state plainly a clean reading here isn't reassuring. Left
running as hard tell on chance it does fire someday (a genuine positive
would still be strong evidence); just stopped pretending a miss means
anything.
