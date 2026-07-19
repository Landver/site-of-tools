# 2026-07-19 — `webdriver_sw`: confirmed across 3 frameworks, left as-is (documentation fix only)

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

Playwright, Selenium/chromedriver, and the original Puppeteer session all show
the same pattern: main thread `webdriver: true` and iframe `iframeWebdriver:
true` correctly, but the Service Worker `swWebdriver: false` — for the *same*
automated session, three separate frameworks, not a fluke. The SW script itself
is written correctly (the `swScript` const in [handler.go](../../../handler.go),
`navigator.webdriver===true`) — Chromium's `ServiceWorkerGlobalScope` appears to
simply not carry the `--enable-automation` flag into `navigator.webdriver`
there, regardless of patching.

**Not re-tiered** (unlike the CDP trio): this isn't a low-precision signal that
sometimes false-positives on humans (the DevTools-open problem) — it's a signal
that structurally never fires true against tested real automation. Tier doesn't
change anything for a check that never triggers either way, so the only
substantive fix available was correcting `report.go`'s explanation text (was:
"a third JavaScript realm automation tools rarely bother to patch," implying
it usually catches unpatched automation — the opposite of what's observed) to
state plainly that a clean reading here isn't reassuring. Left running as a
hard tell on the chance it does fire someday (a genuine positive would still
be strong evidence); just stopped pretending a miss means anything.
