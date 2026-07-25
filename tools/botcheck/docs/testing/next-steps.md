# Bot check — automation-test next steps

*(part of [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for closed items' history)*

Per-check detail (what fired, what fixed, what's still evaded, by which
framework) lives once in [checks/](checks/README.md) — this list only keeps
items that don't belong to single check. Six prior cross-cutting items
closed 2026-07-19 — moved to [findings-log.md](findings-log.md), not
restated here.

1. **Stealth-specific G04/G17/G22 probes: downgraded to soft (2026-07-21);
   only the *sharpening* stays open.** Five evaded probes
   (`native_descriptor_tamper`, `native_callnew_tamper`,
   `navigator_proto_tamper`, `chrome_runtime_tamper`, `chrome_late_injection`)
   moved consistency → soft so no longer oversell stealth coverage or
   false-positive privacy-extension human — see
   [the downgrade finding](findings/2026-07-21-internals-tamper-downgraded-to-soft.md).
   Closes *scoring-honesty* half of item; *detection* half
   still open, no concrete idea yet. `tostring_proxy` (the one fixed,
   see [checks/tostring_proxy.md](checks/tostring_proxy.md)) leaked stealth's
   unstripped proxy-trap frame because current V8 renders it as `[as apply]`
   bracket alias matching neither stealth's anchor-stripper nor our old regex;
   three `native_*`/`navigator_proto` siblings don't route through JS
   Proxy `apply`/`construct` trap, so that alias-frame fix doesn't reach them.
   `chrome_runtime_tamper` has separate untested angle (alias-frame fix on
   its call/new traps, needs HTTPS target — see that check's file). If any
   sharpening lands and proves out vs real stealth, re-promote that check
   from soft.

2. **`playwright/check.mjs` and `nightmare/test-nightmare.cjs` both
   broken in this environment**, unrelated to any botcheck rule.
   Playwright's browser cache missing `chrome-headless-shell-1228` (needs
   `npx playwright install`, a real download); Nightmare's bundled Electron
   failed to install (`Error: Electron failed to install correctly`) &
   framework itself unmaintained since ~2018. Neither blocked
   [2026-07-19 full sweep](findings/2026-07-19-remaining-43-checks-sweep.md)
   — Selenium, raw-cdp, puppeteer-extra-stealth, & two new Puppeteer-based
   probe scripts covered it — but fix before relying on either script again.

3. **Root `automation-harness`'s plain `puppeteer.launch()` reports empty
   `navigator.userAgentData.platform`/`.brands`/`.fullVersionList` against
   this origin**, even completely unmodified (confirmed `isSecureContext:
   true`, so not that). `raw-cdp` & `selenium` — real "Chrome for Testing"
   launched without Puppeteer's own launcher — report full, real Client
   Hints on same origin, so specific to how root `puppeteer`
   package's default launch talks to this browser build, not origin or
   Chrome-for-Testing generally. Never chased (out of scope for
   [2026-07-19 sweep](findings/2026-07-19-remaining-43-checks-sweep.md) that
   found it) — worked around there w/ direct `curl POST /check` payloads
   instead. Matters for anyone extending `ua-mismatch-probe.mjs`'s
   `userAgentData`-dependent scenarios (`ch_platform_mismatch`,
   `ch_brands_mismatch`, `ua_chrome_version_mismatch`, `ua_os_mismatch`).

## Adding / closing an item

Add numbered bullet above for anything cross-cutting (spans checks, or
belongs to none). Once closed, strike it, move substance to
[findings-log.md](findings-log.md) — one-line table row if it fits, its
own dated file under [`findings/`](findings/) if it doesn't — then drop it
from here.
