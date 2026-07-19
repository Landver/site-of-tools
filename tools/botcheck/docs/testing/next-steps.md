# Bot check — automation-test next steps

*(part of [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for closed items' history)*

Per-check detail (what fired, what was fixed, what's still evaded, by which
framework) lives once in [checks/](checks/README.md) — this list only keeps
items that don't belong to a single check. Six prior cross-cutting items
closed 2026-07-19 — moved to [findings-log.md](findings-log.md), not
restated here.

1. **Stealth-specific G04/G17 probes still open, no concrete idea yet.**
   `tostring_proxy` fixed already (see
   [checks/tostring_proxy.md](checks/tostring_proxy.md)) — a *single*
   illegal call already leaked stealth's unstripped proxy-trap frame, since
   current V8 renders it as `[as apply]` bracket alias matching neither
   stealth's own anchor-stripper nor our detector's old regex. Three
   siblings stay evaded: [checks/native_descriptor_tamper.md](checks/native_descriptor_tamper.md),
   [checks/native_callnew_tamper.md](checks/native_callnew_tamper.md),
   [checks/navigator_proto_tamper.md](checks/navigator_proto_tamper.md) —
   none route through a JS Proxy `apply`/`construct` trap the way
   `tostring_proxy` does, so the alias-frame fix doesn't reach them.

2. **`playwright/check.mjs` and `nightmare/test-nightmare.cjs` are both
   broken in this environment**, unrelated to any botcheck rule.
   Playwright's browser cache is missing `chrome-headless-shell-1228` (needs
   `npx playwright install`, a real download); Nightmare's bundled Electron
   failed to install (`Error: Electron failed to install correctly`) and the
   framework itself is unmaintained since ~2018. Neither blocked the
   [2026-07-19 full sweep](findings/2026-07-19-remaining-43-checks-sweep.md)
   — Selenium, raw-cdp, puppeteer-extra-stealth, and two new Puppeteer-based
   probe scripts covered it — but fix before relying on either script again.

3. **Root `automation-harness`'s plain `puppeteer.launch()` reports empty
   `navigator.userAgentData.platform`/`.brands`/`.fullVersionList` against
   this origin**, even completely unmodified (confirmed `isSecureContext:
   true`, so not that). `raw-cdp` and `selenium` — real "Chrome for Testing"
   launched without Puppeteer's own launcher — report full, real Client
   Hints on the same origin, so it's specific to how the root `puppeteer`
   package's default launch talks to this browser build, not the origin or
   Chrome-for-Testing generally. Never chased (out of scope for the
   [2026-07-19 sweep](findings/2026-07-19-remaining-43-checks-sweep.md) that
   found it) — worked around there with direct `curl POST /check` payloads
   instead. Matters for anyone extending `ua-mismatch-probe.mjs`'s
   `userAgentData`-dependent scenarios (`ch_platform_mismatch`,
   `ch_brands_mismatch`, `ua_chrome_version_mismatch`, `ua_os_mismatch`).

## Adding / closing an item

Add a numbered bullet above for anything cross-cutting (spans checks, or
belongs to none). Once closed, strike it, move its substance to
[findings-log.md](findings-log.md) — a one-line table row if it fits, its
own dated file under [`findings/`](findings/) if it doesn't — then drop it
from here.
