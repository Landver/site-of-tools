# 2026-07-19 — real-Chrome baseline via Claude in Chrome: a second (confounded) data point for `chrome_runtime_tamper`

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

Continuing next-steps.md item 2, pointed a genuine consumer Chrome 149
install (macOS, driven by the "Claude in Chrome" browser extension rather
than any npm/Puppeteer harness) at the live production instance,
`https://botcheck.corpberry.com/`. `window.chrome.runtime` was absent
(`window.chrome.app` and `window.chrome.csi` were both present — only
`runtime` was missing), the same shape as the "Chrome for Testing" binary
finding in the [multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md).
The currently-shipped (reverted, lenient) check correctly stayed quiet on this
visit — `window.chrome.runtime fails the integrity probe` read "ok" — so no
regression here.

**Important caveat, not a resolution:** this session is extension-controlled
(almost certainly via the `chrome.debugger` API, since some remote-control
mechanism is how Claude in Chrome drives a real tab), even though
`navigator.webdriver` read `false`. That makes this a *third* "some kind of
tooling is attached" sample (alongside "Chrome for Testing" and the npm
harness itself), not the fully organic, zero-automation-surface control this
open item still needs. The reading is consistent with — but does not prove —
"chrome.runtime is absent on modern consumer Chrome generally." Asked the
repo owner to independently open the production URL in an ordinary Chrome tab
(no extension involved) and report the verdict/score plus
`!!window.chrome.runtime`; that single sample is the one no automation
harness can produce and would settle next-steps.md item 2 either way.
