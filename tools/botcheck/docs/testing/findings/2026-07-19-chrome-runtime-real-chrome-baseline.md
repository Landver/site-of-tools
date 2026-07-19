# 2026-07-19 — real-Chrome baseline via Claude in Chrome: a second (confounded) data point for `chrome_runtime_tamper`

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Continuing next-steps.md item 2: pointed genuine consumer Chrome 149 install
(macOS, driven by "Claude in Chrome" browser extension rather than any
npm/Puppeteer harness) at live production instance,
`https://botcheck.corpberry.com/`. `window.chrome.runtime` was absent
(`window.chrome.app` and `window.chrome.csi` both present — only `runtime`
missing), same shape as "Chrome for Testing" binary finding in
[multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md).
Currently-shipped (reverted, lenient) check correctly stayed quiet on this
visit — `window.chrome.runtime fails the integrity probe` read "ok" — no
regression here.

**Important caveat, not a resolution:** this session is extension-controlled
(almost certainly via `chrome.debugger` API — some remote-control mechanism
is how Claude in Chrome drives a real tab), even though
`navigator.webdriver` read `false`. Makes this *third* "some kind of
tooling attached" sample (alongside "Chrome for Testing" and npm harness
itself), not the fully organic, zero-automation-surface control this open
item still needs. Reading consistent with — but doesn't prove — "chrome.runtime
is absent on modern consumer Chrome generally." Asked repo owner to
independently open production URL in ordinary Chrome tab (no extension
involved) and report verdict/score plus `!!window.chrome.runtime`; that
single sample is the one no automation harness can produce and would
settle next-steps.md item 2 either way.
