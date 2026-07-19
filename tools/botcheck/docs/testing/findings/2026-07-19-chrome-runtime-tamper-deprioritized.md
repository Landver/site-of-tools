# 2026-07-19 — `chrome_runtime_tamper` (item 2): deprioritized, not closed

*(part of the [findings log](../findings-log.md), see the
[botcheck docs index](../../README.md))*

Continuing next-steps.md item 2. Checked whether either browser-automation
tool available in this session could supply the missing genuine-consumer-Chrome
data point the item has been waiting on since the
[real-Chrome baseline finding](2026-07-19-chrome-runtime-real-chrome-baseline.md).
It can't, from either tool, for two different reasons:

- **Claude in Chrome (browser extension):** already tried in that prior
  finding — extension/`chrome.debugger`-controlled, so not organic regardless
  of how clean `navigator.webdriver` reads.
- **The in-app Browser pane tool (this session):** checked fresh —
  `navigator.userAgent` is `...Claude/1.22209.0 Chrome/148.0.7778.271
  Electron/42.5.1 Safari/537.36`. This isn't consumer Chrome at all, it's an
  **Electron** embed (the same class of embedded runtime G13's
  `embedded_runtime` rule is built to flag). `window.chrome` exists but
  `'runtime' in window.chrome` is `false` — same shape as every other sample
  so far, but from a browser that was never a candidate for "genuine consumer
  Chrome" in the first place. A fourth confounded data point, and a
  differently-confounded one: not "some automation tooling attached" like the
  first three, but "wrong browser entirely."

**No tool available to this agent can produce the sample this item needs.**
Every browser surface here is either extension/CDP-controlled or an embedded
Electron shell. The one sample that would settle it — an ordinary person
opening `https://botcheck.corpberry.com/` in their own daily-driver Chrome,
no extensions, no devtools — has to come from a human, not from any agent
tooling. Still worth getting if the repo owner has a moment, but not worth
this item continuing to block on across sessions.

**Recommend deprioritizing regardless of that data point**, per the reasoning
already on record in
[the stealth-source-read finding](2026-07-19-puppeteer-extra-stealth-source-read.md):
stealth's `chrome.runtime` evasion (`evasions/chrome.runtime/index.js`) only
activates when `runtime` is *already* missing — meaning even a clean "real
Chrome also lacks `chrome.runtime`" result would only justify tightening the
check against a *naive* (non-stealth) bot. Against the actual adversary this
audit is built around, stealth fakes the object back in convincingly (real
captured `STATIC_DATA`, correctly-erroring mocks) precisely when it would
otherwise be absent — so presence/absence was never a sound signal against a
stealth-equipped attacker in the first place, organic baseline or not. The
tightened version that was written and reverted would only ever have helped
against unsophisticated bots that don't run stealth at all — and those are
already caught by half a dozen other checks in this tool (UA string,
`navigator.webdriver`, framework globals). The genuinely promising angle here
turned out to be different: see the
[`tostring_proxy` alias-frame fix](2026-07-19-tostring-proxy-alias-frame-fix.md)'s
follow-up note — `chromeRuntimeOK()`'s call/construct traps might have the
same stack-leak weakness `tostring_proxy` did, which would catch stealth's
fake *regardless of* whether real Chrome has `chrome.runtime` — but that
needs an HTTPS target to verify and is tracked separately, not as part of this
item.

**Decision:** leave `chromeRuntimeOK()` exactly as currently shipped (lenient,
absence-tolerant). Don't chase the tightened absence-based version further —
not because the data point is unobtainable (it might still turn up), but
because the reasoning above shows it wouldn't be worth shipping even with a
clean answer. Downgraded from "the single most valuable open item" to closed,
superseded by the stack-leak angle as the more promising direction.
