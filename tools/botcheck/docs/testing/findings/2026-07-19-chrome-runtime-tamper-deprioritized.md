# 2026-07-19 — `chrome_runtime_tamper` (item 2): deprioritized, not closed

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Continuing next-steps.md item 2. Checked whether either browser-automation
tool available this session could supply missing genuine-consumer-Chrome
data point item's been waiting on since
[real-Chrome baseline finding](2026-07-19-chrome-runtime-real-chrome-baseline.md).
Can't, from either tool, two different reasons:

- **Claude in Chrome (browser extension):** already tried in prior finding
  — extension/`chrome.debugger`-controlled, not organic regardless of how
  clean `navigator.webdriver` reads.
- **In-app Browser pane tool (this session):** checked fresh —
  `navigator.userAgent` is `...Claude/1.22209.0 Chrome/148.0.7778.271
  Electron/42.5.1 Safari/537.36`. Not consumer Chrome at all — an
  **Electron** embed (same class of embedded runtime G13's
  `embedded_runtime` rule is built to flag). `window.chrome` exists but
  `'runtime' in window.chrome` is `false` — same shape as every other
  sample so far, but from a browser that was never a candidate for
  "genuine consumer Chrome" in the first place. Fourth confounded data
  point, and differently-confounded one: not "some automation tooling
  attached" like the first three, but "wrong browser entirely."

**No tool available to this agent can produce the sample this item needs.**
Every browser surface here either extension/CDP-controlled or embedded
Electron shell. The one sample that would settle it — ordinary person
opening `https://botcheck.corpberry.com/` in own daily-driver Chrome, no
extensions, no devtools — has to come from a human, not agent tooling.
Still worth getting if repo owner has a moment, not worth this item
continuing to block on across sessions.

**Recommend deprioritizing regardless of that data point**, per reasoning
already on record in
[the stealth-source-read finding](2026-07-19-puppeteer-extra-stealth-source-read.md):
stealth's `chrome.runtime` evasion (`evasions/chrome.runtime/index.js`)
only activates when `runtime` is *already* missing — meaning even clean
"real Chrome also lacks `chrome.runtime`" result would only justify
tightening check against *naive* (non-stealth) bot. Against actual
adversary this audit is built around, stealth fakes object back in
convincingly (real captured `STATIC_DATA`, correctly-erroring mocks)
precisely when it would otherwise be absent — so presence/absence was
never a sound signal against a stealth-equipped attacker in the first
place, organic baseline or not. Tightened version written and reverted
would only ever have helped against unsophisticated bots not running
stealth at all — already caught by half a dozen other checks in this tool
(UA string, `navigator.webdriver`, framework globals). Genuinely promising
angle here turned out different: see
[the `tostring_proxy` alias-frame fix](2026-07-19-tostring-proxy-alias-frame-fix.md)'s
follow-up note — `chromeRuntimeOK()`'s call/construct traps might share
same stack-leak weakness `tostring_proxy` did, which would catch stealth's
fake *regardless of* whether real Chrome has `chrome.runtime` — needs
HTTPS target to verify, tracked separately, not part of this item.

**Decision:** leave `chromeRuntimeOK()` exactly as currently shipped
(lenient, absence-tolerant). Don't chase tightened absence-based version
further — not because data point is unobtainable (might still turn up),
but reasoning above shows it wouldn't be worth shipping even with clean
answer. Downgraded from "single most valuable open item" to closed,
superseded by stack-leak angle as more promising direction.
