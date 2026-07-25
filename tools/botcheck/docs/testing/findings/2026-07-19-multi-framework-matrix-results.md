# 2026-07-19 — multi-framework matrix results

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Five frameworks run via `Workflow` in parallel, each in own
`automation-harness/frameworks/<name>/` subfolder vs local dev
instance — one comprehensive side-by-side view; per-check detail for
any single row now in [checks/](../checks/README.md):

| Framework | Setup | Live score | What actually caught it |
|---|---|---|---|
| Playwright (headless chromium) | ok | 0/100 bot | `webdriver` + `iframe_webdriver` (−60 each), `bot_user_agent` matched "headlesschrome" (−60), `software_renderer` (SwiftShader, −40), `permission_impossible` (−25) |
| Selenium + chromedriver (real "Chrome for Testing" binary) | ok | 0/100 bot | Same webdriver/UA hits, **plus `framework_globals` caught all 7 of chromedriver's classic `$cdc_...` markers** (−60) — works great vs classic Selenium |
| `puppeteer-extra` + `puppeteer-extra-plugin-stealth` 2.11.2 | ok | 25/100 bot | See deep-dive below — headline result of whole audit |
| Raw CDP (`chrome-remote-interface`, hand-spawned Chromium, no `--enable-automation`) | ok | 40/100 bot | Almost entirely `bot_user_agent` matching "headlesschrome" in UA (−60); every architectural check read clean. Detail: [checks/bot_user_agent.md](../checks/bot_user_agent.md), [next-steps.md item 4](../next-steps.md). |
| Nightmare (~2015-2018, Electron-based) | failed to install | n/a | Ancient Electron 2.0.18 has no darwin-arm64 build (404); its Node-v24-incompatible `extract-zip@1.7.0` postinstall step corrupts darwin-x64 fallback under Rosetta. Expected, not pursued — `__nightmare` WINDOW_MARKERS entry stays unexercised. |

**Headline finding — puppeteer-extra-stealth deep-dive, single most
important result of whole audit.** Six checks this codebase built to
target this class of stealth patch — `tostring_proxy`,
`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`,
`chrome_runtime_tamper`, `chrome_late_injection` — **were evaded, all six,
cleanly**, incl. hiding `navigator.webdriver` in every context (main
thread, iframe, *and* Service Worker — more thorough hide than naive
delete-only patch). Yet tool still scored it **25/100, "bot," not
human**: three of its own cross-context consistency checks — none
stealth-specific — caught it instead (`context_ua_mismatch`,
`context_cores_mismatch`, `context_webgl_mismatch`; per-field detail in
their own [checks/](../checks/README.md) files).

Exactly this tool's core design thesis — "strongest checks are
cross-layer/cross-context consistency ones," per `botcheck.go`'s own
package doc — validated vs real, current, actively-maintained
adversarial tool. Six checks built to catch stealth's
*signature* all missed; checks built to catch stealth's *incompleteness*
caught it anyway. Good for architecture, bad for those six
specific checks, each needs own follow-up — see
individual status in [checks/](../checks/README.md)
(`tostring_proxy` since fixed; other five still open, three
investigated further: [checks/chrome_runtime_tamper.md](../checks/chrome_runtime_tamper.md)
covers reverted `chromeRuntimeOK()` tightening in full).
