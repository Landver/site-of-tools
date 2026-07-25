# `bot_user_agent` — User-Agent is a known bot / HTTP client

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** no (server-only)

## What it checks

UA names known bot, scripting HTTP client, or recognised crawler / AI agent — honest automation identifies itself this way on purpose. Caveat cuts both ways: any scraper can copy a UA string, so recognition alone never grants trust here.

## Origin & history

Original day-1 rule, widened by **G36** (good-bot/AI-agent classification, shipped 2026-07-17): every entry in [`goodbots.go`](../../../goodbots.go) allowlist now also counts as `bot_user_agent` match, since several allowlist tokens (`Meta-ExternalAgent`, `Claude-User`) carry no generic "bot" substring original rule would catch. Verified good bot's expected deduction here recorded but not counted against its score (see `goodbots.go` suppression map) — recognition alone never grants leniency to unverified UA claim.

## Test status: Verified — mixed result

Single biggest catch against disciplined raw-CDP client w/ no automation flags: nearly its entire `40/100` score came from literal substring `headlesschrome` in default Chromium UA. Also fires for Playwright/Selenium default Headless UA. Caveat from same audit: custom client normalizing its UA string (trivial, one line) would likely score close to 100 against everything else this tool checks — see [next-steps.md item 4](../next-steps.md).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestServerOnlySkipsClientChecks`, `TestEmptyUserAgentFlags`, `TestElectronUAIsSuspiciousNotHardBot`, `TestGoodBotClassification`; `tests/handler_test.go`: `TestGoodBotResultTemplateRenders`.

---

"What it checks" sourced from [`report.go`](../../../report.go)'s `ruleExplanations["bot_user_agent"]` — same text live result page shows under this check's "why" expander. Update both together if check behavior changes.
