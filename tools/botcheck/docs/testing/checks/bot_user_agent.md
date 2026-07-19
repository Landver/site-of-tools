# `bot_user_agent` — User-Agent is a known bot / HTTP client

*(part of [testing checks index](README.md), see [testing index](../README.md) and [botcheck docs index](../../README.md))*

**Tier:** hard · **Weight:** 60 · **Reads client signal:** no (server-only)

## What it checks

The User-Agent names a known bot, scripting HTTP client, or a recognised crawler / AI agent — honest automation identifies itself this way on purpose. The caveat cuts both ways: any scraper can copy a UA string, which is why recognition alone never grants trust here.

## Origin & history

Original day-1 rule, widened by **G36** (good-bot/AI-agent classification, shipped 2026-07-17): every entry in the [`goodbots.go`](../../../goodbots.go) allowlist now also counts as a `bot_user_agent` match, since several allowlist tokens (`Meta-ExternalAgent`, `Claude-User`) carry no generic "bot" substring the original rule would have caught. A verified good bot's expected deduction here is recorded but not counted against its score (see `goodbots.go`'s suppression map) — recognition alone never grants leniency to an unverified UA claim.

## Test status: Verified — mixed result

The single biggest catch against a disciplined raw-CDP client with no automation flags: nearly its entire `40/100` score came from the literal substring `headlesschrome` in the default Chromium UA. Also fires for Playwright/Selenium's default Headless UA. Caveat from the same audit: a custom client that normalizes its UA string (trivial, one line) would likely score close to 100 against everything else this tool checks — see [next-steps.md item 4](../next-steps.md).

See [finding](../findings/2026-07-19-multi-framework-matrix-results.md).

## Go scorer coverage

`tests/botcheck_test.go`: `TestServerOnlySkipsClientChecks`, `TestEmptyUserAgentFlags`, `TestElectronUAIsSuspiciousNotHardBot`, `TestGoodBotClassification`; `tests/handler_test.go`: `TestGoodBotResultTemplateRenders`.

---

"What it checks" is sourced from [`report.go`](../../../report.go)'s `ruleExplanations["bot_user_agent"]` — the same text the live result page shows under this check's "why" expander. Update both together if the check's behavior changes.
