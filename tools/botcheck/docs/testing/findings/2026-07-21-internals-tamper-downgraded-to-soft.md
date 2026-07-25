# 2026-07-21 — five deep-tamper internals probes downgraded consistency → soft

*(part of [findings log](../findings-log.md), see [botcheck docs index](../../README.md))*

## What changed

Five checks moved from **consistency** tier (individual deductions,
`internals` subgroup) to **soft** tier (weight 8, cluster-only):

| Check | Was | Now |
|---|---|---|
| `native_descriptor_tamper` | consistency / 25 | soft / 8 |
| `native_callnew_tamper` | consistency / 25 | soft / 8 |
| `navigator_proto_tamper` | consistency / 25 | soft / 8 |
| `chrome_runtime_tamper` | consistency / 20 | soft / 8 |
| `chrome_late_injection` | consistency / 15 | soft / 8 |

No `eval` logic changed — each still fires on exactly same input, keeps its
version gate, still shows in breakdown. Only tier, weight &
subgroup changed, so single firing no longer docks score; three or more
soft signals together still cost one 25-point cluster penalty.

## Why

Follow-through on [2026-07-19 false-negative
audit](2026-07-19-multi-framework-matrix-results.md). That audit established two
facts about this whole class of check:

1. **Add nothing vs adversary they targeted.** All five built
   to catch `puppeteer-extra-plugin-stealth`; audit confirmed current
   stealth (2.11.2) evades every one cleanly — its shared `_utils`
   helpers spread original descriptor, fake `chrome.runtime` in place, &
   hide `webdriver` w/ launch flag rather than JS patch (see
   [source read](2026-07-19-puppeteer-extra-stealth-source-read.md)). What
   actually caught stealth in audit = **cross-context** checks
   (`context_ua/cores/webgl_mismatch`), scored it 25/100 — core
   design thesis, validated.

2. **Only things that trip them = naive hand-patch or legitimate
   privacy extension** — latter is real human. Canvas/WebGL noise
   injector (CanvasBlocker, Chameleon, …) can leave impossible descriptor or
   missing call/new trap; `chrome.runtime` fake absent on official
   Chrome-for-Testing binary too. At consistency/25, **two firing on
   privacy-tool user dropped genuine human to 50/"suspicious"** —
   false positive the tool was manufacturing.

So at old tier these five carried real false-positive risk vs real
humans, redundant coverage vs naive bots (already tanked to 0 by hard
`webdriver`/`bot_user_agent`/`software_renderer` tells), & **zero** value
vs stealth adversary they were built for. Exactly the profile
of a signal that should be cluster-only, not standalone deduction.

## Precedent

Identical handling to [CDP-trap trio](../checks/cdp_both.md)
(`cdp_both`/`cdp_main_only`/`cdp_sw_only`), downgraded to soft on 2026-07-19 for
same "kept for corroboration, no longer oversold" reason. Downgraded, not
deleted: still fire, still appear in breakdown for transparency, &
still contribute to soft cluster when several environment tells co-occur —
naive bot that trips three plus other soft signals still gets caught.

## Effect on scoring, proven by tests

- `TestInternalsTamperDowngradedToSoft` — each of five, firing alone on
  otherwise-clean browser, now leaves score at 100/human (soft signal
  never docks on own); three together cross cluster threshold for one
  25-point deduction (75/suspicious), not 3×25.
- `TestStealthCaughtByCrossContextChecks` — replaces old
  `TestStealthPatchedBrowserScoresBot`, whose premise (deep probes firing ⇒ bot)
  the downgrade removes. Now encodes audit's real finding: internals
  probes read clean vs stealth, cross-context checks carry
  bot verdict.
- `TestEveryRuleCanFire` — new fire-path completeness guard still confirms
  all five reach their fire branch.

## Not changed / still open

- **Sharpening** ideas stay open, unaffected by tier move: nested
  proxy-trap probe for `native_*` family, & alias-frame stack-leak fix
  for `chrome_runtime_tamper`'s traps (needs HTTPS target to verify vs
  live stealth session — see that check's file). If any lands and proves out
  vs real stealth, corresponding check can be re-promoted.
- `internals` consistency subgroup keeps checks that actually hold up:
  `webgl_vendor_mismatch`, `gpu_os_mismatch`, `iframe_proxy`,
  `permission_impossible`, `tz_self_inconsistent`, `canvas_unstable`,
  `mobile_no_touch`.
