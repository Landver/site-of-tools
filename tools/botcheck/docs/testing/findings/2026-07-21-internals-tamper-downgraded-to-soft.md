# 2026-07-21 — five deep-tamper internals probes downgraded consistency → soft

*(part of [findings log](../findings-log.md), see [botcheck docs index](../../README.md))*

## What changed

Five checks moved from the **consistency** tier (individual deductions,
`internals` subgroup) to the **soft** tier (weight 8, cluster-only):

| Check | Was | Now |
|---|---|---|
| `native_descriptor_tamper` | consistency / 25 | soft / 8 |
| `native_callnew_tamper` | consistency / 25 | soft / 8 |
| `navigator_proto_tamper` | consistency / 25 | soft / 8 |
| `chrome_runtime_tamper` | consistency / 20 | soft / 8 |
| `chrome_late_injection` | consistency / 15 | soft / 8 |

No `eval` logic changed — each still fires on exactly the same input, keeps its
version gate, and still shows in the breakdown. Only the tier, weight, and
subgroup changed, so a single firing no longer docks the score; three or more
soft signals together still cost one 25-point cluster penalty.

## Why

This is a follow-through on the [2026-07-19 false-negative
audit](2026-07-19-multi-framework-matrix-results.md). That audit established two
facts about this whole class of check:

1. **They add nothing against the adversary they targeted.** All five were built
   to catch `puppeteer-extra-plugin-stealth`, and the audit confirmed current
   stealth (2.11.2) evades every one of them cleanly — its shared `_utils`
   helpers spread the original descriptor, fake `chrome.runtime` in place, and
   hide `webdriver` with a launch flag rather than a JS patch (see the
   [source read](2026-07-19-puppeteer-extra-stealth-source-read.md)). What
   actually caught stealth in the audit was the **cross-context** checks
   (`context_ua/cores/webgl_mismatch`), which scored it 25/100 — the core
   design thesis, validated.

2. **The only things that trip them are a naive hand-patch or a legitimate
   privacy extension** — and the latter is a real human. A canvas/WebGL noise
   injector (CanvasBlocker, Chameleon, …) can leave an impossible descriptor or
   a missing call/new trap; a `chrome.runtime` fake is absent on the official
   Chrome-for-Testing binary too. At consistency/25, **two of these firing on a
   privacy-tool user dropped a genuine human to 50/"suspicious"** — a
   false positive the tool was manufacturing.

So at their old tier these five carried real false-positive risk against real
humans, redundant coverage against naive bots (already tanked to 0 by the hard
`webdriver`/`bot_user_agent`/`software_renderer` tells), and **zero** value
against the stealth adversary they were built for. That is exactly the profile
of a signal that should be cluster-only, not a standalone deduction.

## Precedent

Identical handling to the [CDP-trap trio](../checks/cdp_both.md)
(`cdp_both`/`cdp_main_only`/`cdp_sw_only`), downgraded to soft on 2026-07-19 for
the same "kept for corroboration, no longer oversold" reason. Downgraded, not
deleted: they still fire, still appear in the breakdown for transparency, and
still contribute to a soft cluster when several environment tells co-occur — a
naive bot that trips three of them plus other soft signals still gets caught.

## Effect on scoring, proven by tests

- `TestInternalsTamperDowngradedToSoft` — each of the five, firing alone on an
  otherwise-clean browser, now leaves the score at 100/human (a soft signal
  never docks on its own); three together cross the cluster threshold for one
  25-point deduction (75/suspicious), not 3×25.
- `TestStealthCaughtByCrossContextChecks` — replaces the old
  `TestStealthPatchedBrowserScoresBot`, whose premise (deep probes firing ⇒ bot)
  the downgrade removes. It now encodes the audit's real finding: the internals
  probes read clean against stealth, and the cross-context checks carry the
  bot verdict.
- `TestEveryRuleCanFire` — the new fire-path completeness guard still confirms
  all five reach their fire branch.

## Not changed / still open

- The **sharpening** ideas stay open, unaffected by the tier move: the nested
  proxy-trap probe for the `native_*` family, and the alias-frame stack-leak fix
  for `chrome_runtime_tamper`'s traps (needs an HTTPS target to verify against a
  live stealth session — see that check's file). If any lands and proves out
  against real stealth, the corresponding check can be re-promoted.
- The `internals` consistency subgroup keeps the checks that actually hold up:
  `webgl_vendor_mismatch`, `gpu_os_mismatch`, `iframe_proxy`,
  `permission_impossible`, `tz_self_inconsistent`, `canvas_unstable`,
  `mobile_no_touch`.
