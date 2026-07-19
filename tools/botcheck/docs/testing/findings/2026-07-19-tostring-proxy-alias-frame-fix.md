# 2026-07-19 — `tostring_proxy` fixed: V8's stack-frame format outran both stealth's stripper AND our detector

*(part of [findings log](../findings-log.md), see
[botcheck docs index](../../README.md))*

Per next-steps.md item 3, plan was to prototype untested idea from
[stealth-source-read finding](2026-07-19-puppeteer-extra-stealth-source-read.md):
chain two nested proxy-trap throws to defeat `stripProxyFromErrors`'
single-anchor stack splice. Built throwaway experiment,
`automation-harness/frameworks/puppeteer-extra-stealth/nested-proxy-experiment.mjs`,
to observe real `err.stack` shapes against live stealth 2.11.2 rather than
guess.

**The nesting idea worked, but wasn't needed — the un-nested case was
already broken.** A single illegal call
(`Function.prototype.toString.call(null)` — exactly what the shipped
`nativeToStringProxied()` Tell B already does) produced this raw, completely
unstripped stack against stealth:

```
TypeError: Cannot read properties of null (reading 'toString')
    at newHandler.<computed> [as apply] (eval at <anonymous> (:4:65), <anonymous>:18:30)
```

The nested variant (a `Symbol.toPrimitive` coercion re-entering same
patched `toString` from inside its own illegal call) left **four**
unstripped `newHandler` frames — confirming the mechanism, but single-throw
case alone was already sufficient proof the strip isn't happening.

**Root cause: V8 stack-frame format drift, not a nesting requirement.**
`stripProxyFromErrors` (in `puppeteer-extra`'s `_utils/index.js`) finds its
own anchor by searching for a literal `at Object.newHandler.<computed> [as `
prefix. Current V8 (Chrome 150) renders SAME frame as `at
newHandler.<computed> [as apply]` — **no `Object.` prefix** — so stealth's
own `findIndex` anchor search comes up empty on this V8 build, and "strip"
is a silent no-op on the very first illegal call. Separately, and
independently, our own `nativeToStringProxied()` Tell B regex
(`/at\s+\S*apply\b|\bapply@/`) also failed to match this exact frame shape,
since `apply` sits inside a V8 `[as apply]` bracket-alias annotation, not as
its own contiguous token right after `at`. Two independent bugs on two
different projects' code, both dated to same V8 format change, both meant
artifact was in plain sight the entire time and nobody was looking at it
correctly.

**Fix:** added `TRAP_ALIAS_RE` in
[`botcheck.js`](../../../../../shared/static/js/botcheck.js)'s
`nativeToStringProxied()` — matches V8's `[as <trapname>]` alias annotation
for any of 13 canonical Proxy trap names, not just `apply`. A structural
tell (a genuine native illegal-invocation TypeError never routes through a
differently-named object-literal trap handler), not a signature/name match
on `puppeteer-extra`'s specific `newHandler` variable — should survive a
future stealth rename.

**Verified against local dev instance (`http://botcheck.localhost:8080/`)
via `automation-harness`, restarted after fix:**

| Framework | `tostring_proxy` before | `tostring_proxy` after | Score before → after |
|---|---|---|---|
| `puppeteer-extra` + stealth 2.11.2 | ok (evaded) | **−45, fires** | 25/100 → **0/100** |
| Playwright headless (no stealth) | ok | ok (unchanged) | 0/100 → 0/100 |
| Selenium + real "Chrome for Testing" binary | ok | ok (unchanged) | 0/100 → 0/100 |
| Raw CDP, no automation flags | ok | ok (unchanged) | 40/100 → 40/100 |

Also spot-checked genuine unpatched Chromium (the Electron-based in-app
browser tool) hitting same call: clean, alias-free native stack, rule
correctly stays quiet. No false positive across three independent unpatched
engines; one confirmed true positive against the actual adversarial tool
this check was built for.

**Closes one of six evaded checks from
[multi-framework matrix results](2026-07-19-multi-framework-matrix-results.md).**
Other three stack-trace-adjacent evasions there
(`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`)
don't route through a JS Proxy `apply`/`construct` trap at all — rely on
`replaceProperty`'s faithful descriptor copying and (for
`navigator.webdriver`) a pre-page-load launch-arg, not a JS patch — so this
specific alias-frame fix doesn't reach them; a separate, harder problem (see
next-steps.md item 3 carry-forward below).

**Follow-up idea surfaced but NOT implemented (needs HTTPS target to
verify):** `chromeRuntimeOK()`'s call/construct traps have same shape as
`nativeToStringProxied()`'s Tell B — only check `e instanceof TypeError`,
never `e.stack` — so if stealth's `chrome.runtime.sendMessage`/`connect`
fakes are themselves Proxy-wrapped with same `stripProxyFromErrors` helper,
identical alias-frame leak likely applies there too. Couldn't verify:
stealth's `chrome.runtime` evasion only activates on secure origin, and
this harness's target is `http://botcheck.localhost:8080/` — Chrome treats
`localhost` as secure *context* for API access, but stealth's own check
reads `location.protocol` directly, so never activates against local dev.
Confirmed `window.chrome.runtime` reads as genuinely absent (`'runtime' in
window.chrome` is `false`) in this harness on both `about:blank` and local
dev. Testing against real `https://botcheck.corpberry.com/` would settle
it but was deliberately not done here — per [README.md](../README.md),
production is reserved for validating already-decided behavior, not for
firing untested probes that would inject synthetic traffic into the real
Mongo corpus. Left as a next-steps item, not shipped speculatively.
