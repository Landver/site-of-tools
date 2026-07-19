# Bot check — automation-test next steps

*(part of [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for findings that produced this list)*

1. ~~**Land fixes already made**~~ — done 2026-07-19: `webglGPU()` bug fix
   and CDP-trio re-tier/re-weight/re-doc reviewed, committed, merged to
   `master`, confirmed live on `https://botcheck.corpberry.com/` via CI/CD
   same day.
2. ~~**Resolve `chrome_runtime_tamper` for real**~~ — **deprioritized
   2026-07-19**, downgraded from "single most valuable open item" (see
   [deprioritization finding](findings/2026-07-19-chrome-runtime-tamper-deprioritized.md)).
   Neither browser tool available to agent in this repo can supply fully
   organic consumer-Chrome sample this item waited on — Claude in Chrome is
   extension/debugger-controlled (already known), and in-app Browser pane
   turned out Electron embed, not Chrome at all, so trying it added fourth
   confounded (differently-wrong) sample, resolved nothing. More
   importantly, reasoning already on record in item 3's stealth-source-read
   finding means answer wouldn't change recommendation anyway: stealth's
   `chrome.runtime` evasion only activates when property already missing,
   faking it back convincingly right when it'd otherwise be absent — so
   presence/absence never a sound signal against stealth-equipped
   adversary, clean organic baseline or not. Tightened, reverted version
   would only ever have caught non-stealth bots, which this tool already
   catches several other ways. Left as shipped (lenient, absence-tolerant).
   More promising angle turned out adjacent: see item 3's carry-forward
   note about `chromeRuntimeOK()` possibly sharing `tostring_proxy`'s old
   stack-leak weakness — tracked there, not here, still needs HTTPS target
   to verify.
3. ~~**Stealth-specific G04/G17 probes need own follow-up.**~~ —
   **`tostring_proxy` fixed 2026-07-19** (see
   [alias-frame fix finding](findings/2026-07-19-tostring-proxy-alias-frame-fix.md)):
   planned nested-double-throw prototype turned out unnecessary — *single*
   illegal call already leaked stealth's unstripped proxy-trap frame, since
   current V8 renders it as `[as apply]` bracket alias matching neither
   stealth's own anchor-stripper nor our detector's regex. Broadened regex;
   verified live against harness (stealth score 25→0, other three
   frameworks unchanged). Landed in
   [botcheck.js](../../../../shared/static/js/botcheck.js)'s
   `nativeToStringProxied()`, not yet committed — same status as rest of
   this list's landed-but-uncommitted fixes.
   **Still open:** `native_descriptor_tamper`, `native_callnew_tamper` (G04),
   and `navigator_proto_tamper` (G17) don't route through JS Proxy
   `apply`/`construct` trap like `tostring_proxy` does — defeated by
   `replaceProperty`'s faithful descriptor copying and, for
   `navigator.webdriver`, pre-page-load launch arg rather than JS patch — so
   alias-frame fix doesn't reach them. Genuinely separate, harder problem;
   no concrete probe idea yet. **Also surfaced, not yet implemented:**
   `chromeRuntimeOK()`'s call/construct traps (item 2 below) have exact
   same shape as `tostring_proxy`'s old Tell B — check `e instanceof
   TypeError` but never `e.stack` — so same alias-frame leak plausibly
   applies to `chrome_runtime_tamper` too, *if* stealth's fake
   `sendMessage`/`connect` are themselves proxy-wrapped with same
   `stripProxyFromErrors` helper. Couldn't verify: stealth's
   `chrome.runtime` evasion only activates on secure origin (checked via
   `location.protocol`, not `isSecureContext`), never activates against
   `http://botcheck.localhost:8080/` — confirmed `'runtime' in
   window.chrome` reads `false` there, nothing to probe. Needs HTTPS target
   to test live; deliberately not tested against production for this (see
   item 2's own caveat about not firing untested probes at real corpus).
4. **Raw-CDP / custom-harness gap is the real remaining hole** and has no
   client-side JS fix: disciplined custom automation client that (a) skips
   "Headless" in UA, (b) doesn't trip `navigator.webdriver` or does so
   consistently across every context (unlike stealth's inconsistent
   patching), and (c) injects no framework markers currently evades nearly
   everything in this tool. Honest options are architectural, not
   check-level: lean harder on IP/network reputation and fingerprint-reuse
   corpus (orthogonal signals, already built — see
   [`../storage.md`](../storage.md)), consider behavioral layer
   (mouse/keyboard trajectory, already noted as non-goal in
   [`../roadmap/scoring-fusion.md`](../roadmap/scoring-fusion.md)'s G52 for
   good reason), or accept as known, documented limit of
   client-fingerprint-only, no-ML detector. Don't let future contributor
   "fix" this with another single clever trap without reading
   [findings-log.md](findings-log.md) first — that's exactly how CDP trap
   ended up needing this whole audit.
5. ~~**Revisit [`../roadmap/client-signals.md`](../roadmap/client-signals.md)'s
   G16**~~ — **re-evaluated, re-closed 2026-07-19.** Previously shelved as
   "skip, redundant with CDP trap," which stopped being valid reasoning once
   CDP trap confirmed dead. Re-evaluated properly instead of just
   re-opening it: G16 detects *human* with DevTools open, not automation —
   confirmed none of 5 frameworks in this audit's matrix would've tripped
   it, since Puppeteer/Playwright/Selenium don't open visible DevTools
   panel by default. Building it would score curious/technical real
   visitors as more suspicious for zero automation coverage gained — wrong
   tradeoff for bot detector. Stays **not built**, this time for verified
   reason instead of inherited assumption.
6. **Non-npm evasion tools stay untested by this harness** — Python's
   `undetected-chromedriver`/`nodriver`, browser extensions, and anything
   not on npm: known blind spot of this test setup, not confirmed safe.
   Worth separate pass if this matters enough (needs Python environment,
   out of scope for npm-based harness described in [README.md](README.md)).
7. ~~**`timezone_ip_mismatch` + `webrtc_ip_mismatch` false positive**~~ —
   closed 2026-07-19: 50/100 "Suspicious" reading traced to Claude in
   Chrome sandbox's own network path (egress ≠ browser timezone/WebRTC
   address), not real risk. Owner's ordinary Chrome session (no
   sandbox/proxy) scored clean 100/human on same two checks. See
   [the finding](findings/2026-07-19-timezone-webrtc-ip-mismatch-closed.md). No scoring change needed.
