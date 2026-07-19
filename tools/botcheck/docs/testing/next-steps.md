# Bot check — automation-test next steps

*(part of the [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for the findings that produced this list)*

1. ~~**Land the fixes already made**~~ — done 2026-07-19: the `webglGPU()` bug
   fix and the CDP-trio re-tier/re-weight/re-documentation were reviewed,
   committed, merged to `master`, and confirmed live on
   `https://botcheck.corpberry.com/` via CI/CD the same day.
2. ~~**Resolve `chrome_runtime_tamper` for real**~~ — **deprioritized
   2026-07-19**, downgraded from "the single most valuable open item" (see
   [the deprioritization finding](findings/2026-07-19-chrome-runtime-tamper-deprioritized.md)).
   Neither browser tool available to an agent in this repo can supply the
   fully organic consumer-Chrome sample this item was waiting on — Claude in
   Chrome is extension/debugger-controlled (already known), and the in-app
   Browser pane turned out to be an Electron embed, not Chrome at all, so
   trying it added a fourth confounded (and differently-wrong) sample rather
   than resolving anything. More importantly, the reasoning already on record
   in item 3's stealth-source-read finding means the answer wouldn't change
   the recommendation anyway: stealth's `chrome.runtime` evasion only
   activates when the property is already missing, faking it back in
   convincingly right when it would otherwise be absent — so presence/absence
   was never a sound signal against a stealth-equipped adversary, clean
   organic baseline or not. The tightened, reverted version would only ever
   have caught non-stealth bots, which this tool already catches several
   other ways. Left as shipped (lenient, absence-tolerant). The more
   promising angle turned out to be adjacent: see item 3's carry-forward note
   about `chromeRuntimeOK()` possibly sharing `tostring_proxy`'s old
   stack-leak weakness — tracked there, not here, and still needs an HTTPS
   target to verify.
3. ~~**The stealth-specific G04/G17 probes need their own follow-up.**~~ —
   **`tostring_proxy` fixed 2026-07-19** (see
   [the alias-frame fix finding](findings/2026-07-19-tostring-proxy-alias-frame-fix.md)):
   the planned nested-double-throw prototype turned out to be unnecessary — a
   *single* illegal call already leaked stealth's unstripped proxy-trap frame,
   because current V8 renders it as a `[as apply]` bracket alias that neither
   stealth's own anchor-stripper nor our detector's regex matched. Broadened
   the regex; verified live against the harness (stealth score 25→0, the other
   three frameworks unchanged). Landed in
   [botcheck.js](../../../../shared/static/js/botcheck.js)'s
   `nativeToStringProxied()`, not yet committed — same status as the rest of
   this list's landed-but-uncommitted fixes.
   **Still open:** `native_descriptor_tamper`, `native_callnew_tamper` (G04),
   and `navigator_proto_tamper` (G17) don't route through a JS Proxy
   `apply`/`construct` trap the way `tostring_proxy` does — they're defeated by
   `replaceProperty`'s faithful descriptor copying and, for
   `navigator.webdriver`, a pre-page-load launch arg rather than a JS patch —
   so the alias-frame fix doesn't reach them. Genuinely a separate, harder
   problem; no concrete probe idea yet. **Also surfaced, not yet
   implemented:** `chromeRuntimeOK()`'s call/construct traps (item 2 below)
   have the exact same shape as `tostring_proxy`'s old Tell B — they check
   `e instanceof TypeError` but never `e.stack` — so the same alias-frame leak
   plausibly applies to `chrome_runtime_tamper` too, *if* stealth's fake
   `sendMessage`/`connect` are themselves proxy-wrapped with the same
   `stripProxyFromErrors` helper. Couldn't verify: stealth's `chrome.runtime`
   evasion only activates on a secure origin (checked via `location.protocol`,
   not `isSecureContext`), so it never activates against
   `http://botcheck.localhost:8080/` — confirmed `'runtime' in window.chrome`
   reads `false` there, nothing to probe. Needs an HTTPS target to test live;
   deliberately not tested against production for this (see item 2's own
   caveat about not firing untested probes at the real corpus).
4. **The raw-CDP / custom-harness gap is the real remaining hole** and doesn't
   have a client-side JS fix: a disciplined custom automation client that (a)
   doesn't include "Headless" in its UA, (b) doesn't trip `navigator.webdriver`
   or does so consistently across every context (unlike stealth's inconsistent
   patching), and (c) injects no framework markers currently evades nearly
   everything in this tool. The honest options are architectural, not
   check-level: lean harder on IP/network reputation and the fingerprint-reuse
   corpus (orthogonal signals, already built — see
   [`../storage.md`](../storage.md)), consider a behavioral layer
   (mouse/keyboard trajectory, already noted as a non-goal in
   [`../roadmap/scoring-fusion.md`](../roadmap/scoring-fusion.md)'s G52 for good
   reason), or accept this as a known, documented limit of a
   client-fingerprint-only, no-ML detector. Don't let a future contributor
   "fix" this with another single clever trap without reading
   [findings-log.md](findings-log.md) first — that's exactly how the CDP trap
   ended up needing this whole audit.
5. ~~**Revisit [`../roadmap/client-signals.md`](../roadmap/client-signals.md)'s
   G16**~~ — **re-evaluated and re-closed 2026-07-19.** Previously shelved as
   "skip, redundant with the CDP trap," which stopped being valid reasoning
   once the CDP trap was confirmed dead. Re-evaluated properly instead of just
   re-opening it: G16 detects a *human* with DevTools open, not automation —
   confirmed none of the 5 frameworks in this audit's matrix would have
   tripped it, since Puppeteer/Playwright/Selenium don't open a visible
   DevTools panel by default. Building it would score curious/technical real
   visitors as more suspicious for zero automation coverage gained — the
   wrong tradeoff for a bot detector. Stays **not built**, this time for a
   verified reason instead of an inherited assumption.
6. **Non-npm evasion tools stay untested by this harness** — Python's
   `undetected-chromedriver`/`nodriver`, browser extensions, and anything not
   on npm are a known blind spot of this specific test setup, not confirmed
   safe. Worth a separate pass if this matters enough (would need a Python
   environment, out of scope for the npm-based harness described in
   [README.md](README.md)).
7. ~~**`timezone_ip_mismatch` + `webrtc_ip_mismatch` false positive**~~ —
   closed 2026-07-19: the 50/100 "Suspicious" reading traced to the Claude in
   Chrome sandbox's own network path (egress ≠ browser timezone/WebRTC
   address), not a real risk. Owner's ordinary Chrome session (no
   sandbox/proxy) scored a clean 100/human on the same two checks. See
   [the finding](findings/2026-07-19-timezone-webrtc-ip-mismatch-closed.md). No scoring change needed.
