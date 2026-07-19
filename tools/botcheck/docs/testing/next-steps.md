# Bot check — automation-test next steps

*(part of [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for findings that produced this list)*

Per-check detail (what fired, what was fixed, what's still evaded, by which
framework) now lives once in [checks/](checks/README.md) — this list only
keeps items that don't belong to a single check.

1. ~~**Land fixes already made**~~ — done 2026-07-19: `webglGPU()` bug fix
   and CDP-trio re-tier/re-weight/re-doc reviewed, committed, merged to
   `master`, confirmed live on `https://botcheck.corpberry.com/` via CI/CD
   same day. Per-check detail: [checks/software_renderer.md](checks/software_renderer.md)
   (+ `webgl_vendor_mismatch`, `gpu_os_mismatch`) and
   [checks/cdp_both.md](checks/cdp_both.md) (+ `cdp_main_only`, `cdp_sw_only`).
2. ~~**Resolve `chrome_runtime_tamper` for real**~~ — **deprioritized
   2026-07-19**, downgraded from "single most valuable open item." Full
   reasoning, data points, and the surfaced-but-unverified stack-leak angle:
   [checks/chrome_runtime_tamper.md](checks/chrome_runtime_tamper.md).
3. ~~**Stealth-specific G04/G17 probes need own follow-up.**~~ —
   **`tostring_proxy` fixed 2026-07-19**
   ([checks/tostring_proxy.md](checks/tostring_proxy.md)): planned
   nested-double-throw prototype turned out unnecessary — a *single*
   illegal call already leaked stealth's unstripped proxy-trap frame, since
   current V8 renders it as `[as apply]` bracket alias matching neither
   stealth's own anchor-stripper nor our detector's old regex. **Still
   open**, no concrete probe idea yet:
   [checks/native_descriptor_tamper.md](checks/native_descriptor_tamper.md),
   [checks/native_callnew_tamper.md](checks/native_callnew_tamper.md),
   [checks/navigator_proto_tamper.md](checks/navigator_proto_tamper.md) —
   none route through a JS Proxy `apply`/`construct` trap the way
   `tostring_proxy` does, so the alias-frame fix doesn't reach them.
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
   ended up needing this whole audit. The concrete data point behind this
   item: [checks/bot_user_agent.md](checks/bot_user_agent.md) — a raw CDP
   client with no automation flags scored `40/100` almost entirely off the
   UA string, everything architectural read clean.
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
7. ~~**`tz_mismatch` + `webrtc_ip_mismatch` false positive**~~ — closed
   2026-07-19, confirmed non-issue. Detail:
   [checks/tz_mismatch.md](checks/tz_mismatch.md) and
   [checks/webrtc_ip_mismatch.md](checks/webrtc_ip_mismatch.md).
