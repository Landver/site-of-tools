# Bot check — automation-test next steps

*(part of the [botcheck docs index](../README.md), see
[findings-log.md](findings-log.md) for the findings that produced this list)*

1. ~~**Land the fixes already made**~~ — done 2026-07-19: the `webglGPU()` bug
   fix and the CDP-trio re-tier/re-weight/re-documentation were reviewed,
   committed, merged to `master`, and confirmed live on
   `https://botcheck.corpberry.com/` via CI/CD the same day.
2. **Resolve `chrome_runtime_tamper` for real** — get one real, unmodified
   consumer Google Chrome (not "Chrome for Testing") to check whether
   `chrome.runtime` is reliably present there. If yes, ship the tightened
   version from the 2026-07-19 audit (already written and verified against the
   stealth case, just reverted for lack of this one data point) — it would
   close a confirmed stealth-evasion gap. If no, this check may need retiring
   instead. See [findings-log.md](findings-log.md)'s `chrome_runtime_tamper`
   entry for the full reasoning and where the reverted diff lives (git
   history).
3. **The stealth-specific G04/G22 probes need their own follow-up.**
   `tostring_proxy`, `native_descriptor_tamper`, `native_callnew_tamper`,
   `navigator_proto_tamper` were all built explicitly to catch
   `puppeteer-extra-plugin-stealth` and none of them do anymore against the
   current version (2.11.2) — the plugin evidently evolved past them. Worth a
   focused pass reading the current stealth-plugin source (it's open source)
   to see exactly what changed and whether a sharper probe is feasible, rather
   than assuming the cross-context checks alone are enough going forward (they
   worked this time; that's not a guarantee).
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
5. **Revisit [`../roadmap/client-signals.md`](../roadmap/client-signals.md)'s
   G16** (DevTools-open / debugger-timing detection), previously shelved as
   "skip, redundant with the CDP trap." That reasoning assumed the CDP trap
   works; it doesn't. Note, though: G16 detects a human with DevTools open,
   not automation — Puppeteer/Playwright/Selenium don't open a visible
   DevTools panel by default, so G16 wouldn't actually have caught anything in
   this audit's matrix either. Re-evaluate what it's actually good for before
   building it.
6. **Non-npm evasion tools stay untested by this harness** — Python's
   `undetected-chromedriver`/`nodriver`, browser extensions, and anything not
   on npm are a known blind spot of this specific test setup, not confirmed
   safe. Worth a separate pass if this matters enough (would need a Python
   environment, out of scope for the npm-based harness described in
   [README.md](README.md)).
