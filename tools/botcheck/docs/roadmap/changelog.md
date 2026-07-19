# Roadmap — build-status changelog

*(part of the [roadmap index](README.md))* — dated entries, oldest first.
`botcheck` **built + live**. Shipped in phases: routing + content negotiation,
server-only scorer reusing `iptools`, vendored JS collector, client-vs-server
cross-checks + the ≥3-soft-signal combo rule, and polish (`Accept-CH` opt-in,
"your request" card, IP2Location attribution). Layer-1 and Layer-2 signal sets
in [internal-backlog.md](internal-backlog.md) implemented; their "remaining
candidates" and all Layer 3 are not.

**Quick-win batch shipped (2026-07-17):** first four quick wins now live —
G01, G02, G05, G53. Added three consistency rules (35 → 38); collector
reports `fullVersionList`, `productSub`, and a feature-detected `engine`.
Implementation per rule: [checks/ua_chrome_version_mismatch.md](../testing/checks/ua_chrome_version_mismatch.md),
[checks/productsub_mismatch.md](../testing/checks/productsub_mismatch.md),
[checks/engine_ua_mismatch.md](../testing/checks/engine_ua_mismatch.md).

**Second quick-win batch shipped (2026-07-17):** every remaining quick win now
live — G04, G03, G07+G08, G06. Rule set grew 38 → 50, and collector payload
now versioned (`v: 2`) so stale cached collector skips damning-when-false G04
rules instead of reading as tampered. Implementation, including the WebIDL
enumerability false positive a real-Chrome E2E pass caught and fixed before
deploy: [checks/tostring_proxy.md](../testing/checks/tostring_proxy.md),
[checks/native_descriptor_tamper.md](../testing/checks/native_descriptor_tamper.md),
[checks/context_ua_mismatch.md](../testing/checks/context_ua_mismatch.md),
[checks/webgl_vendor_mismatch.md](../testing/checks/webgl_vendor_mismatch.md),
[checks/gpu_os_mismatch.md](../testing/checks/gpu_os_mismatch.md),
[checks/accept_encoding_missing.md](../testing/checks/accept_encoding_missing.md).

**Good-bot / AI-agent classification shipped (2026-07-17): G36.** Recognised
crawlers and AI agents now named ([`goodbots.go`](../../goodbots.go)) instead
of lumped in w/ curl/scrapers, and a fourth verdict **`good-bot`** downgrades
them — but ONLY when egress ASN **number** is operator's single-tenant crawler
ASN, which an outsider can't originate traffic from. Full mechanism: see
[roadmap/ip-reputation.md](ip-reputation.md) G36; effect on scoring rules:
[checks/bot_user_agent.md](../testing/checks/bot_user_agent.md) and
[checks/fingerprint_reuse.md](../testing/checks/fingerprint_reuse.md).

**Review follow-up (2026-07-17, same day):** an adversarial review of the
batch above fixed two false positives before they mattered (Opera/Vivaldi/
Yandex/Samsung on `ua_chrome_version_mismatch`, iOS Firefox on
`productsub_mismatch` — detail in those checks' files) and dropped the
`pdfViewerEnabled` soft tell entirely (see
[checks/productsub_mismatch.md](../testing/checks/productsub_mismatch.md)).
Regression tests now cover Opera, desktop Safari, and iOS Safari/Firefox/Chrome.

**Wave 1+2 shipped (2026-07-18): 50 → 66 rules.** Wave 1 added the v3
detection batch (G09, G10, G11, G12, G13, G14, G17, G22, G23, plus
plugins/mimeTypes and zero-outerHeight softs — collector payload `v: 3`) and
a reporting/transparency batch (G54 raw fingerprint dump, G55 per-signal
explanations, G56 detected-environment line, G50 per-tier sub-scores, the
G38/G44 conn-card surface — none of these are scoring rules, see
[reporting-ux.md](reporting-ux.md) / [ip-reputation.md](ip-reputation.md)).
Wave 2 made botcheck the third Mongo consumer: the fingerprint corpus (G41/G42,
see [checks/fingerprint_reuse.md](../testing/checks/fingerprint_reuse.md)),
and G46 shipped localStorage-only returning-visitor history (not a scoring
rule). Collector payload now `v: 4` with an additive `env` section (G15, G21),
adding two soft rules (`matchmedia_missing`, `netinfo_incoherent`) — 66 rules
total. A real-Chrome E2E pass (kimi-webbridge) verified 100/human with zero
false fires across all 66. Per-rule implementation for every G-item in this
wave: [checks/](../testing/checks/README.md).

**False-negative audit (2026-07-19).** A manual review found CDP-detection
checks reading "ok" against a session that is in fact CDP-driven, which
turned into a real (npm/Puppeteer+Playwright+Selenium-based, gitignored, not
part of shipped product) test harness against five actual automation tools,
including `puppeteer-extra-plugin-stealth`. Found and fixed a genuine bug:
`webglGPU()` in collector referenced an undefined variable, silently zeroing
`webglVendor`/`webglRenderer` for every visitor since shipped (neutering
`software_renderer`/`webgl_vendor_mismatch`/`gpu_os_mismatch` — 85 points of
scoring logic that had never fired for anyone). Confirmed the CDP-trap trio
(`cdp_both`/`cdp_main_only`/`cdp_sw_only`) never fires against any of five
genuinely CDP-driven sessions tested — technique appears dead on current
Chromium, not evaded by any one browser — and downgraded it from
hard/consistency tier to soft accordingly (kept running, just stopped
overselling it). Headline result: all six checks built specifically to catch
`puppeteer-extra-plugin-stealth` (`tostring_proxy`, `native_descriptor_tamper`,
`native_callnew_tamper`, `navigator_proto_tamper`, `chrome_runtime_tamper`,
`chrome_late_injection`) were evaded cleanly by current plugin version — but
tool's cross-context consistency checks caught it anyway (score 25/100, not
human), validating core design thesis even where purpose-built checks failed.
Real remaining gap: a disciplined custom automation client w/ a normal UA
currently evades nearly everything tested. Full test architecture, findings
log, and prioritized next steps in [`../testing/`](../testing/README.md) —
read that before touching CDP rules, G04/G22 stealth probes, or re-litigating
this audit.

**Docs reorganized (2026-07-19, same day).** This roadmap and top-level
[`README.md`](../README.md) had grown into two multi-topic monoliths (465 and
386 lines) that forced reading everything to find anything. Split by topic
into this `roadmap/` folder, a `testing/` folder, and standalone reference
files alongside `README.md` — see [`../README.md`](../README.md)'s index for
full map. No content dropped, only relocated; check git history for this
commit if a cross-reference looks stale.

**Audit follow-up (2026-07-19, same day): two new data points, no code
shipped yet.** Continuing false-negative audit's next-steps list: (1) a
genuine consumer Chrome 149 session (via the Claude in Chrome browser
extension, not the npm harness) also lacks `window.chrome.runtime` — a second
data point alongside the "Chrome for Testing" binary, though still confounded
by extension/debugger control rather than a fully organic sample; (2) read
current `puppeteer-extra-plugin-stealth` source (`_utils/index.js`) and found
the generic mechanism — `stripProxyFromErrors`, `patchToString`/
`redirectToString`, `replaceProperty` — behind all four dead G04/G17 probes,
plus one untested idea for a sharper probe (chained nested proxy-trap
throws). Same real session also surfaced an unplanned finding: it scored
50/100 "Suspicious" purely from `timezone_ip_mismatch` + `webrtc_ip_mismatch`
firing together, a pattern architecturally identical to any real VPN/proxy
user, which the original audit's same-network test matrix couldn't have
caught. All three findings logged only (see
[`../testing/findings-log.md`](../testing/findings-log.md) and
[`../testing/next-steps.md`](../testing/next-steps.md)) — no scoring or
collector code changed in this pass.

**Result-page UX fixes (2026-07-19, same day).** Two user-reported issues on
the result page fixed. First, the "raw fingerprint" tab buried its JSON dump
behind a `<details>` toggle even though the tab itself is already one click
away and not shown by default — an unnecessary second click removed; the dump
now renders directly under the "Raw fingerprint" tab. Second, **G50 per-tier
sub-scores reverted**: `Report.TierScore("consistency")` computed one score
for the whole consistency tier, but the result page reused that same call in
all four consistency subgroup cards (IP & network, User-Agent, cross-context,
browser internals) — so a card could read e.g. "browser internals
cross-checks — 50/100" while every check inside it showed "ok", the 50
actually coming from a different subgroup's failure. Rather than build a
subgroup-scoped score, the per-card score line was dropped entirely from all
six breakdown cards (hard, soft, and the four consistency subgroups); the
hero score at the top of the page already carries the overall number.
`Report.TierScore` and its tests removed as dead code — see
[reporting-ux.md](reporting-ux.md) (G50).
