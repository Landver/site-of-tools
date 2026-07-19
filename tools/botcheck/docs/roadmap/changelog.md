# Roadmap — build-status changelog

*(part of the [roadmap index](README.md))* — dated entries, oldest first.
`botcheck` is **built and live**. It shipped in phases: routing + content
negotiation, the server-only scorer reusing `iptools`, the vendored JS
collector, the client-vs-server cross-checks + the ≥3-soft-signal combo rule,
and polish (`Accept-CH` opt-in, the "your request" card, IP2Location
attribution). The Layer-1 and Layer-2 signal sets in
[internal-backlog.md](internal-backlog.md) are implemented; their "remaining
candidates" and all of Layer 3 are not.

**Quick-win batch shipped (2026-07-17):** the first four quick wins are now
live — **G01** (a UA-`Chrome/NNN`-major vs `userAgentData` `Chromium`-entry
cross-check), **G02** (`navigator.productSub` engine constant), **G05**
(feature-detect the real Blink/Gecko/WebKit engine vs the engine the UA claims),
and **G53** (on-page scope disclosure). They added three consistency rules (35 →
38) and the collector reports `fullVersionList`, `productSub`, and a
feature-detected `engine`.

**Second quick-win batch shipped (2026-07-17):** every remaining quick win is now
live — **G04** (deep native-tamper detection: descriptor/own-property sanity with
per-spec enumerability, call/new `TypeError` traps, and a
`Function.prototype.toString` Proxy probe), **G03** (cross-context diff beyond UA
— languages, `hardwareConcurrency`, `userAgentData.platform`, worker WebGL — plus
a Service-Worker context served from `/botcheck-sw.js`), **G07+G08** (WebGL
vendor/renderer coherence + GPU-family-vs-claimed-OS coherence), and **G06**
(HTTP header presence/value consistency, soft-tier). The rule set grew 38 → 50,
and the collector payload is now versioned (`v: 2`) so a stale cached collector
skips the damning-when-false G04 rules instead of reading as tampered. A
real-Chrome E2E pass caught and fixed one false positive before deploy: WebIDL
operations are `enumerable: true` by spec, so the descriptor probe now asserts
enumerability per target family (ECMA-262 vs WebIDL) instead of blanket-false.

**Good-bot / AI-agent classification shipped (2026-07-17): G36.** Recognised
crawlers and AI agents are now named ([`goodbots.go`](../../goodbots.go)) instead
of lumped in with curl/scrapers, and a fourth verdict **`good-bot`** downgrades
them — but ONLY when the egress ASN **number** is the operator's single-tenant
crawler ASN, which an outsider can't originate traffic from (Apple/Yandex/Baidu/
Naver/Seznam/Anthropic/Meta/ByteDance). It matches the ASN *number*, not the
owner *name*: a name substring ("yandex") also matches the operator's rentable
public cloud (Yandex Cloud is a separate AS200350), which would let a scraper on
a rented VM verify itself. Multi-tenant crawlers (Googlebot/Bingbot on shared
Google/Microsoft ASNs) and cloud-hosted agents (GPTBot on Azure) are recognised
but stay unverified and fully penalised, so a copied User-Agent never escapes
the bot score (the no-evasion invariant). `bot_user_agent` was widened to every
allowlist token (several — `Meta-ExternalAgent`, `Claude-User` — carry no
generic `bot` substring). Follow-up for full coverage: a published-IP-range
check to verify the multi-tenant and cloud-hosted operators that share their
ASN with paying tenants.

**Review follow-up (2026-07-17, same day):** an adversarial review of the batch
above fixed two false positives before they mattered — the version check now
compares the UA against the `Chromium` `fullVersionList` entry (not the fork's
branded `uaFullVersion`, which made real **Opera/Vivaldi/Yandex/Samsung** score
"suspicious"), and `productSub` derives its expected engine from `engineFromUA`
(so **iOS Firefox**, WebKit under an FxiOS token, is no longer flagged). The
`pdfViewerEnabled` soft tell was **dropped**: it fires on ordinary desktop Chrome
with the "Download PDFs" setting or the `AlwaysOpenPdfExternally` enterprise policy
(a user preference, not a headless tell) and correlates with `empty_plugins`,
eroding the soft-cluster margin — low value for its false-fire cost. Unused
high-entropy fields (`platformVersion`/`architecture`/`bitness`/`model`/
`uaFullVersion`) were trimmed from the collector and struct. Regression tests now
cover Opera, desktop Safari, and iOS Safari/Firefox/Chrome.

**Wave 1+2 shipped (2026-07-18): 50 → 66 rules.** Wave 1 added the v3 detection
batch (G09 WebRTC leak, G10 broken-image, G11 iframe webdriver+proxy, G12
mobile-no-touch, G13 wider automation markers, G14 SW webdriver+CDP, G17
navigator-proto walk, G22 chrome.runtime integrity + late injection, G23
error-stack JS-engine cross-check, plus the plugins/mimeTypes and zero-outerHeight
softs — collector payload `v: 3`) and the reporting/transparency batch (G54 raw
fingerprint dump, G55 per-signal explanations, G56 detected-environment line, G50
per-tier sub-scores, the G38/G44 conn-card surface). Wave 2 made botcheck the
third Mongo consumer: a rolling 30-day **fingerprint corpus** (G41/G42) backs the
`fingerprint_reuse` consistency rule (an exact fingerprint seen from ≥5 distinct
IPs — the scraping-farm catch; suppressed for verified good bots), and the
G38/G44 wiring now feeds ASN/proxy-provider rows into the conn card of both
botcheck and iptools. G46 shipped localStorage-only returning-visitor history (no
server state). The collector payload is now `v: 4` with the additive `env`
section (G15 media/display probes + G21 connection/storage/GPC/permissions/EME
entropy), adding two soft rules (`matchmedia_missing`, `netinfo_incoherent`) —
66 rules total. A real-Chrome E2E pass (kimi-webbridge) verified 100/human with
zero false fires across all 66.

**False-negative audit (2026-07-19).** A manual review found the CDP-detection
checks reading "ok" against a session that is in fact CDP-driven, which turned
into a real (npm/Puppeteer+Playwright+Selenium-based, gitignored, not part of
the shipped product) test harness against five actual automation tools,
including `puppeteer-extra-plugin-stealth`. Found and fixed a genuine bug:
`webglGPU()` in the collector referenced an undefined variable, silently
zeroing `webglVendor`/`webglRenderer` for every visitor since it shipped
(neutering `software_renderer`/`webgl_vendor_mismatch`/`gpu_os_mismatch` — 85
points of scoring logic that had never fired for anyone). Confirmed the
CDP-trap trio (`cdp_both`/`cdp_main_only`/`cdp_sw_only`) never fires against
any of five genuinely CDP-driven sessions tested — the technique appears dead
on current Chromium, not evaded by any one browser — and downgraded it from
hard/consistency tier to soft accordingly (kept running, just stopped
overselling it). The headline result: all six checks built specifically to
catch `puppeteer-extra-plugin-stealth` (`tostring_proxy`,
`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`,
`chrome_runtime_tamper`, `chrome_late_injection`) were evaded cleanly by the
current plugin version — but the tool's cross-context consistency checks
caught it anyway (score 25/100, not human), validating the core design thesis
even where the purpose-built checks failed. The real remaining gap: a
disciplined custom automation client with a normal UA currently evades nearly
everything tested. Full test architecture, findings log, and prioritized
next steps in [`../testing/`](../testing/README.md) — read that before touching
the CDP rules, the G04/G22 stealth probes, or re-litigating this audit.

**Docs reorganized (2026-07-19, same day).** This roadmap and the top-level
[`README.md`](../README.md) had grown into two multi-topic monoliths (465 and
386 lines) that forced reading everything to find anything. Split by topic into
this `roadmap/` folder, a `testing/` folder, and standalone reference files
alongside `README.md` — see [`../README.md`](../README.md)'s index for the full
map. No content was dropped, only relocated; check git history for this
commit if a cross-reference looks stale.

**Audit follow-up (2026-07-19, same day): two new data points, no code shipped
yet.** Continuing the false-negative audit's next-steps list: (1) a genuine
consumer Chrome 149 session (via the Claude in Chrome browser extension, not
the npm harness) also lacks `window.chrome.runtime` — a second data point
alongside the "Chrome for Testing" binary, though still confounded by
extension/debugger control rather than a fully organic sample; (2) read the
current `puppeteer-extra-plugin-stealth` source (`_utils/index.js`) and found
the generic mechanism — `stripProxyFromErrors`, `patchToString`/
`redirectToString`, `replaceProperty` — behind all four dead G04/G17 probes,
plus one untested idea for a sharper probe (chained nested proxy-trap
throws). The same real session also surfaced an unplanned finding: it scored
50/100 "Suspicious" purely from `timezone_ip_mismatch` + `webrtc_ip_mismatch`
firing together, a pattern architecturally identical to any real VPN/proxy
user, which the original audit's same-network test matrix couldn't have
caught. All three findings are logged only (see
[`../testing/findings-log.md`](../testing/findings-log.md) and
[`../testing/next-steps.md`](../testing/next-steps.md)) — no scoring or
collector code changed in this pass.
