# Roadmap — build-status changelog

*(part of [roadmap index](README.md))* — dated, oldest first.
`botcheck` **built + live**. Phases: routing + content negotiation,
server-only scorer reusing `iptools`, vendored JS collector, client-vs-server
cross-checks + ≥3-soft-signal combo rule, polish (`Accept-CH` opt-in,
"your request" card, IP2Location attribution). Layer-1 & Layer-2 signal sets
in [internal-backlog.md](internal-backlog.md) done; their "remaining
candidates" & all Layer 3 not.

**Quick-win batch shipped (2026-07-17):** first four live —
G01, G02, G05, G53. +3 consistency rules (35 → 38); collector
reports `fullVersionList`, `productSub`, & feature-detected `engine`.
Per-rule impl: [checks/ua_chrome_version_mismatch.md](../testing/checks/ua_chrome_version_mismatch.md),
[checks/productsub_mismatch.md](../testing/checks/productsub_mismatch.md),
[checks/engine_ua_mismatch.md](../testing/checks/engine_ua_mismatch.md).

**Second quick-win batch shipped (2026-07-17):** every remaining quick win
live — G04, G03, G07+G08, G06. Rule set 38 → 50; collector payload
now versioned (`v: 2`) so stale cached collector skips damning-when-false G04
rules instead of reading tampered. Impl, incl. WebIDL
enumerability false positive a real-Chrome E2E pass caught & fixed pre-deploy:
[checks/tostring_proxy.md](../testing/checks/tostring_proxy.md),
[checks/native_descriptor_tamper.md](../testing/checks/native_descriptor_tamper.md),
[checks/context_ua_mismatch.md](../testing/checks/context_ua_mismatch.md),
[checks/webgl_vendor_mismatch.md](../testing/checks/webgl_vendor_mismatch.md),
[checks/gpu_os_mismatch.md](../testing/checks/gpu_os_mismatch.md),
[checks/accept_encoding_missing.md](../testing/checks/accept_encoding_missing.md).

**Good-bot / AI-agent classification shipped (2026-07-17): G36.** Recognised
crawlers & AI agents now named ([`goodbots.go`](../../goodbots.go)) vs
lumped w/ curl/scrapers; 4th verdict **`good-bot`** downgrades
them — but ONLY when egress ASN **number** = operator's single-tenant crawler
ASN, which outsider can't originate traffic from. Mechanism:
[roadmap/ip-reputation.md](ip-reputation.md) G36; scoring-rule effect:
[checks/bot_user_agent.md](../testing/checks/bot_user_agent.md) &
[checks/fingerprint_reuse.md](../testing/checks/fingerprint_reuse.md).

**Review follow-up (2026-07-17, same day):** adversarial review of batch
above fixed two false positives pre-impact (Opera/Vivaldi/
Yandex/Samsung on `ua_chrome_version_mismatch`, iOS Firefox on
`productsub_mismatch` — detail in those checks' files) & dropped
`pdfViewerEnabled` soft tell entirely (see
[checks/productsub_mismatch.md](../testing/checks/productsub_mismatch.md)).
Regression tests now cover Opera, desktop Safari, iOS Safari/Firefox/Chrome.

**Wave 1+2 shipped (2026-07-18): 50 → 66 rules.** Wave 1 = v3
detection batch (G09, G10, G11, G12, G13, G14, G17, G22, G23, + plugins/
mimeTypes & zero-outerHeight softs — collector payload `v: 3`) &
reporting/transparency batch (G54 raw fingerprint dump, G55 per-signal
explanations, G56 detected-environment line, G50 per-tier sub-scores,
G38/G44 conn-card surface — none scoring rules, see
[reporting-ux.md](reporting-ux.md) / [ip-reputation.md](ip-reputation.md)).
Wave 2 made botcheck 3rd Mongo consumer: fingerprint corpus (G41/G42,
see [checks/fingerprint_reuse.md](../testing/checks/fingerprint_reuse.md)),
& G46 localStorage-only returning-visitor history (not a scoring
rule). Collector payload now `v: 4` w/ additive `env` section (G15, G21),
+2 soft rules (`matchmedia_missing`, `netinfo_incoherent`) — 66 total.
Real-Chrome E2E pass (kimi-webbridge) verified 100/human w/ zero
false fires across all 66. Per-rule impl for every G-item this
wave: [checks/](../testing/checks/README.md).

**False-negative audit (2026-07-19).** Manual review found CDP-detection
checks reading "ok" against a session in fact CDP-driven, which
became a real (npm/Puppeteer+Playwright+Selenium-based, gitignored, not
part of shipped product) test harness vs five actual automation tools,
incl. `puppeteer-extra-plugin-stealth`. Found & fixed a genuine bug:
`webglGPU()` in collector referenced an undefined variable, silently zeroing
`webglVendor`/`webglRenderer` for every visitor since ship (neutering
`software_renderer`/`webgl_vendor_mismatch`/`gpu_os_mismatch` — 85 points of
scoring logic that never fired for anyone). Confirmed CDP-trap trio
(`cdp_both`/`cdp_main_only`/`cdp_sw_only`) never fires vs any of five
genuinely CDP-driven sessions tested — technique appears dead on current
Chromium, not evaded by one browser — & downgraded it
hard/consistency tier → soft accordingly (kept running, stopped
overselling). Headline: all six checks built specifically to catch
`puppeteer-extra-plugin-stealth` (`tostring_proxy`, `native_descriptor_tamper`,
`native_callnew_tamper`, `navigator_proto_tamper`, `chrome_runtime_tamper`,
`chrome_late_injection`) evaded cleanly by current plugin version — but
tool's cross-context consistency checks caught it anyway (score 25/100, not
human), validating core design thesis even where purpose-built checks failed.
Real remaining gap: a disciplined custom automation client w/ a normal UA
currently evades nearly everything tested. Full test architecture, findings
log, & prioritized next steps in [`../testing/`](../testing/README.md) —
read that before touching CDP rules, G04/G22 stealth probes, or re-litigating
this audit.

**Docs reorganized (2026-07-19, same day).** This roadmap & top-level
[`README.md`](../README.md) had grown into two multi-topic monoliths (465 &
386 lines) forcing reading everything to find anything. Split by topic
into this `roadmap/` folder, a `testing/` folder, & standalone reference
files alongside `README.md` — see [`../README.md`](../README.md)'s index for
full map. No content dropped, only relocated; check git history for this
commit if a cross-reference looks stale.

**Audit follow-up (2026-07-19, same day): two new data points, no code
shipped yet.** Continuing false-negative audit's next-steps: (1) a
genuine consumer Chrome 149 session (via Claude in Chrome browser
extension, not npm harness) also lacks `window.chrome.runtime` — 2nd
data point alongside "Chrome for Testing" binary, still confounded
by extension/debugger control vs a fully organic sample; (2) read
current `puppeteer-extra-plugin-stealth` source (`_utils/index.js`) & found
generic mechanism — `stripProxyFromErrors`, `patchToString`/
`redirectToString`, `replaceProperty` — behind all four dead G04/G17 probes,
plus one untested idea for a sharper probe (chained nested proxy-trap
throws). Same session also surfaced an unplanned finding: scored
50/100 "Suspicious" purely from `timezone_ip_mismatch` + `webrtc_ip_mismatch`
firing together, a pattern architecturally identical to any real VPN/proxy
user, which original audit's same-network test matrix couldn't have
caught. All three logged only (see
[`../testing/findings-log.md`](../testing/findings-log.md) &
[`../testing/next-steps.md`](../testing/next-steps.md)) — no scoring/
collector code changed this pass.

**Result-page UX fixes (2026-07-19, same day).** Two user-reported result-page
issues fixed. First, "raw fingerprint" tab buried its JSON dump
behind a `<details>` toggle though the tab itself is already one click
away & not shown by default — unnecessary 2nd click removed; dump
now renders directly under "Raw fingerprint" tab. Second, **G50 per-tier
sub-scores reverted**: `Report.TierScore("consistency")` computed one score
for whole consistency tier, but result page reused that same call in
all four consistency subgroup cards (IP & network, User-Agent, cross-context,
browser internals) — so a card could read e.g. "browser internals
cross-checks — 50/100" while every check inside showed "ok", the 50
actually from a different subgroup's failure. Rather than build a
subgroup-scoped score, per-card score line dropped entirely from all
six breakdown cards (hard, soft, & four consistency subgroups); hero
score at top already carries overall number.
`Report.TierScore` & its tests removed as dead code — see
[reporting-ux.md](reporting-ux.md) (G50).

**Honesty pass + corpus temporal signal (2026-07-21): 66 → 67 rules.** Two
changes: "make verdict honest, then extend proven strength."

*Step 1 — honesty.* The five deep-tamper internals probes
(`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`,
`chrome_runtime_tamper`, `chrome_late_injection`) **downgraded consistency
→ soft**, following through on 2026-07-19 audit finding current stealth
evades all five while a privacy extension can trip them — at consistency/25, two
firing dropped a real privacy-tool human to 50/"suspicious", a false positive
the tool was manufacturing, while adding nothing vs the stealth
adversary they targeted (cross-context checks catch that). Soft/cluster-only
now: no single one docks a human, only corroborate in a ≥3 cluster. Same
precedent as 2026-07-19 CDP-trap downgrade. `tostring_proxy` stays hard (fixed,
not evaded). Full rationale:
[the downgrade finding](../testing/findings/2026-07-21-internals-tamper-downgraded-to-soft.md).
Paired w/ a new **fire-path completeness guard**, `TestEveryRuleCanFire`:
every rule `Evaluate` emits must have a fixture that trips it, so a dead
predicate — the bug class that let `webglGPU` silently zero 85 points for the
tool's whole life — now fails a test vs rotting unnoticed (it can't see
into JS collector, where that bug lived, so real-automation testing stays
necessary — see [go-test-suite.md](../go-test-suite.md)).

*Step 2 — extend the corpus.* Shipped **G43** as `ip_fingerprint_churn` (soft,
8), temporal inverse of `fingerprint_reuse` on same
`botcheck_fingerprints` corpus: `Corpus.DistinctHashesByIP(ip, 10-min window)`
counts how many distinct fingerprints one egress IP cycled through, fires at ≥8
— the fingerprint-rotation tell. Soft, because corporate NAT legitimately
shows many browsers. Nil-safe like rest of corpus (disabled Mongo →
count 0, rule silent). Rule count 66 → 67. **Rarity/entropy** half of the
crowd layer (G40/G58) deliberately *not* shipped as scoring rule: 2026-07-21
analysis found rarity doesn't discriminate at a self-test tool's scale (every
visitor new, so "rare" describes a first-time human & a bespoke bot
identically) & a real entropy readout would require storing per-attribute
fingerprint detail per visitor — a privacy cost not worth a
non-discriminating signal. A rarity score would re-introduce exactly
the overselling Step 1 removed, so it stays a documented deferral w/ concrete
reason — see [ip-reputation.md](ip-reputation.md) (G40, G43) & per-rule detail
in [checks/](../testing/checks/README.md).

**IP blocklist / abuse reputation shipped (2026-07-21): 67 → 68 rules (G37).**
Added `ip_blocklisted` rule (consistency/network, weight 25) — egress-IP
abuse-reputation signal that sat "Not built", giving a real threat/abuse
read on top of PX12's proxy/VPN/Tor/datacenter *type* classification. Backed by
new **shared** Mongo collection `ip_blocklist` (repository
[`iptools.BlockList`](../../../iptools/blocklist.go)), deliberately not
botcheck-owned: any service/script/workflow can write flagged IPs (fields
`ip`, `source`, `reason`, `count`, `meta`, `created_at`, `updated_at`; unique
`(ip, source)` so each source keeps own record; 60-day TTL on `updated_at` so
reputation self-prunes — "delete if not updated in two months"). A daily
background sync ([`iptools/ipsum.go`](../../../iptools/ipsum.go),
`RunIPsumSync` started in `main.go`) downloads the
[stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed — Unlicense
(public domain), 30+ blocklists folded into `IP<TAB>count` — & bulk-upserts
every IP under source `ipsum`, preserving occurrence count; a `LastSync`
staleness guard keeps cadence honest across restarts. Fire logic: an
ipsum-only listing fires at count ≥3 (ipsum's own auto-ban recommendation), a
deliberate ban from any other source fires regardless, verified good bots
suppressed. Nil-safe end to end (disabled Mongo → silent rule, pure `Evaluate`
unchanged). Data-source pick from a 12-candidate survey w/ adversarial
license/maintenance verification — see [ip-reputation.md](ip-reputation.md) (G37),
[checks/ip_blocklisted.md](../testing/checks/ip_blocklisted.md), &
[storage.md](../storage.md). Spamhaus DROP/EDROP = intended second writer
(pending a ToU §3.1 confirmation owner emailed about); CINS Army a later
maybe (pending written bundling permission).

**IP tool surfaces the blocklist too (2026-07-21, follow-up to G37).** The
`iptools` IP-lookup tool now reads same `ip_blocklist` corpus & renders it
in a renamed "proxy / blocklist / network" result card (+ a JSON `blocklist`
field), keyed on LOOKED-UP IP so any address can be inspected (botcheck only
checks visitor's own egress). DRY: one handler-enriched `Result` feeds both
HTML & JSON, reusing `BlockList.Check`; nil `Blocklist` = "not checked"
(corpus off → row omitted), non-nil empty = "checked, clean". The three
existing type-classification checks (`iptools` proxy section, botcheck
`datacenter_ip`/`proxy_ip`) unchanged — still IP2Proxy-only; blocklist is
an additive reputation axis, not a merge.

**Spamhaus DROP added as a second blocklist feed (2026-07-22, extends G37).**
Spamhaus gave written permission to use their DROP list, on condition of
crediting them & keeping their copyright notice + date "with the file and
data." Added [`iptools/spamhaus.go`](../../../iptools/spamhaus.go)
(`SyncSpamhausDROP`/`RunSpamhausDROPSync`, wired in `main.go` alongside
`RunIPsumSync`), downloading `drop_v4.json` daily under a shared staleness
guard (`BlockList.ShouldSync`, factored out of ipsum sync's old inline
guard — DRY, since both feeds want identical 24h-minus-slack cadence).
DROP = CIDR **netblocks**, not individual IPs — its ~1,669 human-curated,
high-confidence blocks cover ~15 million addresses, ruling out one document
per address. `ip_blocklist` gained `RangeStart`/`RangeEnd` fields (a new
sparse compound index) computed via a new package-internal `ipv4RangeBounds` helper in
[`cidr.go`](../../../iptools/cidr.go) (reuses `ParseSubnet`'s existing network/broadcast math); `Check`'s
Mongo query now does exact-IP-match OR range-containment via one `$or`, so
every existing caller (botcheck, IP tool) gets DROP coverage free w/
zero call-site changes. Spamhaus's condition met two ways: every ingested
record's `meta` carries their copyright notice + timestamp + terms URL +
its own `sblid`/`rir` (data literally keeps "the date and copy text"
attached), & site footer now credits "© The Spamhaus Project" w/ a
link, gated on same `.Attribution` flag as existing IP2Location
credit. IPv6 (`drop_v6.json`) a deliberate non-goal — a 128-bit range
representation isn't worth the complexity now. Tests: offline parse
(`spamhaus_internal_test.go`), offline range-math (`TestIPv4RangeBounds`),
live nil/skip/containment round-trips (`blocklist_test.go`), & footer-credit
assertions on both IP tool & botcheck pages. Full detail:
[checks/ip_blocklisted.md](../testing/checks/ip_blocklisted.md),
[storage.md](../storage.md), [ip-reputation.md](ip-reputation.md) (G37).

**DRY/KISS/YAGNI/no-paranoia pass over the G37 blocklist code (2026-07-22).**
A 4-lens review swarm (one agent per lens, every finding adversarially
verified — 14 raised, 0 refuted) found real duplication between ipsum &
Spamhaus DROP syncs grown once a second feed existed. Fixed:
`ipsum.go`'s & `spamhaus.go`'s near-identical sync/fetch scaffolding
(`IPsumSyncResult`/`DROPSyncResult`, the skip/fetch/parse/chunked-upsert body,
the ticker/timeout/log runner, the GET-with-status-check fetch) consolidated
into shared `BlockSyncResult`/`syncFeed`/`fetchFeed`/`runDailySync` in
`blocklist.go`; `SyncIPsum`/`SyncSpamhausDROP`/`RunIPsumSync`/
`RunSpamhausDROPSync` now thin wrappers. `parseDROP` decoded every line
twice (a classifier probe, then a second parse); collapsed to one unified
`dropRecord` struct, one decode per line. Dropped `dropMeta.Records` — parsed
off feed's metadata line but never read. Unexported
`IPv4RangeBounds` → `ipv4RangeBounds` (no caller outside package iptools;
its test moved to a new white-box `cidr_internal_test.go`, trimming one
redundant assertion same move). Reviewed & explicitly kept as-is:
`Upsert` as a real public entry point for external writers, `Meta` as
`map[string]any` (ipsum & DROP need different key sets),
`BlockLookup.SourcesLabel()` (used by result template), & explicit
`h.bl != nil` check in IP-tool handler (load-bearing, not redundant w/
`Check`'s own nil-safety). Deliberately NOT done: unifying the `liveXDB` test
helper across `iptools/tests`, `botcheck/tests` — real duplication, but
touches stable pre-existing test infra from before this feature for a
test-only, zero-production-risk win; left a known documented deferral
vs churn for its own sake.
