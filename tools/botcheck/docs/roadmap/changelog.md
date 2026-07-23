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

**Honesty pass + corpus temporal signal (2026-07-21): 66 → 67 rules.** Two
changes, framed as "make the verdict honest, then extend the proven strength."

*Step 1 — honesty.* The five deep-tamper internals probes
(`native_descriptor_tamper`, `native_callnew_tamper`, `navigator_proto_tamper`,
`chrome_runtime_tamper`, `chrome_late_injection`) were **downgraded consistency
→ soft**, following through on the 2026-07-19 audit that found current stealth
evades all five while a privacy extension can trip them — at consistency/25, two
firing dropped a real privacy-tool human to 50/"suspicious", a false positive
the tool was manufacturing, all while adding nothing against the stealth
adversary they targeted (the cross-context checks catch that). Soft/cluster-only
now: no single one docks a human, they only corroborate in a ≥3 cluster. Same
precedent as the 2026-07-19 CDP-trap downgrade. `tostring_proxy` stays hard (it
was fixed, not evaded). Full rationale:
[the downgrade finding](../testing/findings/2026-07-21-internals-tamper-downgraded-to-soft.md).
Paired with a new **fire-path completeness guard**, `TestEveryRuleCanFire`:
every rule `Evaluate` emits must have a fixture that trips it, so a dead
predicate — the class of bug that let `webglGPU` silently zero 85 points for the
tool's whole life — now fails a test instead of rotting unnoticed (it can't see
into the JS collector, where that bug lived, so real-automation testing stays
necessary — see [go-test-suite.md](../go-test-suite.md)).

*Step 2 — extend the corpus.* Shipped **G43** as `ip_fingerprint_churn` (soft,
8), the temporal inverse of `fingerprint_reuse` on the same
`botcheck_fingerprints` corpus: `Corpus.DistinctHashesByIP(ip, 10-min window)`
counts how many distinct fingerprints one egress IP cycled through, firing at ≥8
— the fingerprint-rotation tell. Soft, because a corporate NAT legitimately
shows many browsers. Nil-safe like the rest of the corpus (disabled Mongo →
count 0, rule silent). Rule count 66 → 67. The **rarity/entropy** half of the
crowd layer (G40/G58) was deliberately *not* shipped as a scoring rule: 2026-07-21
analysis found rarity doesn't discriminate at a self-test tool's scale (every
visitor is new, so "rare" describes a first-time human and a bespoke bot
identically) and a real entropy readout would require storing per-attribute
fingerprint detail per visitor — a privacy cost not worth paying for a
non-discriminating signal. Shipping a rarity score would re-introduce exactly
the overselling Step 1 removed, so it stays a documented deferral with a concrete
reason — see [ip-reputation.md](ip-reputation.md) (G40, G43) and per-rule detail
in [checks/](../testing/checks/README.md).

**IP blocklist / abuse reputation shipped (2026-07-21): 67 → 68 rules (G37).**
Added the `ip_blocklisted` rule (consistency/network, weight 25) — the egress-IP
abuse-reputation signal that had sat as "Not built", giving a real threat/abuse
read on top of PX12's proxy/VPN/Tor/datacenter *type* classification. Backed by a
new **shared** Mongo collection `ip_blocklist` (repository
[`iptools.BlockList`](../../../iptools/blocklist.go)), deliberately not
botcheck-owned: any service/script/workflow can write flagged IPs into it (fields
`ip`, `source`, `reason`, `count`, `meta`, `created_at`, `updated_at`; unique
`(ip, source)` so each source keeps its own record; 60-day TTL on `updated_at` so
reputation self-prunes — the "delete if not updated in two months" spec). A daily
background sync ([`iptools/ipsum.go`](../../../iptools/ipsum.go),
`RunIPsumSync` started in `main.go`) downloads the
[stamparm/ipsum](https://github.com/stamparm/ipsum) aggregate feed — Unlicense
(public domain), 30+ blocklists folded into `IP<TAB>count` — and bulk-upserts
every IP under source `ipsum`, preserving the occurrence count; a `LastSync`
staleness guard keeps the cadence honest across restarts. Fire logic: an
ipsum-only listing fires at count ≥3 (ipsum's own auto-ban recommendation), a
deliberate ban from any other source fires regardless, verified good bots are
suppressed. Nil-safe end to end (disabled Mongo → silent rule, pure `Evaluate`
unchanged). Data-source pick came from a 12-candidate survey with adversarial
license/maintenance verification — see [ip-reputation.md](ip-reputation.md) (G37),
[checks/ip_blocklisted.md](../testing/checks/ip_blocklisted.md), and
[storage.md](../storage.md). Spamhaus DROP/EDROP is the intended second writer
(pending a ToU §3.1 confirmation the owner emailed about); CINS Army a later
maybe (pending written bundling permission).

**IP tool surfaces the blocklist too (2026-07-21, follow-up to G37).** The
`iptools` IP-lookup tool now reads the same `ip_blocklist` corpus and renders it
in a renamed "proxy / blocklist / network" result card (+ a JSON `blocklist`
field), keyed on the LOOKED-UP IP so any address can be inspected (botcheck only
checks the visitor's own egress). DRY: one handler-enriched `Result` feeds both
HTML and JSON, reusing `BlockList.Check`; a nil `Blocklist` means "not checked"
(corpus off → row omitted), a non-nil empty one means "checked, clean". The three
existing type-classification checks (`iptools` proxy section, botcheck
`datacenter_ip`/`proxy_ip`) are unchanged — still IP2Proxy-only; the blocklist is
an additive reputation axis, not a merge.

**Spamhaus DROP added as a second blocklist feed (2026-07-22, extends G37).**
Spamhaus gave written permission to use their DROP list, on condition of
crediting them and keeping their copyright notice + date "with the file and
data." Added [`iptools/spamhaus.go`](../../../iptools/spamhaus.go)
(`SyncSpamhausDROP`/`RunSpamhausDROPSync`, wired in `main.go` alongside
`RunIPsumSync`), downloading `drop_v4.json` daily under a shared staleness
guard (`BlockList.ShouldSync`, factored out of the ipsum sync's old inline
guard — DRY, since both feeds want the identical 24h-minus-slack cadence).
DROP is CIDR **netblocks**, not individual IPs — its ~1,669 human-curated,
high-confidence blocks cover ~15 million addresses, ruling out one document
per address. `ip_blocklist` gained `RangeStart`/`RangeEnd` fields (a new
sparse compound index) computed via a new package-internal `ipv4RangeBounds` helper in
[`cidr.go`](../../../iptools/cidr.go) (reuses `ParseSubnet`'s existing network/broadcast math); `Check`'s
Mongo query now does exact-IP-match OR range-containment via one `$or`, so
every existing caller (botcheck, the IP tool) gets DROP coverage for free with
zero call-site changes. Spamhaus's condition is met two ways: every ingested
record's `meta` carries their copyright notice + timestamp + terms URL +
its own `sblid`/`rir` (the data literally keeps "the date and copy text"
attached), and the site footer now credits "© The Spamhaus Project" with a
link, gated on the same `.Attribution` flag as the existing IP2Location
credit. IPv6 (`drop_v6.json`) is a deliberate non-goal — a 128-bit range
representation isn't worth the complexity right now. Tests: offline parse
(`spamhaus_internal_test.go`), offline range-math (`TestIPv4RangeBounds`),
live nil/skip/containment round-trips (`blocklist_test.go`), and footer-credit
assertions on both the IP tool and botcheck pages. Full detail:
[checks/ip_blocklisted.md](../testing/checks/ip_blocklisted.md),
[storage.md](../storage.md), [ip-reputation.md](ip-reputation.md) (G37).

**DRY/KISS/YAGNI/no-paranoia pass over the G37 blocklist code (2026-07-22).**
A 4-lens review swarm (one agent per lens, every finding adversarially
verified — 14 raised, 0 refuted) found real duplication between the ipsum and
Spamhaus DROP syncs that had grown once a second feed existed. Fixed:
`ipsum.go`'s and `spamhaus.go`'s near-identical sync/fetch scaffolding
(`IPsumSyncResult`/`DROPSyncResult`, the skip/fetch/parse/chunked-upsert body,
the ticker/timeout/log runner, the GET-with-status-check fetch) consolidated
into shared `BlockSyncResult`/`syncFeed`/`fetchFeed`/`runDailySync` in
`blocklist.go`; `SyncIPsum`/`SyncSpamhausDROP`/`RunIPsumSync`/
`RunSpamhausDROPSync` are now thin wrappers. `parseDROP` decoded every line
twice (a classifier probe, then a second parse); collapsed to one unified
`dropRecord` struct, one decode per line. Dropped `dropMeta.Records` — parsed
off the feed's metadata line but never read by anything. Unexported
`IPv4RangeBounds` → `ipv4RangeBounds` (no caller outside package iptools;
its test moved to a new white-box `cidr_internal_test.go`, trimming one
redundant assertion in the same move). Reviewed and explicitly kept as-is:
`Upsert` as a real public entry point for external writers, `Meta` as
`map[string]any` (ipsum and DROP already need different key sets),
`BlockLookup.SourcesLabel()` (used by the result template), and the explicit
`h.bl != nil` check in the IP-tool handler (load-bearing, not redundant with
`Check`'s own nil-safety). Deliberately NOT done: unifying the `liveXDB` test
helper across `iptools/tests`, `botcheck/tests` — real duplication, but
touches stable pre-existing test infra from before this feature for a
test-only, zero-production-risk win; left as a known, documented deferral
rather than churn for its own sake.
