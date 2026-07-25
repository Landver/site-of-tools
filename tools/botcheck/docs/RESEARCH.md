# Bot-or-not services — research index

Firsthand research: how public "bot-or-not" / browser-check services work — signals collected,
client vs server decision, verdict (if any) emitted. Each service driven live in real browser,
cross-checked vs web research (vendor docs, eng blogs, OSS repos, adversarial review of raw notes).
Goal: inform building our own detector, so every report written for builder — signal lists, arch,
scoring model, OSS reusability, gaps prod stack must still cover.

Test subject throughout: **in-app Claude/Electron browser** (`Claude/… Chrome/148 Electron/42.5.1`,
macOS, M-series), egress via **NordVPN / DataCamp datacenter IP** (`87.249.139.226`, geoloc
Istanbul). That single browser run vs all twelve services = connective thread — see
["How our test browser scored"](#how-our-test-browser-scored-across-all-services) below.

Scope: not all twelve = bot detectors. AmIUnique, EFF Cover Your Tracks = academic/privacy
uniqueness tools; iphey, whoer, pixelscan, browserscan = anti-detect-browser consistency checkers,
audience = *evasion* side. Documented here: signal sets & archs overlap heavily w/ real bot
detection, & contrast in what they catch itself instructive.

## Comparison table

| Service | Category | Registration | Gives a score? (type) | Client / Server / Both | Flagged our test browser as a bot? | Report |
|---|---|---|---|---|---|---|
| deviceandbrowserinfo | Bot detector (researcher, A. Vastel) | No | Boolean `isBot` + per-signal booleans (no number) | Both (collect client, verdict server) | **Yes** — via `isAutomatedWithCDP` alone | [deviceandbrowserinfo.md](reports/deviceandbrowserinfo.md) |
| incolumitas | Bot detector (independent researcher testbed) | No | Behavioral `0–1` float + per-test OK/FAIL (no single number) | Both (hybrid) | **Partial** — no single verdict, but WEBDRIVER / HEADCHR_IFRAME / service-worker checks failed & IP unmasked VPN/datacenter | [incolumitas.md](reports/incolumitas.md) |
| sannysoft | Bot leak-checklist (OSS aggregation) | No | No score — per-test pass/fail table | Client only | **No aggregate verdict**; one red row (HEADCHR_IFRAME) | [sannysoft.md](reports/sannysoft.md) |
| creepjs | Fingerprint / tamper-detection research (OSS) | No | Trust/crowd-blending % + LIES count + headless % (no bot verdict) | Client (server crowd-blending design-inferred) | **No hard verdict** — but caught UA spoof + timezone inconsistency + WebRTC IP leak | [creepjs.md](reports/creepjs.md) |
| fingerprint | Device-intelligence / anti-bot vendor (commercial) | No (playground) | **Yes** — numeric Suspect Score + categorical Bot field | Both (decision server-side) | **No** (Bot = Not detected) — but flagged VPN, datacenter IP, Dev Tools, incognito; Suspect Score 33 | [fingerprint.md](reports/fingerprint.md) |
| browserscan | Fingerprint + bot checker (commercial, anti-detect) | No | Categorical bot verdict (`/bot-detection`) + numeric Trust Score % (home) | Both (bot verdict client; trust score + TLS/HTTP2/IP server) | **No** — "Normal" (missed CDP automation) | [browserscan.md](reports/browserscan.md) |
| pixelscan | Fingerprint multichecker (commercial, anti-detect) | No | Consistency verdict + per-module pass/warn/fail; binary human/bot on `/bot-check` | Both (hybrid) | **No verdict obtained** — report never rendered in our browser (itself weak signal) | [pixelscan.md](reports/pixelscan.md) |
| iphey | Fingerprint / anonymity checker (commercial, MixVisit demo) | No | Categorical trust label + 5 per-group statuses (no number) | Both (mostly client; thin proprietary verdict) | **No** — "Trust Good" (Trustworthy) | [iphey.md](reports/iphey.md) |
| whoer | Anonymity / "disguise" checker (commercial, VPN funnel) | No (basic/extended) | "Disguise" % `0–100` (inverted: high = clean) + insecurity bar | Both (hybrid) | **No** — 100% disguise; didn't even detect Electron | [whoer.md](reports/whoer.md) |
| amiunique | Uniqueness research (academic, Inria/CNRS) — *not a detector* | No | No bot score — per-attribute similarity ratio + uniqueness verdict | Both (collection only; no decision layer) | **N/A** — no bot verdict by design | [amiunique.md](reports/amiunique.md) |
| coveryourtracks | Uniqueness / tracker-blocking (EFF) — *not a detector* | No | No bot score — entropy in bits + tracker-protection verdict | Both (uniqueness scored server-side) | **N/A** — no bot verdict; results flow didn't render | [coveryourtracks.md](reports/coveryourtracks.md) |
| datadome | Enterprise edge anti-bot (commercial) | Yes (Vulnerability Scan); Device Check has no page | **Yes** — real-time per-req trust score → allow / block / challenge (never exposed to client) | Both (decision server-side, edge-first) | **Not testable firsthand** (no public scorer) — inferred very likely block or challenge | [datadome.md](reports/datadome.md) |

## How our test browser scored across all services

Same CDP-driven, datacenter-egress Electron browser vs every service. Results = coherent story of
*which* signal class catches AI/automation browser & which is blind. Ranked "caught it" -> "waved
through":

- **deviceandbrowserinfo — flagged bot.** `isBot: true` from exactly one signal:
  **`isAutomatedWithCDP: true`**; other 19 of 20 = false. Cleanest result in set: CDP (Chrome
  DevTools Protocol) automation detection = single most effective tell vs this browser, since CDP =
  *how* in-app browser driven.

- **incolumitas — multiple red flags, no single verdict.** Behavioral classifier never resolved off
  `...` (synthetic hovers never organic enough to score). But discrete batteries fired:
  **WEBDRIVER FAILED** & **HEADCHR_IFRAME FAILED** (old suite),
  **`inconsistentServiceWorkerNavigatorProperty` FAILED** (new) — Electron/CDP leaks worker-context
  & iframe inconsistencies even though `navigator.webdriver` absent & `window.chrome` present.
  Server-side IP API cleanly unmasked egress: **VPN = NordVPN**, **datacenter = CDN77/DataCamp**,
  Istanbul.

- **CreepJS — read as real Chromium, but caught lies.** Headless module:
  `chromium: true, 44% like headless, 0% headless, 0% stealth` (genuine engine, not flagged
  headless). Earned keep: **caught UA spoof** — UA claims macOS Catalina `10_15_7` while
  `userAgentData` reports macOS `26.5.1` (Electron freezes legacy UA at 10_15_7) — surfaced
  **timezone inconsistency** (`Europe/Moscow` vs IP geoloc Istanbul), & **leaked egress IP** via
  WebRTC.

- **Fingerprint — Bot = Not detected, but heavily flagged elsewhere.** Bot signal targets known
  automation frameworks/VMs, not mere debugging-protocol presence, so didn't fire. Yet Smart Signals
  lit up: **VPN** ("public VPN IP, timezone mismatch"), **IP Blocklist** ("data_center proxy
  provider"), **Developer Tools = Yes**, & **Incognito**, aggregate **Suspect Score 33**. Also
  correctly ID'd browser as "Electron 42.5.1".

- **sannysoft — one red row, no verdict.** Passed headline checks (`navigator.webdriver` missing,
  `window.chrome` present, real "Apple M5 / Metal" WebGL renderer) but red
  **HEADCHR_IFRAME FAILED**. 100% client-side -> structurally blind to datacenter/VPN egress IP.

- **browserscan / iphey — passed us as normal / trustworthy.** BrowserScan `/bot-detection`
  returned **"Normal"** across entire framework battery; CDP category didn't trip *despite genuinely
  CDP-driven browser* — notable miss vs deviceandbrowserinfo. iphey resolved **"Trust Good"
  (Trustworthy)**: consistency-only model, no automation-protocol probe, so self-consistent
  Chrome-on-macOS fingerprint on datacenter IP sailed through.

- **whoer — perfect anonymity score.** "Your disguise: **100%**," insecurity Low. Reported browser
  as plain **Chrome 148 & didn't detect Electron**. Only anomaly: timezone-name mismatch
  (`Europe/Istanbul` zone vs "Moscow Standard Time" system label). Anonymity checker, not automation
  detector.

- **pixelscan — no verdict.** JS+Cloudflare-gated report never advanced past landing in our Electron
  browser. Bootstrap failure itself mild "environment looks non-standard" signal, but no score
  captured.

- **AmIUnique / EFF Cover Your Tracks — no verdict by design.** Neither = bot detector; measure
  fingerprint uniqueness/trackability. Neither looks at egress IP, so datacenter address invisible to
  both.

- **DataDome — not testable, inferred hostile.** No public bot-score page. But our browser hits near
  worst-case profile: datacenter/VPN egress (blockable server-side before any JS runs), CDP-driven
  Electron (exact automation transport its `Error.stack` CDP trick targets), & frozen macOS UA
  inviting TLS/UA & Client-Hints consistency failures. Very likely challenge or hard-block.

**Through-line:** one signal reliably condemning this browser = **CDP automation detection**
(deviceandbrowserinfo caught it on that alone; Fingerprint saw related "Developer Tools = Yes").
2nd liability: **datacenter/VPN egress IP**, visible only to services w/ server-side view
(incolumitas, Fingerprint, whoer's ISP field, &, inferred, DataDome). Client-only fingerprint pages
& consistency/anonymity checkers largely waved it through: presents coherent, real-GPU, non-headless
Chrome-on-macOS fingerprint. Spoofing tells (frozen-UA-vs-`userAgentData` mismatch,
Moscow-tz-vs-Istanbul-IP contradiction, worker/iframe inconsistencies) caught only by services
cross-checking contexts & layers (CreepJS, incolumitas).

## What we built from this

This research fed shipped tool **Bot check** (`botcheck.corpberry.com`). Design + reference doc index
= [`README.md`](README.md): signals collected client-side, which derived server-side (IP/ASN
reputation via `iptools`, header/Client-Hints cross-checks), how pure domain scorer layers below
handler, which OSS collectors it borrows (BotD, CreepJS modules, fp-collect / fp-scanner, MixVisit,
FingerprintJS). What it deliberately *doesn't* do yet — TLS JA3/JA4, HTTP/2 frame + header-order
fingerprinting, TCP/IP OS fingerprinting, behavioral & crowd/rarity scoring — & backlog of what's
next live in [`roadmap/`](roadmap/README.md). Recurring lesson: client signals all spoofable, so
load-bearing checks = cross-layer & cross-context consistency ones + server-observed network facts
browser cannot forge.

## Reports

- [deviceandbrowserinfo.md](reports/deviceandbrowserinfo.md) — transparent bot verdict; the one that caught us (CDP)
- [incolumitas.md](reports/incolumitas.md) — most comprehensive ref; hybrid client + server + behavioral
- [sannysoft.md](reports/sannysoft.md) — classic OSS leak checklist (Intoli + fp-scanner + fp-collect)
- [creepjs.md](reports/creepjs.md) — tamper/"lie" detection + cross-context recompute
- [fingerprint.md](reports/fingerprint.md) — commercial leader; Smart Signals + Suspect Score, server-side decision
- [browserscan.md](reports/browserscan.md) — anti-detect checker; categorical bot verdict + trust score + TLS/HTTP2
- [pixelscan.md](reports/pixelscan.md) — consistency/coherence cross-validation checker
- [iphey.md](reports/iphey.md) — MixVisit-powered consistency trust verdict
- [whoer.md](reports/whoer.md) — anonymity "disguise" score (inverted polarity)
- [amiunique.md](reports/amiunique.md) — academic uniqueness/entropy tool (not a detector)
- [coveryourtracks.md](reports/coveryourtracks.md) — EFF uniqueness + tracker-blocking (not a detector)
- [datadome.md](reports/datadome.md) — enterprise edge anti-bot; documented via research, not firsthand
