# Bot-or-not services — research index

Firsthand research into how public "bot-or-not" / browser-check services actually work: what
signals collected, client or server decision, what verdict (if any) emitted. Each service driven
live in real browser, cross-checked against verified web research (vendor docs, engineering
blogs, open-source repos, adversarial review of raw notes). Goal practical: inform building our
own detector, so every report written for a builder — signal lists, architecture, scoring model,
open-source reusability, gaps a production stack must still cover.

Test subject throughout: **in-app Claude/Electron browser** (`Claude/… Chrome/148 Electron/42.5.1`,
macOS, M-series), egressing through **NordVPN / DataCamp datacenter IP** (`87.249.139.226`,
geolocated Istanbul). That single browser run against all twelve services is connective thread of
this research — see ["How our test browser scored"](#how-our-test-browser-scored-across-all-services)
below.

Note on scope: not all twelve are bot detectors. Several (AmIUnique, EFF Cover Your Tracks) are
academic/privacy uniqueness tools; several (iphey, whoer, pixelscan, browserscan) are
anti-detect-browser consistency checkers whose audience is the *evasion* side. Documented here
because signal sets and architectures overlap heavily with real bot detection, and contrast in
what they catch is itself instructive.

## Comparison table

| Service | Category | Registration | Gives a score? (type) | Client / Server / Both | Flagged our test browser as a bot? | Report |
|---|---|---|---|---|---|---|
| deviceandbrowserinfo | Bot detector (researcher, A. Vastel) | No | Boolean `isBot` + per-signal booleans (no number) | Both (collect client, verdict server) | **Yes** — via `isAutomatedWithCDP` alone | [deviceandbrowserinfo.md](reports/deviceandbrowserinfo.md) |
| incolumitas | Bot detector (independent researcher testbed) | No | Behavioral `0–1` float + per-test OK/FAIL (no single number) | Both (hybrid) | **Partial** — no single verdict, but WEBDRIVER / HEADCHR_IFRAME / service-worker checks failed and IP unmasked as VPN/datacenter | [incolumitas.md](reports/incolumitas.md) |
| sannysoft | Bot leak-checklist (open-source aggregation) | No | No score — per-test pass/fail table | Client only | **No aggregate verdict**; one red row (HEADCHR_IFRAME) | [sannysoft.md](reports/sannysoft.md) |
| creepjs | Fingerprint / tamper-detection research (open-source) | No | Trust/crowd-blending % + LIES count + headless % (no bot verdict) | Client (server crowd-blending is design-inferred) | **No hard verdict** — but caught UA spoof + timezone inconsistency + WebRTC IP leak | [creepjs.md](reports/creepjs.md) |
| fingerprint | Device-intelligence / anti-bot vendor (commercial) | No (playground) | **Yes** — numeric Suspect Score + categorical Bot field | Both (decision server-side) | **No** (Bot = Not detected) — but flagged VPN, datacenter IP, Dev Tools, incognito; Suspect Score 33 | [fingerprint.md](reports/fingerprint.md) |
| browserscan | Fingerprint + bot checker (commercial, anti-detect) | No | Categorical bot verdict (`/bot-detection`) + numeric Trust Score % (home) | Both (bot verdict client; trust score + TLS/HTTP2/IP server) | **No** — "Normal" (missed the CDP automation) | [browserscan.md](reports/browserscan.md) |
| pixelscan | Fingerprint multichecker (commercial, anti-detect) | No | Consistency verdict + per-module pass/warn/fail; binary human/bot on `/bot-check` | Both (hybrid) | **No verdict obtained** — report never rendered in our browser (itself a weak signal) | [pixelscan.md](reports/pixelscan.md) |
| iphey | Fingerprint / anonymity checker (commercial, MixVisit demo) | No | Categorical trust label + 5 per-group statuses (no number) | Both (mostly client; thin proprietary verdict) | **No** — "Trust Good" (Trustworthy) | [iphey.md](reports/iphey.md) |
| whoer | Anonymity / "disguise" checker (commercial, VPN funnel) | No (basic/extended) | "Disguise" % `0–100` (inverted: high = clean) + insecurity bar | Both (hybrid) | **No** — 100% disguise; did not even detect Electron | [whoer.md](reports/whoer.md) |
| amiunique | Uniqueness research (academic, Inria/CNRS) — *not a detector* | No | No bot score — per-attribute similarity ratio + uniqueness verdict | Both (collection only; no decision layer) | **N/A** — no bot verdict by design | [amiunique.md](reports/amiunique.md) |
| coveryourtracks | Uniqueness / tracker-blocking (EFF) — *not a detector* | No | No bot score — entropy in bits + tracker-protection verdict | Both (uniqueness scored server-side) | **N/A** — no bot verdict; results flow did not render | [coveryourtracks.md](reports/coveryourtracks.md) |
| datadome | Enterprise edge anti-bot (commercial) | Yes (Vulnerability Scan); Device Check has no page | **Yes** — real-time per-request trust score → allow / block / challenge (never exposed to client) | Both (decision server-side, edge-first) | **Not testable firsthand** (no public scorer) — inferred it would very likely block or challenge | [datadome.md](reports/datadome.md) |

## How our test browser scored across all services

Same CDP-driven, datacenter-egress Electron browser run against every service. Results form
coherent, instructive story about *which* signal class catches an AI/automation browser and
which is blind to it. Ranked "caught it" to "waved it through":

- **deviceandbrowserinfo — flagged as a bot.** Verdict `isBot: true`, produced by exactly one
  signal: **`isAutomatedWithCDP: true`**. Every other one of its 20 signals returned false.
  Cleanest result in the set: CDP (Chrome DevTools Protocol) automation detection is the single
  most effective tell against this browser, because CDP is *how* the in-app browser is driven.

- **incolumitas — multiple red flags, no single verdict.** Behavioral classifier never resolved
  off `...` (synthetic hovers alone never produced organic-enough mouse trajectory to score). But
  discrete batteries fired: **WEBDRIVER FAILED** and **HEADCHR_IFRAME FAILED** in old suite, and
  **`inconsistentServiceWorkerNavigatorProperty` FAILED** in new one — Electron/CDP browser leaks
  worker-context and iframe inconsistencies even though `navigator.webdriver` absent and
  `window.chrome` present. Server-side, IP API cleanly unmasked egress as **VPN = NordVPN**,
  **datacenter = CDN77/DataCamp**, Istanbul.

- **CreepJS — read as real Chromium, but caught the lies.** Headless module reported
  `chromium: true, 44% like headless, 0% headless, 0% stealth` (genuine engine, not flagged
  headless). Tamper detection is where it earned its keep: **caught User-Agent spoof** — UA
  string claims macOS Catalina `10_15_7` while `userAgentData` reports macOS `26.5.1` (Electron
  freezes legacy UA at 10_15_7) — surfaced **timezone inconsistency** (reported `Europe/Moscow`
  while IP geolocates to Istanbul), and **leaked egress IP** via WebRTC.

- **Fingerprint — Bot = Not detected, but heavily flagged elsewhere.** Bot signal targets known
  automation frameworks/VMs, not mere presence of debugging protocol, so didn't fire. Yet Smart
  Signals lit up: **VPN** ("public VPN IP, timezone mismatch"), **IP Blocklist** ("data_center
  proxy provider"), **Developer Tools = Yes**, and **Incognito**, for aggregate **Suspect Score
  of 33**. Also correctly identified browser as "Electron 42.5.1".

- **sannysoft — one red row, no verdict.** Passed headline checks (`navigator.webdriver` missing,
  `window.chrome` present, real "Apple M5 / Metal" WebGL renderer) but produced red
  **HEADCHR_IFRAME FAILED**. Being 100% client-side, structurally blind to datacenter/VPN egress IP.

- **browserscan / iphey — passed us as normal / trustworthy.** BrowserScan's `/bot-detection`
  returned **"Normal"** across entire framework battery; CDP category didn't trip *despite this
  being a genuinely CDP-driven browser* — notable miss vs deviceandbrowserinfo. iphey resolved to
  **"Trust Good" (Trustworthy)**: consistency-only model has no automation-protocol probe, so
  self-consistent Chrome-on-macOS fingerprint on datacenter IP sailed through.

- **whoer — perfect anonymity score.** "Your disguise: **100%**," insecurity Low. Reported browser
  as plain **Chrome 148 and did not detect Electron**. Only surfaced anomaly: timezone-name
  mismatch (`Europe/Istanbul` zone vs "Moscow Standard Time" system label). Anonymity checker is
  not an automation detector.

- **pixelscan — no verdict.** JS+Cloudflare-gated report never advanced past landing state in our
  Electron browser. Bootstrap failure itself mild "this environment looks non-standard" signal,
  but no score captured.

- **AmIUnique / EFF Cover Your Tracks — no verdict by design.** Neither a bot detector; they
  measure fingerprint uniqueness/trackability. Neither looks at egress IP, so datacenter address
  invisible to both.

- **DataDome — not testable, inferred hostile.** No public bot-score page exists. But our browser
  hits close to its worst-case profile: datacenter/VPN egress (blockable server-side before any JS
  runs), CDP-driven Electron (exact automation transport its `Error.stack` CDP trick targets), and
  frozen macOS UA inviting TLS/UA and Client-Hints consistency failures. Would very likely
  challenge or hard-block.

**The through-line:** one signal that reliably condemns this browser is **CDP automation
detection** (deviceandbrowserinfo caught it on that alone; Fingerprint saw related "Developer
Tools = Yes"). Second liability: **datacenter/VPN egress IP**, visible only to services with
server-side view (incolumitas, Fingerprint, whoer's ISP field, and — inferred — DataDome).
Client-only fingerprint pages and consistency/anonymity checkers largely waved it through, because
it presents coherent, real-GPU, non-headless Chrome-on-macOS fingerprint. Spoofing tells
(frozen-UA-vs-`userAgentData` mismatch, Moscow-timezone-vs-Istanbul-IP contradiction, worker/iframe
inconsistencies) caught only by services that specifically cross-check contexts and layers
(CreepJS, incolumitas).

## What we built from this

This research fed a shipped tool, **Bot check** (`botcheck.corpberry.com`). Design + reference doc
index is [`README.md`](README.md): which signals collected client-side, which derived server-side
(IP/ASN reputation via `iptools`, header/Client-Hints cross-checks), how pure domain scorer layers
below handler, which open-source collectors it borrows (BotD, CreepJS modules, fp-collect /
fp-scanner, MixVisit, FingerprintJS). What it deliberately *doesn't* do yet — TLS JA3/JA4, HTTP/2
frame + header-order fingerprinting, TCP/IP OS fingerprinting, behavioral and crowd/rarity scoring
— and backlog of what to build next live in [`roadmap/`](roadmap/README.md). Recurring lesson
throughout: client signals all spoofable, so load-bearing checks are cross-layer and cross-context
consistency ones plus server-observed network facts browser cannot forge.

## Reports

- [deviceandbrowserinfo.md](reports/deviceandbrowserinfo.md) — transparent bot verdict; the one that caught us (CDP)
- [incolumitas.md](reports/incolumitas.md) — most comprehensive reference; hybrid client + server + behavioral
- [sannysoft.md](reports/sannysoft.md) — classic open-source leak checklist (Intoli + fp-scanner + fp-collect)
- [creepjs.md](reports/creepjs.md) — tamper/"lie" detection and cross-context recompute
- [fingerprint.md](reports/fingerprint.md) — commercial leader; Smart Signals + Suspect Score, server-side decision
- [browserscan.md](reports/browserscan.md) — anti-detect checker; categorical bot verdict + trust score + TLS/HTTP2
- [pixelscan.md](reports/pixelscan.md) — consistency/coherence cross-validation checker
- [iphey.md](reports/iphey.md) — MixVisit-powered consistency trust verdict
- [whoer.md](reports/whoer.md) — anonymity "disguise" score (inverted polarity)
- [amiunique.md](reports/amiunique.md) — academic uniqueness/entropy tool (not a detector)
- [coveryourtracks.md](reports/coveryourtracks.md) — EFF uniqueness + tracker-blocking (not a detector)
- [datadome.md](reports/datadome.md) — enterprise edge anti-bot; documented via research, not firsthand
