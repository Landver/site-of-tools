# Bot-or-not services — research index

This folder is firsthand research into how public "bot-or-not" / browser-check
services actually work: what signals they collect, whether they decide on the
client or the server, and what kind of verdict (if any) they emit. Each service
was driven live in a real browser and then cross-checked against verified web
research (vendor docs, engineering blogs, open-source repos, and adversarial
review of the raw notes). The goal is practical: to inform building our own
detector, so every report is written for a builder — signal lists, architecture,
scoring model, open-source reusability, and the gaps a production stack must
still cover.

The test subject throughout was the **in-app Claude/Electron browser**
(`Claude/… Chrome/148 Electron/42.5.1`, macOS, M-series), egressing through a
**NordVPN / DataCamp datacenter IP** (`87.249.139.226`, geolocated Istanbul).
That single browser run against all twelve services is the connective thread of
this research — see ["How our test browser scored"](#how-our-test-browser-scored-across-all-services)
below.

A note on scope: not all twelve are bot detectors. Several (AmIUnique, EFF Cover
Your Tracks) are academic/privacy uniqueness tools, and several (iphey, whoer,
pixelscan, browserscan) are anti-detect-browser consistency checkers whose
audience is the *evasion* side. They are documented here because their signal
sets and architectures overlap heavily with real bot detection, and the contrast
in what they catch is itself instructive.

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

The same CDP-driven, datacenter-egress Electron browser was run against every
service. The results form a coherent, instructive story about *which* signal
class catches an AI/automation browser and which is blind to it. Ranked from
"caught it" to "waved it through":

- **deviceandbrowserinfo — flagged as a bot.** Verdict `isBot: true`, produced by
  exactly one signal: **`isAutomatedWithCDP: true`**. Every other one of its 20
  signals returned false. This is the cleanest result in the set: CDP (Chrome
  DevTools Protocol) automation detection is the single most effective tell
  against this browser, because CDP is *how* the in-app browser is driven.

- **incolumitas — multiple red flags, no single verdict.** The behavioral
  classifier never resolved off `...` (synthetic hovers alone never produced an
  organic-enough mouse trajectory to score). But the discrete batteries fired:
  **WEBDRIVER FAILED** and **HEADCHR_IFRAME FAILED** in the old suite, and
  **`inconsistentServiceWorkerNavigatorProperty` FAILED** in the new one — the
  Electron/CDP browser leaks worker-context and iframe inconsistencies even
  though `navigator.webdriver` is absent and `window.chrome` is present.
  Server-side, its IP API cleanly unmasked the egress as **VPN = NordVPN**,
  **datacenter = CDN77/DataCamp**, Istanbul.

- **CreepJS — read it as real Chromium, but caught the lies.** The headless
  module reported `chromium: true, 44% like headless, 0% headless, 0% stealth`
  (i.e. a genuine engine, not flagged headless). Its tamper detection is where it
  earned its keep: it **caught the User-Agent spoof** — the UA string claims macOS
  Catalina `10_15_7` while `userAgentData` reports macOS `26.5.1` (Electron
  freezes the legacy UA at 10_15_7) — surfaced a **timezone inconsistency**
  (reported `Europe/Moscow` while the IP geolocates to Istanbul), and **leaked the
  egress IP** via WebRTC.

- **Fingerprint — Bot = Not detected, but heavily flagged elsewhere.** The bot
  signal targets known automation frameworks/VMs, not the mere presence of a
  debugging protocol, so it did not fire. Yet its Smart Signals lit up:
  **VPN** ("public VPN IP, timezone mismatch"), **IP Blocklist**
  ("data_center proxy provider"), **Developer Tools = Yes**, and **Incognito**,
  for an aggregate **Suspect Score of 33**. It also correctly identified the
  browser as "Electron 42.5.1".

- **sannysoft — one red row, no verdict.** Passed the headline checks
  (`navigator.webdriver` missing, `window.chrome` present, real "Apple M5 / Metal"
  WebGL renderer) but produced a red **HEADCHR_IFRAME FAILED**. Being 100%
  client-side, it is structurally blind to the datacenter/VPN egress IP.

- **browserscan / iphey — passed us as normal / trustworthy.** BrowserScan's
  `/bot-detection` returned **"Normal"** across its entire framework battery, and
  its CDP category did not trip *despite this being a genuinely CDP-driven
  browser* — a notable miss versus deviceandbrowserinfo. iphey resolved to
  **"Trust Good" (Trustworthy)**: its consistency-only model has no
  automation-protocol probe, so a self-consistent Chrome-on-macOS fingerprint on
  a datacenter IP sailed through.

- **whoer — perfect anonymity score.** "Your disguise: **100%**," insecurity Low.
  It reported the browser as plain **Chrome 148 and did not detect Electron**. Its
  only surfaced anomaly was a timezone-name mismatch (`Europe/Istanbul` zone vs a
  "Moscow Standard Time" system label). An anonymity checker is not an automation
  detector.

- **pixelscan — no verdict.** The JS+Cloudflare-gated report never advanced past
  the landing state in our Electron browser. The bootstrap failure is itself a
  mild "this environment looks non-standard" signal, but no score was captured.

- **AmIUnique / EFF Cover Your Tracks — no verdict by design.** Neither is a bot
  detector; they measure fingerprint uniqueness/trackability. Neither looks at the
  egress IP, so the datacenter address was invisible to both.

- **DataDome — not testable, inferred hostile.** No public bot-score page exists.
  But our browser hits close to its worst-case profile: datacenter/VPN egress
  (blockable server-side before any JS runs), CDP-driven Electron (the exact
  automation transport its `Error.stack` CDP trick targets), and a frozen macOS
  UA inviting TLS/UA and Client-Hints consistency failures. It would very likely
  challenge or hard-block.

**The through-line:** the one signal that reliably condemns this browser is
**CDP automation detection** (deviceandbrowserinfo caught it on that alone;
Fingerprint saw the related "Developer Tools = Yes"). Its second liability is the
**datacenter/VPN egress IP**, visible only to services with a server-side view
(incolumitas, Fingerprint, whoer's ISP field, and — inferred — DataDome).
Client-only fingerprint pages and consistency/anonymity checkers largely waved it
through, because it presents a coherent, real-GPU, non-headless Chrome-on-macOS
fingerprint. Spoofing tells (the frozen-UA-vs-`userAgentData` mismatch, the
Moscow-timezone-vs-Istanbul-IP contradiction, worker/iframe inconsistencies) were
caught only by the services that specifically cross-check contexts and layers
(CreepJS, incolumitas).

## Building our own

The companion doc [building-our-own.md](building-our-own.md) synthesizes these
twelve reports into a design for our own detector: which signals to collect
client-side, which to derive server-side (IP/ASN reputation, TLS JA3/JA4, HTTP/2
frame + header-order fingerprinting, TCP/IP OS fingerprinting), how to layer a
domain service below the handler per our architecture, and which open-source
collectors to reuse (fp-collect / fp-scanner, CreepJS modules, MixVisit, BotD,
FingerprintJS) versus what has to be built from scratch (the server-side fusion,
consistency cross-checks, and any behavioral layer). It leans on the recurring
lesson above: client signals are all spoofable, so the load-bearing checks are
the cross-layer and cross-context consistency ones plus the server-observed
network facts the browser cannot forge.

## Reports

- [deviceandbrowserinfo.md](reports/deviceandbrowserinfo.md) — transparent bot verdict; the one that caught us (CDP)
- [incolumitas.md](reports/incolumitas.md) — the most comprehensive reference; hybrid client + server + behavioral
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
