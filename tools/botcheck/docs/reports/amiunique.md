# AmIUnique.org

Academic browser-FP **uniqueness/trackability** tool — **not bot detector.** Shows how rare/re-identifiable browser FP vs research corpus. No bot-or-human call.

- **URL:** https://amiunique.org/ · **Category:** privacy/FP tool (open-source academic research page) · **Registration:** No (free, no account; optional ~4-month cookie -> revisit own FP history).
- **Firsthand, test browser** (in-app browser = `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No bot verdict, by design.** Collected FP (HTTP headers + client-side JS attrs POSTed to backend), reports per-attr uniqueness + overall "are you unique?". No bot/not-bot output, **no** egress-IP check -> datacenter/VPN addr invisible. Sharp contrast w/ every real detector in set.

## What it is — common info

Non-commercial research project studying **diversity/uniqueness of browser FPs**; raises FP-tracking awareness + gives public corpus for anti-tracking research. Run by academics @ **Inria + CNRS, France** (FAQ contact `browser-fingerprinting@univ-lille.fr`, Université de Lille), from DiverSE team / DIVERSIFY project. Underpins peer-reviewed paper *"Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints"* (Laperdrix, Rudametkin, Baudry — IEEE S&P 2016, CNIL-Inria award). Audience: end users (tracking awareness) + researchers/devs building FP defenses. Voluntary test adds 1 data point.

Separate distinct domain `amiunique.io` exists in broader FP ecosystem; this doc = `.org` project only. (See Verification notes — claimed `.io` = researcher's "fork" unconfirmed, not repeated.)

## Registration / access

None. Load page -> fingerprinted immediately. FP stateless — no cookie needed to compute. Only stored state: optional persistent cookie -> returning visitor views own FP history over time; contributing FP to corpus voluntary.

## How it decides bot-or-not

**Doesn't.** Answers different question: *how unique/identifiable is this browser?* Collects FP, per attr reports **similarity ratio** (share of DB FPs w/ same value) + overall verdict on whether combined FP unique in dataset. Never classifies bot vs human, no automation-trace verdict, no risk score.

For anti-bot engineer, value indirect but real: canonical **checklist of what to collect** + reference for **entropy/uniqueness angle** (Panopticlick lineage) — which attrs carry most identifying info. Automation artifacts (e.g. `HeadlessChrome` UA, empty plugin list, `SwiftShader` WebGL renderer) appear only incidentally in raw values for human eyeball; AmIUnique draws no conclusion.

## Detection approaches

Reframed as **FP-collection** approaches (no detection/verdict layer):

- **Active FP** — client-side JS / Web-API attr collection (canvas, WebGL, audio, fonts, navigator props, screen, storage, permissions).
- **Passive FP** — server-side read of browser HTTP request headers.
- **Statistical uniqueness / entropy** — compare attr values vs research DB -> similarity ratios + overall uniqueness.
- **Not used:** headless/automation detection as verdict (no `navigator.webdriver`/CDP-trace check), no behavioral/mouse analysis, no TLS/JA3 or HTTP/2 (h2) frame-settings or header-order FP, no IP/proxy/VPN reputation, no WebRTC leak test, no CAPTCHA/challenge, no ML bot classifier.

## Areas / signals scanned

Grouped as AmIUnique presents. (Firsthand grouping/counts override research list.)

**Server-side (HTTP request headers, passive)**
- User-Agent
- Accept
- Accept-Encoding (UI label "Content encoding")
- Accept-Language (UI label "Content language")
- Upgrade-Insecure-Requests
- (FAQ also: Referer, Do-Not-Track, Connection, Cache-Control.)

**Client-side (JS, POSTed to backend)**
- User-Agent (JS view), `navigator.platform`, product / productSub / vendor, `buildID`
- Full `navigator` dump (~80 props observed), `hardwareConcurrency`, `deviceMemory`
- Plugin list
- Timezone
- Screen resolution + available resolution + color depth
- Browser language(s)
- Installed/available fonts (enumeration)
- Canvas FP (hidden 2D-rendered image hash)
- WebGL: vendor / renderer strings + rendered-image data
- AudioContext (audio) FP
- Cookies-enabled flag
- Local/session storage availability + usage
- Ad blocker (AdBlock) presence
- Permissions API per-API state
- Do-Not-Track flag, video/audio codec support, touch/device-class hints

~50 params total. **Notably absent** (exactly what real detectors add): User-Agent Client Hints (`Sec-CH-UA*`), WebRTC IP leak, IP/ASN reputation, TLS/JA3-JA4, HTTP/2 frame-settings & header-order/case analysis, any cross-session identity linkage.

## How it scans (architecture)

**Hybrid collection, no decision layer.** Two layers -> one stored FP:

1. **Client-side JS** in visitor browser gathers active attrs (canvas, WebGL, audio, fonts, screen, plugins, `navigator` props, storage, permissions), **POSTs** to backend.
2. **Server-side** backend reads passive attrs from HTTP request headers.

Combined set stored + compared vs server-side DB -> uniqueness stats. Original open-source impl: **Play Framework 2.3 (JDK8) + MySQL FP store**. No server-side TLS/JA3 or IP-reputation — "decision" = pure statistical similarity/uniqueness over corpus, not client-vs-server coherence check.

## Scoring / output

**No bot score.** Output = uniqueness/trackability measure:

- **Per-attr similarity ratio** — % of DB FPs sharing your exact value. High = common/anonymous; low = rare/identifying.
- **Overall verdict** — whether combined FP unique in dataset (e.g. "unique among N fingerprints"), selectable over timeline (today / 7 / 15 / 30 / 90 days / all).

In research, identifying power per attr quantified w/ **Shannon entropy (bits)**; most discriminating: plugin list, canvas, User-Agent, fonts. (Exact entropy-normalization medium-confidence — see Verification notes.) Number = "how rare/re-identifiable," proxy for trackability — **not** probability visitor is bot.

## Notable techniques

- **Canvas FP** — 2016 paper headline: render hidden image, hash GPU/driver-specific pixel diffs into highly discriminating signal.
- **WebGL FP**, incl unmasked GPU vendor/renderer strings.
- **AudioContext FP** of audio stack.
- **Font enumeration** for installed set (JS-based; historical Flash method retired — see Verification notes).
- **Per-attr entropy quantification** ranking which signals carry most identifying info — reusable for weighting signals in real detector.
- **Combines active JS attrs + passive HTTP headers** into 1 stateless snapshot.
- **Key caveat (AmIUnique-lineage researcher Antoine Vastel, now @ Castle):** pages measure *uniqueness*, not automation. Single stateless snapshot w/ **no cross-session stability, no cross-signal coherence check, no scale/velocity, no cross-layer identity linkage, no server-side/behavioral signals** — exactly what real anti-bot relies on. Real detector flags FP *inconsistencies* (e.g. UA claims Windows Chrome but WebGL renderer = SwiftShader) as automation; AmIUnique surfaces raw values, draws no conclusion. Missing cross-session/cross-signal linkage = why it can't detect.

## What we observed firsthand

- Confirmed **not a bot detector**: no bot/human verdict. Collected FP, reported uniqueness.
- **Two attr groups** as documented: server-side HTTP-header attrs (User-Agent, Accept, "Content encoding" = Accept-Encoding, "Content language" = Accept-Language, Upgrade-Insecure-Requests) + large client-side JS set (canvas, fonts, WebGL vendor/renderer + data, audio, ~80 `navigator` props, plugins, screen, timezone, permissions per-API state, storage usage, adblock, DNT, buildID, product/productSub/vendor, hardwareConcurrency, deviceMemory, more).
- **Network:** client-side JS set POSTed to backend; header attrs read server-side. (No per-request endpoint path captured.)
- **Egress IP not used** — no IP/WebRTC check, so NordVPN/DataCamp Istanbul addr (`87.249.139.226`) had no effect. Other tools flagged that IP heavily; AmIUnique blind to it by design.

Recon didn't record specific unique/not-unique result; takeaway architectural, not a verdict.

## Verification notes

Corrections folded in from adversarial review of research (stated so rest is trustworthy):

- **`amiunique.io` "fork" attribution — dropped.** Claim `.io` = researcher's fork of `.org` unconfirmed by any cited source, risks conflating two distinct services. Not repeated; only notes `.io` = separate domain.
- **89.4%-unique figure — sourcing corrected.** Belongs to **2016 "Beauty and the Beast" paper's own AmIUnique dataset (~118,934 FPs)**. Cited softwarediversity abstract doesn't state it; one secondary citation mis-dates as "2018 study" -> mentioned only w/ caveat, not relied on.
- **Flash font enumeration — anachronistic, corrected.** Flash EOL (Dec 2020), gone from browsers; current AmIUnique font (& former plugin) detection = **JS-only**. Flash method = 2016-era history, not live site.
- **Header names — de-garbled.** Research listed "Accept/Content-Encoding, Accept/Content-Language"; actual = **Accept-Encoding** + **Accept-Language** (UI labels "Content encoding"/"Content language"). FAQ also lists Connection + Cache-Control, omitted by research.
- **Entropy specifics — medium-confidence.** Exact Shannon/normalized-entropy formulas + precise attr count (~50) medium-confidence (full paper PDF behind access wall). "~50 params" corroborated by secondary source; normalization math not independently confirmed.
- **Missing modern surfaces (added above).** Research header inventory all legacy UA-string era; note: AmIUnique collects **no User-Agent Client Hints** (`Sec-CH-UA*`), does **no HTTP/2 / header-order FP**, underspecifies some active surfaces (hardwareConcurrency, deviceMemory, mediaDevices enumeration, full WebGL extension/parameter list). Called out in relevant sections.

Everything else (open-source Inria/CNRS project, no registration, client-side JS + passive HTTP-header collection, similarity-ratio/entropy metric, not a bot detector) corroborated across site pages, GitHub repo, paper, independent write-ups.

## Open source / reusable

- **DIVERSIFY-project/amiunique** — site's own open-source code (Play 2.3 + MySQL): https://github.com/DIVERSIFY-project/amiunique
- Reusable for builder: **attr checklist** (what to collect), **passive-header + active-JS split**, **per-attr entropy weighting** (which signals matter). Note: *collection/uniqueness* codebase, not detection engine — add coherence, stability, cross-layer, IP/TLS, behavioral layers yourself.

## Sources

- [AmIUnique.org homepage](https://amiunique.org/)
- [AmIUnique FAQ (operators, purpose, collection method, attribute list, stateless/no-cookie)](https://www.amiunique.org/faq)
- [DIVERSIFY-project/amiunique README (open-source code; Play 2.3 + MySQL backend)](https://github.com/DIVERSIFY-project/amiunique/blob/master/README.md)
- [Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints (Laperdrix, Rudametkin, Baudry; IEEE S&P 2016)](https://softwarediversity.eu/wp-publications/laperdrix16/)
- [Rebrowser: AmIUnique overview](https://rebrowser.net/browser-fingerprints/amiunique)
- [Plisio: AmIUnique attributes and academic Inria/CNRS operator](https://plisio.net/cybersecurity/amiunique)
- [Undetectable.io: AmIUnique ~50 parameters, passive HTTP vs active JS, similarity ratio, no IP/WebRTC check](https://undetectable.io/amiunique/)
- [Castle blog (Antoine Vastel): what fingerprint tests like AmIUnique show vs what they miss](https://blog.castle.io/what-browser-fingerprinting-tests-like-amiunique-and-browserleaks-really-show-and-what-they-miss/)
