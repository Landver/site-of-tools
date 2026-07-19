# AmIUnique.org

Academic browser-fingerprint **uniqueness/trackability** tool — **not a bot detector.** Shows how rare/re-identifiable your browser fingerprint is vs research corpus. No bot-or-human call made.

- **URL:** https://amiunique.org/ · **Category:** privacy/fingerprint tool (open-source academic research test page) · **Requires registration:** No (free, no account; optional ~4-month cookie just lets you revisit own fingerprint history).
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No bot verdict produced, by design.** AmIUnique collected fingerprint (HTTP headers + client-side JS attribute set POSTed to backend), reports per-attribute uniqueness + overall "are you unique?" answer. Renders no bot/not-bot output, does **not** check egress IP at all — datacenter/VPN address invisible to it. Sharp contrast with every real detector in this set.

## What it is — common info

AmIUnique.org: non-commercial research project studying **diversity/uniqueness of browser fingerprints**, built to raise public awareness of fingerprint-based tracking and give public corpus for anti-tracking research. Run by academics affiliated with **Inria and CNRS in France** (FAQ contact `browser-fingerprinting@univ-lille.fr`, Université de Lille), grew out of DiverSE team / DIVERSIFY project. Underpins peer-reviewed paper *"Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints"* (Laperdrix, Rudametkin, Baudry — IEEE S&P 2016, CNIL-Inria award). Audience: end users (tracking awareness) + researchers/developers building fingerprinting defenses. Running test voluntarily adds one data point to research dataset.

Separate, distinct domain `amiunique.io` exists in broader fingerprinting ecosystem; this doc strictly covers `.org` academic project. (See Verification notes — claimed attribution of `.io` to a specific researcher's "fork" couldn't be confirmed, not repeated here.)

## Registration / access

None. Load page, fingerprinted immediately. Fingerprinting stateless — no cookie needed to compute fingerprint. Only stored state: optional persistent cookie so returning visitor can view own fingerprint history over time; contributing fingerprint to research corpus voluntary.

## How it decides bot-or-not

**Doesn't.** Tool answers different question: *how unique/identifiable is this browser?* Collects fingerprint, then per attribute reports **similarity ratio** (share of fingerprints in DB with same value) + overall verdict on whether combined fingerprint is unique in dataset. Never classifies visitor bot or human, runs no automation-trace checks as verdict, applies no risk score.

For anti-bot engineer, value is indirect but real: AmIUnique is canonical **checklist of what to collect** and reference for **entropy/uniqueness angle** (Panopticlick lineage) — which attributes carry most identifying info. Automation artifacts (e.g. `HeadlessChrome` UA, empty plugin list, `SwiftShader` WebGL renderer) show up only incidentally in raw attribute values for human to eyeball; AmIUnique draws no conclusion from them.

## Detection approaches

Reframed as **fingerprint-collection** approaches (no detection/verdict layer):

- **Active fingerprinting** — client-side JavaScript / Web-API attribute collection (canvas, WebGL, audio, fonts, navigator props, screen, storage, permissions).
- **Passive fingerprinting** — server-side reading of browser's HTTP request headers.
- **Statistical uniqueness / entropy analysis** — comparing attribute values against research database to compute similarity ratios and overall uniqueness.
- **Not used:** headless/automation detection as verdict (no `navigator.webdriver`/CDP-trace bot check), no behavioral/mouse analysis, no TLS/JA3 or HTTP/2 (h2) frame-settings or header-order fingerprinting, no IP/proxy/VPN reputation, no WebRTC leak test, no CAPTCHA/challenge, no ML bot classifier.

## Areas / signals scanned

Grouped as AmIUnique presents them. (Firsthand-observed grouping/counts take precedence over research list.)

**Server-side (HTTP request headers, passive)**
- User-Agent
- Accept
- Accept-Encoding (labeled "Content encoding" in UI)
- Accept-Language (labeled "Content language" in UI)
- Upgrade-Insecure-Requests
- (FAQ also lists Referer, Do-Not-Track, Connection, Cache-Control.)

**Client-side (JavaScript, POSTed to backend)**
- User-Agent (JS view), `navigator.platform`, product / productSub / vendor, `buildID`
- Full `navigator` property dump (~80 properties observed), `hardwareConcurrency`, `deviceMemory`
- Plugin list
- Timezone
- Screen resolution + available resolution + color depth
- Browser language(s)
- Installed/available fonts (enumeration)
- Canvas fingerprint (hidden 2D-rendered image hash)
- WebGL: vendor / renderer strings + rendered-image data
- AudioContext (audio) fingerprint
- Cookies-enabled flag
- Local/session storage availability + storage usage
- Ad blocker (AdBlock) presence
- Permissions API per-API state
- Do-Not-Track flag, video/audio codec support, touch/device-class hints

Roughly ~50 parameters total. **Notably absent** (exactly what real detectors add): User-Agent Client Hints (`Sec-CH-UA*`), WebRTC IP leak, IP/ASN reputation, TLS/JA3-JA4, HTTP/2 frame-settings and header-order/case analysis, any cross-session identity linkage.

## How it scans (architecture)

**Hybrid collection, no decision layer.** Two layers feed one stored fingerprint:

1. **Client-side JS** runs in visitor's browser, gathers active attributes (canvas, WebGL, audio, fonts, screen, plugins, `navigator` props, storage, permissions), **POSTs** them to backend.
2. **Server-side**, backend reads passive attributes directly from incoming HTTP request headers.

Combined attribute set stored in and compared against server-side database to compute uniqueness statistics. Original open-source implementation: **Play Framework 2.3 (JDK8) backend with MySQL fingerprint store**. No server-side TLS/JA3 or IP-reputation analysis — "decision" purely statistical similarity/uniqueness computation over stored corpus, not client-vs-server coherence cross-check.

## Scoring / output

**No bot score.** Output = uniqueness/trackability measure:

- **Per-attribute similarity ratio** — percentage of database fingerprints sharing your exact value for that attribute. High ratio = common/anonymous; low ratio = rare/identifying.
- **Overall verdict** — whether full combined fingerprint is unique in dataset (e.g. "you are unique among N fingerprints"), selectable over timeline (today / 7 / 15 / 30 / 90 days / all).

In underlying research, identifying power of each attribute quantified with **Shannon entropy (bits)**, most discriminating attributes typically plugin list, canvas, User-Agent, fonts. (Exact entropy-normalization details medium-confidence — see Verification notes.) Number means "how rare/re-identifiable is this browser," proxy for trackability — explicitly **not** a probability visitor is bot.

## Notable techniques

- **Canvas fingerprinting** — 2016 paper's headline contribution: render hidden image, hash GPU/driver-specific pixel differences into highly discriminating signal.
- **WebGL fingerprinting**, including unmasked GPU vendor/renderer strings.
- **AudioContext fingerprinting** of audio stack.
- **Font enumeration** to detect installed font set (JavaScript-based; historical Flash method retired — see Verification notes).
- **Per-attribute entropy quantification** to rank which signals carry most identifying info — reusable insight for weighting signals in real detector.
- **Combining active JS attributes with passive HTTP headers** into one stateless snapshot.
- **Key caveat (from AmIUnique-lineage researcher Antoine Vastel, now at Castle):** these pages measure *uniqueness*, not automation. AmIUnique deliberately captures single stateless snapshot with **no cross-session stability, no cross-signal coherence/consistency check, no scale/velocity, no cross-layer identity linkage, no server-side/behavioral signals** — exact things real anti-bot systems rely on. Real detector flags fingerprint *inconsistencies* (e.g. UA claims Windows Chrome but WebGL renderer is SwiftShader) as automation; AmIUnique surfaces raw values but draws no such conclusion. That absence of cross-session/cross-signal linkage is precisely why it can't function as detector.

## What we observed firsthand

- Confirmed **not a bot detector**: no bot/human verdict of any kind. Tool collected fingerprint, reported uniqueness.
- **Two attribute groups** as documented: server-side HTTP-header attributes (User-Agent, Accept, "Content encoding" = Accept-Encoding, "Content language" = Accept-Language, Upgrade-Insecure-Requests) and large client-side JS attribute set (canvas, fonts, WebGL vendor/renderer + data, audio, ~80 `navigator` props, plugins, screen, timezone, permissions per-API state, storage usage, adblock, DNT, buildID, product/productSub/vendor, hardwareConcurrency, deviceMemory, more).
- **Network:** client-side JS attribute set POSTed to AmIUnique backend; header attributes read server-side from request. (No specific per-request endpoint path captured in recon.)
- **Egress IP not used** — AmIUnique doesn't check IP or WebRTC, so NordVPN/DataCamp Istanbul address (`87.249.139.226`) had no effect on output. Other tools in this set flagged that IP heavily; AmIUnique blind to it by design.

Firsthand recon didn't record specific unique/not-unique result for test browser; takeaway is architectural, not a verdict.

## Verification notes

Corrections folded in from adversarial review of research (stated so rest is trustworthy):

- **`amiunique.io` "fork" attribution — dropped.** Research's claim `amiunique.io` is specific researcher's fork of `.org` project couldn't be confirmed by any cited source, risks conflating two distinct services. This doc doesn't repeat it, only notes `.io` is separate domain.
- **89.4%-unique figure — sourcing corrected.** Figure belongs to **2016 "Beauty and the Beast" paper's own AmIUnique dataset (~118,934 fingerprints)**. Cited softwarediversity abstract page doesn't actually state number, one secondary citation mis-dates it as "2018 study," so number mentioned only with that caveat rather than relied on.
- **Flash font enumeration — anachronistic, corrected.** Flash reached end-of-life (Dec 2020), gone from browsers; current AmIUnique font (and former plugin) detection is **JavaScript-only**. Flash-based method is 2016-era paper history, not how live site works.
- **Header names — de-garbled.** Research listed "Accept/Content-Encoding, Accept/Content-Language"; actual HTTP request headers are **Accept-Encoding** and **Accept-Language** (AmIUnique's UI labels them "Content encoding"/"Content language"). FAQ also lists Connection and Cache-Control, which research omitted.
- **Entropy specifics — flagged medium-confidence.** Exact Shannon/normalized-entropy formulas and precise attribute count (~50) medium-confidence in research (full paper PDF behind access wall). "~50 parameters" figure corroborated by secondary source; normalization math not independently confirmed.
- **Missing modern surfaces (added above).** Research's header inventory entirely legacy UA-string era; anti-bot engineer should note AmIUnique collects **no User-Agent Client Hints** (`Sec-CH-UA*`), does **no HTTP/2 / header-order fingerprinting**, underspecifies some active surfaces (hardwareConcurrency, deviceMemory, mediaDevices enumeration, full WebGL extension/parameter list). Called out in relevant sections.

Everything else (open-source Inria/CNRS academic project, no registration, client-side JS + passive HTTP-header collection, similarity-ratio/entropy uniqueness metric, not a bot detector) corroborated across site's own pages, GitHub repo, paper, independent write-ups.

## Open source / reusable

- **DIVERSIFY-project/amiunique** — site's own open-source code (Play Framework 2.3 + MySQL backend): https://github.com/DIVERSIFY-project/amiunique
- Reusable ideas for builder: **attribute checklist** (what to collect), **passive-header + active-JS split**, **per-attribute entropy weighting** to decide which signals matter. Note: *collection/uniqueness* codebase, not detection engine — you'd add coherence, stability, cross-layer, IP/TLS, behavioral layers yourself.

## Sources

- [AmIUnique.org homepage](https://amiunique.org/)
- [AmIUnique FAQ (operators, purpose, collection method, attribute list, stateless/no-cookie)](https://www.amiunique.org/faq)
- [DIVERSIFY-project/amiunique README (open-source code; Play 2.3 + MySQL backend)](https://github.com/DIVERSIFY-project/amiunique/blob/master/README.md)
- [Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints (Laperdrix, Rudametkin, Baudry; IEEE S&P 2016)](https://softwarediversity.eu/wp-publications/laperdrix16/)
- [Rebrowser: AmIUnique overview](https://rebrowser.net/browser-fingerprints/amiunique)
- [Plisio: AmIUnique attributes and academic Inria/CNRS operator](https://plisio.net/cybersecurity/amiunique)
- [Undetectable.io: AmIUnique ~50 parameters, passive HTTP vs active JS, similarity ratio, no IP/WebRTC check](https://undetectable.io/amiunique/)
- [Castle blog (Antoine Vastel): what fingerprint tests like AmIUnique show vs what they miss](https://blog.castle.io/what-browser-fingerprinting-tests-like-amiunique-and-browserleaks-really-show-and-what-they-miss/)
