# AmIUnique.org

An academic browser-fingerprint **uniqueness/trackability** tool — **not a bot detector.** It shows how rare and re-identifiable your browser's fingerprint is against a research corpus, and makes no bot-or-human determination.

- **URL:** https://amiunique.org/ · **Category:** privacy/fingerprint tool (open-source academic research test page) · **Requires registration:** No (free, no account; an optional ~4-month cookie only lets you revisit your own fingerprint history).
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **No bot verdict is produced, by design.** AmIUnique collected the fingerprint (HTTP headers + a client-side JS attribute set POSTed to its backend) and reports per-attribute uniqueness plus an overall "are you unique?" answer. It renders no bot/not-bot output and does **not** look at the egress IP at all, so the datacenter/VPN address is invisible to it — a sharp contrast with every actual detector in this set.

## What it is — common info

AmIUnique.org is a non-commercial research project studying the **diversity and uniqueness of browser fingerprints**, built to raise public awareness of fingerprint-based tracking and to give a public corpus for anti-tracking research. It is run by academics affiliated with **Inria and CNRS in France** (FAQ contact `browser-fingerprinting@univ-lille.fr`, Université de Lille), growing out of the DiverSE team / DIVERSIFY project. It underpins the peer-reviewed paper *"Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints"* (Laperdrix, Rudametkin, Baudry — IEEE S&P 2016, CNIL-Inria award). The audience is end users (tracking awareness) and researchers/developers building fingerprinting defenses. Running the test voluntarily contributes one data point to the research dataset.

There is a separate, distinct domain `amiunique.io` in the broader fingerprinting ecosystem; this document is strictly about the `.org` academic project. (See Verification notes — a claimed attribution of `.io` to a specific researcher's "fork" could not be confirmed and is not repeated here.)

## Registration / access

None. Load the page and it fingerprints you immediately. Fingerprinting is stateless — no cookie is required to compute the fingerprint. The only stored state is an optional persistent cookie so a returning visitor can view their own fingerprint history over time; contributing your fingerprint to the research corpus is voluntary.

## How it decides bot-or-not

**It does not.** This tool answers a different question: *how unique/identifiable is this browser?* It collects a fingerprint, then for each attribute reports a **similarity ratio** (the share of fingerprints in its database with the same value) and an overall verdict on whether your combined fingerprint is unique in the dataset. It never classifies the visitor as bot or human, runs no automation-trace checks as a verdict, and applies no risk score.

For an anti-bot engineer the value is indirect but real: AmIUnique is the canonical **checklist of what to collect** and the reference for the **entropy/uniqueness angle** (the Panopticlick lineage) — i.e. which attributes carry the most identifying information. Automation artifacts (e.g. a `HeadlessChrome` UA, an empty plugin list, a `SwiftShader` WebGL renderer) only show up incidentally in the raw attribute values for a human to eyeball; AmIUnique draws no conclusion from them.

## Detection approaches

Reframed as **fingerprint-collection** approaches (there is no detection/verdict layer):

- **Active fingerprinting** — client-side JavaScript / Web-API attribute collection (canvas, WebGL, audio, fonts, navigator props, screen, storage, permissions).
- **Passive fingerprinting** — server-side reading of the browser's HTTP request headers.
- **Statistical uniqueness / entropy analysis** — comparing your attribute values against the research database to compute similarity ratios and overall uniqueness.
- **Not used:** headless/automation detection as a verdict (no `navigator.webdriver`/CDP-trace bot check), no behavioral/mouse analysis, no TLS/JA3 or HTTP/2 (h2) frame-settings or header-order fingerprinting, no IP/proxy/VPN reputation, no WebRTC leak test, no CAPTCHA/challenge, no ML bot classifier.

## Areas / signals scanned

Grouped as AmIUnique itself presents them. (Firsthand-observed grouping and counts take precedence over the research list.)

**Server-side (HTTP request headers, passive)**
- User-Agent
- Accept
- Accept-Encoding (labeled "Content encoding" in the UI)
- Accept-Language (labeled "Content language" in the UI)
- Upgrade-Insecure-Requests
- (FAQ also lists Referer, Do-Not-Track, Connection, Cache-Control.)

**Client-side (JavaScript, POSTed to the backend)**
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

Roughly ~50 parameters total. **Notably absent** (relevant because they are exactly what real detectors add): User-Agent Client Hints (`Sec-CH-UA*`), WebRTC IP leak, IP/ASN reputation, TLS/JA3-JA4, HTTP/2 frame-settings and header-order/case analysis, and any cross-session identity linkage.

## How it scans (architecture)

**Hybrid collection, no decision layer.** Two layers feed one stored fingerprint:

1. **Client-side JS** runs in the visitor's browser to gather active attributes (canvas, WebGL, audio, fonts, screen, plugins, `navigator` props, storage, permissions) and **POSTs** them to the backend.
2. **Server-side**, the backend reads passive attributes directly from the incoming HTTP request headers.

The combined attribute set is stored in and compared against a server-side database to compute the uniqueness statistics. The original open-source implementation is a **Play Framework 2.3 (JDK8) backend with a MySQL fingerprint store**. There is no server-side TLS/JA3 or IP-reputation analysis — the "decision" is purely a statistical similarity/uniqueness computation over the stored corpus, not a client-vs-server coherence cross-check.

## Scoring / output

There is **no bot score.** Output is a uniqueness/trackability measure:

- **Per-attribute similarity ratio** — the percentage of database fingerprints sharing your exact value for that attribute. High ratio = common/anonymous; low ratio = rare/identifying.
- **Overall verdict** — whether your full combined fingerprint is unique in the dataset (e.g. "you are unique among N fingerprints"), selectable over a timeline (today / 7 / 15 / 30 / 90 days / all).

In the underlying research the identifying power of each attribute is quantified with **Shannon entropy (bits)**, with the most discriminating attributes typically being the plugin list, canvas, User-Agent, and fonts. (Exact entropy-normalization details are medium-confidence — see Verification notes.) The number means "how rare/re-identifiable is this browser," a proxy for trackability — explicitly **not** a probability that the visitor is a bot.

## Notable techniques

- **Canvas fingerprinting** — the 2016 paper's headline contribution: render a hidden image and hash GPU/driver-specific pixel differences into a highly discriminating signal.
- **WebGL fingerprinting**, including unmasked GPU vendor/renderer strings.
- **AudioContext fingerprinting** of the audio stack.
- **Font enumeration** to detect the installed font set (JavaScript-based; the historical Flash method is retired — see Verification notes).
- **Per-attribute entropy quantification** to rank which signals carry the most identifying information — the reusable insight for weighting signals in a real detector.
- **Combining active JS attributes with passive HTTP headers** into one stateless snapshot.
- **Key caveat (from AmIUnique-lineage researcher Antoine Vastel, now at Castle):** these pages measure *uniqueness*, not automation. AmIUnique deliberately captures a single stateless snapshot with **no cross-session stability, no cross-signal coherence/consistency check, no scale/velocity, no cross-layer identity linkage, and no server-side/behavioral signals** — the very things real anti-bot systems rely on. A real detector flags fingerprint *inconsistencies* (e.g. UA claims Windows Chrome but WebGL renderer is SwiftShader) as automation; AmIUnique surfaces the raw values but draws no such conclusion. That absence of any cross-session/cross-signal linkage is precisely why it cannot function as a detector.

## What we observed firsthand

- Confirmed **not a bot detector**: no bot/human verdict of any kind. The tool collected the fingerprint and reported uniqueness.
- **Two attribute groups** as documented: server-side HTTP-header attributes (User-Agent, Accept, "Content encoding" = Accept-Encoding, "Content language" = Accept-Language, Upgrade-Insecure-Requests) and a large client-side JS attribute set (canvas, fonts, WebGL vendor/renderer + data, audio, ~80 `navigator` props, plugins, screen, timezone, permissions per-API state, storage usage, adblock, DNT, buildID, product/productSub/vendor, hardwareConcurrency, deviceMemory, and more).
- **Network:** the client-side JS attribute set is POSTed to the AmIUnique backend; the header attributes are read server-side from the request. (No specific per-request endpoint path was captured in recon.)
- **Egress IP was not used** — AmIUnique does not check IP or WebRTC, so the NordVPN/DataCamp Istanbul address (`87.249.139.226`) had no effect on its output. Other tools in this set flagged that IP heavily; AmIUnique is blind to it by design.

Firsthand recon did not record the specific unique/not-unique result for the test browser; the takeaway is architectural, not a verdict.

## Verification notes

Corrections folded in from the adversarial review of the research (stated so the rest is trustworthy):

- **`amiunique.io` "fork" attribution — dropped.** The research's claim that `amiunique.io` is a specific researcher's fork of the `.org` project could not be confirmed by any cited source and risks conflating two distinct services. This document does not repeat it and only notes that `.io` is a separate domain.
- **89.4%-unique figure — sourcing corrected.** The figure belongs to the **2016 "Beauty and the Beast" paper's own AmIUnique dataset (~118,934 fingerprints)**. The cited softwarediversity abstract page does not actually state the number, and one secondary citation mis-dates it as a "2018 study," so the number is mentioned only with that caveat rather than relied on.
- **Flash font enumeration — anachronistic, corrected.** Flash reached end-of-life (Dec 2020) and is gone from browsers; current AmIUnique font (and former plugin) detection is **JavaScript-only**. The Flash-based method is 2016-era paper history, not how the live site works.
- **Header names — de-garbled.** The research listed "Accept/Content-Encoding, Accept/Content-Language"; the actual HTTP request headers are **Accept-Encoding** and **Accept-Language** (AmIUnique's UI labels them "Content encoding"/"Content language"). The FAQ also lists Connection and Cache-Control, which the research omitted.
- **Entropy specifics — flagged medium-confidence.** The exact Shannon/normalized-entropy formulas and the precise attribute count (~50) are medium-confidence in the research (the full paper PDF was behind an access wall). The "~50 parameters" figure is corroborated by a secondary source; the normalization math is not independently confirmed.
- **Missing modern surfaces (added above).** The research's header inventory is entirely legacy UA-string era; an anti-bot engineer should note AmIUnique collects **no User-Agent Client Hints** (`Sec-CH-UA*`), does **no HTTP/2 / header-order fingerprinting**, and underspecifies some active surfaces (hardwareConcurrency, deviceMemory, mediaDevices enumeration, full WebGL extension/parameter list). These are called out in the relevant sections.

Everything else (open-source Inria/CNRS academic project, no registration, client-side JS + passive HTTP-header collection, similarity-ratio/entropy uniqueness metric, and that it is not a bot detector) is corroborated across the site's own pages, its GitHub repo, its paper, and independent write-ups.

## Open source / reusable

- **DIVERSIFY-project/amiunique** — the site's own open-source code (Play Framework 2.3 + MySQL backend): https://github.com/DIVERSIFY-project/amiunique
- Reusable ideas for a builder: the **attribute checklist** (what to collect), the **passive-header + active-JS split**, and the **per-attribute entropy weighting** to decide which signals matter. Note this is a *collection/uniqueness* codebase, not a detection engine — you would add the coherence, stability, cross-layer, IP/TLS, and behavioral layers yourself.

## Sources

- [AmIUnique.org homepage](https://amiunique.org/)
- [AmIUnique FAQ (operators, purpose, collection method, attribute list, stateless/no-cookie)](https://www.amiunique.org/faq)
- [DIVERSIFY-project/amiunique README (open-source code; Play 2.3 + MySQL backend)](https://github.com/DIVERSIFY-project/amiunique/blob/master/README.md)
- [Beauty and the Beast: Diverting Modern Web Browsers to Build Unique Browser Fingerprints (Laperdrix, Rudametkin, Baudry; IEEE S&P 2016)](https://softwarediversity.eu/wp-publications/laperdrix16/)
- [Rebrowser: AmIUnique overview](https://rebrowser.net/browser-fingerprints/amiunique)
- [Plisio: AmIUnique attributes and academic Inria/CNRS operator](https://plisio.net/cybersecurity/amiunique)
- [Undetectable.io: AmIUnique ~50 parameters, passive HTTP vs active JS, similarity ratio, no IP/WebRTC check](https://undetectable.io/amiunique/)
- [Castle blog (Antoine Vastel): what fingerprint tests like AmIUnique show vs what they miss](https://blog.castle.io/what-browser-fingerprinting-tests-like-amiunique-and-browserleaks-really-show-and-what-they-miss/)
