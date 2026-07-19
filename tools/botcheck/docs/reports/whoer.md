# whoer.net

Anonymity / "disguise" checker scoring how consistent and leak-free your connection looks. Privacy/anonymity tool, not dedicated bot classifier: detects proxies, VPNs, fingerprint inconsistencies (overlap with, but not same as, automation detection).

- **URL:** https://whoer.net/ · **Category:** privacy/anonymity + fingerprint tool (freemium marketing funnel for paid Whoer VPN) · **Requires registration:** No for free basic and extended browser checks; account/promo only gates paid Whoer VPN and some extended features.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **"Your disguise: 100%"**, Level of insecurity = Low. IP `87.249.139.226`, Istanbul, ISP "Datacamp", Proxy: No, Anonymizer: No, Blacklist: No. Reported Browser = **Chrome 148 and did NOT detect Electron**, OS = Mac OS X. One anomaly surfaced: timezone-name mismatch (Time Zone = `Europe/Istanbul` while system time labeled "Moscow Standard Time"). Net: didn't flag our datacenter-egress automated browser as suspicious.

## What it is — common info

whoer.net: consumer-facing "how anonymous do I look / is my connection leaking" diagnostic. Run by WHOIX LTD, registered in Strovolos, Nicosia, Cyprus, operated in some form since roughly 2008 (ownership otherwise opaque). Free checker exists primarily as lead-gen / trust-builder for paid **Whoer VPN**: shows "anonymity percentage" plus any leaks, then positions VPN as the fix.

Real-world audience skews heavily toward antidetect-browser / multi-accounting / proxy community — people validating masked setup "looks like genuine, consistent human user." Page carries heavy antidetect marketing (WADE X multi-account browser, Decodo proxies). Because of that audience, framing is consistency-and-leaks, not automation-per-se.

Note the semantic inversion vs anti-bot vendor: whoer's headline number is an **anonymity/"disguise" score where HIGH is clean/desirable result**, opposite of "bot probability" where high is bad.

## Registration / access

Free web check (both basic view and extended/interactive tests) runs in browser on page load, no login. Registration only applies to paid/trial Whoer VPN, separate freemium funnel. (This split corroborated indirectly by secondary reviews rather than whoer's own docs — medium confidence.)

## How it decides bot-or-not

whoer doesn't produce bot/human verdict. Produces single **"disguise" percentage (0–100%)** plus "Level of insecurity" bar (Low/Medium/High). Number starts high, is **deducted** for each detected problem or inconsistency:

- WebRTC or DNS leak exposing real IP behind proxy/VPN.
- Timezone (from JS) not matching IP's geolocation.
- `navigator.language` / Accept-Language not matching IP region.
- DNS resolver geolocation not matching connection's proxy/VPN egress.
- Blacklisted, datacenter, or proxy/VPN-classified IP.
- Proxy-revealing HTTP headers present.
- Enabled script/plugin surfaces (Java, Flash, ActiveX) and other fingerprint tells.

Core philosophy: **consistency** — cross-check what browser *claims* (UA, OS, timezone, language) against what network *reveals* (IP geo/ASN, DNS egress, blacklist, connection characteristics). Mismatches lower score. Heuristic/rule-based tally, not ML classifier, exact weights undisclosed. 100% "disguise" doesn't guarantee target site won't block you — only means whoer found no leaks or internal contradictions.

## Detection approaches

- **Browser/device fingerprinting** — client-side JS collecting navigator/UA, canvas, WebGL, fonts, screen, plugins, timezone, language, DNT, script-support flags.
- **IP / proxy / VPN / datacenter reputation + DNSBL blacklist lookups** — server-side.
- **Leak detection** — WebRTC STUN local/public IP leak; DNS leak (browser makes requests to whoer-controlled resolvers, correlated server-side).
- **Server-side connection analysis** — HTTP header inspection for proxy signatures; open-port scan against connecting IP. Passive TCP/IP OS fingerprinting and two-way-ping/MTU tunnel heuristics are *plausibly* used but not confirmed for whoer specifically (see Verification notes).
- **Cross-signal consistency checking** (rule/heuristic) — IP-geo vs DNS-geo vs timezone vs Accept-Language vs OS/UA must agree.
- **Persistent-tracking test** — Evercookie / supercookie persistence.
- **NOT observed:** ML bot scoring, mouse/keystroke behavioral biometrics, request-cadence/rate analysis, or active CAPTCHA/proof-of-work challenge. Score is single page-load snapshot.

## Areas / signals scanned

### Client-side (JS)
- User-Agent string; OS type/version; browser type/version.
- Screen resolution / window size / color depth.
- Canvas fingerprint (HTML5 2D rendering hash).
- WebGL fingerprint (GPU/renderer).
- Installed system fonts.
- Browser plugins/extensions.
- System timezone (JS `Date`/`Intl`), compared against IP-based timezone.
- `navigator.language`.
- Do Not Track (DNT).
- Script/plugin support flags: JavaScript, Java, Flash, ActiveX, VBScript, Cookies enabled.
- WebRTC STUN probe for local (RFC1918) and public IP.

### Server-side (IP / DNS / TCP / HTTP headers)
- Public IP, country/region/city, ISP, ASN, ZIP, hosting/datacenter classification.
- IP blacklist / DNSBL status.
- DNS resolver IP(s) and their geolocation (DNS leak / DNS-vs-IP mismatch).
- HTTP request headers, including proxy-revealing headers (Via, X-Forwarded-For / Forwarded, Client-IP).
- Open network ports on connecting IP (port scanner).
- Proxy checker across HTTP / HTTPS / SOCKS5.
- VPN / anonymizer detection.
- (Inferred, unverified for whoer) passive TCP/IP OS fingerprint of connecting stack; two-way ping + MTU tunnel heuristics.
- Speed test (download/upload + ping).

### Behavioral
- None. No mouse/keystroke biometrics, no session/velocity analysis, no challenge. Static per-load snapshot.

## How it scans (architecture)

**Hybrid, client + server, correlated.**

- **Client side:** JavaScript in visitor's browser gathers fingerprint and leak signals (canvas, WebGL, fonts, screen, navigator/UA, plugins, timezone, language, DNT, script-support flags), runs WebRTC STUN probe and DNS-leak test (browser induced to make requests to whoer-controlled resolvers). Results sent to whoer's backend to be scored and rendered.
- **Server side:** backend independently analyzes connection it can't see from JS — source IP geo/ASN/blacklist, HTTP header inspection for proxy signatures, open-port scans against client IP, and (plausibly) passive TCP/IP fingerprinting and latency/MTU tunnel heuristics.
- **Decision:** score computed server-side by **correlating** the two — e.g. JS-reported timezone/OS vs server-observed IP-geo, DNS egress, connection characteristics. Mismatches between browser-claimed identity and network-observed reality are the substance of the deduction.

No specific ingestion/scoring endpoint captured firsthand for whoer (unlike some sibling tools in this set), so no endpoint asserted here.

## Scoring / output

- **Headline:** "Your disguise: N%" (0–100), color-coded — green/high = looks like consistent real user with no leaks; red/low = leaks or anomalies.
- **Level of insecurity:** Low / Medium / High bar.
- **Per-signal detail:** IP block (IP, geo, ISP, ASN), Proxy / Anonymizer / Blacklist flags (Yes/No), browser & OS, WebRTC/DNS leak results, enabled-tech flags, any surfaced inconsistencies (e.g. timezone-name mismatch we saw).
- **Computation:** heuristic deduction from 100% per detected problem; weights undisclosed; **inverted polarity** vs bot score (high is good).

## Notable techniques

- **Cross-checking browser-claimed identity against network-observed reality** as entire detection philosophy — reusable idea for bot-or-not builder.
- **Timezone (JS) vs IP-geo mismatch** as masking tell (what fired on our test browser: `Europe/Istanbul` zone but "Moscow Standard Time" system label).
- **DNS-vs-IP geolocation correlation** — DNS should egress through same proxy/VPN as traffic, else score drops.
- **WebRTC STUN probe** to leak true local/public IP behind VPN.
- **Interactive/extended test** surfacing system settings and vulnerabilities (see Verification notes — earlier descriptions of Flash/Java "unmasking real IP" overstate what sources support).
- (Inferred, unverified for whoer) two-way ping + MTU asymmetry and passive TCP/IP OS fingerprinting to betray tunnel even when UA spoofed.

## What we observed firsthand

Running in-app browser (Claude/Electron 42.5.1, Chrome 148, macOS) through free check:

- **Disguise: 100%**, Level of insecurity: Low.
- IP `87.249.139.226`, Istanbul; ISP "Datacamp"; Proxy: No; Anonymizer: No; Blacklist: No.
- Browser reported as **Chrome 148 — Electron NOT detected**; OS = Mac OS X.
- **Only anomaly surfaced:** timezone-name mismatch — Time Zone `Europe/Istanbul` vs system time labeled "Moscow Standard Time" (zone-vs-system inconsistency).

Significance for anti-bot builder: whoer gave our automated, datacenter-egress browser perfect anonymity score, didn't identify it as Electron or automation-driven. Contrast with deviceandbrowserinfo.com, flagged same browser as bot purely via CDP detection. whoer's IP even resolved as plain "Datacamp" datacenter without Proxy/Anonymizer/Blacklist flag firing. Takeaway: **anonymity/consistency checker is not an automation detector** — can pass headless/CDP-driven browser as long as its self-reported signals are internally consistent and it isn't leaking. No fingerprint POST endpoint or worker captured for whoer this session.

## Verification notes

Research findings reviewed adversarially; following corrected or flagged, this document already reflects them:

- **Flash/Java "unmask the real IP behind a proxy" — overstated.** Sources confirm interactive/extended test revealing system settings and vulnerabilities, and whoer flags ActiveX/Java/VBScript *support*, but none states Flash/Java applets were used specifically to expose real IP behind proxy. Softened to "surfaces system settings and vulnerabilities."
- **Server-side TCP/IP fingerprinting, two-way-ping and MTU heuristics — attribution uncertain.** Primarily described by competitor (thesafety.us) documenting its *own* whoer-style checker, not by whoer's own docs. Labeled "inferred, unverified for whoer" here rather than stated as fact.
- **"Concealed/privacy-protected WHOIS" — dropped.** Sources corroborate general lack of corporate disclosure (no phone number) but don't confirm domain WHOIS is privacy-protected.
- **`berdof/whoer` GitHub repo — not a clone.** Exists but is minimal Node/JS app with no description or stated purpose; couldn't be confirmed to reimplement whoer.net. Treated as unrelated/unverified third-party repo, not whoer's engine.

Angles research didn't resolve (relevant to bot-or-not builder):

- **Headless/automation detection is unconfirmed.** Not established whether whoer surfaces `navigator.webdriver`, CDP artifacts, HeadlessChrome UA, or Puppeteer/Playwright/Selenium tells at all. Firsthand evidence suggests it's weak here — didn't detect our Electron/automation environment.
- **TLS ClientHello (JA3/JA4) and HTTP/2 frame/SETTINGS fingerprinting** not mentioned; research covers TCP layer only. Absence at TLS/HTTP2 layer is notable gap vs modern network-level detection.
- **AudioContext fingerprinting, User-Agent Client Hints (Sec-CH-UA) consistency, device attributes** (`hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`) not enumerated in whoer's signal set.
- **No session/rate/challenge dimension** — whoer is single page-load snapshot: no request-cadence analysis, no rate limiting, no active challenge (CAPTCHA / JS proof-of-work). Bounds what it can detect vs real anti-bot stack.

Overall confidence: medium. whoer.net blocked direct fetching, so research rests on secondary technical reviews (several from proxy/antidetect vendors) plus firsthand browser observation. Core facts — freemium/WHOIX-Cyprus, signal list, client+server split, consistency-based heuristic score, closed source — corroborated; exact server-side mechanics and scoring formula not confirmed from whoer's own documentation.

## Open source / reusable

**None usable.** whoer's engine closed source. `berdof/whoer` repo is unrelated/unverified third-party JS app, not whoer's engine, shouldn't be treated as reimplementation. Builder wanting whoer-style consistency checks should reuse the *technique* (cross-check browser-claimed identity vs network-observed reality) rather than any whoer code, pull actual collector code from open-source tools documented elsewhere in this set (e.g. fp-collect/fp-scanner, CreepJS, MixVisit).

## Sources

- [NodeMaven — Whoer.net: What It Is, How It Works & How to Stay Undetected Online](https://nodemaven.com/blog/whoer-net/)
- [Undetectable.io — Whoer.net and Antidetect Browser: How to Check Anonymity](https://undetectable.io/whoer/)
- [Dolphin{anty} — Whoer.net Review: Is Your Online Anonymity Real?](https://dolphin-anty.com/blog/en/whoer-review/)
- [BitBrowser — Whoer.net Review 2025](https://www.bitbrowser.net/blog/whoer-review)
- [AlwaysVPN — Whoer VPN Review (WHOIX LTD, Cyprus)](https://www.alwaysvpn.com/reviews/whoer)
- [GitHub — berdof/whoer (unrelated/unverified third-party JS repo, not whoer's engine)](https://github.com/berdof/whoer)
- [whoer.net (service)](https://whoer.net/)
