# whoer.net

An anonymity / "disguise" checker that scores how consistent and leak-free your connection looks. It is a privacy/anonymity tool, not a dedicated bot classifier: it detects proxies, VPNs, and fingerprint inconsistencies (which overlap with, but are not the same as, automation detection).

- **URL:** https://whoer.net/ · **Category:** privacy/anonymity + fingerprint tool (freemium marketing funnel for the paid Whoer VPN) · **Requires registration:** No for the free basic and extended browser checks; an account/promo only gates the paid Whoer VPN and some extended features.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP `87.249.139.226` = NordVPN/DataCamp datacenter, Istanbul): **"Your disguise: 100%"**, Level of insecurity = Low. IP `87.249.139.226`, Istanbul, ISP "Datacamp", Proxy: No, Anonymizer: No, Blacklist: No. It reported Browser = **Chrome 148 and did NOT detect Electron**, OS = Mac OS X. The one anomaly it surfaced was a timezone-name mismatch (Time Zone = `Europe/Istanbul` while the system time was labeled "Moscow Standard Time"). Net: it did not flag our datacenter-egress automated browser as suspicious.

## What it is — common info

whoer.net is a consumer-facing "how anonymous do I look / is my connection leaking" diagnostic. It is run by WHOIX LTD, registered in Strovolos, Nicosia, Cyprus, and has operated in some form since roughly 2008 (ownership is otherwise opaque). The free checker exists primarily as lead-gen / trust-builder for the paid **Whoer VPN**: it shows an "anonymity percentage" plus any leaks, then positions the VPN as the fix.

Its real-world audience skews heavily toward the antidetect-browser / multi-accounting / proxy community — people validating that a masked setup "looks like a genuine, consistent human user." The page carries heavy antidetect marketing (WADE X multi-account browser, Decodo proxies). Because of that audience, its framing is consistency-and-leaks, not automation-per-se.

Note the semantic inversion versus an anti-bot vendor: whoer's headline number is an **anonymity/"disguise" score where HIGH is the clean/desirable result**, the opposite of a "bot probability" where high is bad.

## Registration / access

The free web check (both the basic view and the extended/interactive tests) runs in the browser on page load with no login. Registration only applies to the paid/trial Whoer VPN, a separate freemium funnel. (This split is corroborated indirectly by secondary reviews rather than whoer's own docs — medium confidence.)

## How it decides bot-or-not

whoer does not produce a bot/human verdict. It produces a single **"disguise" percentage (0–100%)** plus a "Level of insecurity" bar (Low/Medium/High). The number starts high and is **deducted** for each detected problem or inconsistency:

- A WebRTC or DNS leak that exposes the real IP behind a proxy/VPN.
- Timezone (from JS) not matching the IP's geolocation.
- `navigator.language` / Accept-Language not matching the IP region.
- DNS resolver geolocation not matching the connection's proxy/VPN egress.
- A blacklisted, datacenter, or proxy/VPN-classified IP.
- Proxy-revealing HTTP headers present.
- Enabled script/plugin surfaces (Java, Flash, ActiveX) and other fingerprint tells.

The core philosophy is **consistency**: cross-check what the browser *claims* (UA, OS, timezone, language) against what the network *reveals* (IP geo/ASN, DNS egress, blacklist, connection characteristics). Mismatches lower the score. It is a heuristic/rule-based tally, not an ML classifier, and the exact weights are undisclosed. A 100% "disguise" does not guarantee a target site won't block you — it only means whoer found no leaks or internal contradictions.

## Detection approaches

- **Browser/device fingerprinting** — client-side JS collecting navigator/UA, canvas, WebGL, fonts, screen, plugins, timezone, language, DNT, and script-support flags.
- **IP / proxy / VPN / datacenter reputation + DNSBL blacklist lookups** — server-side.
- **Leak detection** — WebRTC STUN local/public IP leak; DNS leak (browser makes requests to whoer-controlled resolvers, correlated server-side).
- **Server-side connection analysis** — HTTP header inspection for proxy signatures; open-port scan against the connecting IP. Passive TCP/IP OS fingerprinting and two-way-ping/MTU tunnel heuristics are *plausibly* used but not confirmed for whoer specifically (see Verification notes).
- **Cross-signal consistency checking** (rule/heuristic) — IP-geo vs DNS-geo vs timezone vs Accept-Language vs OS/UA must agree.
- **Persistent-tracking test** — Evercookie / supercookie persistence.
- **NOT observed:** ML bot scoring, mouse/keystroke behavioral biometrics, request-cadence/rate analysis, or an active CAPTCHA/proof-of-work challenge. The score is a single page-load snapshot.

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
- Open network ports on the connecting IP (port scanner).
- Proxy checker across HTTP / HTTPS / SOCKS5.
- VPN / anonymizer detection.
- (Inferred, unverified for whoer) passive TCP/IP OS fingerprint of the connecting stack; two-way ping + MTU tunnel heuristics.
- Speed test (download/upload + ping).

### Behavioral
- None. No mouse/keystroke biometrics, no session/velocity analysis, no challenge. This is a static per-load snapshot.

## How it scans (architecture)

**Hybrid, client + server, correlated.**

- **Client side:** JavaScript in the visitor's browser gathers the fingerprint and leak signals (canvas, WebGL, fonts, screen, navigator/UA, plugins, timezone, language, DNT, script-support flags) and runs the WebRTC STUN probe and DNS-leak test (the browser is induced to make requests to whoer-controlled resolvers). Results are sent to whoer's backend to be scored and rendered.
- **Server side:** the backend independently analyzes the connection it cannot see from JS — source IP geo/ASN/blacklist, HTTP header inspection for proxy signatures, open-port scans against the client IP, and (plausibly) passive TCP/IP fingerprinting and latency/MTU tunnel heuristics.
- **Decision:** the score is computed server-side by **correlating** the two — e.g. JS-reported timezone/OS vs server-observed IP-geo, DNS egress, and connection characteristics. Mismatches between browser-claimed identity and network-observed reality are the substance of the deduction.

No specific ingestion/scoring endpoint was captured firsthand for whoer (unlike some sibling tools in this set), so no endpoint is asserted here.

## Scoring / output

- **Headline:** "Your disguise: N%" (0–100), color-coded — green/high = looks like a consistent real user with no leaks; red/low = leaks or anomalies.
- **Level of insecurity:** Low / Medium / High bar.
- **Per-signal detail:** IP block (IP, geo, ISP, ASN), Proxy / Anonymizer / Blacklist flags (Yes/No), browser & OS, WebRTC/DNS leak results, enabled-tech flags, and any surfaced inconsistencies (e.g. the timezone-name mismatch we saw).
- **Computation:** heuristic deduction from 100% per detected problem; weights undisclosed; **inverted polarity** vs a bot score (high is good).

## Notable techniques

- **Cross-checking browser-claimed identity against network-observed reality** as the entire detection philosophy — the reusable idea for a bot-or-not builder.
- **Timezone (JS) vs IP-geo mismatch** as a masking tell (this is what fired on our test browser: `Europe/Istanbul` zone but "Moscow Standard Time" system label).
- **DNS-vs-IP geolocation correlation** — DNS should egress through the same proxy/VPN as the traffic, else the score drops.
- **WebRTC STUN probe** to leak the true local/public IP behind a VPN.
- An **interactive/extended test** that surfaces system settings and vulnerabilities (see Verification notes — earlier descriptions of Flash/Java "unmasking the real IP" overstate what the sources support).
- (Inferred, unverified for whoer) two-way ping + MTU asymmetry and passive TCP/IP OS fingerprinting to betray a tunnel even when the UA is spoofed.

## What we observed firsthand

Running the in-app browser (Claude/Electron 42.5.1, Chrome 148, macOS) through the free check:

- **Disguise: 100%**, Level of insecurity: Low.
- IP `87.249.139.226`, Istanbul; ISP "Datacamp"; Proxy: No; Anonymizer: No; Blacklist: No.
- Browser reported as **Chrome 148 — Electron was NOT detected**; OS = Mac OS X.
- **The only anomaly surfaced:** a timezone-name mismatch — Time Zone `Europe/Istanbul` vs system time labeled "Moscow Standard Time" (a zone-vs-system inconsistency).

Significance for an anti-bot builder: whoer gave our automated, datacenter-egress browser a perfect anonymity score and did not identify it as Electron or as automation-driven. Contrast this with deviceandbrowserinfo.com, which flagged the same browser as a bot purely via CDP detection. whoer's IP even resolved as a plain "Datacamp" datacenter without a Proxy/Anonymizer/Blacklist flag firing. The takeaway: **an anonymity/consistency checker is not an automation detector** — it can pass a headless/CDP-driven browser as long as its self-reported signals are internally consistent and it isn't leaking. No fingerprint POST endpoint or worker was captured for whoer this session.

## Verification notes

The research findings were reviewed adversarially; the following were corrected or flagged, and this document already reflects them:

- **Flash/Java "unmask the real IP behind a proxy" — overstated.** Sources confirm an interactive/extended test that reveals system settings and vulnerabilities, and that whoer flags ActiveX/Java/VBScript *support*, but none states Flash/Java applets were used specifically to expose the real IP behind a proxy. Softened to "surfaces system settings and vulnerabilities."
- **Server-side TCP/IP fingerprinting, two-way-ping and MTU heuristics — attribution uncertain.** These are primarily described by a competitor (thesafety.us) documenting its *own* whoer-style checker, not by whoer's own docs. They are labeled "inferred, unverified for whoer" here rather than stated as fact.
- **"Concealed/privacy-protected WHOIS" — dropped.** Sources corroborate a general lack of corporate disclosure (no phone number) but do not confirm the domain WHOIS is privacy-protected.
- **`berdof/whoer` GitHub repo — not a clone.** It exists but is a minimal Node/JS app with no description or stated purpose; it could not be confirmed to reimplement whoer.net. Treated as an unrelated/unverified third-party repo, not whoer's engine.

Angles the research did not resolve (relevant to a bot-or-not builder):

- **Headless/automation detection is unconfirmed.** It is not established whether whoer surfaces `navigator.webdriver`, CDP artifacts, HeadlessChrome UA, or Puppeteer/Playwright/Selenium tells at all. Firsthand evidence suggests it is weak here — it did not detect our Electron/automation environment.
- **TLS ClientHello (JA3/JA4) and HTTP/2 frame/SETTINGS fingerprinting** are not mentioned; the research covers the TCP layer only. Absence at the TLS/HTTP2 layer is a notable gap versus modern network-level detection.
- **AudioContext fingerprinting, User-Agent Client Hints (Sec-CH-UA) consistency, and device attributes** (`hardwareConcurrency`, `deviceMemory`, `maxTouchPoints`) are not enumerated in whoer's signal set.
- **No session/rate/challenge dimension** — whoer is a single page-load snapshot: no request-cadence analysis, no rate limiting, no active challenge (CAPTCHA / JS proof-of-work). This bounds what it can detect versus a real anti-bot stack.

Overall confidence: medium. whoer.net blocked direct fetching, so the research rests on secondary technical reviews (several from proxy/antidetect vendors) plus firsthand browser observation. Core facts — freemium/WHOIX-Cyprus, the signal list, the client+server split, the consistency-based heuristic score, and closed source — are corroborated; exact server-side mechanics and the scoring formula are not confirmed from whoer's own documentation.

## Open source / reusable

**None usable.** whoer's engine is closed source. The `berdof/whoer` repo is an unrelated/unverified third-party JS app, not whoer's engine, and should not be treated as a reimplementation. A builder wanting whoer-style consistency checks should reuse the *technique* (cross-check browser-claimed identity vs network-observed reality) rather than any whoer code, and pull actual collector code from the open-source tools documented elsewhere in this set (e.g. fp-collect/fp-scanner, CreepJS, MixVisit).

## Sources

- [NodeMaven — Whoer.net: What It Is, How It Works & How to Stay Undetected Online](https://nodemaven.com/blog/whoer-net/)
- [Undetectable.io — Whoer.net and Antidetect Browser: How to Check Anonymity](https://undetectable.io/whoer/)
- [Dolphin{anty} — Whoer.net Review: Is Your Online Anonymity Real?](https://dolphin-anty.com/blog/en/whoer-review/)
- [BitBrowser — Whoer.net Review 2025](https://www.bitbrowser.net/blog/whoer-review)
- [AlwaysVPN — Whoer VPN Review (WHOIX LTD, Cyprus)](https://www.alwaysvpn.com/reviews/whoer)
- [GitHub — berdof/whoer (unrelated/unverified third-party JS repo, not whoer's engine)](https://github.com/berdof/whoer)
- [whoer.net (service)](https://whoer.net/)
