# BrowserScan.net

Free, no-login browser-FP & bot-detection checker for anti-detect-browser / multi-accounting crowd: how detectable & consistent your (often spoofed) browser looks. Output = categorical bot verdict + numeric "authenticity" trust score.

- **URL:** https://www.browserscan.net/bot-detection (bot verdict) · https://www.browserscan.net/ (full FP + trust score) · https://www.browserscan.net/tls (TLS/HTTP2) · **Category:** privacy/anonymity FP tool, self-test for anti-detect-browser ecosystem (AdsPower, Multilogin, GoLogin, Dolphin Anty, etc.); not open-source test page, not enterprise vendor demo · **Registration:** No (scan on load; optional Google "Sign in"/"Join now" not needed).
- **Firsthand verdict, test browser** (in-app = `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): **"Normal"**, not flagged. Every framework check "Normal," CDP category didn't trip despite browser genuinely CDP-driven. Miss: same browser flagged bot by deviceandbrowserinfo.com solely on `isAutomatedWithCDP`; Fingerprint.com reported Developer Tools = Yes. BrowserScan CDP detection missed it.

## What it is — common info

Free public FP checker. Stated purpose: show full FP + "browser FP authenticity" score -> judge identifiability/consistency. Real audience = anti-detect-browser & multi-accounting community: confirm spoofed profile looks like coherent real browser w/ no leak of real IP/timezone/automation traces. Companion blog (blog.browserscan.net) = content hub reviewing anti-detect browsers -> places site in that ecosystem; firsthand recon noted AdsPower affiliation/banners. Owner undisclosed, unconfirmed from primary sources -> ownership low-confidence.

Don't conflate: **BrowserScan.net** (live, closed source) vs **browserscan.org**, separate open-source lookalike (GitHub `browerscan/browerscan`), different Next.js/Cloudflare codebase. `.org` repo not source of `.net`; implements similar "deduction-based 0–100 scoring" idea.

## Registration / access

None. Load runs scan automatically w/in few sec. Optional sign-in gates nothing in free self-test. (Caveat: "no registration/payment" corroborated firsthand + one third-party review, not by BrowserScan own docs — see Verification notes.)

## How it decides bot-or-not

Two surfaces, two output styles:

- **`/bot-detection` subpage**: *categorical* verdict. Battery of named automation-framework checks + per-signal checks (Webdriver, UA, CDP, Navigator), each "Normal" or flagged. Top-line: category label (**Normal** vs bot type). No %.
- **Home page**: *numeric* **Trust Score (0–100%)** = "FP authenticity" over full FP (canvas, WebGL, audio, fonts, hardware, WebRTC, timezone/geo, TLS, etc.). Deduction/consistency model: start high, subtract per anomaly/leak/spoofing tell (timezone vs IP geo mismatch, WebRTC real-IP leak, UA vs platform mismatch, automation traces, TLS-vs-UA mismatch). Flagged items red; higher = more coherent/"human-looking."

Score = "does this look like coherent, non-automated, real browser that blends in" = authenticity/consistency, not probabilistic bot likelihood. Site frames checks as same as Cloudflare Turnstile & Google reCAPTCHA; splits "good bots" (search crawlers) vs "malicious bots" (Selenium/Puppeteer/Playwright).

## Detection approaches

- **Browser fingerprinting** — canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext, fonts, media devices, ClientRects, screen, hardware & navigator attrs; all client-side.
- **Headless/automation detection** — `navigator.webdriver`, CDP usage, named framework battery: WebDriver, WebDriver Advance, Selenium, NightmareJS, PhantomJS, Awesomium, CEF, CefSharp, Coaches, FMiner, Born, Phantomas, Rhino, WebdriverIO, Headless Chrome (all observed firsthand, all "Normal" for test browser).
- **Deception/spoofing-anomaly detection** — "Native Navigator" check dumps full navigator (incl. `userAgentData`), tests each method's `Function.prototype.toString()` for `"[native code]"` -> catch monkey-patched/overridden props from anti-detect tooling.
- **Consistency cross-checks** — timezone vs IP geo, UA vs actual platform, WebRTC-exposed IP vs proxy egress IP, & (per research) TLS/JA3 vs browser UA claims.
- **Network/TLS/HTTP2 fingerprinting** — server-side JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions + Akamai-format HTTP/2 FP (SETTINGS frame, WINDOW_UPDATE, stream priority, pseudo-header ordering). On `/tls`.
- **IP/proxy/geo reputation** — IP, ISP, proxy detection, geo, DNS leak, IPv6 leak.
- **Port scanning** — probes e.g. 22 (SSH) & 3389 (RDP) -> reveal server/VPS/remote-desktop env (per research).
- **Rule/deduction-based scoring**, no documented ML classifier. Behavioral timing (typing/mouse) = documented technique, not clearly part of automated one-page scan.

## Areas / signals scanned

**Client-side (JS):**
- `navigator` props + "deceptive"/modified props; `navigator.webdriver`; `userAgentData`.
- CDP traces; Selenium/WebDriver artifact keys; PhantomJS/NightmareJS/CEF/CefSharp/Awesomium markers.
- Canvas (`toDataURL`), WebGL vendor/renderer, WebGPU, AudioContext FP.
- Installed fonts, media devices, ClientRects.
- Screen resolution, color depth, touch support; GPU, `hardwareConcurrency`, `deviceMemory`.
- Languages/Intl; plugins; incognito detection.
- WebRTC IP leak (real IP behind VPN/proxy).
- Cookies enabled, Do Not Track.
- Legacy Java/Flash/ActiveX plugin section — dead in modern browsers; low-value legacy signal, not active vector.

**Server-side (IP/TLS/TCP/HTTP headers):**
- IP, ISP, proxy detection, geo (country/region/city/postal/lat-long); DNS leak, IPv6 leak.
- Timezone/local time vs IP geo.
- TLS/SSL: JA3, JA3 hash, JA4, cipher suites, extensions, key-exchange groups, protocol versions.
- HTTP/2: SETTINGS, WINDOW_UPDATE, stream priority, pseudo-header ordering, Akamai FP (hash + text).
- Open-port scan (22 SSH, 3389 RDP).

**Behavioral:** documented (typing/mouse timing), not clearly wired into automated scan; don't assume runs on load.

## How it scans (architecture)

Hybrid, meaningful client/server split.

- Bulk of FP collected **client-side** by JS bundle (`dist/*.js`). Also spins up **`blob:` Web Worker** to recompute FP in 2nd JS context — standard cross-context trick exposing spoofing that only patches main window.
- **Firsthand network observation:** `/bot-detection` **did not POST** results anywhere — categorical verdict computed/rendered in-browser. Home-page trust-score flow **does POST** collected FP to **`api.browserscan.net`**. So: bot verdict client-only (observed), trust score = backend round-trip.
- **TLS/SSL & HTTP/2 FPs inherently server-side** — from raw ClientHello & HTTP/2 setup frames of incoming connection, which client JS can't produce. IP/geo/proxy/port-scan likewise server-side. Lets backend independently fingerprint actual connection, compare to client JS claim (e.g. Chrome UA whose JA3 doesn't look Chrome). Exact wiring correlating the two not published — correlation inferred, not documented.

Net: decision surface split — categorical bot checks resolve client-side; trust score & all network-layer analysis need backend.

## Scoring / output

- **`/bot-detection`:** discrete per-category results (Normal vs flagged) across Webdriver, UA, CDP, Navigator + framework battery — categorical verdict, no %.
- **Home page:** single **Trust Score % (0–100%)**, deduction-based. 100% = no issues; problem items red. Independent guidance cites ~90% as rough "looks unique/inconsistent" threshold. Closest thing to unified number — home page, **not** bot-detection page.

## Notable techniques

- `Function.prototype.toString()` `[native code]` probing across navigator methods -> detect overridden/patched props — detects *spoofing itself*, not just spoofed value.
- `blob:` Web Worker cross-context recomputation -> catch masks covering only main window.
- Named framework battery (15+ automation tools) reported individually, not one opaque score.
- Server-observed JA3/JA4 + Akamai HTTP/2 FP -> catch handshake-vs-claimed-browser mismatches.
- Port scan (22/3389) -> expose server/VPS/RDP setups betraying non-consumer env.
- Consistency triangulation: timezone vs IP geo, UA vs platform, WebRTC IP vs egress IP.

## What we observed firsthand

- Verdict: **"Normal"** (not bot). All framework checks Normal; CDP & Dev Tool categories present but not tripped, despite genuinely CDP-driven Electron browser. Under-detected vs peers — concrete data point: CDP/automation detection weaker than deviceandbrowserinfo.com's (flagged identical browser on CDP alone).
- Native Navigator check dumped full navigator incl. `userAgentData`, applied `[native code]` toString test.
- Architecture confirmed by traffic: client-side `dist/*.js` bundle + `blob:` Web Worker. **`/bot-detection` issued no results POST.** Home-page trust-score flow POSTed FP to **`api.browserscan.net`**.

## Verification notes

Adversarial review confirmed research well-supported; corrections folded in above:

- **CapMonster review not "independent," only one exists.** "Multiple independent reviews confirm no registration/payment" overstated: exactly one third-party review found (capmonster.cloud), from CAPTCHA-solving vendor in same anti-detect ecosystem — promotional, not neutral audit. Factual sub-claims (50+ data points, canvas `toDataURL`, no login) check out; neutrality doesn't. Report treats "no registration" as corroborated by firsthand observation, not that review.
- **Citation looseness on "no registration":** cited BrowserScan how-to-use doc doesn't state registration unnecessary, only describes visiting & waiting. Claim almost certainly true (scan on load) but not documented at cited source.
- **Don't attach trust % to bot-detection page.** `/bot-detection` shows discrete Webdriver/UA/CDP/Navigator pass-fail; 0–100% authenticity score = home page.
- **`browserscan.net` ≠ `browserscan.org`.** GitHub `browerscan/browerscan` = separate open-source lookalike for `.org`, not `.net` source. Don't collapse.
- **Legacy plugin detection (Flash/ActiveX/Java) anachronistic** — dead legacy section, low-value not active vector.
- **Ownership unconfirmed** (low confidence), **client↔server correlation inferred**, not documented verbatim.

Gaps anti-bot engineer should note (stronger builder would add, several not clearly covered):

- **UA Client Hints triangulation** — cross-check legacy UA string, JS `navigator.userAgentData`, `Sec-CH-UA`/`Sec-CH-UA-Platform`/`Sec-CH-UA-Mobile` headers. Anti-detect browsers frequently desync these three; primary 2024+ surface.
- **Canvas/audio/WebGL noise-injection detection** — arguably core reason audience uses it, yet not surfaced. Anti-detect browsers randomize canvas/audio per session; strong checker detects non-determinism (or statistically improbable hashes) across repeated reads, not just one `toDataURL`.
- **Property-level headless tells** — `Notification.permission === 'denied'` while `permissions.query` state `'default'`; empty `navigator.plugins`/`mimeTypes`; missing `window.chrome` runtime; empty `navigator.languages`. BrowserScan names webdriver/CDP but not these classics.
- **TLS ordering + GREASE** — cipher-suite/extension *order* & GREASE pattern must match exact Chrome/Firefox build UA claims; reordered ClientHello from Go/Python/`curl-impersonate` = giveaway. State ordering dimension explicitly, not "mismatch" abstractly.
- **Passive TCP/IP (p0f-style) OS fingerprinting** — compare OS inferred from TCP options/window size/TTL vs UA-claimed OS. Almost certainly **out of scope** for BrowserScan JS+TLS design; note gap deliberately (incolumitas covers it; BrowserScan doesn't).
- **Cross-tab/storage/TLS-session-resumption re-identification** — no evidence BrowserScan probes `localStorage`/IndexedDB persistence, evercookie stability, or TLS session-ticket resumption to link "fresh" profile to prior visit.

## Open source / reusable

**None for BrowserScan.net itself** — closed source. GitHub `browerscan/browerscan` = *separate* open-source lookalike backing browserscan.org (Next.js/Cloudflare, deduction-based 0–100 scoring); usable as reference for scoring *idea*, not BrowserScan.net code, lacks server-side TLS/HTTP2/IP machinery.

## Sources

- [BrowserScan — home (fingerprint + trust score)](https://www.browserscan.net/)
- [BrowserScan — bot detection page (Webdriver / User-Agent / CDP / Navigator)](https://www.browserscan.net/bot-detection)
- [BrowserScan — HTTP2/SSL/TLS fingerprint page (JA3, JA4, Akamai)](https://www.browserscan.net/tls)
- [BrowserScan docs — Bot Detection (webdriver, _selenium markers, behavioral timing)](https://blog.browserscan.net/docs/bot-detection)
- [BrowserScan docs — How to Use BrowserScan](https://blog.browserscan.net/docs/how-to-use-browserscan)
- [CapMonster — BrowserScan Review 2025 (third-party, promotional / same-ecosystem)](https://capmonster.cloud/en/blog/browserscan-review-2025/)
- [GitHub — browerscan/browerscan (separate open-source project for browserscan.ORG; not browserscan.net's code)](https://github.com/browerscan/browerscan)
