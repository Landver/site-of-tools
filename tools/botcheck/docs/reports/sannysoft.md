# bot.sannysoft.com

Free, client-side "antibot" diagnostic page running three well-known open-source headless/fingerprint test suites in your browser, renders each check as green (human-like) or red (bot-like) table row. A leak checklist for automation authors, not a scoring engine.

- **URL:** https://bot.sannysoft.com/ · **Category:** open-source test page (community-hosted aggregation of open-source suites; not commercial vendor demo, not paid product) · **Requires registration:** No — load URL, JS tests run immediately.
- **Firsthand verdict for test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): No aggregate verdict emitted — page is per-test pass/fail table read by human. Test browser passed headline checks (`navigator.webdriver` missing → pass; `window.chrome` present → pass; real WebGL renderer "Apple M5 / Metal", not SwiftShader → pass) but produced at least one red row: **HEADCHR_IFRAME FAILED** (`window.chrome`-inside-iframe consistency check). Since sannysoft is 100% client-side, datacenter/VPN egress IP completely invisible to it — structural blind spot, not a pass.

## What it is — common info

`bot.sannysoft.com`: convenience aggregation page widely used by scraping/automation community to check whether headless or automated browser (Puppeteer, Playwright, Selenium, undetected-chromedriver, stealth plugins) leaks tell-tale signals. Bundles and runs, in visitor's own browser, three open-source test suites, paints results as color-coded tables:

1. **Intoli's headless-Chrome detection tests** — from Evan Sangaline / Intoli (2017–2018 blog posts "Making Chrome Headless Undetectable" and "It is *not* possible to detect and block Chrome headless").
2. **fp-scanner** — Antoine Vastel's bot-detection library (`antoinevastel/fpscanner`).
3. **fp-collect** — Antoine Vastel's fingerprint-collection module (`antoinevastel/fp-collect`), which produces the fingerprint object fp-scanner analyzes.

Antoine Vastel: device-fingerprinting / bot-detection researcher (formerly VP of Research at DataDome; currently Head of Research at Castle). Operator of `sannysoft.com` domain itself not documented in accessible primary sources; page functions as community-run mirror of these open tools rather than branded vendor product. Heavily cited (Hacker News, puppeteer-extra issues), considered somewhat dated: core checks derive from 2017–2019 PhantomJS/Selenium/early-headless-Chrome era.

## Registration / access

None. No account, login, signup, or API key. Tests execute the moment page loads, render locally. Verified firsthand — no auth wall, no registration prompt.

## How it decides bot-or-not

Doesn't, in the sense a vendor scorer does. **No aggregate bot score, no server verdict.** fp-collect gathers fingerprint object in-browser (`fpCollect.generateFingerprint()`); fp-scanner and inline Intoli tests inspect that object plus few live DOM/API probes; each individual check written into HTML table row with observed value, colored green (consistent with normal human browser) or red (bot-like leak). Human reads the table. Community convention: "all rows green" means automated browser well-masked; any red row is leak a real anti-bot vendor could exploit.

## Detection approaches

- **Browser fingerprinting** — navigator/JS object inspection, canvas, WebGL, audio/video codec support, screen geometry, media-device enumeration.
- **Headless-browser detection** — `HeadlessChrome` UA token, missing `window.chrome`, headless default screen resolution, SwiftShader/Mesa software WebGL renderer, zero-length plugins.
- **Automation-framework marker detection** — `navigator.webdriver`, Selenium/`$cdc_`/`$wdc_` globals, PhantomJS, NightmareJS, Sequentum crawler, debug-tool hints.
- **Consistency / anti-spoofing checks** — Permissions API vs `Notification.permission` mismatch, navigator-prototype tampering, cross-context checks (e.g. `window.chrome` inside iframe), canvas rendered in sandboxed iframes, error-stack / error-string anomalies, recursion stack-overflow message (PhantomJS tell).
- **Not present:** behavioral biometrics, ML scoring, and (structurally) any network/TLS/IP-side analysis — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the entire surface

Grouped as live page groups them (per firsthand observation):

- **"Intoli.com tests + additions":** User Agent, WebDriver (`navigator.webdriver` present/absent), WebDriver Advanced (descriptor/writability), Chrome (`window.chrome` present), Permissions (Permissions API vs `Notification.permission`), Plugins Length + `PluginArray` type, Languages (`navigator.languages`), WebGL Vendor/Renderer, Broken Image Dimensions (0×0).
- **fp-scanner battery (Vastel):** PHANTOM_UA, PHANTOM_PROPERTIES, PHANTOM_ETSL, PHANTOM_LANGUAGE, PHANTOM_WEBSOCKET, MQ_SCREEN (media-query/screen), PHANTOM_OVERFLOW (recursion stack overflow), PHANTOM_WINDOW_HEIGHT, HEADCHR_UA (HeadlessChrome token), HEADCHR_CHROME_OBJ, HEADCHR_PERMISSIONS, HEADCHR_PLUGINS, **HEADCHR_IFRAME** (chrome-in-iframe — *failed for test browser*), CHR_DEBUG_TOOLS, SELENIUM_DRIVER, CHR_BATTERY, CHR_MEMORY (`deviceMemory`), TRANSPARENT_PIXEL, SEQUENTUM, VIDEO_CODECS.
- **"Some details" dump:** full `navigator.*` property dump, `screen.*` (width/height/avail/colorDepth/pixelDepth, window inner/outer, `devicePixelRatio`), canvas hashes (Canvas1–5 including iframe/sandboxed variants), `getBattery`.
- **"Fp-collect info":** full JSON fingerprint dump — plugins, mimeTypes, UA, platform, languages, screen, WebGL, touch, media devices, `navigatorPrototype`, etc.

Additional fp-collect / Intoli signals documented in suites' sources: `navigator.platform`/`productSub`, Modernizr hairline (0.5px border `offsetHeight`) feature, touchscreen support, multimedia-device enumeration (speakers/mics/webcams), `navigatorPrototype` descriptor walk (spoofed-getter detection), `etsl` (error-to-string length; `e.toString().length`), `resOverflow`, automation globals (`$cdc_`/`$wdc_`, `__selenium`/`__webdriver`, `_phantom`/`callPhantom`, `__nightmare`, Sequentum via `window.external`).

### Server-side

**None.** No TLS/JA3/JA4, no HTTP-header order heuristics, no HTTP/2 frame fingerprinting, no IP/proxy/VPN reputation lookup, no server scoring. Only server contact observed was Cloudflare RUM analytics (see below), unrelated to detection.

### Behavioral

**None.** No mouse-movement, keystroke, scroll, or pointer-timing analysis.

## How it scans (architecture)

**Pure client-side JavaScript; decision rendered, not computed on server.** Firsthand network capture confirms page loads three scripts from own origin — `fpCollect.min.js`, `modernizr.js`, `fpScanner.js` — runs tests locally, writes pass/fail directly into DOM tables. **No fingerprint POST to any backend.** Only POST observed during session was `POST /cdn-cgi/rum?` → `204` (Cloudflare Real User Monitoring, site analytics), carries no detection role. Defining contrast with hybrid pages like `bot.incolumitas.com`, additionally analyzing connection's IP reputation, TCP/IP SYN, TLS handshake server-side.

## Scoring / output

Per-test pass/fail only. Each signal one table row: observed value + green/red color. Under the hood, classic fp-scanner returns per-test consistency judgment (roughly CONSISTENT / INCONSISTENT / UNSURE per check — exact enum names approximated) rather than numeric score. Modern fp-scanner rewrite reported to expose single "fires if any automation signal trips" boolean plus per-check details, but exact identifiers **unverified** (see Verification notes). Either way, bot.sannysoft.com surfaces no weighted or ML-derived trust score — it's a diagnostic checklist.

## Notable techniques

- **Permissions mismatch:** masked headless browser can return `Notification.permission === 'denied'` while `navigator.permissions.query({name:'notifications'})` reports `'prompt'` — impossible contradiction for real browser.
- **chrome-in-iframe (HEADCHR_IFRAME):** `window.chrome` present in top frame but absent inside nested iframe catches naive spoofing that only patches main frame. *This is the check that failed for test browser.*
- **navigatorPrototype inspection:** walks `navigator`'s prototype property descriptors to detect getters overridden by stealth scripts (faking `webdriver`, `plugins`, etc.).
- **Cross-context checks:** verifying `webdriver`/platform/WebGL across main frame, iframe, and (in fp-collect) worker contexts, so value patched only in main context is exposed.
- **Software-rendering WebGL tell:** renderer strings "Google SwiftShader" / "Mesa OffScreen" reveal headless GPU-less rendering. (Test browser instead reported real "Apple M5 / Metal" renderer, so didn't trip.)
- **resOverflow:** deliberately triggering recursion stack overflow, reading error message — PhantomJS-specific signature.
- **etsl / Function.toString tamper detection:** catches monkey-patched native functions.
- **tpCanvas:** canvas-*consistency* probe (transparent-pixel render check), not tracking-canvas fingerprint — fp-collect explicitly avoids classic tracking-canvas fingerprinting. Rendered across five canvas variants incl. sandboxed iframes to defeat per-context spoofing.
- **Broken-image 0×0 dimensions** and **Modernizr hairline** (0.5px `offsetHeight`) rendering quirks distinguishing headless rendering.

## What we observed firsthand

- Title "Antibot". Free, instant, no registration.
- 100% client-side. Loaded `fpCollect.min.js`, `modernizr.js`, `fpScanner.js`.
- **No fingerprint POST.** Only server contact: `POST /cdn-cgi/rum?` → `204` (Cloudflare RUM analytics).
- Test-browser rows: `navigator.webdriver` missing → **pass**; `window.chrome` present → **pass**; WebGL = Apple M5 / Metal (real GPU) → **pass**; but **HEADCHR_IFRAME → FAILED** (red).
- `navigator.languages` = `en-US,ru-RU` (worth noting: `en-US` UA paired with `ru-RU` locale is kind of soft inconsistency stricter engine would weight; sannysoft only displays it).
- No single score; human reads table. Datacenter/VPN egress IP not surfaced at all — sannysoft has no server-side view of it.

## Verification notes

Adversarial review flagged several claims in underlying research; corrections folded in above:

- **`devicesBlockedByBrave` — dropped.** Not in classic fp-collect's default attributes, not on live page; belongs to modern Castle-era fp-scanner rewrite, not classic page sannysoft serves.
- **Timezone / language-timezone-consistency check — dropped as sannysoft signal.** Timezone not among fp-collect's collected attributes, didn't appear on live page. Such checks belong to newer pages (e.g. incolumitas) or modern fp-scanner. (Separately, raw `languages` value *is* shown — but sannysoft does no consistency scoring on it.)
- **`fastBotDetection` / `fastBotDetectionDetails` — unverified.** These modern-API identifiers couldn't be confirmed in current fp-scanner source; treat as illustrative, not authoritative.
- **Classic result model — approximated.** Classic fp-scanner uses per-test consistency labels (~CONSISTENT / INCONSISTENT / UNSURE), not passed/failed/UNKNOWN enum; names approximate.
- **`etsl`** expands to error-to-**string** length (`e.toString().length`), not "error-to-source length".
- **`tpCanvas`** is bot-detection canvas-consistency probe (transparent-pixel), not tracking fingerprint.
- **Version nuance:** fp-collect source the page pulls is still classic JS; fp-scanner's public master is now Castle-sponsored TypeScript rewrite. Live page reflects classic-era behavior.
- **Vastel's title:** Head of Research at Castle (not "research lead"); DataDome tenure was VP of Research.

Blind spots anti-bot engineer should note (things sannysoft does **not** cover but production stack must):

- **CDP-driven automation** (Puppeteer/Playwright over DevTools Protocol) — e.g. `Runtime.enable` / `console.debug` getter stack-trace trick. sannysoft only has vague "debug tools" row; CDP detection was single signal that flagged test browser on other services, so major gap.
- **UA Client Hints consistency** — `navigator.userAgentData` / `Sec-CH-UA` high-entropy values vs legacy UA string. Not checked here.
- **Playwright markers** (`__playwright`, `__pw_*`) — automation-marker list stops at Selenium/PhantomJS/Nightmare/Sequentum.
- **`hardwareConcurrency` / CPU-count plausibility** — no sanity check on unrealistic core counts.
- **Behavioral biometrics** (mouse/keystroke/scroll timing) — largest real-world detection dimension, entirely absent.
- **Network/transport signals** — TLS JA3/JA4, HTTP/2 frame + header-order fingerprinting, datacenter-ASN / residential-proxy / VPN reputation. These dominate production anti-bot decisions, structurally impossible for purely client-side page to see (exactly why test browser's datacenter IP went unnoticed here).
- **Deeper fingerprint depth** — font enumeration and parameter-level WebGL fingerprinting (MAX_TEXTURE_SIZE, extensions, precision) beyond single vendor/renderer string.

## Open source / reusable

Yes — detection logic open source (MIT); only sannysoft wrapper page not published as a repo.

- **fp-scanner:** https://github.com/antoinevastel/fpscanner (current master is modern TypeScript rewrite maintained under Castle; page uses classic 2017–2019 version).
- **fp-collect:** https://github.com/antoinevastel/fp-collect (fingerprint-collection module; raw attribute list: `src/fpCollect.js`).
- **Intoli headless tests:** published inline in Evan Sangaline's Intoli blog posts (`chrome-headless-test.js`).

Builder can lift fp-collect for client-side signal collection and fp-scanner for per-signal consistency rules, then layer missing server-side and behavioral dimensions on top.

## Sources

- [bot.sannysoft.com — Antibot test page (live, no login)](https://bot.sannysoft.com/)
- [antoinevastel/fpscanner — browser fingerprinting & bot detection (signals list)](https://github.com/antoinevastel/fpscanner)
- [antoinevastel/fp-collect — fingerprint collection module](https://github.com/antoinevastel/fp-collect)
- [fp-collect fpCollect.js source (raw attribute list)](https://raw.githubusercontent.com/antoinevastel/fp-collect/master/src/fpCollect.js)
- [Intoli — It is *not* possible to detect and block Chrome headless](https://intoli.com/blog/not-possible-to-block-chrome-headless/)
- [Intoli — Making Chrome Headless Undetectable](https://intoli.com/blog/making-chrome-headless-undetectable/)
- [Antoine Vastel — bot/fraud detection researcher (author identity)](https://antoinevastel.com/)
- [Hacker News — discussion referencing bot.sannysoft.com relevance/limits](https://news.ycombinator.com/item?id=29262765)
- [puppeteer-extra issue #402 — sannysoft described as "a bit old" vs newer pages](https://github.com/berstend/puppeteer-extra/issues/402)
