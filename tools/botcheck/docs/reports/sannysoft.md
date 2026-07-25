# bot.sannysoft.com

Free client-side "antibot" diagnostic page: runs 3 well-known open-source headless/FP test suites in-browser, renders each check green (human-like) or red (bot-like) table row. Leak checklist for automation authors, not scoring engine.

- **URL:** https://bot.sannysoft.com/ · **Category:** open-source test page (community-hosted aggregation of open-source suites; not commercial vendor demo, not paid product) · **Requires registration:** No — load URL, JS tests run immediately.
- **Firsthand verdict for test browser** (in-app browser reports `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): no aggregate verdict — per-test pass/fail table read by human. Test browser passed headline checks (`navigator.webdriver` missing -> pass; `window.chrome` present -> pass; real WebGL renderer "Apple M5 / Metal", not SwiftShader -> pass) but ≥1 red row: **HEADCHR_IFRAME FAILED** (`window.chrome`-inside-iframe consistency check). sannysoft 100% client-side -> datacenter/VPN egress IP invisible to it — structural blind spot, not pass.

## What it is — common info

`bot.sannysoft.com`: convenience aggregation page, widely used by scraping/automation community to check if headless/automated browser (Puppeteer, Playwright, Selenium, undetected-chromedriver, stealth plugins) leaks tell-tale signals. Bundles + runs, in visitor's own browser, 3 open-source suites, paints results as color-coded tables:

1. **Intoli's headless-Chrome detection tests** — Evan Sangaline / Intoli (2017–2018 posts "Making Chrome Headless Undetectable", "It is *not* possible to detect and block Chrome headless").
2. **fp-scanner** — Antoine Vastel's bot-detection library (`antoinevastel/fpscanner`).
3. **fp-collect** — Vastel's FP-collection module (`antoinevastel/fp-collect`); produces the FP object fp-scanner analyzes.

Antoine Vastel: device-FP / bot-detection researcher (formerly VP Research at DataDome; now Head of Research at Castle). Operator of `sannysoft.com` domain undocumented in accessible primary sources; page = community-run mirror of these open tools, not branded vendor product. Heavily cited (Hacker News, puppeteer-extra issues), considered dated: core checks derive from 2017–2019 PhantomJS/Selenium/early-headless-Chrome era.

## Registration / access

None. No account, login, signup, API key. Tests run the moment page loads, render locally. Verified firsthand — no auth wall, no registration prompt.

## How it decides bot-or-not

Doesn't, in a vendor-scorer sense. **No aggregate bot score, no server verdict.** fp-collect gathers FP object in-browser (`fpCollect.generateFingerprint()`); fp-scanner + inline Intoli tests inspect that object plus a few live DOM/API probes; each check -> HTML table row w/ observed value, colored green (consistent w/ normal human browser) or red (bot-like leak). Human reads table. Community convention: all rows green = automated browser well-masked; any red row = leak a real anti-bot vendor could exploit.

## Detection approaches

- **Browser FP** — navigator/JS object inspection, canvas, WebGL, audio/video codec support, screen geometry, media-device enumeration.
- **Headless-browser detection** — `HeadlessChrome` UA token, missing `window.chrome`, headless default screen resolution, SwiftShader/Mesa software WebGL renderer, zero-length plugins.
- **Automation-framework markers** — `navigator.webdriver`, Selenium/`$cdc_`/`$wdc_` globals, PhantomJS, NightmareJS, Sequentum crawler, debug-tool hints.
- **Consistency / anti-spoofing** — Permissions API vs `Notification.permission` mismatch, navigator-prototype tampering, cross-context (e.g. `window.chrome` inside iframe), canvas in sandboxed iframes, error-stack/error-string anomalies, recursion stack-overflow message (PhantomJS tell).
- **Not present:** behavioral biometrics, ML scoring, & (structurally) any network/TLS/IP-side analysis — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the entire surface

Grouped as live page groups them (firsthand obs):

- **"Intoli.com tests + additions":** User Agent, WebDriver (`navigator.webdriver` present/absent), WebDriver Advanced (descriptor/writability), Chrome (`window.chrome` present), Permissions (Permissions API vs `Notification.permission`), Plugins Length + `PluginArray` type, Languages (`navigator.languages`), WebGL Vendor/Renderer, Broken Image Dimensions (0×0).
- **fp-scanner battery (Vastel):** PHANTOM_UA, PHANTOM_PROPERTIES, PHANTOM_ETSL, PHANTOM_LANGUAGE, PHANTOM_WEBSOCKET, MQ_SCREEN (media-query/screen), PHANTOM_OVERFLOW (recursion stack overflow), PHANTOM_WINDOW_HEIGHT, HEADCHR_UA (HeadlessChrome token), HEADCHR_CHROME_OBJ, HEADCHR_PERMISSIONS, HEADCHR_PLUGINS, **HEADCHR_IFRAME** (chrome-in-iframe — *failed for test browser*), CHR_DEBUG_TOOLS, SELENIUM_DRIVER, CHR_BATTERY, CHR_MEMORY (`deviceMemory`), TRANSPARENT_PIXEL, SEQUENTUM, VIDEO_CODECS.
- **"Some details" dump:** full `navigator.*` dump, `screen.*` (width/height/avail/colorDepth/pixelDepth, window inner/outer, `devicePixelRatio`), canvas hashes (Canvas1–5 incl. iframe/sandboxed variants), `getBattery`.
- **"Fp-collect info":** full JSON FP dump — plugins, mimeTypes, UA, platform, languages, screen, WebGL, touch, media devices, `navigatorPrototype`, etc.

Additional fp-collect / Intoli signals in suites' sources: `navigator.platform`/`productSub`, Modernizr hairline (0.5px border `offsetHeight`) feature, touchscreen support, multimedia-device enumeration (speakers/mics/webcams), `navigatorPrototype` descriptor walk (spoofed-getter detection), `etsl` (error-to-string length; `e.toString().length`), `resOverflow`, automation globals (`$cdc_`/`$wdc_`, `__selenium`/`__webdriver`, `_phantom`/`callPhantom`, `__nightmare`, Sequentum via `window.external`).


### Server-side

**None.** No TLS/JA3/JA4, no HTTP-header-order heuristics, no HTTP/2 frame FP, no IP/proxy/VPN reputation lookup, no server scoring. Only server contact observed = Cloudflare RUM analytics (below), unrelated to detection.

### Behavioral

**None.** No mouse-movement, keystroke, scroll, or pointer-timing analysis.

## How it scans (architecture)

**Pure client-side JS; decision rendered, not computed on server.** Firsthand network capture confirms page loads 3 scripts from own origin — `fpCollect.min.js`, `modernizr.js`, `fpScanner.js` — runs tests locally, writes pass/fail directly into DOM tables. **No FP POST to any backend.** Only POST observed = `POST /cdn-cgi/rum?` -> `204` (Cloudflare Real User Monitoring, site analytics), no detection role. Contrast w/ hybrid pages like `bot.incolumitas.com`, which additionally analyze connection's IP reputation, TCP/IP SYN, TLS handshake server-side.

## Scoring / output

Per-test pass/fail only. Each signal = one table row: observed value + green/red. Under hood, classic fp-scanner returns per-test consistency judgment (~CONSISTENT / INCONSISTENT / UNSURE per check — enum names approximated), not numeric score. Modern fp-scanner rewrite reported to expose single "fires if any automation signal trips" boolean plus per-check details, but exact identifiers **unverified** (see Verification notes). Either way, bot.sannysoft.com surfaces no weighted or ML-derived trust score — diagnostic checklist.

## Notable techniques

- **Permissions mismatch:** masked headless browser can return `Notification.permission === 'denied'` while `navigator.permissions.query({name:'notifications'})` reports `'prompt'` — impossible contradiction for real browser.
- **chrome-in-iframe (HEADCHR_IFRAME):** `window.chrome` present in top frame but absent inside nested iframe catches naive spoofing that only patches main frame. *Failed for test browser.*
- **navigatorPrototype inspection:** walks `navigator`'s prototype property descriptors to detect getters overridden by stealth scripts (faking `webdriver`, `plugins`, etc.).
- **Cross-context checks:** verifies `webdriver`/platform/WebGL across main frame, iframe, & (in fp-collect) worker contexts -> value patched only in main context exposed.
- **Software-rendering WebGL tell:** renderer strings "Google SwiftShader" / "Mesa OffScreen" reveal headless GPU-less rendering. (Test browser reported real "Apple M5 / Metal", so didn't trip.)
- **resOverflow:** deliberately triggers recursion stack overflow, reads error message — PhantomJS-specific signature.
- **etsl / Function.toString tamper detection:** catches monkey-patched native functions.
- **tpCanvas:** canvas-*consistency* probe (transparent-pixel render check), not tracking-canvas FP — fp-collect explicitly avoids classic tracking-canvas FP. Rendered across 5 canvas variants incl. sandboxed iframes to defeat per-context spoofing.
- **Broken-image 0×0 dimensions** & **Modernizr hairline** (0.5px `offsetHeight`) rendering quirks distinguishing headless rendering.

## What we observed firsthand

- Title "Antibot". Free, instant, no registration.
- 100% client-side. Loaded `fpCollect.min.js`, `modernizr.js`, `fpScanner.js`.
- **No FP POST.** Only server contact: `POST /cdn-cgi/rum?` -> `204` (Cloudflare RUM analytics).
- Test-browser rows: `navigator.webdriver` missing -> **pass**; `window.chrome` present -> **pass**; WebGL = Apple M5 / Metal (real GPU) -> **pass**; but **HEADCHR_IFRAME -> FAILED** (red).
- `navigator.languages` = `en-US,ru-RU` (`en-US` UA paired w/ `ru-RU` locale = soft inconsistency a stricter engine would weight; sannysoft only displays it).
- No single score; human reads table. Datacenter/VPN egress IP not surfaced — sannysoft has no server-side view of it.

## Verification notes

Adversarial review flagged several claims in underlying research; corrections folded in above:

- **`devicesBlockedByBrave` — dropped.** Not in classic fp-collect's default attributes, not on live page; belongs to modern Castle-era fp-scanner rewrite, not the classic page sannysoft serves.
- **Timezone / language-timezone-consistency check — dropped as sannysoft signal.** Timezone not among fp-collect's collected attributes, absent from live page. Such checks belong to newer pages (e.g. incolumitas) or modern fp-scanner. (Raw `languages` value *is* shown — but sannysoft does no consistency scoring on it.)
- **`fastBotDetection` / `fastBotDetectionDetails` — unverified.** Modern-API identifiers unconfirmed in current fp-scanner source; treat as illustrative, not authoritative.
- **Classic result model — approximated.** Classic fp-scanner uses per-test consistency labels (~CONSISTENT / INCONSISTENT / UNSURE), not passed/failed/UNKNOWN enum; names approximate.
- **`etsl`** = error-to-**string** length (`e.toString().length`), not "error-to-source length".
- **`tpCanvas`** = bot-detection canvas-consistency probe (transparent-pixel), not tracking FP.
- **Version nuance:** fp-collect source the page pulls is still classic JS; fp-scanner's public master now = Castle-sponsored TypeScript rewrite. Live page reflects classic-era behavior.
- **Vastel's title:** Head of Research at Castle (not "research lead"); DataDome tenure = VP of Research.

Blind spots an anti-bot engineer should note (things sannysoft does **not** cover but production stack must):

- **CDP-driven automation** (Puppeteer/Playwright over DevTools Protocol) — e.g. `Runtime.enable` / `console.debug` getter stack-trace trick. sannysoft only has vague "debug tools" row; CDP detection = single signal that flagged test browser on other services, so major gap.
- **UA Client Hints consistency** — `navigator.userAgentData` / `Sec-CH-UA` high-entropy values vs legacy UA string. Not checked here.
- **Playwright markers** (`__playwright`, `__pw_*`) — automation-marker list stops at Selenium/PhantomJS/Nightmare/Sequentum.
- **`hardwareConcurrency` / CPU-count plausibility** — no sanity check on unrealistic core counts.
- **Behavioral biometrics** (mouse/keystroke/scroll timing) — largest real-world detection dimension, entirely absent.
- **Network/transport signals** — TLS JA3/JA4, HTTP/2 frame + header-order FP, datacenter-ASN / residential-proxy / VPN reputation. These dominate production anti-bot decisions, structurally impossible for a purely client-side page to see (why test browser's datacenter IP went unnoticed).
- **Deeper FP depth** — font enumeration & parameter-level WebGL FP (MAX_TEXTURE_SIZE, extensions, precision) beyond single vendor/renderer string.

## Open source / reusable

Yes — detection logic open source (MIT); only sannysoft wrapper page unpublished as repo.

- **fp-scanner:** https://github.com/antoinevastel/fpscanner (current master = modern TypeScript rewrite under Castle; page uses classic 2017–2019 version).
- **fp-collect:** https://github.com/antoinevastel/fp-collect (FP-collection module; raw attribute list: `src/fpCollect.js`).
- **Intoli headless tests:** published inline in Evan Sangaline's Intoli blog posts (`chrome-headless-test.js`).

Builder can lift fp-collect for client-side signal collection & fp-scanner for per-signal consistency rules, then layer missing server-side & behavioral dimensions on top.

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
