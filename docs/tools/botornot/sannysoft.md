# bot.sannysoft.com

A free, client-side "antibot" diagnostic page that runs three well-known open-source headless/fingerprint test suites in your browser and renders each check as a green (human-like) or red (bot-like) table row. It is a leak checklist for automation authors, not a scoring engine.

- **URL:** https://bot.sannysoft.com/ · **Category:** open-source test page (community-hosted aggregation of open-source suites; not a commercial vendor demo, not a paid product) · **Requires registration:** No — load the URL and the JS tests run immediately.
- **Firsthand verdict for the test browser** (in-app browser reports as `Claude/… Chrome/148 Electron/42.5.1`, macOS, egress IP 87.249.139.226 = NordVPN/DataCamp datacenter, Istanbul): No aggregate verdict is emitted — the page is a per-test pass/fail table read by a human. The test browser passed the headline checks (`navigator.webdriver` missing → pass; `window.chrome` present → pass; real WebGL renderer "Apple M5 / Metal", not SwiftShader → pass) but produced at least one red row: **HEADCHR_IFRAME FAILED** (the `window.chrome`-inside-iframe consistency check). Because sannysoft is 100% client-side, the datacenter/VPN egress IP is completely invisible to it — a structural blind spot, not a pass.

## What it is — common info

`bot.sannysoft.com` is a convenience aggregation page widely used by the scraping/automation community to check whether a headless or automated browser (Puppeteer, Playwright, Selenium, undetected-chromedriver, stealth plugins) leaks tell-tale signals. It bundles and runs, in the visitor's own browser, three open-source test suites and paints the results as color-coded tables:

1. **Intoli's headless-Chrome detection tests** — from Evan Sangaline / Intoli (2017–2018 blog posts "Making Chrome Headless Undetectable" and "It is *not* possible to detect and block Chrome headless").
2. **fp-scanner** — Antoine Vastel's bot-detection library (`antoinevastel/fpscanner`).
3. **fp-collect** — Antoine Vastel's fingerprint-collection module (`antoinevastel/fp-collect`), which produces the fingerprint object fp-scanner analyzes.

Antoine Vastel is a device-fingerprinting / bot-detection researcher (formerly VP of Research at DataDome; currently Head of Research at Castle). The operator of the `sannysoft.com` domain itself is not documented in accessible primary sources; the page functions as a community-run mirror of these open tools rather than a branded vendor product. It is heavily cited (Hacker News, puppeteer-extra issues) and considered somewhat dated: its core checks derive from the 2017–2019 PhantomJS/Selenium/early-headless-Chrome era.

## Registration / access

None. No account, login, signup, or API key. The tests execute the moment the page loads and render locally. Verified firsthand — no auth wall, no registration prompt.

## How it decides bot-or-not

It doesn't, in the sense a vendor scorer does. There is **no aggregate bot score and no server verdict**. fp-collect gathers a fingerprint object in-browser (`fpCollect.generateFingerprint()`); fp-scanner and the inline Intoli tests inspect that object plus a few live DOM/API probes; each individual check is written into an HTML table row with its observed value and colored green (consistent with a normal human browser) or red (bot-like leak). A human reads the table. The community convention: "all rows green" means the automated browser is well-masked; any red row is a leak a real anti-bot vendor could exploit.

## Detection approaches

- **Browser fingerprinting** — navigator/JS object inspection, canvas, WebGL, audio/video codec support, screen geometry, media-device enumeration.
- **Headless-browser detection** — `HeadlessChrome` UA token, missing `window.chrome`, headless default screen resolution, SwiftShader/Mesa software WebGL renderer, zero-length plugins.
- **Automation-framework marker detection** — `navigator.webdriver`, Selenium/`$cdc_`/`$wdc_` globals, PhantomJS, NightmareJS, Sequentum crawler, debug-tool hints.
- **Consistency / anti-spoofing checks** — Permissions API vs `Notification.permission` mismatch, navigator-prototype tampering, cross-context checks (e.g. `window.chrome` inside an iframe), canvas rendered in sandboxed iframes, error-stack / error-string anomalies, recursion stack-overflow message (PhantomJS tell).
- **Not present:** behavioral biometrics, ML scoring, and (structurally) any network/TLS/IP-side analysis — see Verification notes.

## Areas / signals scanned

### Client-side (JS) — the entire surface

Grouped as the live page groups them (per firsthand observation):

- **"Intoli.com tests + additions":** User Agent, WebDriver (`navigator.webdriver` present/absent), WebDriver Advanced (descriptor/writability), Chrome (`window.chrome` present), Permissions (Permissions API vs `Notification.permission`), Plugins Length + `PluginArray` type, Languages (`navigator.languages`), WebGL Vendor/Renderer, Broken Image Dimensions (0×0).
- **fp-scanner battery (Vastel):** PHANTOM_UA, PHANTOM_PROPERTIES, PHANTOM_ETSL, PHANTOM_LANGUAGE, PHANTOM_WEBSOCKET, MQ_SCREEN (media-query/screen), PHANTOM_OVERFLOW (recursion stack overflow), PHANTOM_WINDOW_HEIGHT, HEADCHR_UA (HeadlessChrome token), HEADCHR_CHROME_OBJ, HEADCHR_PERMISSIONS, HEADCHR_PLUGINS, **HEADCHR_IFRAME** (chrome-in-iframe — *failed for the test browser*), CHR_DEBUG_TOOLS, SELENIUM_DRIVER, CHR_BATTERY, CHR_MEMORY (`deviceMemory`), TRANSPARENT_PIXEL, SEQUENTUM, VIDEO_CODECS.
- **"Some details" dump:** full `navigator.*` property dump, `screen.*` (width/height/avail/colorDepth/pixelDepth, window inner/outer, `devicePixelRatio`), canvas hashes (Canvas1–5 including iframe/sandboxed variants), `getBattery`.
- **"Fp-collect info":** full JSON fingerprint dump — plugins, mimeTypes, UA, platform, languages, screen, WebGL, touch, media devices, `navigatorPrototype`, etc.

Additional fp-collect / Intoli signals documented in the suites' sources: `navigator.platform`/`productSub`, Modernizr hairline (0.5px border `offsetHeight`) feature, touchscreen support, multimedia-device enumeration (speakers/mics/webcams), `navigatorPrototype` descriptor walk (spoofed-getter detection), `etsl` (error-to-string length; `e.toString().length`), `resOverflow`, and automation globals (`$cdc_`/`$wdc_`, `__selenium`/`__webdriver`, `_phantom`/`callPhantom`, `__nightmare`, Sequentum via `window.external`).

### Server-side

**None.** No TLS/JA3/JA4, no HTTP-header order heuristics, no HTTP/2 frame fingerprinting, no IP/proxy/VPN reputation lookup, no server scoring. The only server contact observed was Cloudflare RUM analytics (see below), unrelated to detection.

### Behavioral

**None.** No mouse-movement, keystroke, scroll, or pointer-timing analysis.

## How it scans (architecture)

**Pure client-side JavaScript; the decision is rendered, not computed on a server.** Firsthand network capture confirms the page loads three scripts from its own origin — `fpCollect.min.js`, `modernizr.js`, `fpScanner.js` — runs the tests locally, and writes pass/fail directly into the DOM tables. There is **no fingerprint POST to any backend**. The single POST observed during the session was `POST /cdn-cgi/rum?` → `204` (Cloudflare Real User Monitoring, i.e. site analytics), which carries no detection role. This is the defining contrast with hybrid pages like `bot.incolumitas.com`, which additionally analyze the connection's IP reputation, TCP/IP SYN, and TLS handshake server-side.

## Scoring / output

Per-test pass/fail only. Each signal is one table row: observed value + green/red color. Under the hood, classic fp-scanner returns a per-test consistency judgment (roughly CONSISTENT / INCONSISTENT / UNSURE per check — exact enum names approximated) rather than a numeric score. The modern fp-scanner rewrite is reported to expose a single "fires if any automation signal trips" boolean plus per-check details, but those exact identifiers are **unverified** (see Verification notes). Either way, bot.sannysoft.com surfaces no weighted or ML-derived trust score — it is a diagnostic checklist.

## Notable techniques

- **Permissions mismatch:** a masked headless browser can return `Notification.permission === 'denied'` while `navigator.permissions.query({name:'notifications'})` reports `'prompt'` — an impossible contradiction for a real browser.
- **chrome-in-iframe (HEADCHR_IFRAME):** `window.chrome` present in the top frame but absent inside a nested iframe catches naive spoofing that only patches the main frame. *This is the check that failed for the test browser.*
- **navigatorPrototype inspection:** walks `navigator`'s prototype property descriptors to detect getters overridden by stealth scripts (faking `webdriver`, `plugins`, etc.).
- **Cross-context checks:** verifying `webdriver`/platform/WebGL across main frame, iframe, and (in fp-collect) worker contexts, so a value patched only in the main context is exposed.
- **Software-rendering WebGL tell:** renderer strings "Google SwiftShader" / "Mesa OffScreen" reveal headless GPU-less rendering. (The test browser instead reported a real "Apple M5 / Metal" renderer, so this did not trip.)
- **resOverflow:** deliberately triggering a recursion stack overflow and reading the error message — a PhantomJS-specific signature.
- **etsl / Function.toString tamper detection:** catches monkey-patched native functions.
- **tpCanvas:** a canvas-*consistency* probe (transparent-pixel render check), not a tracking-canvas fingerprint — fp-collect explicitly avoids classic tracking-canvas fingerprinting. Rendered across five canvas variants incl. sandboxed iframes to defeat per-context spoofing.
- **Broken-image 0×0 dimensions** and **Modernizr hairline** (0.5px `offsetHeight`) rendering quirks distinguishing headless rendering.

## What we observed firsthand

- Title "Antibot". Free, instant, no registration.
- 100% client-side. Loaded `fpCollect.min.js`, `modernizr.js`, `fpScanner.js`.
- **No fingerprint POST.** Only server contact: `POST /cdn-cgi/rum?` → `204` (Cloudflare RUM analytics).
- Test-browser rows: `navigator.webdriver` missing → **pass**; `window.chrome` present → **pass**; WebGL = Apple M5 / Metal (real GPU) → **pass**; but **HEADCHR_IFRAME → FAILED** (red).
- `navigator.languages` = `en-US,ru-RU` (worth noting: an `en-US` UA paired with a `ru-RU` locale is the kind of soft inconsistency a stricter engine would weight; sannysoft only displays it).
- No single score; the human reads the table. The datacenter/VPN egress IP is not surfaced at all — sannysoft has no server-side view of it.

## Verification notes

The adversarial review flagged several claims in the underlying research; corrections folded in above:

- **`devicesBlockedByBrave` — dropped.** Not in classic fp-collect's default attributes and not on the live page; it belongs to the modern Castle-era fp-scanner rewrite, not the classic page sannysoft serves.
- **Timezone / language-timezone-consistency check — dropped as a sannysoft signal.** Timezone is not among fp-collect's collected attributes and did not appear on the live page. Such checks belong to newer pages (e.g. incolumitas) or the modern fp-scanner. (Separately, the raw `languages` value *is* shown — but sannysoft does no consistency scoring on it.)
- **`fastBotDetection` / `fastBotDetectionDetails` — unverified.** These modern-API identifiers could not be confirmed in the current fp-scanner source; treat as illustrative, not authoritative.
- **Classic result model — approximated.** Classic fp-scanner uses per-test consistency labels (~CONSISTENT / INCONSISTENT / UNSURE), not a passed/failed/UNKNOWN enum; names are approximate.
- **`etsl`** expands to error-to-**string** length (`e.toString().length`), not "error-to-source length".
- **`tpCanvas`** is a bot-detection canvas-consistency probe (transparent-pixel), not a tracking fingerprint.
- **Version nuance:** the fp-collect source the page pulls is still the classic JS; fp-scanner's public master is now a Castle-sponsored TypeScript rewrite. The live page reflects classic-era behavior.
- **Vastel's title:** Head of Research at Castle (not "research lead"); DataDome tenure was VP of Research.

Blind spots an anti-bot engineer should note (things sannysoft does **not** cover but a production stack must):

- **CDP-driven automation** (Puppeteer/Playwright over DevTools Protocol) — e.g. the `Runtime.enable` / `console.debug` getter stack-trace trick. sannysoft only has a vague "debug tools" row; CDP detection was the single signal that flagged the test browser on other services, so this is a major gap.
- **UA Client Hints consistency** — `navigator.userAgentData` / `Sec-CH-UA` high-entropy values vs the legacy UA string. Not checked here.
- **Playwright markers** (`__playwright`, `__pw_*`) — the automation-marker list stops at Selenium/PhantomJS/Nightmare/Sequentum.
- **`hardwareConcurrency` / CPU-count plausibility** — no sanity check on unrealistic core counts.
- **Behavioral biometrics** (mouse/keystroke/scroll timing) — the largest real-world detection dimension, entirely absent.
- **Network/transport signals** — TLS JA3/JA4, HTTP/2 frame + header-order fingerprinting, and datacenter-ASN / residential-proxy / VPN reputation. These dominate production anti-bot decisions and are structurally impossible for a purely client-side page to see (which is exactly why the test browser's datacenter IP went unnoticed here).
- **Deeper fingerprint depth** — font enumeration and parameter-level WebGL fingerprinting (MAX_TEXTURE_SIZE, extensions, precision) beyond the single vendor/renderer string.

## Open source / reusable

Yes — the detection logic is open source (MIT); only the sannysoft wrapper page is not published as a repo.

- **fp-scanner:** https://github.com/antoinevastel/fpscanner (current master is a modern TypeScript rewrite maintained under Castle; the page uses the classic 2017–2019 version).
- **fp-collect:** https://github.com/antoinevastel/fp-collect (fingerprint-collection module; raw attribute list: `src/fpCollect.js`).
- **Intoli headless tests:** published inline in Evan Sangaline's Intoli blog posts (`chrome-headless-test.js`).

A builder can lift fp-collect for client-side signal collection and fp-scanner for the per-signal consistency rules, then layer the missing server-side and behavioral dimensions on top.

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
