package botcheck

import (
	"strconv"
	"strings"
)

// report.go: presentation helpers template renders on top of scored Report —
// per-signal explanations (G55) + detected-environment line (G56). Nothing here
// changes scoring → pure read-only views over what Evaluate already computed.

// Explanation: G55 per-signal write-up — what check looks at, why it fires,
// known limitation. Candor = what makes transparency tool trustworthy. "" for
// unknown rule ID (e.g. check added w/o map entry) → template hides "why" expander.
func (c Check) Explanation() string { return ruleExplanations[c.ID] }

// ruleExplanations maps every rule ID → one or two plain sentences. Covers full
// current rule set + IDs reserved for rules being built in parallel (inert till
// those rules land). Kept as map beside template-facing accessor, not field on
// rule → write-ups live in one reviewable block; report_internal_test.go asserts
// no rule lacks one.
var ruleExplanations = map[string]string{
	// ── Hard tells ────────────────────────────────────────────────────────────
	"webdriver":         "navigator.webdriver is the W3C-standard flag a browser sets when it is driven by automation (Selenium, Puppeteer, Playwright). A human's browser never sets it — but a well-patched bot can delete the property, so a clean value proves nothing.",
	"framework_globals": "Automation frameworks leave their own global variables on the page (phantom, nightmare, __webdriver_evaluate, …), which no real site defines. The list only catches frameworks that leak globals; custom or fully patched tooling won't appear here.",
	"bot_user_agent":    "The User-Agent names a known bot, scripting HTTP client, or a recognised crawler / AI agent — honest automation identifies itself this way on purpose. The caveat cuts both ways: any scraper can copy a UA string, which is why recognition alone never grants trust here.",
	"native_tamper":     "Built-in JavaScript functions stringify as '[native code]'; automation stealth patches that replace them (usually to hide webdriver) often fail this check. It only catches shallow patches — a Proxy-based replacement fakes the string, which is what the toString-proxy probe is for.",
	"tostring_proxy":    "Proxying Function.prototype.toString exists for one reason: making patched functions look native — the hallmark of puppeteer-extra-style stealth plugins. No legitimate software does it. It can't see patches installed by other means, e.g. a modified browser build.",
	"software_renderer": "The WebGL renderer is a software rasteriser (SwiftShader, llvmpipe, …) — what a headless browser without a GPU reports. It also appears on real machines inside VMs or with disabled GPU drivers, so it is strong but not absolute proof.",

	// ── Consistency cross-checks ───────────────────────────────────────────────
	"ua_header_mismatch":         "navigator.userAgent and the HTTP User-Agent header are the same string in a real browser — page JavaScript cannot change the header. A difference means one side was rewritten by an anti-detect tool or a proxy; rare privacy setups that rewrite headers can also trip this.",
	"context_ua_mismatch":        "Anti-detect tools overwhelmingly patch only the top frame's navigator, so the User-Agent re-read inside a Web Worker, iframe, or Service Worker leaks the real one. It only compares when both contexts answer — an unsupported API or probe timeout is never treated as evidence.",
	"context_language_mismatch":  "The cross-context idea applied to navigator.languages: a worker, iframe, or Service Worker reporting a different primary language than the top frame means one context was patched. Privacy browsers that clamp the language list do it in every context, so they stay consistent and silent.",
	"context_cores_mismatch":     "hardwareConcurrency re-read in a secondary context disagrees with the main thread. Real anti-fingerprint throttling (Firefox resistFingerprinting, Brave's farbling) caps the value globally, so only a spoof that patched one context and forgot the others fires this.",
	"context_platform_mismatch":  "userAgentData.platform re-read in a worker, iframe, or Service Worker disagrees with the top frame — a platform spoof that didn't reach every JavaScript context. Empty values (unsupported API, probe timeout) are never treated as a mismatch.",
	"context_webgl_mismatch":     "The WebGL renderer read inside a Web Worker differs from the main thread's — same browser, same GPU, so the strings should match. Fires only when both reads succeed; OffscreenCanvas WebGL is often unsupported, which just leaves nothing to compare.",
	"ch_platform_mismatch":       "The Sec-CH-UA-Platform request header and navigator.userAgentData.platform come from the same source in a real Chromium browser, so a spoof that edits one and forgets the other disagrees here. Non-Chromium browsers send neither and simply skip the check.",
	"ua_os_mismatch":             "The OS named in the User-Agent string disagrees with userAgentData.platform — the classic sign of a hand-edited UA. Either side being unreadable (an unusual UA, a non-Chromium browser) counts as 'can't tell', not as a mismatch.",
	"engine_ua_mismatch":         "The page feature-detects the real rendering engine (Blink/Gecko/WebKit) and compares it to the engine the User-Agent claims — a UA string cannot change what the engine actually supports. Only a confident disagreement fires; an engine that can't be identified is no signal.",
	"ua_chrome_version_mismatch": "The Chrome major version in the UA string must equal the Chromium version userAgentData reports — even forks like Opera or Vivaldi expose the true engine version there. A mismatch means the UA was hand-edited or frozen, as anti-detect and older Electron setups do.",
	"embedded_runtime":           "The User-Agent belongs to an embedded runtime (Electron, CEF, QtWebEngine, NW.js): a real Chromium engine wrapped in a desktop app. Legitimate for an app, but unusual for browsing arbitrary sites — and the standard shell for custom automation — so it reads as suspicious, not definitive.",
	"tz_mismatch":                "The browser's timezone offset disagrees with the timezone of the egress IP — the shape of a proxy or VPN exit in another region, or a spoofed timezone. Travel and corporate VPNs can trip this honestly, which is why it is one cross-check among many.",
	"datacenter_ip":              "The egress IP belongs to a datacenter/hosting range or is a Tor exit — where automation lives, not where humans usually browse from. Verified good crawlers are expected to trip this, and a human on a cloud-routed work VPN can too.",
	"proxy_ip":                   "The egress IP is a known VPN or public proxy. Plenty of privacy-conscious people use one, so this is transparency about the connection rather than an accusation — it only weighs in alongside other evidence, and never for an address the datacenter/Tor check already caught.",
	"permission_impossible":      "The Permissions API says notifications would 'prompt' while Notification.permission is 'denied' — a combination a genuine browser never shows. It historically caught automation that mocked the Permissions API without keeping the Notification mirror in sync.",
	"lang_mismatch":              "navigator.languages and the Accept-Language header are set from the same browser preference, so a spoofed locale that changed only one side disagrees here. Either side missing counts as 'can't tell'.",
	"tz_self_inconsistent":       "The browser's IANA timezone name implies a different UTC offset than Date().getTimezoneOffset() reports — spoofers commonly change one and forget the other. Needs no IP lookup at all; a genuinely misconfigured machine could trip it, which is why it weighs less than a hard tell.",
	"canvas_unstable":            "Two identical canvas draws produced different hashes — the image output is being randomised between reads, exactly what noise-injecting anti-fingerprint tools and stealth plugins do. Some privacy browsers do this openly, so it is a consistency signal, not a bot proof.",
	"ch_brands_mismatch":         "The brand list in the Sec-CH-UA header disagrees with navigator.userAgentData.brands — two views of the same value that a UA spoofer must keep in sync. The GREASE decoy brand is ignored, and stripped or absent client hints simply skip the check.",
	"vendor_mismatch":            "A Chromium-family User-Agent whose navigator.vendor isn't 'Google Inc.' — real Chrome, Edge, and Opera all report it. Only fires when a vendor string is present and wrong; forks that drop the field entirely yield no signal.",
	"app_version_mismatch":       "navigator.appVersion is always the User-Agent minus its 'Mozilla/' prefix on every mainstream browser. A hand-built spoof that sets the two values independently usually forgets this coupling.",
	"productsub_mismatch":        "navigator.productSub is a fixed per-engine constant — '20030107' on every WebKit/Blink browser, '20100101' on Gecko. A value that doesn't match the engine the UA claims is a spoof or patched-runtime tell; an empty value is treated as no signal.",
	"language_primary_mismatch":  "navigator.language must equal navigator.languages[0] — the same preference exposed twice. Spoofers that patch the single field but not the array disagree here.",
	"webgl_vendor_mismatch":      "The unmasked WebGL vendor and renderer both come from the same GPU driver, so a real browser never reports them in different vendor families (e.g. vendor Apple, renderer NVIDIA). Unparseable strings — VMs, masked values — count as no signal, never a mismatch.",
	"gpu_os_mismatch":            "The GPU family is impossible on the OS the User-Agent claims (an Apple GPU on Windows, a desktop NVIDIA on a phone OS, …): the UA was rewritten but WebGL still names the real hardware. It fires only on enumerated impossible pairs — plausible-but-unusual combinations (AMD in an Intel Mac, Adreno on a Snapdragon laptop) stay silent by design.",
	"native_descriptor_tamper":   "A native function's property descriptor doesn't match the spec — a naive monkey-patch gets enumerability or writability wrong. Downgraded to a soft, cluster-only signal on 2026-07-21: current puppeteer-extra-stealth evades it (it spreads the original descriptor), while a legitimate privacy extension patching DOM APIs can trip it, so on its own it says little either way.",
	"native_callnew_tamper":      "Genuine native functions throw specific TypeErrors when called or constructed the wrong way; a naive JavaScript override misses those traps. Soft, cluster-only since 2026-07-21 for the same reason as the descriptor probe — evaded by current stealth, and a privacy extension's override can also miss the traps, so it isn't standalone evidence.",
	"fingerprint_reuse":          "The same stable browser fingerprint (User-Agent, screen, GPU, timezone, …) arrived from many distinct IP addresses within the rolling 30-day corpus — the shape of a scraping farm that locks one fingerprint and rotates its proxy pool. One person roaming across networks accumulates a couple of IPs honestly, which is why this only counts from five; verified crawler fleets share one fingerprint by design and are exempt.",

	// ── Soft heuristics (only bite as a cluster of ≥3) ─────────────────────────
	"empty_plugins":              "navigator.plugins is empty — typical of headless builds, but also of modern desktop browsers that report an empty list anyway. That ambiguity is exactly why this only counts as part of a cluster.",
	"empty_languages":            "navigator.languages is an empty array. Real browsers always carry at least one language, though some hardened setups empty it on purpose — weak alone, it only counts with other signals.",
	"default_geometry":           "The screen is exactly 800×600, the default of headless images and fresh VMs. Real displays that size are rare but exist (old machines, embedded panels), so it's a soft hint only.",
	"impossible_window":          "window.outerWidth is smaller than innerWidth — geometrically impossible for a real window, and a classic math slip in a spoofed environment. Fires only when both values are present.",
	"no_chrome_object":           "A Chrome User-Agent but no window.chrome object, which real desktop Chrome always exposes. Some Chromium forks drop it honestly, so it only counts in a cluster.",
	"implausible_hardware":       "hardwareConcurrency or deviceMemory sits outside any plausible range (negative, or above 128). Values like that come from careless spoofing, not from real hardware.",
	"screen_avail_impossible":    "The available screen area is reported larger than the physical screen — impossible on a real display, and the sign of a spoofed screen object that doesn't model taskbar/menu-bar math.",
	"low_color_depth":            "The screen reports a colour depth below 16 bits. No real modern display looks like that; minimal headless or VM environments sometimes do.",
	"sec_fetch_missing":          "A browser-claimed User-Agent but no Sec-Fetch-* headers, which real browsers send on every navigation and fetch. Scripted clients usually don't bother — but a proxy in the path can strip headers too, the caveat that keeps this soft.",
	"accept_encoding_missing":    "Every real browser sends Accept-Encoding (they all support at least gzip); its absence means a scripted client that didn't bother, or a proxy that rewrote it — the caveat that keeps this soft.",
	"accept_language_missing":    "Every real browser sends Accept-Language. Its total absence suggests a scripted client; kept soft because a proxy can strip the header in transit.",
	"accept_nav_mismatch":        "A real browser's navigation/fetch Accept includes text/html; bare API clients send */* or application/json. Legitimate JSON consumers of this tool trip it too — harmless, because one soft signal alone never moves the score.",
	"canvas_blank":               "A canvas draw produced a fully transparent, empty image — the canvas API is blocked or the environment renders nothing. Some privacy tools block canvas reads openly, so it's a soft signal.",
	"missing_proprietary_codecs": "Stock desktop browsers ship H.264 and AAC support; stripped or headless Chromium builds often have neither. Linux installs with open codec packs can look similar, which is why this only counts in a cluster.",
	"no_fonts":                   "No probe fonts could be detected at all — a neutralised font-enumeration surface or a font-less headless/VM environment. Aggressive anti-fingerprint settings suppress fonts too, so it's a soft cluster signal.",
	"matchmedia_missing":         "window.matchMedia is part of every real browser's CSS support, desktop and mobile alike, so a browser-claimed User-Agent without it is a stripped JavaScript environment (jsdom-style) wearing a browser UA. An exotic embedded webview could conceivably lack it too, which is why this only counts inside a soft cluster.",
	"netinfo_incoherent":         "navigator.connection derives its effectiveType from the very rtt/downlink estimates it reports, so claiming a faster type than its own numbers imply means the object was overridden by a spoof. Firefox and Safari usually lack this API entirely — a normal absence that reads as no signal here, and a network change mid-read can briefly disagree, so it only counts in a cluster.",
	"ip_fingerprint_churn":       "The same egress IP presented many different browser fingerprints within a few minutes — the shape of a client rotating its fingerprint to evade tracking, the temporal opposite of the fingerprint-reuse check. Kept soft because a large shared network (a corporate NAT) can legitimately show many browsers, so it only counts alongside other signals.",
	"cdp_both":                   "A Chrome DevTools Protocol client was detected reading an Error's stack getter in both the main thread and a Web Worker while it was being logged — the classic 'CDP builds an object preview, which touches getters' tell. Downgraded to soft on 2026-07-19: tested against five genuinely CDP-driven sessions (Puppeteer, Playwright, Selenium/chromedriver, a hand-rolled Runtime.enable CDP client, puppeteer-extra-stealth) and it fired zero times — the technique doesn't appear to work on current Chromium at all, automation or not, so a clean value here proves very little either way.",
	"cdp_main_only":              "The same CDP-preview trap as cdp_both, but only the main thread tripped it (not a Worker). Same 2026-07-19 finding applies: it didn't fire against any of five real automation frameworks tested, so treat a miss here as inconclusive rather than reassuring.",
	"cdp_sw_only":                "The same CDP-preview trap as cdp_both, tripped only in the Service Worker context. Same 2026-07-19 finding applies — not shown reliable against real automation, kept only because it's free when silent.",

	// ── Reserved IDs (rules being built in parallel; inert until they land) ────
	"iframe_webdriver":             "navigator.webdriver re-read inside a fresh same-origin iframe — automation often deletes the flag from the top frame but forgets new browsing contexts, so a clean top frame with webdriver still true in the iframe is the tell.",
	"iframe_proxy":                 "The JavaScript Proxy constructor re-checked inside an iframe's separate realm: runtimes that instrument only the main window disagree with themselves there.",
	"mobile_no_touch":              "A mobile (Android/iOS) User-Agent with no touch support, though every real phone browser reports touch points — a desktop spoofing a mobile UA usually forgets the touch surface. Desktop-mode edge cases are why it isn't a hard tell.",
	"webdriver_sw":                 "navigator.webdriver re-read inside the Service Worker. In practice this rarely fires even against confirmed automation (Puppeteer, Playwright, Selenium/chromedriver all tested clean here on 2026-07-19 despite reading true elsewhere in the same session) — Chromium's Service Worker scope appears not to inherit the automation flag at all, patched or not. Left in as a hard tell on the rare chance it does fire, but don't read a clean value as reassurance.",
	"navigator_proto_tamper":       "The Navigator prototype chain was modified — replaced getters or unexpected own properties, the way a hand-rolled 'undeletable' webdriver patch is installed. Soft, cluster-only since 2026-07-21: modern stealth hides webdriver with a launch flag and never touches the prototype, so this catches only a naive patch or a legitimate extension — tamper evidence, not a verdict.",
	"chrome_runtime_tamper":        "window.chrome and its runtime sub-object don't have the shape real Chrome ships — a naive fake built to pass hasChromeObject-style checks usually misses properties or prototypes. Downgraded to soft, cluster-only on 2026-07-21: puppeteer-extra-plugin-stealth 2.11.2 fakes chrome.runtime perfectly (evading it), AND the official Chrome for Testing binary lacks chrome.runtime entirely (so tightening it risked flagging real visitors) — leaving it able to catch only a naive fake, which is not worth an individual deduction.",
	"chrome_late_injection":        "window.chrome appears among the last window keys, as if bolted on after startup rather than created during page setup — the old CreepJS hasHighChromeIndex tell for a late-injected fake. Soft, cluster-only since 2026-07-21: current stealth fakes chrome.runtime in place instead of late-injecting, so this only catches a naive bolt-on.",
	"jsengine_ua_mismatch":         "JavaScript engine behaviour (error formats and other V8/SpiderMonkey/JavaScriptCore quirks) disagrees with the engine family the User-Agent claims — the UA lies about the browser, but the JS VM underneath can't.",
	"webrtc_ip_mismatch":           "The address WebRTC reports disagrees with the connection's egress IP — the shape of a proxy or VPN that tunnels HTTP but leaks the real path over WebRTC. Browsers with WebRTC disabled or mDNS-masked candidates simply yield no signal.",
	"image_broken":                 "A deliberately broken image reports dimensions that don't match what the claimed browser/engine produces — an engine tell spoofed environments rarely reproduce faithfully.",
	"system_color_headless":        "CSS system colours resolve to values no real desktop theme produces — headless builds have no OS theme underneath, so themed colours fall back to defaults.",
	"plugins_mimetypes_incoherent": "navigator.plugins and navigator.mimeTypes must cross-reference each other; a spoofed plugin list that isn't wired both ways is internally incoherent.",
	"zero_outer_height":            "window.outerHeight is exactly 0 — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.",
}

// Environment names detected browsing environment in one short human line
// (G56) — the credibility flex: "Chrome 125 · macOS · Blink", "Firefox 128 ·
// Windows · Gecko", "Electron 32.1.1 (embedded Chromium)". Parses only
// client-reported UA (NavMainUA), reuses same osFromUA/engineFromUA vocab rules
// use, returns "" when can't tell → template hides line then. Every part
// independently omittable: unparseable OS or engine just drops its segment,
// never guesses.
func (s Signals) Environment() string {
	ua := s.NavMainUA
	if ua == "" {
		return ""
	}
	if env := embeddedEnvironment(ua); env != "" {
		return env
	}
	name, ok := browserNameVersion(ua)
	if !ok {
		return ""
	}
	parts := []string{name}
	if os := osFromUA(ua); os != "" {
		parts = append(parts, os)
	}
	if e := engineDisplay(engineFromUA(ua)); e != "" {
		parts = append(parts, e)
	}
	return strings.Join(parts, " · ")
}

// embeddedEnvironment names embedded runtime from its UA token, w/ version
// when UA carries one ("Electron/32.1.1" → "Electron 32.1.1") — Fingerprint-
// style naming. All embedded runtimes we recognise wrap Chromium engine, hence
// uniform suffix. "" when UA holds no embedded-runtime token.
func embeddedEnvironment(ua string) string {
	tok := embeddedRuntimeToken(ua)
	if tok == "" {
		return ""
	}
	name, ok := map[string]string{
		"electron":    "Electron",
		"cef":         "CEF",
		"cefsharp":    "CefSharp",
		"qtwebengine": "QtWebEngine",
		"nw.js":       "NW.js",
		"nwjs":        "NW.js",
	}[strings.ToLower(tok)]
	if !ok {
		return "" // a token with no display name: can't tell, don't guess
	}
	if v := uaTokenVersion(ua, tok); v != "" {
		name += " " + v
	}
	return name + " (embedded Chromium)"
}

// browserNameVersion extracts "Chrome 125"-style name + major version from UA.
// Order matters: Edge/Opera UAs also carry "Chrome/", iOS browsers carry
// "Safari/", real Safari version lives in "Version/" token, not "Safari/"
// (engine build). ok=false when no known browser token appears → callers treat
// as "can't tell".
func browserNameVersion(ua string) (string, bool) {
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"},
		{"OPR/", "Opera"},
		{"CriOS/", "Chrome"},  // iOS Chrome (WebKit under the hood — the engine segment says so)
		{"FxiOS/", "Firefox"}, // iOS Firefox, same
		{"Firefox/", "Firefox"},
		{"Chromium/", "Chromium"},
		{"Chrome/", "Chrome"},
	} {
		if strings.Contains(ua, b.token) {
			if m := uaTokenMajor(ua, b.token); m > 0 {
				return b.name + " " + strconv.Itoa(m), true
			}
			return b.name, true
		}
	}
	if strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/") {
		if m := uaTokenMajor(ua, "Version/"); m > 0 {
			return "Safari " + strconv.Itoa(m), true
		}
		return "Safari", true
	}
	return "", false
}

// engineDisplay maps internal engine vocab → display names. "" for unknown
// case → segment just drops out of environment line.
func engineDisplay(engine string) string {
	switch engine {
	case "blink":
		return "Blink"
	case "gecko":
		return "Gecko"
	case "webkit":
		return "WebKit"
	default:
		return ""
	}
}

// uaTokenMajor parses major version of UA token ("Firefox/128.0" ⇒ 128). 0 ⇒
// token absent or no leading digits.
func uaTokenMajor(ua, token string) int {
	if i := strings.Index(ua, token); i >= 0 {
		return majorOf(ua[i+len(token):])
	}
	return 0
}

// uaTokenVersion parses full dotted version of UA token, case-insensitive
// ("Electron/32.1.1" ⇒ "32.1.1"). "" ⇒ absent. Used for embedded runtimes,
// where whole version string is credibility flex, not just major.
func uaTokenVersion(ua, token string) string {
	i := strings.Index(strings.ToLower(ua), strings.ToLower(token)+"/")
	if i < 0 {
		return ""
	}
	v := ua[i+len(token)+1:]
	end := 0
	for end < len(v) && (v[end] >= '0' && v[end] <= '9' || v[end] == '.') {
		end++
	}
	return strings.Trim(v[:end], ".")
}
