package botcheck

import (
	"strconv"
	"strings"
)

// report.go holds the presentation helpers the result template renders on top
// of the scored Report — per-signal explanations (G55), the detected-environment
// line (G56), and per-tier sub-scores (G50). Nothing here changes scoring: these
// are pure read-only views over what Evaluate already computed, so the score and
// the numbers shown beside it can never drift apart (TierScore re-derives a
// tier's score from the same checks the overall score used).

// Explanation is the G55 per-signal write-up: what the check looks at, why it
// fires, and its known limitation — the candor that makes a transparency tool
// trustworthy. "" for an unknown rule ID (e.g. a check added without a map
// entry); the template hides the "why" expander then.
func (c Check) Explanation() string { return ruleExplanations[c.ID] }

// ruleExplanations maps every rule ID to one or two plain sentences. It covers
// the full current rule set plus IDs reserved for rules being built in parallel
// (their entries are inert until those rules land). Kept as a map beside the
// template-facing accessor rather than a field on rule, so the write-ups live
// in one reviewable block; report_internal_test.go asserts no rule lacks one.
var ruleExplanations = map[string]string{
	// ── Hard tells ────────────────────────────────────────────────────────────
	"webdriver":         "navigator.webdriver is the W3C-standard flag a browser sets when it is driven by automation (Selenium, Puppeteer, Playwright). A human's browser never sets it — but a well-patched bot can delete the property, so a clean value proves nothing.",
	"framework_globals": "Automation frameworks leave their own global variables on the page (phantom, nightmare, __webdriver_evaluate, …), which no real site defines. The list only catches frameworks that leak globals; custom or fully patched tooling won't appear here.",
	"bot_user_agent":    "The User-Agent names a known bot, scripting HTTP client, or a recognised crawler / AI agent — honest automation identifies itself this way on purpose. The caveat cuts both ways: any scraper can copy a UA string, which is why recognition alone never grants trust here.",
	"native_tamper":     "Built-in JavaScript functions stringify as '[native code]'; automation stealth patches that replace them (usually to hide webdriver) often fail this check. It only catches shallow patches — a Proxy-based replacement fakes the string, which is what the toString-proxy probe is for.",
	"tostring_proxy":    "Proxying Function.prototype.toString exists for one reason: making patched functions look native — the hallmark of puppeteer-extra-style stealth plugins. No legitimate software does it. It can't see patches installed by other means, e.g. a modified browser build.",
	"software_renderer": "The WebGL renderer is a software rasteriser (SwiftShader, llvmpipe, …) — what a headless browser without a GPU reports. It also appears on real machines inside VMs or with disabled GPU drivers, so it is strong but not absolute proof.",
	"cdp_both":          "A Chrome DevTools Protocol connection was detected in both the main thread and a Web Worker — the shape of a Puppeteer/CDP-driven browser. Simply opening DevTools can trip a CDP probe, which is why this only counts when two separate contexts agree.",

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
	"cdp_main_only":              "CDP automation was detected on the main thread but not in a Worker. Weaker than the two-context case on purpose: a real user with DevTools open can look exactly like this, which is the known false-positive this rule's lower weight reflects.",
	"tz_self_inconsistent":       "The browser's IANA timezone name implies a different UTC offset than Date().getTimezoneOffset() reports — spoofers commonly change one and forget the other. Needs no IP lookup at all; a genuinely misconfigured machine could trip it, which is why it weighs less than a hard tell.",
	"canvas_unstable":            "Two identical canvas draws produced different hashes — the image output is being randomised between reads, exactly what noise-injecting anti-fingerprint tools and stealth plugins do. Some privacy browsers do this openly, so it is a consistency signal, not a bot proof.",
	"ch_brands_mismatch":         "The brand list in the Sec-CH-UA header disagrees with navigator.userAgentData.brands — two views of the same value that a UA spoofer must keep in sync. The GREASE decoy brand is ignored, and stripped or absent client hints simply skip the check.",
	"vendor_mismatch":            "A Chromium-family User-Agent whose navigator.vendor isn't 'Google Inc.' — real Chrome, Edge, and Opera all report it. Only fires when a vendor string is present and wrong; forks that drop the field entirely yield no signal.",
	"app_version_mismatch":       "navigator.appVersion is always the User-Agent minus its 'Mozilla/' prefix on every mainstream browser. A hand-built spoof that sets the two values independently usually forgets this coupling.",
	"productsub_mismatch":        "navigator.productSub is a fixed per-engine constant — '20030107' on every WebKit/Blink browser, '20100101' on Gecko. A value that doesn't match the engine the UA claims is a spoof or patched-runtime tell; an empty value is treated as no signal.",
	"language_primary_mismatch":  "navigator.language must equal navigator.languages[0] — the same preference exposed twice. Spoofers that patch the single field but not the array disagree here.",
	"webgl_vendor_mismatch":      "The unmasked WebGL vendor and renderer both come from the same GPU driver, so a real browser never reports them in different vendor families (e.g. vendor Apple, renderer NVIDIA). Unparseable strings — VMs, masked values — count as no signal, never a mismatch.",
	"gpu_os_mismatch":            "The GPU family is impossible on the OS the User-Agent claims (an Apple GPU on Windows, a desktop NVIDIA on a phone OS, …): the UA was rewritten but WebGL still names the real hardware. It fires only on enumerated impossible pairs — plausible-but-unusual combinations (AMD in an Intel Mac, Adreno on a Snapdragon laptop) stay silent by design.",
	"native_descriptor_tamper":   "A native function's property descriptor doesn't match the spec — patched-in fakes usually get enumerability or writability wrong. A privacy extension patching DOM APIs can leave the same trace, so this is a consistency hit, not standalone bot proof.",
	"native_callnew_tamper":      "Genuine native functions throw specific TypeErrors when called or constructed the wrong way; JavaScript overrides typically miss those traps. Same caveat as the descriptor probe — a privacy extension's override can also fail the traps, so it isn't a hard tell.",

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

	// ── Reserved IDs (rules being built in parallel; inert until they land) ────
	"iframe_webdriver":             "navigator.webdriver re-read inside a fresh same-origin iframe — automation often deletes the flag from the top frame but forgets new browsing contexts, so a clean top frame with webdriver still true in the iframe is the tell.",
	"iframe_proxy":                 "The JavaScript Proxy constructor re-checked inside an iframe's separate realm: runtimes that instrument only the main window disagree with themselves there.",
	"mobile_no_touch":              "A mobile (Android/iOS) User-Agent with no touch support, though every real phone browser reports touch points — a desktop spoofing a mobile UA usually forgets the touch surface. Desktop-mode edge cases are why it isn't a hard tell.",
	"webdriver_sw":                 "navigator.webdriver re-read inside the Service Worker — a third JavaScript realm automation tools rarely bother to patch.",
	"cdp_sw_only":                  "CDP automation detected only in the Service Worker context: the harness touched an out-of-sight realm while the main thread looks clean. Weaker than the two-context case by design.",
	"navigator_proto_tamper":       "The Navigator prototype chain was modified — replaced getters or unexpected own properties, which is how 'undeletable' webdriver patches are installed. Legitimate extensions can touch it too, so it reads as tamper evidence, not a verdict.",
	"chrome_runtime_tamper":        "window.chrome and its runtime sub-object don't have the shape real Chrome ships — a fake built to pass hasChromeObject-style checks usually misses properties or prototypes.",
	"chrome_late_injection":        "Traces of scripts injected into the page after load (the way CDP's Page.addScriptToEvaluateOnNewDocument installs automation shims) were observed — real browsers don't inject scripts into their own startup.",
	"jsengine_ua_mismatch":         "JavaScript engine behaviour (error formats and other V8/SpiderMonkey/JavaScriptCore quirks) disagrees with the engine family the User-Agent claims — the UA lies about the browser, but the JS VM underneath can't.",
	"webrtc_ip_mismatch":           "The address WebRTC reports disagrees with the connection's egress IP — the shape of a proxy or VPN that tunnels HTTP but leaks the real path over WebRTC. Browsers with WebRTC disabled or mDNS-masked candidates simply yield no signal.",
	"image_broken":                 "A deliberately broken image reports dimensions that don't match what the claimed browser/engine produces — an engine tell spoofed environments rarely reproduce faithfully.",
	"system_color_headless":        "CSS system colours resolve to values no real desktop theme produces — headless builds have no OS theme underneath, so themed colours fall back to defaults.",
	"plugins_mimetypes_incoherent": "navigator.plugins and navigator.mimeTypes must cross-reference each other; a spoofed plugin list that isn't wired both ways is internally incoherent.",
	"zero_outer_height":            "window.outerHeight is exactly 0 — no real browser window has zero outer height, but a headless environment that never creates a visible window reports it.",
}

// TierScore is the G50 per-tier sub-score: 100 minus the weights of that tier's
// triggered, non-suppressed checks, clamped at 0. For the soft tier the only
// possible deduction is the cluster penalty (soft checks never dock points
// individually), so it reads 100 unless the cluster is active. Suppressed
// checks (expected of a verified good bot) deduct nothing here, exactly as they
// deduct nothing from the overall score — the sub-scores always sum with the
// hero number.
func (r Report) TierScore(tier string) int {
	score := 100
	if tier == TierSoft {
		if r.SoftClusterActive() {
			score -= softComboWeight
		}
		return max(score, 0)
	}
	for _, c := range r.Checks {
		if c.Tier == tier && c.Triggered && !c.Suppressed {
			score -= c.Weight
		}
	}
	return max(score, 0)
}

// Environment names the detected browsing environment in one short human line
// (G56) — the credibility flex: "Chrome 125 · macOS · Blink", "Firefox 128 ·
// Windows · Gecko", "Electron 32.1.1 (embedded Chromium)". It parses only the
// client-reported UA (NavMainUA), reusing the same osFromUA/engineFromUA
// vocabulary the rules use, and returns "" when it can't tell — the template
// hides the line then. Every part is independently omittable: an unparseable OS
// or engine just drops its segment rather than guessing.
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

// embeddedEnvironment names an embedded runtime from its UA token, with the
// version when the UA carries one ("Electron/32.1.1" → "Electron 32.1.1") —
// the Fingerprint-style environment naming. All embedded runtimes we recognise
// wrap a Chromium engine, hence the uniform suffix. "" when the UA holds no
// embedded-runtime token.
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

// browserNameVersion extracts "Chrome 125"-style name + major version from a
// UA. Order matters: Edge/Opera UAs also carry "Chrome/", iOS browsers carry
// "Safari/", and a real Safari version lives in the "Version/" token, not
// "Safari/" (which is the engine build). ok=false when no known browser token
// appears — callers treat that as "can't tell".
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

// engineDisplay maps the internal engine vocabulary to display names. "" for
// the unknown case, so the segment simply drops out of the environment line.
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

// uaTokenMajor parses the major version of a UA token ("Firefox/128.0" ⇒ 128).
// 0 ⇒ token absent or no leading digits.
func uaTokenMajor(ua, token string) int {
	if i := strings.Index(ua, token); i >= 0 {
		return majorOf(ua[i+len(token):])
	}
	return 0
}

// uaTokenVersion parses the full dotted version of a UA token, case-insensitively
// ("Electron/32.1.1" ⇒ "32.1.1"). "" ⇒ absent. Used for embedded runtimes, where
// the whole version string is the credibility flex, not just the major.
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
