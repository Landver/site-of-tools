package botcheck

import (
	"fmt"
	"strings"
)

// rule is one detection signal. eval reports whether the anomaly fired and a
// short human detail for the table. needsClient marks rules that read a
// client-collected field, so Evaluate can skip (not fail) them on a server-only
// request. Weights are a starting proposal, tuned against botcheck/tests — not
// gospel; adjust there, with fixtures, rather than by feel.
type rule struct {
	id          string
	label       string
	tier        string
	weight      int
	needsClient bool
	eval        func(Signals) (bool, string)
}

// rules is the full ordered signal set. Hard tells first (each near-standalone),
// then cross-layer/cross-context consistency checks (the load-bearing ones),
// then soft heuristics (only counted as a cluster — see Evaluate). The score is
// the sum of triggered weights subtracted from 100.
var rules = []rule{
	// ── Hard tells ────────────────────────────────────────────────────────────
	{
		id: "webdriver", label: "navigator.webdriver is true", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.Webdriver, "" },
	},
	{
		id: "framework_globals", label: "Automation framework globals present", tier: TierHard, weight: 60, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if len(s.FrameworkGlobals) == 0 {
				return false, ""
			}
			return true, strings.Join(s.FrameworkGlobals, ", ")
		},
	},
	{
		id: "bot_user_agent", label: "User-Agent is a known bot / HTTP client", tier: TierHard, weight: 60,
		eval: func(s Signals) (bool, string) {
			if tok := botUAToken(s.HTTPUserAgent); tok != "" {
				return true, "matched " + tok
			}
			return false, ""
		},
	},
	{
		id: "native_tamper", label: "A native function was monkey-patched (toString)", tier: TierHard, weight: 45, needsClient: true,
		eval: func(s Signals) (bool, string) { return !s.NativeToStringOK, "" },
	},
	{
		id: "software_renderer", label: "WebGL uses a software renderer (headless tell)", tier: TierHard, weight: 40, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.WebGLRenderer != "" && isSoftwareRenderer(s.WebGLRenderer) {
				return true, s.WebGLRenderer
			}
			return false, ""
		},
	},
	{
		id: "cdp_both", label: "CDP automation detected in main thread and Worker", tier: TierHard, weight: 40, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && s.CDPWorker, "" },
	},

	// ── Consistency (client claim vs. server / second context) ─────────────────
	{
		id: "ua_header_mismatch", label: "JS User-Agent ≠ HTTP User-Agent", tier: TierConsistency, weight: 35, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavMainUA == "" || s.HTTPUserAgent == "" || s.NavMainUA == s.HTTPUserAgent {
				return false, ""
			}
			return true, "navigator vs header differ"
		},
	},
	{
		id: "context_ua_mismatch", label: "Worker/iframe User-Agent ≠ main-thread User-Agent", tier: TierConsistency, weight: 35, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavMainUA == "" {
				return false, ""
			}
			if s.NavWorkerUA != "" && s.NavWorkerUA != s.NavMainUA {
				return true, "worker differs"
			}
			if s.NavIframeUA != "" && s.NavIframeUA != s.NavMainUA {
				return true, "iframe differs"
			}
			return false, ""
		},
	},
	{
		id: "ch_platform_mismatch", label: "Sec-CH-UA-Platform ≠ navigator.userAgentData.platform", tier: TierConsistency, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			h, j := normPlatform(s.SecCHUAPlatform), normPlatform(s.UAData.Platform)
			if h == "" || j == "" || h == j {
				return false, ""
			}
			return true, fmt.Sprintf("header %s vs JS %s", h, j)
		},
	},
	{
		id: "ua_os_mismatch", label: "OS in User-Agent ≠ userAgentData.platform", tier: TierConsistency, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			ua := osFromUA(s.NavMainUA)
			if ua == "" {
				ua = osFromUA(s.HTTPUserAgent)
			}
			j := normPlatform(s.UAData.Platform)
			if ua == "" || j == "" || ua == j {
				return false, ""
			}
			return true, fmt.Sprintf("UA %s vs platform %s", ua, j)
		},
	},
	{
		// Feature-detect the real rendering engine (Blink/Gecko/WebKit) client-side
		// and compare to the engine the UA claims. Robust against a spoofed UA string:
		// the engine probes read capabilities the UA can't fake. Only fires on a
		// confident disagreement (both sides known and different).
		id: "engine_ua_mismatch", label: "Feature-detected engine ≠ engine the User-Agent claims", tier: TierConsistency, weight: 30, needsClient: true,
		eval: func(s Signals) (bool, string) {
			want := engineFromUA(clientUA(s))
			if want == "" || s.Engine == "" || s.Engine == want {
				return false, ""
			}
			return true, fmt.Sprintf("engine %s vs UA implies %s", s.Engine, want)
		},
	},
	{
		// A UA-string spoof that edits "Chrome/NNN" but leaves userAgentData intact
		// disagrees here: the UA's Chromium major must equal the "Chromium" brand entry
		// of fullVersionList (see chVersionMajor). The CreepJS/Electron frozen-UA catch.
		id: "ua_chrome_version_mismatch", label: "User-Agent Chrome version ≠ userAgentData version", tier: TierConsistency, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			uaM, chM := uaChromeMajor(clientUA(s)), chVersionMajor(s.UAData)
			if uaM == 0 || chM == 0 || uaM == chM {
				return false, ""
			}
			return true, fmt.Sprintf("UA Chrome %d vs userAgentData %d", uaM, chM)
		},
	},
	{
		id: "embedded_runtime", label: "User-Agent is an embedded app runtime (Electron/CEF)", tier: TierConsistency, weight: 25,
		eval: func(s Signals) (bool, string) {
			ua := s.HTTPUserAgent
			if ua == "" {
				ua = s.NavMainUA
			}
			if tok := embeddedRuntimeToken(ua); tok != "" {
				return true, "matched " + tok
			}
			return false, ""
		},
	},
	{
		id: "tz_mismatch", label: "Browser timezone ≠ IP timezone", tier: TierConsistency, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.BrowserTZ == "" || s.IPTimezone == "" {
				return false, ""
			}
			// IP2Location gives a UTC offset ("+03:00"); the browser gives an IANA
			// name ("Europe/Moscow"). Compare offset-to-offset — a plain string
			// compare would fire for every real visitor (formats never match).
			if offsetFormat(s.IPTimezone) {
				bo, ok := ianaOffset(s.BrowserTZ, s.Now)
				if !ok || bo == s.IPTimezone {
					return false, "" // unknown/unstampable zone ⇒ can't verify, don't fire
				}
				return true, fmt.Sprintf("browser %s (%s) vs IP %s", s.BrowserTZ, bo, s.IPTimezone)
			}
			// Both look like IANA names (other IP DB formats) — name compare.
			if strings.EqualFold(s.BrowserTZ, s.IPTimezone) {
				return false, ""
			}
			return true, fmt.Sprintf("browser %s vs IP %s", s.BrowserTZ, s.IPTimezone)
		},
	},
	{
		id: "datacenter_ip", label: "Egress IP is a datacenter / Tor address", tier: TierConsistency, weight: 30,
		eval: func(s Signals) (bool, string) {
			if s.IsDatacenter {
				return true, "datacenter / hosting"
			}
			if s.IsTor {
				return true, "Tor exit node"
			}
			return false, ""
		},
	},
	{
		// Mutually exclusive with datacenter_ip: IP2Proxy marks datacenters/Tor as
		// proxies too, so only fire here for a VPN or an otherwise-uncategorised
		// proxy — never double-count an address the datacenter rule already caught.
		id: "proxy_ip", label: "Egress IP is a proxy / VPN", tier: TierConsistency, weight: 20,
		eval: func(s Signals) (bool, string) {
			if s.IsVPN {
				return true, "VPN"
			}
			if s.IsProxy && !s.IsDatacenter && !s.IsTor {
				return true, "public/other proxy"
			}
			return false, ""
		},
	},
	{
		id: "permission_impossible", label: "Impossible permission state (prompt while denied)", tier: TierConsistency, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return s.PermissionState == "prompt" && s.NotificationPerm == "denied", ""
		},
	},
	{
		id: "lang_mismatch", label: "navigator.languages ≠ Accept-Language", tier: TierConsistency, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			var nav string
			if len(s.Languages) > 0 {
				nav = primaryLang(s.Languages[0])
			}
			hdr := primaryLang(s.AcceptLanguage)
			if nav == "" || hdr == "" || nav == hdr {
				return false, ""
			}
			return true, fmt.Sprintf("JS %s vs header %s", nav, hdr)
		},
	},
	{
		id: "cdp_main_only", label: "CDP automation detected in main thread only", tier: TierConsistency, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CDPMainThread && !s.CDPWorker, "" },
	},
	{
		// Self-consistency (no IP needed): the browser's own IANA timezone must
		// agree with its own Date().getTimezoneOffset(). Spoofers commonly change
		// one and forget the other.
		id: "tz_self_inconsistent", label: "Timezone name disagrees with getTimezoneOffset()", tier: TierConsistency, weight: 25, needsClient: true,
		eval: func(s Signals) (bool, string) {
			secs, ok := zoneOffsetSeconds(s.BrowserTZ, s.Now)
			if s.BrowserTZ == "" || !ok {
				return false, ""
			}
			expected := -secs / 60 // getTimezoneOffset is minutes west of UTC
			if expected == s.TZOffset {
				return false, ""
			}
			return true, fmt.Sprintf("%s implies %d min but reported %d", s.BrowserTZ, expected, s.TZOffset)
		},
	},
	{
		// Randomised canvas output (two identical draws hashing differently) is a
		// noise-injecting anti-fingerprint / stealth tool.
		id: "canvas_unstable", label: "Canvas output is randomised between draws", tier: TierConsistency, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && !s.CanvasStable, "" },
	},
	{
		// Parse the Sec-CH-UA header brand list (server) and compare to the JS
		// userAgentData.brands (client); a spoofed User-Agent that forgets to keep
		// the two in sync is caught here. GREASE decoy brand is ignored.
		id: "ch_brands_mismatch", label: "Sec-CH-UA header brands ≠ userAgentData.brands", tier: TierConsistency, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			hdr, js := realBrandSet(chBrandNames(s.SecCHUA)), realBrandSet(s.Brands)
			if len(hdr) == 0 || len(js) == 0 || sameStringSet(hdr, js) {
				return false, "" // can't compare (stripped / non-Chromium) or they match
			}
			return true, "header and JS brand lists differ"
		},
	},
	{
		id: "vendor_mismatch", label: "Chromium User-Agent but navigator.vendor ≠ \"Google Inc.\"", tier: TierConsistency, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			ua := clientUA(s)
			if strings.Contains(ua, "Chrome") && s.Vendor != "" && s.Vendor != "Google Inc." {
				return true, "vendor=" + s.Vendor
			}
			return false, ""
		},
	},
	{
		id: "app_version_mismatch", label: "navigator.appVersion inconsistent with User-Agent", tier: TierConsistency, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			// Every mainstream browser reports appVersion as the UA minus "Mozilla/".
			if s.NavMainUA == "" || s.AppVersion == "" || !strings.HasPrefix(s.NavMainUA, "Mozilla/") {
				return false, ""
			}
			return s.AppVersion != strings.TrimPrefix(s.NavMainUA, "Mozilla/"), ""
		},
	},
	{
		// navigator.productSub is a fixed per-engine constant ("20030107" on every
		// WebKit/Blink browser, "20100101" on Gecko). A value that doesn't match the
		// engine the UA claims is a classic spoof/patched-runtime tell.
		id: "productsub_mismatch", label: "navigator.productSub not the engine's constant", tier: TierConsistency, weight: 20, needsClient: true,
		eval: func(s Signals) (bool, string) {
			want := expectedProductSub(clientUA(s))
			if want == "" || s.ProductSub == "" || s.ProductSub == want {
				return false, ""
			}
			return true, fmt.Sprintf("productSub %s, expected %s", s.ProductSub, want)
		},
	},
	{
		id: "language_primary_mismatch", label: "navigator.language ≠ navigator.languages[0]", tier: TierConsistency, weight: 15, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.NavLanguage == "" || len(s.Languages) == 0 || s.Languages[0] == "" {
				return false, ""
			}
			if strings.EqualFold(s.NavLanguage, s.Languages[0]) {
				return false, ""
			}
			return true, fmt.Sprintf("language %s vs languages[0] %s", s.NavLanguage, s.Languages[0])
		},
	},

	// ── Soft heuristics (only bite as a cluster of ≥3) ─────────────────────────
	{
		id: "empty_plugins", label: "No browser plugins", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.Plugins == 0, "" },
	},
	{
		id: "empty_languages", label: "navigator.languages is empty", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return len(s.Languages) == 0, "" },
	},
	{
		id: "default_geometry", label: "Default 800×600 screen", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.ScreenW == 800 && s.ScreenH == 600, "" },
	},
	{
		id: "impossible_window", label: "Outer window smaller than inner (impossible)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return s.OuterW > 0 && s.InnerW > 0 && s.OuterW < s.InnerW, ""
		},
	},
	{
		id: "no_chrome_object", label: "window.chrome missing on a Chrome User-Agent", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return strings.Contains(clientUA(s), "Chrome") && !s.HasChromeObject, ""
		},
	},
	{
		id: "implausible_hardware", label: "Implausible hardwareConcurrency / deviceMemory", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.HardwareCores < 0 || s.HardwareCores > 128 {
				return true, fmt.Sprintf("cores=%d", s.HardwareCores)
			}
			if s.DeviceMemory < 0 || s.DeviceMemory > 128 {
				return true, fmt.Sprintf("memory=%.0f", s.DeviceMemory)
			}
			return false, ""
		},
	},
	{
		id: "screen_avail_impossible", label: "Available screen area larger than the physical screen", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return (s.AvailW > 0 && s.ScreenW > 0 && s.AvailW > s.ScreenW) ||
				(s.AvailH > 0 && s.ScreenH > 0 && s.AvailH > s.ScreenH), ""
		},
	},
	{
		id: "low_color_depth", label: "Unusually low screen colour depth", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			if s.ColorDepth > 0 && s.ColorDepth < 16 {
				return true, fmt.Sprintf("colorDepth=%d", s.ColorDepth)
			}
			return false, ""
		},
	},
	{
		// Real browsers send Sec-Fetch-* on every navigation and fetch; a scripted
		// client wearing a browser User-Agent usually omits them. Soft, because a
		// proxy could in theory strip them.
		id: "sec_fetch_missing", label: "Browser User-Agent but no Sec-Fetch-* headers", tier: TierSoft, weight: 8,
		eval: func(s Signals) (bool, string) {
			if s.SecFetchMode == "" && looksLikeBrowser(s.HTTPUserAgent) {
				return true, "no Sec-Fetch-Mode"
			}
			return false, ""
		},
	},
	{
		// A canvas that renders nothing (all transparent) is blocked or headless.
		id: "canvas_blank", label: "Canvas renders blank (blocked / headless)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.CanvasSupported && s.CanvasBlank, "" },
	},
	{
		// Stock desktop Chrome/Edge/Safari ship H.264 + AAC; a stripped/Chromium
		// headless build often supports neither.
		id: "missing_proprietary_codecs", label: "Browser lacks H.264 and AAC (stripped/headless build)", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) {
			return looksLikeBrowser(clientUA(s)) && !s.CodecH264 && !s.CodecAAC, ""
		},
	},
	{
		// No detectable fonts at all points to a neutralised font-enumeration
		// surface or a font-less headless/VM environment.
		id: "no_fonts", label: "No system fonts detectable", tier: TierSoft, weight: 8, needsClient: true,
		eval: func(s Signals) (bool, string) { return s.FontCount == 0, "" },
	},
}
