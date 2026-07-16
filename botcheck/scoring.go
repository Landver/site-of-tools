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
		id: "tz_mismatch", label: "Browser timezone ≠ IP timezone", tier: TierConsistency, weight: 25,
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
			ua := s.NavMainUA
			if ua == "" {
				ua = s.HTTPUserAgent
			}
			return strings.Contains(ua, "Chrome") && !s.HasChromeObject, ""
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
}
