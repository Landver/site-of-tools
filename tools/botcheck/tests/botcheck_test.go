// Package tests holds botcheck's black-box tests; the scorer is a pure function of Signals.
package tests

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/botcheck"
)

const chromeMacUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// boolPtr: v4 env bools are pointers, so "not supplied" never reads as a determined false.
func boolPtr(b bool) *bool { return &b }

// testNow is a winter instant, so America/New_York is a fixed -05:00.
var testNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// cleanChrome: realistic, fully-consistent human browser on residential IP.
func cleanChrome() botcheck.Signals {
	return botcheck.Signals{
		ClientCollected:  true,
		HeadersSupplied:  true,
		IPSupplied:       true,
		CorpusConsulted:  true,
		CollectorV:       4, // current payload version (v4 env section present)
		NativeToStringOK: true,
		HasChromeObject:  true,
		NavMainUA:        chromeMacUA,
		NavWorkerUA:      chromeMacUA,
		NavIframeUA:      chromeMacUA,
		HTTPUserAgent:    chromeMacUA,
		Languages:        []string{"en-US", "en"},
		NavLanguage:      "en-US",
		Vendor:           "Google Inc.",
		AppVersion:       strings.TrimPrefix(chromeMacUA, "Mozilla/"),
		AcceptLanguage:   "en-US,en;q=0.9",
		// G06 server-observed headers — as real Chrome sends.
		HTTPAccept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		HTTPAcceptEncoding: "gzip, deflate, br, zstd",
		WebGLRenderer:      "ANGLE (Apple, Apple M1, OpenGL 4.1)",
		WebGLVendor:        "Google Inc. (Apple)", // Chrome's ANGLE vendor shim — same family as renderer → G07/G08 stay silent
		Plugins:            3,
		ScreenW:            1920, ScreenH: 1080,
		AvailW: 1920, AvailH: 1040,
		ColorDepth: 30,
		OuterW:     1680, InnerW: 1400,
		HardwareCores: 8, DeviceMemory: 8,
		BrowserTZ:       "America/New_York",
		IPTimezone:      "-05:00", // IP2Location returns UTC offset, not IANA name
		SecCHUAPlatform: `"macOS"`,
		SecFetchMode:    "cors",
		UAData: botcheck.UAData{
			Platform: "macOS",
			FullVersionList: []botcheck.BrandVersion{
				{Brand: "Chromium", Version: "125.0.6422.60"}, // major 125 == Chrome/125 in UA
				{Brand: "Google Chrome", Version: "125.0.6422.60"},
				{Brand: "Not.A/Brand", Version: "24.0.0.0"},
			},
		},
		Now: testNow,
		// Layer-2, all internally consistent → clean browser scores 100.
		TZOffset:        300, // America/New_York in January (UTC-5)
		CanvasSupported: true,
		CanvasStable:    true,
		CanvasBlank:     false,
		Brands:          []string{"Chromium", "Google Chrome", "Not.A/Brand"},
		SecCHUA:         `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
		CodecH264:       true,
		CodecAAC:        true,
		FontCount:       8,
		// Quick-win signals (G01/G02/G05), all consistent w/ real Chrome 125.
		ProductSub: "20030107", // WebKit/Blink constant
		Engine:     "blink",    // feature-detected engine matches Chrome UA
		// G03: every extra context mirrors the main thread, as a real browser's do.
		SWUA:                chromeMacUA,
		WorkerLanguages:     []string{"en-US", "en"},
		IframeLanguages:     []string{"en-US", "en"},
		SWLanguages:         []string{"en-US", "en"},
		WorkerCores:         8,
		IframeCores:         8,
		SWCores:             8,
		WorkerPlatform:      "macOS",
		IframePlatform:      "macOS",
		SWPlatform:          "macOS",
		WorkerWebGLRenderer: "ANGLE (Apple, Apple M1, OpenGL 4.1)",
		// G04: a genuine browser passes all three (proxied is inverted: true = toString Proxy).
		NativeDescriptorsOK:   true,
		NativeCallNewOK:       true,
		NativeToStringProxied: false,
		// v3 batch (G09–G14, G17, G22, G23), all consistent with real desktop Chrome 125.
		IframeWebdriver:       false,
		IframeProxied:         false,
		MaxTouchPoints:        0, // desktop: no touch screen
		SWWebdriver:           false,
		SWCDP:                 false,
		NavProtoDescriptorsOK: true,
		ChromeRuntimeOK:       true,
		ChromeLateInjection:   false,
		JSEngine:              "v8",
		WebRTCIPs:             []string{"192.168.1.50"}, // host candidate only — private, never a tell
		EgressIP:              "85.105.22.17",
		ImageBroken:           false,
		MimeTypes:             2,
		OuterH:                900,
		InnerH:                800,
		// v4 env (G15/G21) as real desktop Chrome sends it; Chrome exposes no GPC property (nil = absent).
		Env: botcheck.EnvInfo{
			MatchMedia:     true,
			DPR:            2,
			ColorScheme:    "light",
			DynamicRange:   "standard",
			Gamut:          "p3",
			Connection:     botcheck.ConnectionInfo{EffectiveType: "4g", Downlink: 10, RTT: 50},
			StorageQuotaMB: 285000,
			Permissions:    botcheck.PermissionSample{Notifications: "default", Geolocation: "prompt"},
			EMEClearKey:    boolPtr(true),
		},
	}
}

func triggeredIDs(r botcheck.Report) []string {
	var ids []string
	for _, c := range r.Checks {
		if c.Triggered {
			ids = append(ids, c.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func check(t *testing.T, r botcheck.Report, id string) botcheck.Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check with id %q in report", id)
	return botcheck.Check{}
}

func TestCleanChromeScoresHuman(t *testing.T) {
	r := botcheck.Evaluate(cleanChrome())
	if r.Score != 100 || r.Verdict != "human" {
		t.Fatalf("clean Chrome: score=%d verdict=%q, want 100/human (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}
}

// ruleFirePaths maps every rule ID to a fixture firing exactly it. That proves each Go predicate is
// reachable, not that botcheck.js collects its fields: real-automation testing stays necessary.
var ruleFirePaths = map[string]func() botcheck.Signals{
	// ── Hard tells ──────────────────────────────────────────────────────────────
	"webdriver":         func() botcheck.Signals { s := cleanChrome(); s.Webdriver = true; return s },
	"framework_globals": func() botcheck.Signals { s := cleanChrome(); s.FrameworkGlobals = []string{"__nightmare"}; return s },
	"bot_user_agent":    func() botcheck.Signals { s := cleanChrome(); s.HTTPUserAgent = "curl/8.7.1"; return s },
	"native_tamper":     func() botcheck.Signals { s := cleanChrome(); s.NativeToStringOK = false; return s },
	"tostring_proxy":    func() botcheck.Signals { s := cleanChrome(); s.NativeToStringProxied = true; return s },
	"software_renderer": func() botcheck.Signals { s := cleanChrome(); s.WebGLRenderer = "Google SwiftShader"; return s },
	"iframe_webdriver":  func() botcheck.Signals { s := cleanChrome(); s.IframeWebdriver = true; return s },
	"webdriver_sw":      func() botcheck.Signals { s := cleanChrome(); s.SWWebdriver = true; return s },

	// ── Consistency cross-checks ────────────────────────────────────────────────
	"ua_header_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.HTTPUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.1 Safari/537.36"
		return s
	},
	"context_ua_mismatch":       func() botcheck.Signals { s := cleanChrome(); s.NavWorkerUA = firefoxUA; return s },
	"context_language_mismatch": func() botcheck.Signals { s := cleanChrome(); s.WorkerLanguages = []string{"fr-FR", "fr"}; return s },
	"context_cores_mismatch":    func() botcheck.Signals { s := cleanChrome(); s.WorkerCores = 4; return s },
	"context_platform_mismatch": func() botcheck.Signals { s := cleanChrome(); s.WorkerPlatform = "Linux"; return s },
	"context_webgl_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.WorkerWebGLRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
		return s
	},
	"ch_platform_mismatch": func() botcheck.Signals { s := cleanChrome(); s.SecCHUAPlatform = `"Windows"`; return s },
	"ua_os_mismatch":       func() botcheck.Signals { s := cleanChrome(); s.UAData.Platform = "Windows"; return s },
	"engine_ua_mismatch":   func() botcheck.Signals { s := cleanChrome(); s.Engine = "gecko"; return s },
	"ua_chrome_version_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.UAData.FullVersionList[0].Version = "124.0.6300.0"
		return s
	},
	"embedded_runtime": func() botcheck.Signals {
		s := cleanChrome()
		s.HTTPUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Electron/32.1.1 Safari/537.36"
		return s
	},
	"tz_mismatch":   func() botcheck.Signals { s := cleanChrome(); s.IPTimezone = "+09:00"; return s },
	"datacenter_ip": func() botcheck.Signals { s := cleanChrome(); s.IsDatacenter = true; return s },
	"proxy_ip":      func() botcheck.Signals { s := cleanChrome(); s.IsVPN = true; return s },
	"permission_impossible": func() botcheck.Signals {
		s := cleanChrome()
		s.PermissionState, s.NotificationPerm = "prompt", "denied"
		return s
	},
	"lang_mismatch":        func() botcheck.Signals { s := cleanChrome(); s.AcceptLanguage = "fr-FR,fr;q=0.9"; return s },
	"tz_self_inconsistent": func() botcheck.Signals { s := cleanChrome(); s.TZOffset = 0; return s },
	"canvas_unstable":      func() botcheck.Signals { s := cleanChrome(); s.CanvasStable = false; return s },
	"ch_brands_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.SecCHUA = `"Chromium";v="125", "Microsoft Edge";v="125", "Not.A/Brand";v="24"`
		return s
	},
	"vendor_mismatch":           func() botcheck.Signals { s := cleanChrome(); s.Vendor = "Apple Computer, Inc."; return s },
	"app_version_mismatch":      func() botcheck.Signals { s := cleanChrome(); s.AppVersion = "wrong/1.0"; return s },
	"productsub_mismatch":       func() botcheck.Signals { s := cleanChrome(); s.ProductSub = "20100101"; return s },
	"language_primary_mismatch": func() botcheck.Signals { s := cleanChrome(); s.NavLanguage = "fr-FR"; return s },
	"webgl_vendor_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.WebGLRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
		return s
	},
	"gpu_os_mismatch": func() botcheck.Signals {
		s := cleanChrome()
		s.NavMainUA = chromeWinGPUUA
		s.WebGLVendor, s.WebGLRenderer = angleAppleVendor, angleAppleRenderer
		return s
	},
	"iframe_proxy":         func() botcheck.Signals { s := cleanChrome(); s.IframeProxied = true; return s },
	"mobile_no_touch":      func() botcheck.Signals { s := realAndroid(); s.MaxTouchPoints = 0; return s },
	"jsengine_ua_mismatch": func() botcheck.Signals { s := cleanChrome(); s.JSEngine = "spidermonkey"; return s },
	"webrtc_ip_mismatch":   func() botcheck.Signals { s := cleanChrome(); s.WebRTCIPs = []string{"203.0.113.9"}; return s },
	"fingerprint_reuse":    func() botcheck.Signals { s := cleanChrome(); s.FingerprintIPs = 5; return s },
	"ip_blocklisted": func() botcheck.Signals {
		s := cleanChrome()
		s.IPBlocklistSources = []string{"ipsum"}
		s.IPBlocklistCount = 5 // ≥ ipsumBlocklistFloor (3), so the ipsum-only listing fires
		return s
	},

	// ── Soft heuristics (fire alone; only bite score at ≥3 cluster) ─────────────
	"empty_plugins":   func() botcheck.Signals { s := cleanChrome(); s.Plugins = 0; return s },
	"empty_languages": func() botcheck.Signals { s := cleanChrome(); s.Languages = []string{}; return s },
	"default_geometry": func() botcheck.Signals {
		s := cleanChrome()
		s.ScreenW, s.ScreenH, s.AvailW, s.AvailH = 800, 600, 800, 600
		return s
	},
	"impossible_window":            func() botcheck.Signals { s := cleanChrome(); s.OuterW, s.InnerW = 100, 200; return s },
	"no_chrome_object":             func() botcheck.Signals { s := cleanChrome(); s.HasChromeObject = false; return s },
	"implausible_hardware":         func() botcheck.Signals { s := cleanChrome(); s.DeviceMemory = 999; return s },
	"screen_avail_impossible":      func() botcheck.Signals { s := cleanChrome(); s.AvailW = 9999; return s },
	"low_color_depth":              func() botcheck.Signals { s := cleanChrome(); s.ColorDepth = 8; return s },
	"sec_fetch_missing":            func() botcheck.Signals { s := cleanChrome(); s.SecFetchMode = ""; return s },
	"accept_encoding_missing":      func() botcheck.Signals { s := cleanChrome(); s.HTTPAcceptEncoding = ""; return s },
	"accept_language_missing":      func() botcheck.Signals { s := cleanChrome(); s.AcceptLanguage = ""; return s },
	"accept_nav_mismatch":          func() botcheck.Signals { s := cleanChrome(); s.HTTPAccept = "application/json"; return s },
	"canvas_blank":                 func() botcheck.Signals { s := cleanChrome(); s.CanvasBlank = true; return s },
	"missing_proprietary_codecs":   func() botcheck.Signals { s := cleanChrome(); s.CodecH264, s.CodecAAC = false, false; return s },
	"no_fonts":                     func() botcheck.Signals { s := cleanChrome(); s.FontCount = 0; return s },
	"image_broken":                 func() botcheck.Signals { s := cleanChrome(); s.ImageBroken = true; return s },
	"plugins_mimetypes_incoherent": func() botcheck.Signals { s := cleanChrome(); s.MimeTypes = 0; return s },
	"zero_outer_height":            func() botcheck.Signals { s := cleanChrome(); s.OuterH = 0; return s },
	"matchmedia_missing":           func() botcheck.Signals { s := cleanChrome(); s.Env.MatchMedia = false; return s },
	"netinfo_incoherent":           func() botcheck.Signals { s := cleanChrome(); s.Env.Connection.RTT = 2000; return s },
	"ip_fingerprint_churn":         func() botcheck.Signals { s := cleanChrome(); s.FingerprintChurn = 20; return s },
	"cdp_both":                     func() botcheck.Signals { s := cleanChrome(); s.CDPMainThread, s.CDPWorker = true, true; return s },
	"cdp_main_only":                func() botcheck.Signals { s := cleanChrome(); s.CDPMainThread = true; return s },
	"cdp_sw_only":                  func() botcheck.Signals { s := cleanChrome(); s.SWCDP = true; return s },
	"native_descriptor_tamper":     func() botcheck.Signals { s := cleanChrome(); s.NativeDescriptorsOK = false; return s },
	"native_callnew_tamper":        func() botcheck.Signals { s := cleanChrome(); s.NativeCallNewOK = false; return s },
	"navigator_proto_tamper":       func() botcheck.Signals { s := cleanChrome(); s.NavProtoDescriptorsOK = false; return s },
	"chrome_runtime_tamper":        func() botcheck.Signals { s := cleanChrome(); s.ChromeRuntimeOK = false; return s },
	"chrome_late_injection":        func() botcheck.Signals { s := cleanChrome(); s.ChromeLateInjection = true; return s },
}

// A rule without a fire-path fixture, or with a dead predicate, fails loudly instead of rotting silently.
func TestEveryRuleCanFire(t *testing.T) {
	// (1) Coverage: every scored rule needs a fire-path fixture.
	for _, c := range botcheck.Evaluate(cleanChrome()).Checks {
		if _, ok := ruleFirePaths[c.ID]; !ok {
			t.Errorf("rule %q has no ruleFirePaths fixture — add one so a dead predicate can't go unnoticed", c.ID)
		}
	}
	// (2) Each fixture fires its target; clean fixture never does.
	for id, mk := range ruleFirePaths {
		if check(t, botcheck.Evaluate(cleanChrome()), id).Triggered {
			t.Errorf("%s fires on the clean fixture — it must stay silent on a perfect human", id)
		}
		if c := check(t, botcheck.Evaluate(mk()), id); !c.Triggered {
			t.Errorf("%s did not fire on its fire-path fixture — the predicate may be dead (cf. the webglGPU collector bug)", id)
		}
	}
}

func TestHeadlessChromeScoresBot(t *testing.T) {
	s := cleanChrome()
	s.Webdriver = true
	s.WebGLRenderer = "Google SwiftShader"
	s.CDPMainThread, s.CDPWorker = true, true
	s.HasChromeObject = false

	r := botcheck.Evaluate(s)
	if r.Verdict != "bot" {
		t.Errorf("headless Chrome: verdict=%q, want bot (score=%d)", r.Verdict, r.Score)
	}
	if r.Score != 0 {
		t.Errorf("headless Chrome: score=%d, want 0 (well past the bot floor)", r.Score)
	}
	for _, id := range []string{"webdriver", "software_renderer", "cdp_both"} {
		if !check(t, r, id).Triggered {
			t.Errorf("expected %q to fire for headless Chrome", id)
		}
	}
}

func TestSoftwareRendererVarieties(t *testing.T) {
	renderers := []string{
		"Google SwiftShader",
		"llvmpipe (LLVM 15.0.6, 256 bits)",
		"Mesa / Vulkan software rasterizer (lavapipe)",
		"Mesa DRI swrast (Software Rasterizer)",
		"softpipe",
		"virgl (Mesa DRI)",
		"SVGA3D; build: RELEASE;",
		"VMware SVGA",
		"VirtualBox Graphics Adapter",
		"QEMU Virtual Video",
		"software (WebGL unavailable)",
	}
	for _, rend := range renderers {
		s := cleanChrome()
		s.WebGLRenderer = rend
		r := botcheck.Evaluate(s)
		if !check(t, r, "software_renderer").Triggered {
			t.Errorf("renderer %q should trigger software_renderer", rend)
		}
	}

	cleanRenderers := []string{
		"ANGLE (Apple, Apple M1, OpenGL 4.1)",
		"NVIDIA GeForce RTX 3080",
		"AMD Radeon RX 6600",
		"Intel Iris Xe Graphics",
		"WebKit WebGL",
	}
	for _, rend := range cleanRenderers {
		s := cleanChrome()
		s.WebGLRenderer = rend
		r := botcheck.Evaluate(s)
		if check(t, r, "software_renderer").Triggered {
			t.Errorf("real GPU renderer %q must not trigger software_renderer", rend)
		}
	}
}

func TestStealthSpoofScoresBot(t *testing.T) {
	// Spoofed UA, tz disagreeing with the IP and a datacenter egress: 3 consistency signals.
	s := cleanChrome()
	s.HTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	s.BrowserTZ, s.TZOffset = "Europe/Moscow", -180 // self-consistent Moscow, but ≠ the IP
	s.IsDatacenter, s.IsProxy = true, true

	r := botcheck.Evaluate(s)
	want := []string{"datacenter_ip", "tz_mismatch", "ua_header_mismatch"}
	if diff := cmp.Diff(want, triggeredIDs(r)); diff != "" {
		t.Errorf("stealth spoof fired wrong checks (-want +got):\n%s", diff)
	}
	// 35 + 25 + 30 = 90 → score 10 → bot.
	if r.Score != 10 || r.Verdict != "bot" {
		t.Errorf("stealth spoof: score=%d verdict=%q, want 10/bot", r.Score, r.Verdict)
	}
}

func TestPlatformSpoofScoresSuspicious(t *testing.T) {
	// UA claims macOS, userAgentData says Windows: one 30-weight consistency hit ⇒ 70 ⇒ suspicious.
	s := cleanChrome()
	s.SecCHUAPlatform = "" // isolate the ua_os check from the CH-platform check
	s.UAData = botcheck.UAData{Platform: "Windows"}
	// Secondary contexts claim Windows too, so only the UA-vs-platform tell fires.
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "Windows", "Windows", "Windows"

	r := botcheck.Evaluate(s)
	if diff := cmp.Diff([]string{"ua_os_mismatch"}, triggeredIDs(r)); diff != "" {
		t.Errorf("platform spoof fired wrong checks (-want +got):\n%s", diff)
	}
	if r.Score != 70 || r.Verdict != "suspicious" {
		t.Errorf("platform spoof: score=%d verdict=%q, want 70/suspicious", r.Score, r.Verdict)
	}
}

func TestTwoSoftSignalsStayHuman(t *testing.T) {
	// A privacy-conscious human must NOT be condemned by soft signals alone: <3 ⇒ no deduction.
	s := cleanChrome()
	s.Plugins = 0                   // empty_plugins (soft)
	s.ScreenW, s.ScreenH = 800, 600 // default_geometry (soft)
	s.AvailW, s.AvailH = 800, 600   // keep avail ≤ screen (else screen_avail_impossible adds 3rd)

	r := botcheck.Evaluate(s)
	if !check(t, r, "empty_plugins").Triggered || !check(t, r, "default_geometry").Triggered {
		t.Fatalf("expected the two soft signals to be flagged")
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("two soft signals: score=%d verdict=%q, want 100/human (combo rule)", r.Score, r.Verdict)
	}
	// Display helpers agree: 2 soft ⇒ "flagged", with no per-row or cluster deduction.
	if r.SoftFired() != 2 || r.SoftClusterActive() {
		t.Errorf("2 soft: SoftFired=%d clusterActive=%v, want 2 / false", r.SoftFired(), r.SoftClusterActive())
	}
}

func TestThreeSoftSignalsPromoteToSuspicious(t *testing.T) {
	s := cleanChrome()
	s.Plugins = 0                   // empty_plugins
	s.ScreenW, s.ScreenH = 800, 600 // default_geometry
	s.AvailW, s.AvailH = 800, 600   // avoid incidental 4th soft (avail ≤ screen)
	s.Languages = nil               // empty_languages (also clears lang cross-check)

	r := botcheck.Evaluate(s)
	// ≥3 soft ⇒ single 25 deduction ⇒ 75 ⇒ suspicious.
	if r.Score != 75 || r.Verdict != "suspicious" {
		t.Errorf("three soft signals: score=%d verdict=%q, want 75/suspicious (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}
	// The cluster penalty is all that moved the score, so it must equal 100 - score.
	if r.SoftFired() != 3 || !r.SoftClusterActive() {
		t.Errorf("3 soft: SoftFired=%d clusterActive=%v, want 3 / true", r.SoftFired(), r.SoftClusterActive())
	}
	if got := r.SoftClusterPenalty(); got != 100-r.Score {
		t.Errorf("SoftClusterPenalty=%d, want %d (100-score)", got, 100-r.Score)
	}
}

func TestServerOnlySkipsClientChecks(t *testing.T) {
	// Plain curl posts no fingerprint: client checks are Skipped, neither counted nor read as a pass.
	r := botcheck.Evaluate(botcheck.Signals{HeadersSupplied: true, IPSupplied: true, HTTPUserAgent: "curl/8.4.0"})

	if !check(t, r, "webdriver").Skipped {
		t.Errorf("client check webdriver should be Skipped on a server-only request")
	}
	if check(t, r, "webdriver").Triggered {
		t.Errorf("a skipped client check must not read as triggered")
	}
	// tz_mismatch needs the client-only BrowserTZ, so it skips too (as tz_self_inconsistent does).
	if !check(t, r, "tz_mismatch").Skipped {
		t.Errorf("tz_mismatch should be Skipped on a server-only request (needs client BrowserTZ)")
	}
	// GPU coherence rules read only client-collected WebGL strings, so they skip too.
	for _, id := range []string{"webgl_vendor_mismatch", "gpu_os_mismatch"} {
		if !check(t, r, id).Skipped {
			t.Errorf("%s should be Skipped on a server-only request", id)
		}
	}
	bot := check(t, r, "bot_user_agent")
	if bot.Skipped || !bot.Triggered {
		t.Errorf("bot_user_agent should fire (not skip) for a curl UA: %+v", bot)
	}
	if r.Verdict != "bot" { // 100 - 60 = 40 ⇒ bot
		t.Errorf("curl: verdict=%q score=%d, want bot", r.Verdict, r.Score)
	}
}

func TestEmptyUserAgentFlags(t *testing.T) {
	r := botcheck.Evaluate(botcheck.Signals{HeadersSupplied: true})
	if !check(t, r, "bot_user_agent").Triggered {
		t.Errorf("an empty User-Agent should trip bot_user_agent")
	}
}

func TestElectronUAIsSuspiciousNotHardBot(t *testing.T) {
	// Electron reads suspicious (embedded_runtime), NOT a curl-class bot; browser headers isolate it.
	const electronUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Claude/1.2 Chrome/148.0.0.0 Electron/42.5.1 Safari/537.36"
	r := botcheck.Evaluate(botcheck.Signals{
		HeadersSupplied:    true,
		IPSupplied:         true,
		HTTPUserAgent:      electronUA,
		SecFetchMode:       "navigate",
		AcceptLanguage:     "en-US,en;q=0.9",
		HTTPAcceptEncoding: "gzip, deflate, br",
	})

	if check(t, r, "bot_user_agent").Triggered {
		t.Errorf("Electron UA must NOT trip the hard bot_user_agent rule")
	}
	if !check(t, r, "embedded_runtime").Triggered {
		t.Errorf("Electron UA should trip embedded_runtime")
	}
	if r.Score != 75 || r.Verdict != "suspicious" {
		t.Errorf("Electron UA: score=%d verdict=%q, want 75/suspicious", r.Score, r.Verdict)
	}
}

func TestVendorMismatchFlags(t *testing.T) {
	s := cleanChrome()
	s.Vendor = "Apple Computer, Inc." // a Chrome UA must report "Google Inc."
	r := botcheck.Evaluate(s)
	if !check(t, r, "vendor_mismatch").Triggered {
		t.Errorf("vendor_mismatch should fire for a Chrome UA with a non-Google vendor")
	}
	if r.Score != 80 { // one 20-weight consistency hit
		t.Errorf("vendor mismatch: score=%d, want 80 (fired: %v)", r.Score, triggeredIDs(r))
	}
}

func TestAppVersionAndLanguageMismatchFlag(t *testing.T) {
	s := cleanChrome()
	s.AppVersion = "not-the-user-agent"
	s.NavLanguage = "fr-FR" // languages[0] is en-US
	r := botcheck.Evaluate(s)
	if !check(t, r, "app_version_mismatch").Triggered {
		t.Errorf("app_version_mismatch should fire when appVersion ≠ UA sans Mozilla/")
	}
	if !check(t, r, "language_primary_mismatch").Triggered {
		t.Errorf("language_primary_mismatch should fire when language ≠ languages[0]")
	}
}

func TestSecFetchMissingFlagsScriptedBrowserUA(t *testing.T) {
	// A browser UA with no Sec-Fetch-* is a scripted client; clean browsers send the header.
	scripted := botcheck.Evaluate(botcheck.Signals{HeadersSupplied: true, HTTPUserAgent: chromeMacUA}) // SecFetchMode empty
	if !check(t, scripted, "sec_fetch_missing").Triggered {
		t.Errorf("sec_fetch_missing should fire for a browser UA lacking Sec-Fetch-*")
	}
	if check(t, botcheck.Evaluate(cleanChrome()), "sec_fetch_missing").Triggered {
		t.Errorf("sec_fetch_missing must NOT fire for a browser that sent Sec-Fetch-Mode")
	}
}

// G06: soft (proxies strip headers); fires only when a claimed browser omits what all browsers send.
func TestHeaderPresenceSignals(t *testing.T) {
	browserNoEnc := cleanChrome()
	browserNoEnc.HTTPAcceptEncoding = ""
	browserNoLang := cleanChrome()
	browserNoLang.AcceptLanguage = ""
	browserStarAccept := cleanChrome()
	browserStarAccept.HTTPAccept = "*/*" // the bare-curl tell
	browserJSONAccept := cleanChrome()
	browserJSONAccept.HTTPAccept = "application/json" // the API-client tell
	browserNoAccept := cleanChrome()
	browserNoAccept.HTTPAccept = "" // absent = "not supplied" — must not fire

	cases := []struct {
		name string
		s    botcheck.Signals
		id   string
		want bool
	}{
		{"encoding missing under a browser UA fires", browserNoEnc, "accept_encoding_missing", true},
		{"encoding present does not fire", cleanChrome(), "accept_encoding_missing", false},
		{"encoding missing under a curl UA ignored", botcheck.Signals{HeadersSupplied: true, HTTPUserAgent: "curl/8.4.0"}, "accept_encoding_missing", false},
		{"encoding missing under an empty UA ignored", botcheck.Signals{HeadersSupplied: true}, "accept_encoding_missing", false},
		{"language missing under a browser UA fires", browserNoLang, "accept_language_missing", true},
		{"language present does not fire", cleanChrome(), "accept_language_missing", false},
		{"language missing under a curl UA ignored", botcheck.Signals{HeadersSupplied: true, HTTPUserAgent: "curl/8.4.0"}, "accept_language_missing", false},
		{"language missing under an empty UA ignored", botcheck.Signals{HeadersSupplied: true}, "accept_language_missing", false},
		{"Accept */* under a browser UA fires", browserStarAccept, "accept_nav_mismatch", true},
		{"Accept application/json under a browser UA fires", browserJSONAccept, "accept_nav_mismatch", true},
		{"a real browser Accept does not fire", cleanChrome(), "accept_nav_mismatch", false},
		{"an absent Accept never fires", browserNoAccept, "accept_nav_mismatch", false},
		{"Accept */* under a curl UA ignored", botcheck.Signals{HeadersSupplied: true, HTTPUserAgent: "curl/8.4.0", HTTPAccept: "*/*"}, "accept_nav_mismatch", false},
		{"Accept */* under an empty UA ignored", botcheck.Signals{HeadersSupplied: true, HTTPAccept: "*/*"}, "accept_nav_mismatch", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check(t, botcheck.Evaluate(tc.s), tc.id).Triggered; got != tc.want {
				t.Errorf("%s: Triggered = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

func TestSingleHeaderSoftSignalStaysHuman(t *testing.T) {
	// One missing header is ONE free soft signal, else a header-rewriting proxy would condemn a real user.
	s := cleanChrome()
	s.HTTPAcceptEncoding = ""

	r := botcheck.Evaluate(s)
	if !check(t, r, "accept_encoding_missing").Triggered {
		t.Fatalf("accept_encoding_missing should be flagged")
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("one header soft signal: score=%d verdict=%q, want 100/human (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}
	if r.SoftFired() != 1 || r.SoftClusterActive() {
		t.Errorf("1 soft: SoftFired=%d clusterActive=%v, want 1 / false", r.SoftFired(), r.SoftClusterActive())
	}
}

func TestTimezoneOffsetComparedNotStringMatched(t *testing.T) {
	// IP2Location gives a UTC offset, the browser an IANA name: Europe/Moscow vs +03:00 must match.
	same := cleanChrome()
	same.BrowserTZ, same.TZOffset, same.IPTimezone = "Europe/Moscow", -180, "+03:00"
	if check(t, botcheck.Evaluate(same), "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch must not fire when the IANA zone's offset equals the IP offset")
	}

	// Genuine offset disagreement still fires.
	diff := cleanChrome()
	diff.BrowserTZ, diff.TZOffset, diff.IPTimezone = "America/Los_Angeles", 480, "+03:00" // -08:00 vs +03:00
	if !check(t, botcheck.Evaluate(diff), "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch should fire when the browser and IP offsets truly differ")
	}
}

func TestLayer2Signals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		{"tz self-inconsistent", func(s *botcheck.Signals) { s.TZOffset = 0 }, "tz_self_inconsistent"}, // NY zone but offset 0
		{"canvas randomised", func(s *botcheck.Signals) { s.CanvasStable = false }, "canvas_unstable"},
		{"canvas blank", func(s *botcheck.Signals) { s.CanvasBlank = true }, "canvas_blank"},
		{"CH brands differ", func(s *botcheck.Signals) { s.Brands = []string{"Microsoft Edge", "Not.A/Brand"} }, "ch_brands_mismatch"},
		{"no proprietary codecs", func(s *botcheck.Signals) { s.CodecH264, s.CodecAAC = false, false }, "missing_proprietary_codecs"},
		{"no fonts", func(s *botcheck.Signals) { s.FontCount = 0 }, "no_fonts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire", tc.id)
			}
		})
	}
}

func TestCleanBrowserPassesLayer2(t *testing.T) {
	// The clean fixture (all Layer-2 fields internally consistent) stays 100/human.
	r := botcheck.Evaluate(cleanChrome())
	if r.Score != 100 || r.Verdict != "human" {
		t.Fatalf("clean browser with Layer-2 signals: score=%d verdict=%q, want 100/human (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}
}

func TestUnknownIPTimezoneDoesNotTripCrossCheck(t *testing.T) {
	// An empty IP timezone (localhost, unknown IP) must not fire against a real browser timezone.
	s := cleanChrome()
	s.BrowserTZ, s.TZOffset = "Europe/Moscow", -180 // self-consistent Moscow
	s.IPTimezone = ""                               // handler maps IP2Location's "-" to ""

	r := botcheck.Evaluate(s)
	if check(t, r, "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch must not fire when the IP timezone is unknown")
	}
	if r.Verdict != "human" {
		t.Errorf("clean browser with unknown IP tz: verdict=%q, want human", r.Verdict)
	}
}

// crawler builds what a real bot presents: no client fingerprint (crawlers don't run our JS).
func crawler(ua, asn string) botcheck.Signals {
	return botcheck.Signals{HeadersSupplied: true, IPSupplied: true, HTTPUserAgent: ua, ASN: asn}
}

// "good-bot" needs the operator's single-tenant crawler ASN, which outsiders (even on its cloud)
// can't originate from; multi-tenant Googlebot and cloud-hosted GPTBot stay unverified.
func TestGoodBotClassification(t *testing.T) {
	const (
		yandex     = "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
		gptbot     = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot"
		claudeUser = "Mozilla/5.0 (compatible; Claude-User/1.0; +Anthropic)"
		claudeBot  = "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com/claudebot)"
		googlebot  = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
		bingbot    = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
		applebot   = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
		metaFetch  = "meta-externalfetcher/1.1"
		metaAgent  = "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)"
		bytespider = "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"
		seznam     = "Mozilla/5.0 (compatible; SeznamBot/4.0; +https://o-seznam.cz/)"
		yeti       = "Mozilla/5.0 (compatible; Yeti/1.1; +https://naver.me/bot)"
		yetiNoMark = "Mozilla/5.0 (compatible; Yeti/1.1)"
	)
	// ASN numbers: crawler ASNs (verify) vs clouds/others (must NOT verify).
	const (
		asnYandex      = "13238"  // YandexBot's own AS
		asnYandexCloud = "200350" // Yandex Cloud — rentable, DIFFERENT AS (red-team evasion)
		asnApple       = "714"    // Applebot
		asnMeta        = "32934"  // Meta
		asnSeznam      = "43037"  // SeznamBot
		asnNaver       = "23576"  // Yeti / Naver
		asnAnthropic   = "399358" // Claude-User
		asnByteDance   = "396986" // Bytespider
		asnGoogle      = "15169"  // Google (multi-tenant: crawler + GCP)
		asnMicrosoft   = "8075"   // Microsoft (multi-tenant: Bing + Azure + GPTBot host)
		asnAWS         = "16509"  // Amazon AWS (cloud host)
		asnDO          = "14061"  // DigitalOcean (off-network)
		asnCloudflare  = "13335"  // Cloudflare (off-network)
	)
	cases := []struct {
		name     string
		ua       string
		asn      string
		verdict  string
		botName  string // "" ⇒ expect Bot == nil (not a recognised bot)
		verified bool
	}{
		{"YandexBot from Yandex", yandex, asnYandex, "good-bot", "YandexBot", true},
		{"YandexBot from Yandex CLOUD (rented VM — must not verify)", yandex, asnYandexCloud, "bot", "YandexBot", false},
		{"YandexBot off-network (spoof)", yandex, asnDO, "bot", "YandexBot", false},
		{"YandexBot no ASN (fail closed)", yandex, "", "bot", "YandexBot", false},
		{"GPTBot on Azure (declared, not spoof-flagged)", gptbot, asnMicrosoft, "bot", "GPTBot (OpenAI)", false},
		{"Claude-User from Anthropic", claudeUser, asnAnthropic, "good-bot", "Claude-User (Anthropic)", true},
		{"Claude-User off-network (AWS)", claudeUser, asnAWS, "bot", "Claude-User (Anthropic)", false},
		{"ClaudeBot declared-only", claudeBot, asnAWS, "bot", "ClaudeBot (Anthropic)", false},
		{"Googlebot multi-tenant (never verified even from Google AS)", googlebot, asnGoogle, "bot", "Googlebot", false},
		{"Bingbot multi-tenant", bingbot, asnMicrosoft, "bot", "Bingbot", false},
		{"Applebot from Apple", applebot, asnApple, "good-bot", "Applebot", true},
		{"Applebot from AS 'AS714' (prefix-normalised)", applebot, "AS714", "good-bot", "Applebot", true},
		{"Meta-ExternalFetcher from Meta (no generic bot token)", metaFetch, asnMeta, "good-bot", "Meta-ExternalFetcher", true},
		{"Meta-ExternalAgent off-network still penalised", metaAgent, asnCloudflare, "bot", "Meta-ExternalAgent", false},
		{"Bytespider from ByteDance", bytespider, asnByteDance, "good-bot", "Bytespider (ByteDance)", true},
		{"Bytespider off-network (AWS)", bytespider, asnAWS, "bot", "Bytespider (ByteDance)", false},
		{"SeznamBot from Seznam", seznam, asnSeznam, "good-bot", "SeznamBot", true},
		{"Yeti with naver marker from Naver", yeti, asnNaver, "good-bot", "Yeti (Naver)", true},
		{"Yeti without the naver marker is not recognised", yetiNoMark, asnNaver, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(crawler(tc.ua, tc.asn))
			if tc.botName == "" {
				if r.Bot != nil {
					t.Fatalf("expected Bot == nil, got %+v", r.Bot)
				}
				return
			}
			if r.Bot == nil {
				t.Fatalf("expected Bot %q, got nil (verdict %s)", tc.botName, r.Verdict)
			}
			if r.Bot.Name != tc.botName || r.Bot.Verified != tc.verified {
				t.Errorf("Bot = %+v, want name %q verified %v", r.Bot, tc.botName, tc.verified)
			}
			if r.Verdict != tc.verdict {
				t.Errorf("Verdict = %q, want %q (score %d)", r.Verdict, tc.verdict, r.Score)
			}
			// No-evasion: every recognised bot trips bot_user_agent, suppressed only when verified.
			bua := check(t, r, "bot_user_agent")
			if !bua.Triggered {
				t.Errorf("bot_user_agent must fire for recognised bot %q (no silent escape)", tc.botName)
			}
			if bua.Suppressed != tc.verified {
				t.Errorf("bot_user_agent Suppressed = %v, want %v (suppressed iff verified)", bua.Suppressed, tc.verified)
			}
		})
	}
}

// The classifier needs a bot token: curl stays an unnamed bot, a human is never touched.
func TestCurlAndHumanAreNotGoodBots(t *testing.T) {
	if r := botcheck.Evaluate(crawler("curl/8.4.0", "24940")); r.Bot != nil || r.Verdict != "bot" {
		t.Errorf("curl: Bot=%+v verdict=%q, want nil / bot", r.Bot, r.Verdict)
	}
	// A human on Apple's network with a Chrome UA: no bot token, so the ASN is never consulted.
	h := cleanChrome()
	h.ASN = "714"
	if r := botcheck.Evaluate(h); r.Bot != nil || r.Verdict != "human" {
		t.Errorf("human on a crawler ASN: Bot=%+v verdict=%q, want nil / human", r.Bot, r.Verdict)
	}
}

// G37: an ipsum-only listing must clear the floor; a deliberate ban fires at any count.
func TestIPBlocklistedRule(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*botcheck.Signals)
		fires   bool
		verdict string
	}{
		{"not listed", func(s *botcheck.Signals) {}, false, "human"},
		{"ipsum-only below floor (count 2)", func(s *botcheck.Signals) {
			s.IPBlocklistSources, s.IPBlocklistCount = []string{"ipsum"}, 2
		}, false, "human"},
		{"ipsum-only at floor (count 3)", func(s *botcheck.Signals) {
			s.IPBlocklistSources, s.IPBlocklistCount = []string{"ipsum"}, 3
		}, true, "suspicious"},
		{"deliberate source, no count, bypasses floor", func(s *botcheck.Signals) {
			s.IPBlocklistSources, s.IPBlocklistDeliberate = []string{"rate-limiter"}, true
		}, true, "suspicious"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			r := botcheck.Evaluate(s)
			if got := check(t, r, "ip_blocklisted").Triggered; got != tc.fires {
				t.Errorf("ip_blocklisted Triggered = %v, want %v (score %d)", got, tc.fires, r.Score)
			}
			if r.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q (score %d)", r.Verdict, tc.verdict, r.Score)
			}
		})
	}
}

// A verified crawler's blocklist hit is recorded, not counted, like its datacenter/proxy hits.
func TestIPBlocklistedSuppressedForVerifiedGoodBot(t *testing.T) {
	s := crawler("Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)", "714") // verified from Apple's ASN
	s.IPBlocklistSources, s.IPBlocklistCount = []string{"ipsum"}, 8
	r := botcheck.Evaluate(s)
	if r.Verdict != "good-bot" {
		t.Fatalf("verdict = %q, want good-bot (score %d)", r.Verdict, r.Score)
	}
	c := check(t, r, "ip_blocklisted")
	if !c.Triggered || !c.Suppressed {
		t.Errorf("ip_blocklisted for verified good bot: Triggered=%v Suppressed=%v, want both true", c.Triggered, c.Suppressed)
	}
}

// G01/G02/G05: each mutation fires one cross-check against the clean Chrome fixture.
func TestQuickWinSignals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// G05: engine feature-detected Gecko while UA claims Chrome (Blink).
		{"engine vs UA", func(s *botcheck.Signals) { s.Engine = "gecko" }, "engine_ua_mismatch"},
		// G01: UA says Chrome/125 but userAgentData's Chromium entry reports 120.
		{"UA version vs userAgentData Chromium entry", func(s *botcheck.Signals) {
			s.UAData.FullVersionList = []botcheck.BrandVersion{{Brand: "Chromium", Version: "120.0.0.0"}, {Brand: "Not.A/Brand", Version: "24"}}
		}, "ua_chrome_version_mismatch"},
		// G01 fallback: no Chromium entry, "Google Chrome" entry still disagrees.
		{"version via Google Chrome entry", func(s *botcheck.Signals) {
			s.UAData.FullVersionList = []botcheck.BrandVersion{{Brand: "Google Chrome", Version: "120.0.0.0"}, {Brand: "Not.A/Brand", Version: "24"}}
		}, "ua_chrome_version_mismatch"},
		// G02: productSub is Gecko's constant on a Chrome (WebKit/Blink) UA.
		{"productSub wrong for engine", func(s *botcheck.Signals) { s.ProductSub = "20100101" }, "productsub_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire", tc.id)
			}
		})
	}
}

// Genuine non-Chrome UAs whose engine-aware checks must NOT false-positive (Opera, Safari, iOS).
const (
	operaUA     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0"
	safariUA    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	iosSafariUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/605.1.15"
	fxiosUA     = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/119.0 Mobile/15E148 Safari/605.1.15"
	criosUA     = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1"
	firefoxUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
)

// v3RuleIDs must fire on crafted signals and stay silent on every real-browser fixture.
var v3RuleIDs = []string{
	"iframe_webdriver", "webdriver_sw", // hard (G11/G14)
	"iframe_proxy", "mobile_no_touch", "jsengine_ua_mismatch", "webrtc_ip_mismatch", // consistency
	// soft
	"cdp_sw_only", "navigator_proto_tamper", "chrome_runtime_tamper", "chrome_late_injection",
	"image_broken", "plugins_mimetypes_incoherent", "zero_outer_height",
}

// v4RuleIDs (G15/G21) follow the same contract as v3RuleIDs.
var v4RuleIDs = []string{"matchmedia_missing", "netinfo_incoherent"}

// mirrorUA sets the UA in every context plus appVersion, keeping the fixture consistent.
func mirrorUA(s *botcheck.Signals, ua string) {
	s.NavMainUA, s.NavWorkerUA, s.NavIframeUA, s.SWUA, s.HTTPUserAgent = ua, ua, ua, ua, ua
	s.AppVersion = strings.TrimPrefix(ua, "Mozilla/")
}

// The real* builders below are fully consistent, so exactly 100 guards every cross-check.

// realOpera: branded 111 over Chromium 125, so version checks must use the Chromium entry.
func realOpera() botcheck.Signals {
	s := cleanChrome()
	mirrorUA(&s, operaUA)
	s.Brands = []string{"Chromium", "Opera", "Not.A/Brand"}
	s.SecCHUA = `"Chromium";v="125", "Opera";v="111", "Not.A/Brand";v="24"`
	s.UAData.FullVersionList = []botcheck.BrandVersion{
		{Brand: "Chromium", Version: "125.0.6422.60"},
		{Brand: "Opera", Version: "111.0.5067.24"},
		{Brand: "Not.A/Brand", Version: "24.0.0.0"},
	}
	return s
}

// realSafari: WebKit, no userAgentData (so no Sec-CH-UA), Apple's vendor, no window.chrome.
func realSafari() botcheck.Signals {
	s := cleanChrome()
	mirrorUA(&s, safariUA)
	s.Engine, s.JSEngine = "webkit", "jsc"
	s.Vendor = "Apple Computer, Inc."
	s.HasChromeObject = false
	s.UAData = botcheck.UAData{} // WebKit exposes no userAgentData
	s.Brands = nil
	s.SecCHUA, s.SecCHUAPlatform = "", "" // so sends no Sec-CH-UA hints
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "", "", ""
	s.WebGLVendor, s.WebGLRenderer = "Apple Inc.", "Apple GPU"
	s.WorkerWebGLRenderer = "Apple GPU"
	// WebKit has no Network Information API; Safari's EME is FairPlay only, so ClearKey is false.
	s.Env.Connection = botcheck.ConnectionInfo{}
	s.Env.EMEClearKey = boolPtr(false)
	return s
}

// realFirefox on Windows: Gecko constants, empty vendor, no userAgentData, no plugins.
func realFirefox() botcheck.Signals {
	s := cleanChrome()
	mirrorUA(&s, firefoxUA)
	s.Engine, s.JSEngine = "gecko", "spidermonkey"
	s.ProductSub = "20100101"
	s.Vendor = "" // Firefox reports empty navigator.vendor
	s.HasChromeObject = false
	s.UAData = botcheck.UAData{}
	s.Brands = nil
	s.SecCHUA, s.SecCHUAPlatform = "", ""
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "", "", ""
	s.WebGLVendor, s.WebGLRenderer = "NVIDIA Corporation", "NVIDIA GeForce RTX 3080"
	s.WorkerWebGLRenderer = "NVIDIA GeForce RTX 3080"
	s.Plugins, s.MimeTypes = 0, 0
	// Firefox has no Network Information API by default but exposes GPC (default off).
	s.Env.Connection = botcheck.ConnectionInfo{}
	s.Env.GPC = boolPtr(false)
	return s
}

// realIPhone: every iOS browser is WebKit (Apple mandates it), no window.chrome, real touch.
func realIPhone(ua string) botcheck.Signals {
	s := cleanChrome()
	mirrorUA(&s, ua)
	s.Engine, s.JSEngine = "webkit", "jsc"
	s.Vendor = "Apple Computer, Inc."
	s.HasChromeObject = false
	s.UAData = botcheck.UAData{}
	s.Brands = nil
	s.SecCHUA, s.SecCHUAPlatform = "", ""
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "", "", ""
	s.MaxTouchPoints = 5 // real iPhones report touch
	s.ScreenW, s.ScreenH = 390, 844
	s.AvailW, s.AvailH = 390, 844
	s.OuterW, s.InnerW = 390, 390
	s.OuterH, s.InnerH = 700, 700
	s.WebGLVendor, s.WebGLRenderer = "Apple Inc.", "Apple GPU"
	s.WorkerWebGLRenderer = "Apple GPU"
	// No Network Information API: it's Chromium-only, and every iOS browser is WebKit.
	s.Env.Connection = botcheck.ConnectionInfo{}
	return s
}

// realAndroid: Chrome on a Pixel, with touch, Android hints, an Adreno GPU and no plugins.
func realAndroid() botcheck.Signals {
	s := cleanChrome()
	mirrorUA(&s, chromeAndroidGPUUA)
	s.MaxTouchPoints = 5
	s.UAData = botcheck.UAData{
		Platform: "Android",
		FullVersionList: []botcheck.BrandVersion{
			{Brand: "Chromium", Version: "125.0.6422.60"},
			{Brand: "Google Chrome", Version: "125.0.6422.60"},
			{Brand: "Not.A/Brand", Version: "24.0.0.0"},
		},
	}
	s.SecCHUAPlatform = `"Android"`
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "Android", "Android", "Android"
	s.Plugins, s.MimeTypes = 0, 0
	s.ScreenW, s.ScreenH = 393, 873
	s.AvailW, s.AvailH = 393, 873
	s.OuterW, s.InnerW = 393, 393
	s.OuterH, s.InnerH = 740, 700
	s.WebGLVendor, s.WebGLRenderer = adrenoVendor, adrenoRenderer
	s.WorkerWebGLRenderer = adrenoRenderer
	// Android Chrome does expose navigator.connection: a coherent cellular 4g estimate.
	s.Env.Connection = botcheck.ConnectionInfo{EffectiveType: "4g", Downlink: 2.5, RTT: 100}
	return s
}

// Genuine browsers, tricky ones included, must score 100 with no v3/v4 false fires.
func TestRealBrowsersDoNotFalsePositive(t *testing.T) {
	cases := []struct {
		name string
		s    botcheck.Signals
	}{
		{"desktop Chrome on macOS", cleanChrome()},
		{"desktop Opera (Chromium fork, branded version diverges)", realOpera()},
		{"desktop Safari (WebKit, no userAgentData)", realSafari()},
		{"desktop Firefox (Gecko)", realFirefox()},
		{"iOS Safari (WebKit)", realIPhone(iosSafariUA)},
		{"iOS Chrome (WebKit under CriOS)", realIPhone(criosUA)},
		{"iOS Firefox (WebKit under FxiOS)", realIPhone(fxiosUA)},
		{"Android Chrome (Pixel)", realAndroid()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(tc.s)
			if r.Score != 100 || r.Verdict != "human" {
				t.Errorf("%s: score=%d verdict=%q, want 100/human (fired: %v)", tc.name, r.Score, r.Verdict, triggeredIDs(r))
			}
			for _, id := range v3RuleIDs {
				if check(t, r, id).Triggered {
					t.Errorf("%s: v3 rule %s false-fired for %s (detail: %q)", tc.name, id, tc.name, check(t, r, id).Detail)
				}
			}
			for _, id := range v4RuleIDs {
				if check(t, r, id).Triggered {
					t.Errorf("%s: v4 rule %s false-fired for %s (detail: %q)", tc.name, id, tc.name, check(t, r, id).Detail)
				}
			}
		})
	}
}

// ── G07/G08: WebGL GPU coherence ─────────────────────────────────────────────

// UAs for the GPU/OS matrix (chromeMacUA, criosUA + friends defined above).
const (
	chromeWinGPUUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	chromeLinuxGPUUA   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	chromeAndroidGPUUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
)

// Real WebGL vendor/renderer pairs, one per reporting style (Chrome ANGLE, Safari, Firefox, Android).
const (
	angleAppleVendor   = "Google Inc. (Apple)"
	angleAppleRenderer = "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"
	angleNVVendor      = "Google Inc. (NVIDIA)"
	angleNVRenderer    = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
	angleAMDVendor     = "Google Inc. (AMD)"
	angleAMDRenderer   = "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"
	angleIntelVendor   = "Google Inc. (Intel)"
	angleIntelRenderer = "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"
	adrenoVendor       = "Qualcomm"
	adrenoRenderer     = "Adreno (TM) 740"
	maliVendor         = "ARM" // "ARM" alone parses to no family — renderer carries "Mali"
	maliRenderer       = "Mali-G78"
)

// gpuSignals carries just a UA and a GPU pair; the other rules are covered elsewhere.
func gpuSignals(ua, vendor, renderer string) botcheck.Signals {
	return botcheck.Signals{
		ClientCollected:  true,
		NativeToStringOK: true,
		NavMainUA:        ua,
		HTTPUserAgent:    ua,
		WebGLVendor:      vendor,
		WebGLRenderer:    renderer,
	}
}

// G07: vendor and renderer share a driver; fires only when both parse to known, different families.
func TestWebGLVendorMismatch(t *testing.T) {
	fires := []struct{ name, vendor, renderer string }{
		{"Apple vendor vs NVIDIA renderer", "Apple Inc.", angleNVRenderer},
		{"NVIDIA vendor vs AMD renderer", "NVIDIA Corporation", "AMD Radeon RX 6600"},
		{"Intel vendor vs Adreno renderer", "Intel Inc.", adrenoRenderer},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(gpuSignals(chromeMacUA, tc.vendor, tc.renderer))
			if !check(t, r, "webgl_vendor_mismatch").Triggered {
				t.Errorf("webgl_vendor_mismatch should fire for vendor %q vs renderer %q", tc.vendor, tc.renderer)
			}
		})
	}
	silent := []struct{ name, vendor, renderer string }{
		{"ANGLE Apple pair", angleAppleVendor, angleAppleRenderer},
		{"ANGLE NVIDIA pair", angleNVVendor, angleNVRenderer},
		{"Firefox NVIDIA pair", "NVIDIA Corporation", "NVIDIA GeForce RTX 3080"},
		{"Safari generalised Apple pair", "Apple Inc.", "Apple GPU"},
		{"ARM vendor + Mali renderer (normal Android)", maliVendor, maliRenderer},
		{"absent vendor", "", angleNVRenderer},
		{"absent renderer", "NVIDIA Corporation", ""},
		{"both absent", "", ""},
		{"software rasteriser (no family)", "Google Inc. (Google)", "Google SwiftShader"},
		{"VM passthrough (no family)", "VMware, Inc.", "SVGA3D; build: RELEASE;"},
	}
	for _, tc := range silent {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(gpuSignals(chromeMacUA, tc.vendor, tc.renderer))
			if check(t, r, "webgl_vendor_mismatch").Triggered {
				t.Errorf("webgl_vendor_mismatch must not fire for vendor %q vs renderer %q", tc.vendor, tc.renderer)
			}
		})
	}
}

// G03: each mutation makes one secondary context contradict the main thread, firing exactly its rule.
func TestCrossContextSignals(t *testing.T) {
	const linuxChromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// context_ua_mismatch covers the Service Worker too.
		{"service worker UA differs", func(s *botcheck.Signals) { s.SWUA = linuxChromeUA }, "context_ua_mismatch"},
		// A different primary language in any one context fires the language rule.
		{"worker language differs", func(s *botcheck.Signals) { s.WorkerLanguages = []string{"ru-RU", "ru"} }, "context_language_mismatch"},
		{"iframe language differs", func(s *botcheck.Signals) { s.IframeLanguages = []string{"de-DE", "de"} }, "context_language_mismatch"},
		{"service worker language differs", func(s *botcheck.Signals) { s.SWLanguages = []string{"fr-FR"} }, "context_language_mismatch"},
		// A different core count in any one context fires the cores rule.
		{"worker cores differ", func(s *botcheck.Signals) { s.WorkerCores = 4 }, "context_cores_mismatch"},
		{"iframe cores differ", func(s *botcheck.Signals) { s.IframeCores = 16 }, "context_cores_mismatch"},
		{"service worker cores differ", func(s *botcheck.Signals) { s.SWCores = 2 }, "context_cores_mismatch"},
		// A different userAgentData.platform in any one context fires the platform rule.
		{"worker platform differs", func(s *botcheck.Signals) { s.WorkerPlatform = "Linux" }, "context_platform_mismatch"},
		{"iframe platform differs", func(s *botcheck.Signals) { s.IframePlatform = "Windows" }, "context_platform_mismatch"},
		{"service worker platform differs", func(s *botcheck.Signals) { s.SWPlatform = "Chrome OS" }, "context_platform_mismatch"},
		// The worker's OffscreenCanvas WebGL renderer disagrees with the main thread's.
		{"worker WebGL renderer differs", func(s *botcheck.Signals) {
			s.WorkerWebGLRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)"
		}, "context_webgl_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire", tc.id)
			}
		})
	}
}

// G04 rules fire on bad values, stay silent when clean, and Skip with no client fingerprint.
func TestDeepTamperSignals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// The stealth hallmark: Function.prototype.toString carries Proxy artifacts.
		{"toString proxied", func(s *botcheck.Signals) { s.NativeToStringProxied = true }, "tostring_proxy"},
		// A monkey-patched native leaves an impossible property descriptor.
		{"descriptor tamper", func(s *botcheck.Signals) { s.NativeDescriptorsOK = false }, "native_descriptor_tamper"},
		// A patched native misses the call/new TypeError traps a genuine one throws.
		{"call/new tamper", func(s *botcheck.Signals) { s.NativeCallNewOK = false }, "native_callnew_tamper"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" fires", func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire on the bad value (%s)", tc.id, tc.name)
			}
		})
		t.Run(tc.name+" passes clean", func(t *testing.T) {
			if check(t, botcheck.Evaluate(cleanChrome()), tc.id).Triggered {
				t.Errorf("%s must not fire on the clean fixture", tc.id)
			}
		})
		t.Run(tc.name+" skips server-only", func(t *testing.T) {
			r := botcheck.Evaluate(botcheck.Signals{HTTPUserAgent: chromeMacUA})
			if c := check(t, r, tc.id); !c.Skipped || c.Triggered {
				t.Errorf("%s should be Skipped (not triggered) without a client fingerprint: %+v", tc.id, c)
			}
		})
	}
}

// A stale collector's missing keys bind false; read as tampering they'd cost a human 95 points.
func TestDeepTamperSkipsStalePayload(t *testing.T) {
	s := cleanChrome()
	s.CollectorV = 0 // pre-G04 collector: none of the deep-tamper keys were sent
	s.NativeDescriptorsOK = false
	s.NativeCallNewOK = false
	s.NativeToStringProxied = true

	r := botcheck.Evaluate(s)
	for _, id := range []string{"tostring_proxy", "native_descriptor_tamper", "native_callnew_tamper"} {
		if check(t, r, id).Triggered {
			t.Errorf("%s must not fire on a pre-v2 payload", id)
		}
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("stale-collector payload: score=%d verdict=%q, want 100/human", r.Score, r.Verdict)
	}
}

// G08: only enumerated impossible GPU/OS pairs fire; odd-but-real ones (AMD on an Intel Mac,
// Adreno on a Snapdragon Windows laptop) stay silent.
func TestGPUOSMismatch(t *testing.T) {
	fires := []struct{ name, ua, vendor, renderer string }{
		{"Apple GPU + Windows UA", chromeWinGPUUA, angleAppleVendor, angleAppleRenderer},
		{"Apple GPU + Linux UA", chromeLinuxGPUUA, angleAppleVendor, angleAppleRenderer},
		{"Apple GPU + Android UA", chromeAndroidGPUUA, angleAppleVendor, angleAppleRenderer},
		{"NVIDIA + iOS UA", criosUA, angleNVVendor, angleNVRenderer},
		{"NVIDIA + Android UA", chromeAndroidGPUUA, angleNVVendor, angleNVRenderer},
		{"AMD Radeon + iOS UA", criosUA, angleAMDVendor, angleAMDRenderer},
		{"AMD Radeon + Android UA", chromeAndroidGPUUA, angleAMDVendor, angleAMDRenderer},
		{"Adreno + macOS UA", chromeMacUA, adrenoVendor, adrenoRenderer},
		{"Adreno + iOS UA", criosUA, adrenoVendor, adrenoRenderer},
		{"Mali + macOS UA", chromeMacUA, maliVendor, maliRenderer},
		{"Mali + iOS UA", criosUA, maliVendor, maliRenderer},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(gpuSignals(tc.ua, tc.vendor, tc.renderer))
			if !check(t, r, "gpu_os_mismatch").Triggered {
				t.Errorf("gpu_os_mismatch should fire for %s", tc.name)
			}
			// These pairs are internally consistent, so G07 stays silent: G08 alone catches the OS spoof.
			if check(t, r, "webgl_vendor_mismatch").Triggered {
				t.Errorf("webgl_vendor_mismatch must not fire for the consistent pair in %s", tc.name)
			}
		})
	}
	silent := []struct{ name, ua, vendor, renderer string }{
		{"AMD Radeon + macOS (Intel Macs exist)", chromeMacUA, angleAMDVendor, angleAMDRenderer},
		{"NVIDIA + macOS (pre-2014 NVIDIA Macs)", chromeMacUA, "NVIDIA Corporation", "NVIDIA GeForce GT 650M"},
		{"Adreno + Windows (Snapdragon ARM laptop)", chromeWinGPUUA, adrenoVendor, adrenoRenderer},
		{"Intel + Windows", chromeWinGPUUA, angleIntelVendor, angleIntelRenderer},
		{"Intel + Linux", chromeLinuxGPUUA, "Intel", "Mesa Intel(R) UHD Graphics 630"},
		{"Intel + Android (old Atom phones)", chromeAndroidGPUUA, "Intel", "Intel HD Graphics"},
		{"NVIDIA + Windows", chromeWinGPUUA, angleNVVendor, angleNVRenderer},
		{"NVIDIA + Linux", chromeLinuxGPUUA, "NVIDIA Corporation", "NVIDIA GeForce RTX 3080"},
		{"AMD + Linux", chromeLinuxGPUUA, "AMD", "AMD Radeon RX 6600 (radeonsi, navi23, LLVM 15.0.0)"},
		{"Apple + macOS", chromeMacUA, angleAppleVendor, angleAppleRenderer},
		{"Apple + iOS (Safari generalised)", criosUA, "Apple Inc.", "Apple GPU"},
		{"Adreno + Android", chromeAndroidGPUUA, adrenoVendor, adrenoRenderer},
		{"Mali + Android", chromeAndroidGPUUA, maliVendor, maliRenderer},
		{"Mesa llvmpipe + Linux (unknown family)", chromeLinuxGPUUA, "Mesa", "llvmpipe (LLVM 15.0.6, 256 bits)"},
		{"unknown VM GPU + Windows", chromeWinGPUUA, "VMware, Inc.", "SVGA3D; build: RELEASE;"},
		{"Apple GPU + unparseable UA", "some-unparseable-agent", angleAppleVendor, angleAppleRenderer},
		{"both strings absent + Windows", chromeWinGPUUA, "", ""},
	}
	for _, tc := range silent {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(gpuSignals(tc.ua, tc.vendor, tc.renderer))
			if check(t, r, "gpu_os_mismatch").Triggered {
				t.Errorf("gpu_os_mismatch must not fire for %s", tc.name)
			}
		})
	}
}

// Legitimate spelling variants (a language's region, a platform alias) must stay quiet.
func TestCrossContextSignalsDoNotFalsePositive(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// Same primary language, only a region variant: comparing full tags would flag real users.
		{"worker language is a region variant", func(s *botcheck.Signals) {
			s.WorkerLanguages = []string{"en-GB"}
		}, "context_language_mismatch"},
		// Platform spelling variants normalise to the same value.
		{"worker platform spelling variant", func(s *botcheck.Signals) {
			s.WorkerPlatform = "Mac OS X"
		}, "context_platform_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s must not fire for %s", tc.id, tc.name)
			}
		})
	}
}

// An empty context value is "no signal", never "mismatch", whichever side is absent.
func TestCrossContextAbsentDataNeverFires(t *testing.T) {
	ids := []string{
		"context_ua_mismatch", "context_language_mismatch", "context_cores_mismatch",
		"context_platform_mismatch", "context_webgl_mismatch",
	}

	// Context side absent (probes unsupported / timed out): clean 100.
	s := cleanChrome()
	s.SWUA = ""
	s.WorkerLanguages, s.IframeLanguages, s.SWLanguages = nil, nil, nil
	s.WorkerCores, s.IframeCores, s.SWCores = 0, 0, 0
	s.WorkerPlatform, s.IframePlatform, s.SWPlatform = "", "", ""
	s.WorkerWebGLRenderer = ""
	r := botcheck.Evaluate(s)
	for _, id := range ids {
		if check(t, r, id).Triggered {
			t.Errorf("%s fired with every context value absent", id)
		}
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("all context probes empty: score=%d verdict=%q, want 100/human", r.Score, r.Verdict)
	}

	// Main side absent while a context reports: still can't compare.
	m := cleanChrome()
	m.Languages = nil // no main language list (also clears lang cross-checks)
	m.HardwareCores = 0
	m.UAData.Platform = ""
	m.WebGLRenderer = ""
	r = botcheck.Evaluate(m)
	for _, id := range ids {
		if check(t, r, id).Triggered {
			t.Errorf("%s fired with the main-thread value absent", id)
		}
	}
}

// G03 roadmap scenario (how Bright Data was caught): a macOS top frame over a Worker leaking Linux.
func TestBrightDataStyleWorkerSpoof(t *testing.T) {
	s := cleanChrome() // top frame claims macOS
	s.NavWorkerUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	s.WorkerPlatform = "Linux"
	s.WorkerCores = 4

	r := botcheck.Evaluate(s)
	want := []string{"context_cores_mismatch", "context_platform_mismatch", "context_ua_mismatch"}
	if diff := cmp.Diff(want, triggeredIDs(r)); diff != "" {
		t.Errorf("Bright Data style spoof fired wrong checks (-want +got):\n%s", diff)
	}
	// 35 (context UA) + 25 (platform) + 20 (cores) = 80 → score 20 → bot.
	if r.Score != 20 || r.Verdict != "bot" {
		t.Errorf("Bright Data style spoof: score=%d verdict=%q, want 20/bot", r.Score, r.Verdict)
	}
}

// Current puppeteer-extra-stealth evades every internals tamper probe (2026-07-19 audit); patching
// only its top frame, it leaks the real OS in its Worker, and that alone scores it a bot.
func TestStealthCaughtByCrossContextChecks(t *testing.T) {
	s := cleanChrome() // top frame claims macOS/Chrome, all internals probes clean
	// The stealth patch didn't reach the Web Worker context — it leaks Linux.
	s.NavWorkerUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	s.WorkerPlatform = "Linux"
	s.WorkerCores = 4

	r := botcheck.Evaluate(s)
	// Modern stealth reads clean on every internals probe, so the verdict rests on cross-context checks.
	for _, id := range []string{
		"tostring_proxy", "native_descriptor_tamper", "native_callnew_tamper",
		"navigator_proto_tamper", "chrome_runtime_tamper", "chrome_late_injection",
	} {
		if check(t, r, id).Triggered {
			t.Errorf("%s should read clean: stealth evades the internals probes; the context checks are what catch it", id)
		}
	}
	// The cross-context checks catch it, and the verdict is still bot.
	want := []string{"context_cores_mismatch", "context_platform_mismatch", "context_ua_mismatch"}
	if diff := cmp.Diff(want, triggeredIDs(r)); diff != "" {
		t.Errorf("stealth browser fired wrong checks (-want +got):\n%s", diff)
	}
	// 35 (context UA) + 25 (platform) + 20 (cores) = 80 → score 20 → bot.
	if r.Score != 20 || r.Verdict != "bot" {
		t.Errorf("stealth browser caught by context: score=%d verdict=%q, want 20/bot", r.Score, r.Verdict)
	}
}

// Stealth evades the internals probes and privacy extensions trip them, so they're soft (cluster-only).
func TestInternalsTamperDowngradedToSoft(t *testing.T) {
	fire := map[string]func(*botcheck.Signals){
		"native_descriptor_tamper": func(s *botcheck.Signals) { s.NativeDescriptorsOK = false },
		"native_callnew_tamper":    func(s *botcheck.Signals) { s.NativeCallNewOK = false },
		"navigator_proto_tamper":   func(s *botcheck.Signals) { s.NavProtoDescriptorsOK = false },
		"chrome_runtime_tamper":    func(s *botcheck.Signals) { s.ChromeRuntimeOK = false },
		"chrome_late_injection":    func(s *botcheck.Signals) { s.ChromeLateInjection = true },
	}
	// Each ALONE is soft, still fires, and costs nothing: a privacy-extension human keeps 100.
	for id, mut := range fire {
		s := cleanChrome()
		mut(&s)
		r := botcheck.Evaluate(s)
		c := check(t, r, id)
		if !c.Triggered {
			t.Errorf("%s should still fire on its bad value", id)
		}
		if c.Tier != "soft" {
			t.Errorf("%s tier = %q, want soft (downgraded 2026-07-21)", id, c.Tier)
		}
		if r.Score != 100 || r.Verdict != "human" {
			t.Errorf("%s alone: score=%d verdict=%q, want 100/human — a soft signal must never dock on its own", id, r.Score, r.Verdict)
		}
	}
	// Three together cross soft-cluster threshold: one 25-point deduction, not 3×25.
	s := cleanChrome()
	s.NativeDescriptorsOK = false
	s.NativeCallNewOK = false
	s.NavProtoDescriptorsOK = false
	r := botcheck.Evaluate(s)
	if !r.SoftClusterActive() {
		t.Fatalf("three soft tamper signals should form a cluster")
	}
	if r.Score != 75 || r.Verdict != "suspicious" {
		t.Errorf("three soft tamper signals: score=%d verdict=%q, want 75/suspicious (one 25-point cluster)", r.Score, r.Verdict)
	}
}

// ── v3 batch signals (G09–G14, G17, G22, G23 + Layer-1 backlog) ───────────────

// v3 rules, fires direction; guard directions are covered per rule below.
func TestV3Signals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// G11: iframe's fresh realm leaks webdriver although top frame was patched clean.
		{"iframe webdriver", func(s *botcheck.Signals) { s.IframeWebdriver = true }, "iframe_webdriver"},
		{"iframe contentWindow proxied", func(s *botcheck.Signals) { s.IframeProxied = true }, "iframe_proxy"},
		// G14: webdriver/CDP visible only in Service Worker context.
		{"service worker webdriver", func(s *botcheck.Signals) { s.SWWebdriver = true }, "webdriver_sw"},
		{"CDP in service worker only", func(s *botcheck.Signals) { s.SWCDP = true }, "cdp_sw_only"},
		// G17: Navigator.prototype accessor descriptor is wrong.
		{"navigator prototype tamper", func(s *botcheck.Signals) { s.NavProtoDescriptorsOK = false }, "navigator_proto_tamper"},
		// G22: chrome.runtime fails integrity / chrome object injected late.
		{"chrome runtime tamper", func(s *botcheck.Signals) { s.ChromeRuntimeOK = false }, "chrome_runtime_tamper"},
		{"chrome late injection", func(s *botcheck.Signals) { s.ChromeLateInjection = true }, "chrome_late_injection"},
		// G23: Error-stack engine (SpiderMonkey) disagrees with the Chrome UA (V8).
		{"JS engine vs UA", func(s *botcheck.Signals) { s.JSEngine = "spidermonkey" }, "jsengine_ua_mismatch"},
		// G10 + Layer-1 backlog soft tells.
		{"broken image", func(s *botcheck.Signals) { s.ImageBroken = true }, "image_broken"},
		{"plugins without mimeTypes", func(s *botcheck.Signals) { s.MimeTypes = 0 }, "plugins_mimetypes_incoherent"},
		{"zero outerHeight", func(s *botcheck.Signals) { s.OuterH = 0 }, "zero_outer_height"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" fires", func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire (%s)", tc.id, tc.name)
			}
		})
		t.Run(tc.name+" passes clean", func(t *testing.T) {
			if check(t, botcheck.Evaluate(cleanChrome()), tc.id).Triggered {
				t.Errorf("%s must not fire on the clean fixture", tc.id)
			}
		})
	}
}

// cdp_sw_only adds the SW-only observation; when main or worker tripped too, older rules own it.
func TestCDPSWOnlyDoesNotDoubleCount(t *testing.T) {
	s := cleanChrome()
	s.SWCDP, s.CDPMainThread = true, true
	r := botcheck.Evaluate(s)
	if check(t, r, "cdp_sw_only").Triggered {
		t.Errorf("cdp_sw_only must not fire when the main thread also tripped the trap")
	}
	if !check(t, r, "cdp_main_only").Triggered {
		t.Errorf("cdp_main_only should fire when main+SW tripped but the worker didn't")
	}

	s = cleanChrome()
	s.SWCDP, s.CDPMainThread, s.CDPWorker = true, true, true
	r = botcheck.Evaluate(s)
	if check(t, r, "cdp_sw_only").Triggered {
		t.Errorf("cdp_sw_only must not fire when cdp_both already counts the observation")
	}
	if !check(t, r, "cdp_both").Triggered {
		t.Errorf("cdp_both should fire when main+worker tripped the trap")
	}
}

// A stale v2 payload lacks every v3 key, so damning-when-false fields bind bad: gated rules skip.
func TestV3GateSkipsStalePayload(t *testing.T) {
	v2 := func(mut func(*botcheck.Signals)) botcheck.Signals {
		s := cleanChrome()
		s.CollectorV = 2
		mut(&s)
		return s
	}
	cases := []struct {
		name string
		s    botcheck.Signals
		id   string
	}{
		{"navigator_proto_tamper", v2(func(s *botcheck.Signals) { s.NavProtoDescriptorsOK = false }), "navigator_proto_tamper"},
		{"chrome_runtime_tamper", v2(func(s *botcheck.Signals) { s.ChromeRuntimeOK = false }), "chrome_runtime_tamper"},
		{"plugins_mimetypes_incoherent", v2(func(s *botcheck.Signals) { s.MimeTypes = 0 }), "plugins_mimetypes_incoherent"},
		{"mobile_no_touch", v2(func(s *botcheck.Signals) {
			mirrorUA(s, chromeAndroidGPUUA)
			s.MaxTouchPoints = 0
		}), "mobile_no_touch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if check(t, botcheck.Evaluate(tc.s), tc.id).Triggered {
				t.Errorf("%s must not fire on a pre-v3 payload", tc.id)
			}
		})
	}

	// Ungated v3 rules are true=bad or value comparisons, so missing keys bind safe by construction.
	stale := cleanChrome()
	stale.CollectorV = 2
	stale.NavProtoDescriptorsOK = false
	stale.ChromeRuntimeOK = false
	stale.MaxTouchPoints = 0
	stale.MimeTypes = 0
	r := botcheck.Evaluate(stale)
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("stale v2 payload: score=%d verdict=%q, want 100/human (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}

	// zero_outer_height needs no gate: its InnerH > 0 guard skips a stale payload (both bind 0).
	zero := cleanChrome()
	zero.CollectorV = 2
	zero.OuterH, zero.InnerH = 0, 0
	if check(t, botcheck.Evaluate(zero), "zero_outer_height").Triggered {
		t.Errorf("zero_outer_height must not fire when both height fields are absent (stale payload)")
	}
}

// G12: no real phone reports 0 touch points; no reverse rule, as touch-screen Windows laptops exist.
func TestMobileNoTouch(t *testing.T) {
	// Positive: mobile UA w/ zero touch points, per OS.
	for _, mk := range []func() botcheck.Signals{
		func() botcheck.Signals { s := realAndroid(); s.MaxTouchPoints = 0; return s },
		func() botcheck.Signals { s := realIPhone(criosUA); s.MaxTouchPoints = 0; return s },
	} {
		if !check(t, botcheck.Evaluate(mk()), "mobile_no_touch").Triggered {
			t.Errorf("mobile_no_touch should fire for a mobile UA with maxTouchPoints=0")
		}
	}

	// Negative: real phones report touch — every real mobile fixture stays silent.
	for name, fx := range map[string]botcheck.Signals{
		"iOS Safari":     realIPhone(iosSafariUA),
		"iOS Chrome":     realIPhone(criosUA),
		"iOS Firefox":    realIPhone(fxiosUA),
		"Android Chrome": realAndroid(),
	} {
		if check(t, botcheck.Evaluate(fx), "mobile_no_touch").Triggered {
			t.Errorf("mobile_no_touch must not fire for a real phone (%s reports touch)", name)
		}
	}

	// Negative: desktop UA w/ zero touch — no reverse direction by design.
	if check(t, botcheck.Evaluate(cleanChrome()), "mobile_no_touch").Triggered {
		t.Errorf("mobile_no_touch must not fire for a desktop UA")
	}
}

// G23: stack engine vs UA engine (blink→v8, gecko→spidermonkey, webkit→jsc, iOS included).
func TestJSEngineUAMismatch(t *testing.T) {
	fires := []struct{ name, ua, detected string }{
		{"Chrome UA on SpiderMonkey", chromeMacUA, "spidermonkey"},
		{"Chrome UA on JSC", chromeMacUA, "jsc"},
		{"Firefox UA on V8", firefoxUA, "v8"},
		{"Safari UA on V8", safariUA, "v8"},
		{"iOS Chrome UA on V8 (Apple mandates WebKit/JSC)", criosUA, "v8"},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			s := cleanChrome()
			mirrorUA(&s, tc.ua)
			s.JSEngine = tc.detected
			if !check(t, botcheck.Evaluate(s), "jsengine_ua_mismatch").Triggered {
				t.Errorf("jsengine_ua_mismatch should fire for %s", tc.name)
			}
		})
	}
	silent := []struct{ name, ua, detected string }{
		{"detection matches the UA", chromeMacUA, "v8"},
		{"iOS Chrome on JSC", criosUA, "jsc"},
		{"iOS Firefox on JSC", fxiosUA, "jsc"},
		{"Firefox on SpiderMonkey", firefoxUA, "spidermonkey"},
		{"Safari on JSC", safariUA, "jsc"},
		{"empty detection (probe failed)", chromeMacUA, ""},
		{"unparseable UA", "some-unparseable-agent", "v8"},
	}
	for _, tc := range silent {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			s := cleanChrome()
			mirrorUA(&s, tc.ua)
			s.JSEngine = tc.detected
			if check(t, botcheck.Evaluate(s), "jsengine_ua_mismatch").Triggered {
				t.Errorf("jsengine_ua_mismatch must not fire for %s", tc.name)
			}
		})
	}
}

// G22 rules key on a Chrome UA, so a non-Chrome browser's chrome object never counts against it.
func TestChromeRulesNeedAChromeUA(t *testing.T) {
	s := realSafari()
	s.ChromeRuntimeOK = false
	s.ChromeLateInjection = true
	r := botcheck.Evaluate(s)
	for _, id := range []string{"chrome_runtime_tamper", "chrome_late_injection"} {
		if check(t, r, id).Triggered {
			t.Errorf("%s must not fire without a Chrome UA", id)
		}
	}
}

// G09: a differing PUBLIC candidate pierces a VPN; private/CGNAT ones are normal NAT, and only the
// egress's address family is compared (dual-stack stays silent).
func TestWebRTCIPMismatch(t *testing.T) {
	const (
		egressV4 = "85.105.22.17"
		otherV4  = "203.0.113.9"
		egressV6 = "2a02:1234:5678::1"
		otherV6  = "2a02:1234:5678::2"
	)
	fires := []struct {
		name, egress string
		ips          []string
	}{
		{"public IPv4 candidate ≠ egress", egressV4, []string{otherV4}},
		{"public IPv6 candidate ≠ IPv6 egress", egressV6, []string{otherV6}},
		{"one public candidate among private hosts", egressV4, []string{"192.168.1.5", "10.0.0.2", otherV4}},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			s := cleanChrome()
			s.EgressIP, s.WebRTCIPs = tc.egress, tc.ips
			if !check(t, botcheck.Evaluate(s), "webrtc_ip_mismatch").Triggered {
				t.Errorf("webrtc_ip_mismatch should fire for %s", tc.name)
			}
		})
	}
	silent := []struct {
		name, egress string
		ips          []string
	}{
		{"candidate equals egress", egressV4, []string{egressV4}},
		{"private host candidates (normal NAT)", egressV4, []string{"192.168.1.5", "10.0.0.2", "172.16.0.3"}},
		{"loopback / link-local / ULA", egressV4, []string{"127.0.0.1", "169.254.1.1", "fe80::1", "fd00::5"}},
		{"CGNAT host candidate (carrier NAT is normal)", egressV4, []string{"100.64.0.5"}},
		{"IPv4-mapped-IPv6 private form", egressV4, []string{"::ffff:192.168.1.5"}},
		{"dual-stack: IPv6 candidate vs IPv4 egress", egressV4, []string{"2606:4700:4700::1111"}},
		{"dual-stack: IPv4 candidate vs IPv6 egress", egressV6, []string{otherV4}},
		{"empty candidate list", egressV4, nil},
		{"empty egress", "", []string{otherV4}},
		{"unparseable egress", "not-an-ip", []string{otherV4}},
		{"unparseable candidate", egressV4, []string{"garbage", ":::"}},
	}
	for _, tc := range silent {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			s := cleanChrome()
			s.EgressIP, s.WebRTCIPs = tc.egress, tc.ips
			if check(t, botcheck.Evaluate(s), "webrtc_ip_mismatch").Triggered {
				t.Errorf("webrtc_ip_mismatch must not fire for %s", tc.name)
			}
		})
	}
}

// ── v4 batch signals (G15/G21) ───────────────────────────────────────────────

// v4 rules, fires direction; guard directions are covered per rule below.
func TestV4Signals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*botcheck.Signals)
		id     string
	}{
		// G15: browser UA from an environment with no window.matchMedia.
		{"matchMedia missing", func(s *botcheck.Signals) { s.Env.MatchMedia = false }, "matchmedia_missing"},
		// G21: connection's effectiveType claims faster than its own metrics.
		{"effectiveType faster than its own rtt", func(s *botcheck.Signals) { s.Env.Connection.RTT = 2000 }, "netinfo_incoherent"},
		{"effectiveType faster than its own downlink", func(s *botcheck.Signals) { s.Env.Connection.Downlink = 0.3 }, "netinfo_incoherent"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" fires", func(t *testing.T) {
			s := cleanChrome()
			tc.mutate(&s)
			if !check(t, botcheck.Evaluate(s), tc.id).Triggered {
				t.Errorf("%s should fire (%s)", tc.id, tc.name)
			}
		})
		t.Run(tc.name+" passes clean", func(t *testing.T) {
			if check(t, botcheck.Evaluate(cleanChrome()), tc.id).Triggered {
				t.Errorf("%s must not fire on the clean fixture", tc.id)
			}
		})
	}
}

// Fires only on a browser UA (hard rules already catch declared bots); skips server-only requests.
func TestMatchMediaMissing(t *testing.T) {
	fires := cleanChrome()
	fires.Env.MatchMedia = false
	if !check(t, botcheck.Evaluate(fires), "matchmedia_missing").Triggered {
		t.Errorf("matchmedia_missing should fire for a browser UA without matchMedia")
	}

	// A non-browser UA never fires.
	for name, ua := range map[string]string{
		"curl":           "curl/8.4.0",
		"HeadlessChrome": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.0.0 Safari/537.36",
		"Googlebot":      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"unparseable":    "some-unparseable-agent",
	} {
		s := cleanChrome()
		mirrorUA(&s, ua)
		s.Env.MatchMedia = false
		if check(t, botcheck.Evaluate(s), "matchmedia_missing").Triggered {
			t.Errorf("matchmedia_missing must not fire for a non-browser UA (%s)", name)
		}
	}

	// Server-only request: skipped, not triggered.
	r := botcheck.Evaluate(botcheck.Signals{HTTPUserAgent: chromeMacUA})
	if c := check(t, r, "matchmedia_missing"); !c.Skipped || c.Triggered {
		t.Errorf("matchmedia_missing should be Skipped (not triggered) without a client fingerprint: %+v", c)
	}
}

// A browser derives effectiveType from the worst of its own rtt/downlink (spec table), so a FASTER
// claim is a spoof. Thresholds allow for the API's rounding; slower claims never fire.
func TestNetinfoIncoherent(t *testing.T) {
	conn := func(ect string, rtt int, downlink float64) botcheck.Signals {
		s := cleanChrome()
		s.Env.Connection = botcheck.ConnectionInfo{EffectiveType: ect, RTT: rtt, Downlink: downlink}
		return s
	}
	fires := []struct {
		name     string
		ect      string
		rtt      int
		downlink float64
	}{
		{"'4g' with rtt 2000 (implies 2g at best)", "4g", 2000, 10},
		{"'4g' with rtt 3000 (implies slow-2g)", "4g", 3000, 0},
		{"'4g' with downlink 0.04 (implies slow-2g)", "4g", 0, 0.04},
		{"'3g' with rtt 2000 (implies 2g at best)", "3g", 2000, 0.5},
		{"'3g' with downlink 0.06 (implies slow-2g)", "3g", 100, 0.06},
		{"'2g' with rtt 3000 (implies slow-2g)", "2g", 3000, 0},
		{"'4g', fast rtt but 3g downlink (worst of the two)", "4g", 50, 0.3},
	}
	for _, tc := range fires {
		t.Run("fires/"+tc.name, func(t *testing.T) {
			if !check(t, botcheck.Evaluate(conn(tc.ect, tc.rtt, tc.downlink)), "netinfo_incoherent").Triggered {
				t.Errorf("netinfo_incoherent should fire for %s", tc.name)
			}
		})
	}
	silent := []struct {
		name     string
		ect      string
		rtt      int
		downlink float64
	}{
		{"coherent 4g", "4g", 50, 10},
		{"coherent 3g (downlink drives the type)", "3g", 300, 0.5},
		{"rounding boundary: reported rtt 270 still allows '4g'", "4g", 270, 10},
		{"claims SLOWER than its metrics imply (never fires)", "3g", 50, 10},
		{"slow-2g with rtt 2000 (coherent real case)", "slow-2g", 2000, 0},
		{"slow-2g with mixed 2g/slow-2g metrics (worst wins)", "slow-2g", 1500, 0.06},
		{"unknown effectiveType (a future value)", "5g", 3000, 0.01},
		{"effectiveType absent (metrics alone are not compared)", "", 3000, 0.01},
		{"no metrics reported (can't verify the claim)", "4g", 0, 0},
	}
	for _, tc := range silent {
		t.Run("silent/"+tc.name, func(t *testing.T) {
			if check(t, botcheck.Evaluate(conn(tc.ect, tc.rtt, tc.downlink)), "netinfo_incoherent").Triggered {
				t.Errorf("netinfo_incoherent must not fire for %s", tc.name)
			}
		})
	}
}

// v4 rules skip on a stale v3 payload; the version stamp decides, so smuggled v4 values skip too.
func TestV4GateSkipsStalePayload(t *testing.T) {
	// Genuine stale v3 payload: no env keys at all, everything binds zero.
	absent := cleanChrome()
	absent.CollectorV = 3
	absent.Env = botcheck.EnvInfo{}
	r := botcheck.Evaluate(absent)
	for _, id := range v4RuleIDs {
		if check(t, r, id).Triggered {
			t.Errorf("%s must not fire on a pre-v4 payload with no env section", id)
		}
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("stale v3 payload (no env): score=%d verdict=%q, want 100/human", r.Score, r.Verdict)
	}

	// Crafted v3-stamped payload w/ bad v4-shaped values: still skipped.
	crafted := cleanChrome()
	crafted.CollectorV = 3
	crafted.Env.MatchMedia = false
	crafted.Env.Connection = botcheck.ConnectionInfo{EffectiveType: "4g", RTT: 3000}
	r = botcheck.Evaluate(crafted)
	for _, id := range v4RuleIDs {
		if check(t, r, id).Triggered {
			t.Errorf("%s must skip a pre-v4 payload even when v4-shaped values are present", id)
		}
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("crafted v3-stamped payload: score=%d verdict=%q, want 100/human", r.Score, r.Verdict)
	}
}
