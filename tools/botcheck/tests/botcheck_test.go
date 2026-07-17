// Package tests holds the black-box tests for the botcheck package. The domain
// scorer is a pure function of a Signals struct, so these need no HTTP and no
// databases — they construct Signals directly.
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

// testNow is a fixed winter instant so timezone-offset checks are deterministic
// (America/New_York is -05:00 in January).
var testNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// cleanChrome is a realistic, fully-consistent human browser on a residential IP.
func cleanChrome() botcheck.Signals {
	return botcheck.Signals{
		ClientCollected:  true,
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
		WebGLRenderer:    "ANGLE (Apple, Apple M1, OpenGL 4.1)",
		Plugins:          3,
		ScreenW:          1920, ScreenH: 1080,
		AvailW: 1920, AvailH: 1040,
		ColorDepth: 30,
		OuterW:     1680, InnerW: 1400,
		HardwareCores: 8, DeviceMemory: 8,
		BrowserTZ:       "America/New_York",
		IPTimezone:      "-05:00", // IP2Location returns a UTC offset, not an IANA name
		SecCHUAPlatform: `"macOS"`,
		SecFetchMode:    "cors",
		UAData:          botcheck.UAData{Platform: "macOS"},
		Now:             testNow,
		// Layer-2, all internally consistent (so a clean browser scores 100).
		TZOffset:        300, // America/New_York in January (UTC-5)
		CanvasSupported: true,
		CanvasStable:    true,
		CanvasBlank:     false,
		Brands:          []string{"Chromium", "Google Chrome", "Not.A/Brand"},
		SecCHUA:         `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
		CodecH264:       true,
		CodecAAC:        true,
		FontCount:       8,
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

func TestStealthSpoofScoresBot(t *testing.T) {
	// A spoofed UA + a timezone that disagrees with the IP + a datacenter egress:
	// three consistency signals that should not co-occur.
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
	// UA claims macOS but userAgentData reports Windows — a single consistency
	// tell (the CreepJS/Electron catch). One 30-weight hit ⇒ 70 ⇒ suspicious.
	s := cleanChrome()
	s.SecCHUAPlatform = "" // isolate the ua_os check from the CH-platform check
	s.UAData = botcheck.UAData{Platform: "Windows"}

	r := botcheck.Evaluate(s)
	if diff := cmp.Diff([]string{"ua_os_mismatch"}, triggeredIDs(r)); diff != "" {
		t.Errorf("platform spoof fired wrong checks (-want +got):\n%s", diff)
	}
	if r.Score != 70 || r.Verdict != "suspicious" {
		t.Errorf("platform spoof: score=%d verdict=%q, want 70/suspicious", r.Score, r.Verdict)
	}
}

func TestTwoSoftSignalsStayHuman(t *testing.T) {
	// A privacy-conscious human (no plugins, odd screen) must NOT be condemned by
	// soft signals alone: fewer than 3 ⇒ zero deduction.
	s := cleanChrome()
	s.Plugins = 0                   // empty_plugins (soft)
	s.ScreenW, s.ScreenH = 800, 600 // default_geometry (soft)
	s.AvailW, s.AvailH = 800, 600   // keep avail ≤ screen (else screen_avail_impossible adds a 3rd)

	r := botcheck.Evaluate(s)
	if !check(t, r, "empty_plugins").Triggered || !check(t, r, "default_geometry").Triggered {
		t.Fatalf("expected the two soft signals to be flagged")
	}
	if r.Score != 100 || r.Verdict != "human" {
		t.Errorf("two soft signals: score=%d verdict=%q, want 100/human (combo rule)", r.Score, r.Verdict)
	}
	// The display helpers must agree: 2 soft ⇒ flagged but no cluster penalty, so
	// the UI shows them as "flagged" with no per-row or cluster deduction.
	if r.SoftFired() != 2 || r.SoftClusterActive() {
		t.Errorf("2 soft: SoftFired=%d clusterActive=%v, want 2 / false", r.SoftFired(), r.SoftClusterActive())
	}
}

func TestThreeSoftSignalsPromoteToSuspicious(t *testing.T) {
	s := cleanChrome()
	s.Plugins = 0                   // empty_plugins
	s.ScreenW, s.ScreenH = 800, 600 // default_geometry
	s.AvailW, s.AvailH = 800, 600   // avoid an incidental 4th soft (avail ≤ screen)
	s.Languages = nil               // empty_languages (also clears lang cross-check)

	r := botcheck.Evaluate(s)
	// ≥3 soft ⇒ single 25 deduction ⇒ 75 ⇒ suspicious.
	if r.Score != 75 || r.Verdict != "suspicious" {
		t.Errorf("three soft signals: score=%d verdict=%q, want 75/suspicious (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
	}
	// The cluster is active now, so the UI shows one deduction line. Its penalty is
	// the only thing that moved the score here, so it must equal 100 - score.
	if r.SoftFired() != 3 || !r.SoftClusterActive() {
		t.Errorf("3 soft: SoftFired=%d clusterActive=%v, want 3 / true", r.SoftFired(), r.SoftClusterActive())
	}
	if got := r.SoftClusterPenalty(); got != 100-r.Score {
		t.Errorf("SoftClusterPenalty=%d, want %d (100-score)", got, 100-r.Score)
	}
}

func TestServerOnlySkipsClientChecks(t *testing.T) {
	// A plain curl: no client fingerprint posted. Client checks must be Skipped
	// (neither counted nor read as a pass); only server signals score.
	r := botcheck.Evaluate(botcheck.Signals{HTTPUserAgent: "curl/8.4.0"})

	if !check(t, r, "webdriver").Skipped {
		t.Errorf("client check webdriver should be Skipped on a server-only request")
	}
	if check(t, r, "webdriver").Triggered {
		t.Errorf("a skipped client check must not read as triggered")
	}
	// tz_mismatch depends on the client-only BrowserTZ, so it must skip (not read as a
	// passing check) on a server-only request — same contract as tz_self_inconsistent.
	if !check(t, r, "tz_mismatch").Skipped {
		t.Errorf("tz_mismatch should be Skipped on a server-only request (needs client BrowserTZ)")
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
	r := botcheck.Evaluate(botcheck.Signals{})
	if !check(t, r, "bot_user_agent").Triggered {
		t.Errorf("an empty User-Agent should trip bot_user_agent")
	}
}

func TestElectronUAIsSuspiciousNotHardBot(t *testing.T) {
	// An Electron browser (like the in-app one) should read as suspicious via the
	// dedicated embedded-runtime signal, NOT as a definitive curl-class bot.
	const electronUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Claude/1.2 Chrome/148.0.0.0 Electron/42.5.1 Safari/537.36"
	r := botcheck.Evaluate(botcheck.Signals{HTTPUserAgent: electronUA})

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
	// A browser User-Agent with no Sec-Fetch-* header (a scripted client wearing a
	// browser UA). Clean browsers send the header, so cleanChrome must NOT fire.
	scripted := botcheck.Evaluate(botcheck.Signals{HTTPUserAgent: chromeMacUA}) // SecFetchMode empty
	if !check(t, scripted, "sec_fetch_missing").Triggered {
		t.Errorf("sec_fetch_missing should fire for a browser UA lacking Sec-Fetch-*")
	}
	if check(t, botcheck.Evaluate(cleanChrome()), "sec_fetch_missing").Triggered {
		t.Errorf("sec_fetch_missing must NOT fire for a browser that sent Sec-Fetch-Mode")
	}
}

func TestTimezoneOffsetComparedNotStringMatched(t *testing.T) {
	// IP2Location returns a UTC offset; the browser an IANA name. A same-offset
	// pair must NOT fire (this was a real prod false positive: Europe/Moscow is
	// +03:00, so "Europe/Moscow" vs "+03:00" is a match, not a mismatch).
	same := cleanChrome()
	same.BrowserTZ, same.TZOffset, same.IPTimezone = "Europe/Moscow", -180, "+03:00"
	if check(t, botcheck.Evaluate(same), "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch must not fire when the IANA zone's offset equals the IP offset")
	}

	// A genuine offset disagreement still fires.
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
	// A cleaned/empty IP timezone (localhost, unknown IP) must not make the tz
	// cross-check fire against a real browser timezone.
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
