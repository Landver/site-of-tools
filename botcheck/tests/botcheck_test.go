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

	"github.com/Landver/site-of-tools/botcheck"
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
		IPCountry:       "US",
		SecCHUAPlatform: `"macOS"`,
		SecFetchMode:    "cors",
		UAData:          botcheck.UAData{Platform: "macOS", PlatformVersion: "14.5.0"},
		Now:             testNow,
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
	s.BrowserTZ = "Europe/Moscow" // vs IP America/New_York
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
	same.BrowserTZ, same.IPTimezone = "Europe/Moscow", "+03:00"
	if check(t, botcheck.Evaluate(same), "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch must not fire when the IANA zone's offset equals the IP offset")
	}

	// A genuine offset disagreement still fires.
	diff := cleanChrome()
	diff.BrowserTZ, diff.IPTimezone = "America/Los_Angeles", "+03:00" // -08:00 vs +03:00
	if !check(t, botcheck.Evaluate(diff), "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch should fire when the browser and IP offsets truly differ")
	}
}

func TestUnknownIPTimezoneDoesNotTripCrossCheck(t *testing.T) {
	// A cleaned/empty IP timezone (localhost, unknown IP) must not make the tz
	// cross-check fire against a real browser timezone.
	s := cleanChrome()
	s.BrowserTZ = "Europe/Moscow"
	s.IPTimezone = "" // handler maps IP2Location's "-" to ""

	r := botcheck.Evaluate(s)
	if check(t, r, "tz_mismatch").Triggered {
		t.Errorf("tz_mismatch must not fire when the IP timezone is unknown")
	}
	if r.Verdict != "human" {
		t.Errorf("clean browser with unknown IP tz: verdict=%q, want human", r.Verdict)
	}
}
