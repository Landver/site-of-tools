package tests

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/botcheck"
)

// report_test.go covers presentation helpers (report.go: G55 explanations,
// G56 environment line) + rendering in result.html. Like domain tests → no
// HTTP, no DB: Reports built by hand, fragment rendered straight thru real
// templates.

func TestSubgroup(t *testing.T) {
	rep := botcheck.Report{Checks: []botcheck.Check{
		{ID: "webdriver", Tier: "hard"},
		{ID: "tz_mismatch", Tier: "consistency", Subgroup: "network"},
		{ID: "datacenter_ip", Tier: "consistency", Subgroup: "network"},
		{ID: "ua_header_mismatch", Tier: "consistency", Subgroup: "ua"},
	}}
	got := rep.Subgroup("consistency", "network")
	if len(got) != 2 || got[0].ID != "tz_mismatch" || got[1].ID != "datacenter_ip" {
		t.Errorf("Subgroup(consistency, network) = %+v, want the two network checks", got)
	}
	if got := rep.Subgroup("hard", "network"); len(got) != 0 {
		t.Errorf("Subgroup(hard, network) = %+v, want empty", got)
	}
	if got := rep.Subgroup("consistency", "no-such-subgroup"); len(got) != 0 {
		t.Errorf("Subgroup(consistency, no-such-subgroup) = %+v, want empty", got)
	}
}

func TestEnvironment(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"Chrome on macOS", chromeMacUA, "Chrome 125 · macOS · Blink"},
		{"Firefox on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
			"Firefox 128 · Windows · Gecko"},
		{"iOS Safari",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
			"Safari 17 · iOS · WebKit"},
		{"iOS Chrome is named Chrome but WebKit-engined",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
			"Chrome 125 · iOS · WebKit"},
		{"Edge on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.67",
			"Edge 125 · Windows · Blink"},
		{"Electron names the runtime and full version",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Electron/32.1.2",
			"Electron 32.1.2 (embedded Chromium)"},
		{"empty UA", "", ""},
		{"garbage UA", "not a browser at all", ""},
		{"bot UA with no browser tokens", "curl/8.7.1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := botcheck.Signals{NavMainUA: tt.ua}.Environment()
			if got != tt.want {
				t.Errorf("Environment() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExplanation(t *testing.T) {
	if got := (botcheck.Check{ID: "webdriver"}).Explanation(); got == "" {
		t.Error("a known rule ID must have an explanation")
	}
	if got := (botcheck.Check{ID: "no_such_rule"}).Explanation(); got != "" {
		t.Errorf("an unknown rule ID must have no explanation, got %q", got)
	}
	// Reserved IDs for in-flight rules must already carry theirs → go live
	// at merge time, not follow-up.
	for _, id := range []string{"iframe_webdriver", "webrtc_ip_mismatch", "zero_outer_height"} {
		if got := (botcheck.Check{ID: id}).Explanation(); got == "" {
			t.Errorf("reserved rule ID %q must already have an explanation", id)
		}
	}
}

// renderResult renders result fragment thru real embedded templates, same
// way handler does.
func renderResult(t *testing.T, rep botcheck.Report) string {
	t.Helper()
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: botcheck.Templates, DevDir: "tools/botcheck/templates"},
	)
	var buf bytes.Buffer
	if err := r.Render(nil, &buf, "botcheck/result", map[string]any{"Report": rep}); err != nil {
		t.Fatalf("render result fragment: %v", err)
	}
	return buf.String()
}

func TestResultTemplateShowsNewSections(t *testing.T) {
	payload := botcheck.Signals{NavMainUA: chromeMacUA, Webdriver: true}
	rep := botcheck.Report{
		Score: 40, Verdict: "bot",
		Checks: []botcheck.Check{
			{ID: "webdriver", Label: "navigator.webdriver is true", Tier: "hard", Weight: 60, Triggered: true},
		},
		ClientPayload: &payload,
	}
	body := renderResult(t, rep)
	for _, want := range []string{
		"Detected environment:",      // G56 line
		"Chrome 125 · macOS · Blink", // …naming the environment
		"raw fingerprint",            // G54 dump card
		"webdriver",                  // …with the POSTed values inside
		">why</summary>",             // G55 per-signal expander
	} {
		if !strings.Contains(body, want) {
			t.Errorf("result fragment missing %q:\n%s", want, body)
		}
	}
}

func TestCheckFragmentShowsReportingSections(t *testing.T) {
	// Handler-level proof: POST /check wires fingerprint into new reporting
	// sections — raw dump, detected-environment line, per-tier sub-scores,
	// per-signal "why" expanders — all render in swapped-in fragment.
	body := `{"navMainUA":"` + chromeMacUA + `","webdriver":true,"nativeToStringOK":true}`
	rec := post(newTestApp(fakeLooker{}), "/check", body, map[string]string{"Accept": "text/html", "User-Agent": chromeMacUA})
	frag := rec.Body.String()
	for _, want := range []string{
		"raw fingerprint",
		"Detected environment:",
		"Chrome 125 · macOS · Blink",
		">why</summary>",
	} {
		if !strings.Contains(frag, want) {
			t.Errorf("POST /check fragment missing %q:\n%s", want, frag)
		}
	}
}

func TestResultTemplateWithoutPayloadHidesNewSections(t *testing.T) {
	// Server-only GET view (+ error path) has no client payload → raw dump +
	// environment line must not render.
	rep := botcheck.Report{
		Score: 100, Verdict: "human",
		Checks: []botcheck.Check{
			{ID: "webdriver", Label: "navigator.webdriver is true", Tier: "hard", Weight: 60},
		},
	}
	body := renderResult(t, rep)
	for _, absent := range []string{"raw fingerprint", "Detected environment:"} {
		if strings.Contains(body, absent) {
			t.Errorf("server-only fragment must not contain %q:\n%s", absent, body)
		}
	}
}
