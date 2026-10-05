package mcptools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClean(t *testing.T) {
	cases := []struct{ in, want string }{
		{"\u202e\u200b\u200c\u200d\ufeff\u2066\u2069\u200e\u200f\u061c", `\u{202E}\u{200B}\u{200C}\u{200D}\u{FEFF}\u{2066}\u{2069}\u{200E}\u{200F}\u{061C}`},
		{"tag\U000E0041\U000E007F", `tag\u{E0041}\u{E007F}`},
		{"vs\ufe00\ufe0f\U000E0100\U000E01EF", `vs\u{FE00}\u{FE0F}\u{E0100}\u{E01EF}`},
		{"del\x7f c1\u0080\u0085\u009f", `del\u{007F} c1\u{0080}\u{0085}\u{009F}`},
		{"line\u2028para\u2029", `line\u{2028}para\u{2029}`},
		{"\u115f\u1160\u3164\uffa0", `\u{115F}\u{1160}\u{3164}\u{FFA0}`},
		{"tab\tand\nnewline, emoji 👍 and ü stay", "tab\tand\nnewline, emoji 👍 and ü stay"},
		// é is two bytes, so the cut steps back to a rune boundary.
		{"x" + strings.Repeat("é", maxString), "x" + strings.Repeat("é", (maxString-1)/2) + "…[truncated 2050 bytes]"},
	}
	for _, tc := range cases {
		if got := clean(tc.in, maxString); got != tc.want {
			t.Errorf("clean(%.40q) = %.80q, want %.80q", tc.in, got, tc.want)
		}
	}
}

func TestSanitize(t *testing.T) {
	long := strings.Repeat("v", 3000)
	cases := []struct {
		whole bool
		in    map[string]any
		want  string
	}{
		{false, map[string]any{"X-\u202eEvil": long, "exact": json.Number("12345678901234567890"), "url": "https://x.test/?a=1&b=<2>"},
			`{"X-\\u{202E}Evil":"` + long[:maxString] + `…[truncated 952 bytes]","exact":12345678901234567890,"url":"https://x.test/?a=1&b=<2>"}`},
		{true, map[string]any{"pem": long, "text": "a\u202eb"}, `{"pem":"` + long + `","text":"a\\u{202E}b"}`},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.in)
		res, size, err := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(raw)}, "", tc.whole)
		if err != nil || res.IsError {
			t.Fatalf("sanitize = %v %v", res, err)
		}
		txt := res.Content[0].(*mcp.TextContent).Text
		if diff := cmp.Diff(tc.want, txt); diff != "" {
			t.Errorf("whole %v (-want +got):\n%s", tc.whole, diff)
		}
		if size != len(txt) || string(res.StructuredContent.(json.RawMessage)) != txt {
			t.Errorf("structuredContent differs from the text block, or size %d != %d", size, len(txt))
		}
	}

	got, _, _ := sanitize(errorResult("upstream said \u202eevil "+strings.Repeat("e", 5000)), "", false)
	if txt := got.Content[0].(*mcp.TextContent).Text; !got.IsError || !strings.Contains(txt, `\u{202E}`) || len(txt) > maxString+40 {
		t.Errorf("error text = %.60q (%d bytes), want escaped and capped", txt, len(txt))
	}
}

func TestSanitizeRefuses(t *testing.T) {
	rows := make([]string, 2000)
	for i := range rows {
		rows[i] = strings.Repeat("r", 60)
	}
	for _, tc := range []struct {
		whole bool
		in    map[string]any
	}{
		{false, map[string]any{"rows": rows}},
		{true, map[string]any{"text": strings.Repeat("x", maxResult)}},
	} {
		raw, _ := json.Marshal(tc.in)
		res, _, err := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(raw)}, "Ask for less.", tc.whole)
		if err != nil || !res.IsError || !strings.HasSuffix(res.Content[0].(*mcp.TextContent).Text, "Ask for less.") {
			t.Errorf("whole %v over the hard cap = %+v %v, want an error that says how to narrow", tc.whole, res, err)
		}
	}

	for _, sc := range []any{nil, json.RawMessage(`[1,2]`), json.RawMessage(`"s"`)} {
		if _, _, err := sanitize(&mcp.CallToolResult{StructuredContent: sc}, "", false); err == nil {
			t.Errorf("structuredContent %v accepted; it must be an object", sc)
		}
	}
}
