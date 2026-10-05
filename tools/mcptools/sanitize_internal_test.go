package mcptools

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// White-box: the sanitizer's edge cases need inputs no tool can produce yet
// (map keys from a third party, nesting, non-object results).

func TestClean(t *testing.T) {
	long := strings.Repeat("a", 10<<10)
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a\u202eb", `a\u{202E}b`},
		{"\u200b\u200c\u200d\ufeff\u2066\u2069\u200e\u200f\u061c", `\u{200B}\u{200C}\u{200D}\u{FEFF}\u{2066}\u{2069}\u{200E}\u{200F}\u{061C}`},
		{"tag\U000E0041\U000E007F", `tag\u{E0041}\u{E007F}`},
		{"vs︀️\U000E0100\U000E01EF", `vs\u{FE00}\u{FE0F}\u{E0100}\u{E01EF}`},
		{"del\x7f c1\u0080\u0085\u009f", `del\u{007F} c1\u{0080}\u{0085}\u{009F}`},
		{"line para ", `line\u{2028}para\u{2029}`},
		{"ᅟᅠㅤﾠ", `\u{115F}\u{1160}\u{3164}\u{FFA0}`},
		{"tab\tand\nnewline stay", "tab\tand\nnewline stay"},
		{"emoji 👍 and ü stay", "emoji 👍 and ü stay"},
		{long, long[:maxString] + "…[truncated 8192 bytes]"},
		// The cut lands on a rune boundary: é is two bytes.
		{"x" + strings.Repeat("é", maxString), "x" + strings.Repeat("é", (maxString-1)/2) + "…[truncated 2050 bytes]"},
	}
	for _, tc := range cases {
		if got := clean(tc.in, maxString); got != tc.want {
			t.Errorf("clean(%.40q) = %.80q, want %.80q", tc.in, got, tc.want)
		}
	}
}

func TestSanitize(t *testing.T) {
	ns := make([]any, 9)
	for i := range ns {
		ns[i] = map[string]any{"host": "ns" + string(rune('1'+i)) + ".example", "ttl": json.Number("3600")}
	}
	in := map[string]any{
		"nameservers": ns,
		"headers":     map[string]any{"X-\u202eEvil": strings.Repeat("v", 3000)},
		"exact":       json.Number("12345678901234567890"),
		"url":         "https://x.test/?a=1&b=<2>",
	}
	raw, _ := json.Marshal(in)
	res, size, err := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(raw)}, "", false)
	if err != nil || res.IsError {
		t.Fatalf("sanitize = %v %v", res, err)
	}
	txt := res.Content[0].(*mcp.TextContent).Text
	if size != len(txt) || string(res.StructuredContent.(json.RawMessage)) != txt {
		t.Errorf("text block and structuredContent differ, or size %d != %d", size, len(txt))
	}
	var got map[string]any
	dec := json.NewDecoder(strings.NewReader(txt))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if n := len(got["nameservers"].([]any)); n != 9 {
		t.Errorf("kept %d of 9 nameservers; lists are never cut", n)
	}
	hdrs := got["headers"].(map[string]any)
	v, ok := hdrs[`X-\u{202E}Evil`].(string)
	if !ok || !strings.HasSuffix(v, "…[truncated 952 bytes]") {
		t.Errorf("headers = %.80v, want the key escaped and the value capped", hdrs)
	}
	if got["exact"] != json.Number("12345678901234567890") {
		t.Errorf("exact = %v: numbers must survive as written", got["exact"])
	}
	if !strings.Contains(txt, "a=1&b=<2>") {
		t.Errorf("text is HTML-escaped: %s", txt)
	}
}

func TestSanitizeRefuses(t *testing.T) {
	big := map[string]any{"rows": make([]string, 2000)}
	for i := range 2000 {
		big["rows"].([]string)[i] = strings.Repeat("r", 60)
	}
	raw, _ := json.Marshal(big)
	res, _, err := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(raw)}, "Ask for one record type.", false)
	if err != nil || !res.IsError || !strings.HasSuffix(res.Content[0].(*mcp.TextContent).Text, "Ask for one record type.") {
		t.Errorf("over the hard cap = %+v %v, want an error that says how to narrow", res, err)
	}

	for _, sc := range []any{nil, json.RawMessage(`[1,2]`), json.RawMessage(`"s"`)} {
		if _, _, err := sanitize(&mcp.CallToolResult{StructuredContent: sc}, "", false); err == nil {
			t.Errorf("structuredContent %v accepted; it must be an object", sc)
		}
	}

	errRes := errorResult("upstream said \u202eevil " + strings.Repeat("e", 5000))
	got, _, _ := sanitize(errRes, "", false)
	if txt := got.Content[0].(*mcp.TextContent).Text; !got.IsError || !strings.Contains(txt, `\u{202E}`) || len(txt) > maxString+40 {
		t.Errorf("error text = %.60q (%d bytes), want escaped and capped", txt, len(txt))
	}
}

func TestSanitizeKeepsOrderOfLists(t *testing.T) {
	raw := json.RawMessage(`{"a":[3,1,2],"b":{"z":1,"y":2}}`)
	res, _, err := sanitize(&mcp.CallToolResult{StructuredContent: raw}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(`{"a":[3,1,2],"b":{"y":2,"z":1}}`, res.Content[0].(*mcp.TextContent).Text); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}

// A whole result, such as a generated RSA-4096 key, keeps its long strings;
// invisible characters are still shown and the hard cap still holds.
func TestSanitizeWhole(t *testing.T) {
	pem := strings.Repeat("k", 3300)
	raw, _ := json.Marshal(map[string]any{"private_pem": pem, "text": "a\u202eb"})
	res, _, err := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(raw)}, "", true)
	if err != nil || res.IsError {
		t.Fatalf("sanitize = %v %v", res, err)
	}
	if diff := cmp.Diff(`{"private_pem":"`+pem+`","text":"a\\u{202E}b"}`, res.Content[0].(*mcp.TextContent).Text); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
	big, _ := json.Marshal(map[string]any{"text": strings.Repeat("x", maxResult)})
	if res, _, _ := sanitize(&mcp.CallToolResult{StructuredContent: json.RawMessage(big)}, "", true); !res.IsError {
		t.Error("a whole result over the hard cap was sent")
	}
}
