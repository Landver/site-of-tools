package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func sources(t *testing.T, obj map[string]any) []string {
	t.Helper()
	list, _ := obj["attribution"].([]any)
	var out []string
	for _, c := range list {
		m, _ := c.(map[string]any)
		out = append(out, m["source"].(string))
	}
	return out
}

func TestIPLookup(t *testing.T) {
	s := newStack(t, stackOpts{chk: fakeChecker{lk: iptools.BlockLookup{Sources: []string{"spamhaus-drop"}}}})
	cs := s.client(t, "/mcp/ip", nil, nil)

	got := object(t, call(t, cs, "ip_lookup", map[string]any{"ip": " 8.8.8.8 "}))
	if got["ip"] != "8.8.8.8" || got["as_name"] != "Google LLC" || got["self"] != nil {
		t.Errorf("lookup = %v, want 8.8.8.8 / Google LLC, not self", got)
	}
	if bl, _ := got["blocklist"].(map[string]any); bl == nil || len(bl["sources"].([]any)) != 1 {
		t.Errorf("blocklist = %v, want the checker's listing", got["blocklist"])
	}
	want := []string{"IP2Location LITE", "The Spamhaus Project", "Shodan InternetDB"}
	if diff := cmp.Diff(want, sources(t, got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}

	for ip, want := range map[string]string{"nope": `"nope" is not a valid IP address`, "": "minLength"} {
		res := call(t, cs, "ip_lookup", map[string]any{"ip": ip})
		if !res.IsError || res.StructuredContent != nil || !strings.Contains(text(t, res), want) {
			t.Errorf("ip_lookup %q = %q, want an isError result saying %q", ip, text(t, res), want)
		}
	}
	if res := call(t, cs, "ip_lookup", map[string]any{}); !res.IsError || !strings.Contains(text(t, res), "ip") {
		t.Errorf("ip_lookup without ip = %q, want a validation error naming ip", text(t, res))
	}
}

func TestIPLookupErrorsAreTheRESTMessages(t *testing.T) {
	s := newStack(t, stackOpts{geo: &fakeGeo{err: iptools.ErrUnavailable}})
	res := call(t, s.client(t, "/mcp", nil, nil), "ip_lookup", map[string]any{"ip": "1.2.3.4"})
	if !res.IsError || text(t, res) != iptools.ErrUnavailable.Error() {
		t.Errorf("unavailable = %q, want %q", text(t, res), iptools.ErrUnavailable)
	}
}

func TestIPLookupSelf(t *testing.T) {
	geo := &fakeGeo{res: richResult}
	s := newStack(t, stackOpts{geo: geo})
	// The raw address, not its limiter key: for IPv6 that is a /64.
	const v6 = "2001:db8:1:2::7"
	cs := s.client(t, "/mcp/ip", map[string]string{"CF-Connecting-IP": v6}, nil)
	got := object(t, call(t, cs, "ip_lookup", map[string]any{"ip": "self"}))
	if geo.lastAsked() != v6 || got["ip"] != v6 || got["self"] != true {
		t.Errorf("self asked %q, result %v; want %s and self: true", geo.lastAsked(), got, v6)
	}
	if notes := got["notes"].([]any); len(notes) != 1 || !strings.Contains(notes[0].(string), "MCP client") {
		t.Errorf("notes = %v, want the note naming whose address this is", notes)
	}

	loop := s.client(t, "/mcp/ip", map[string]string{"CF-Connecting-IP": "127.0.0.1"}, nil)
	if res := call(t, loop, "ip_lookup", map[string]any{"ip": "SELF"}); !res.IsError || !strings.Contains(text(t, res), "not a public address") {
		t.Errorf("self from loopback = %q, want refused as not public", text(t, res))
	}
}

func TestIPLookupShodanSkipped(t *testing.T) {
	r := richResult
	r.Shodan = &iptools.ShodanInfo{Skipped: true}
	s := newStack(t, stackOpts{geo: &fakeGeo{res: r}})
	got := object(t, call(t, s.client(t, "/mcp", nil, nil), "ip_lookup", map[string]any{"ip": "8.8.8.8"}))
	if diff := cmp.Diff([]string{"IP2Location LITE", "The Spamhaus Project"}, sources(t, got)); diff != "" {
		t.Errorf("attribution when Shodan was skipped (-want +got):\n%s", diff)
	}
	if notes, _ := got["notes"].([]any); len(notes) != 1 || !strings.Contains(notes[0].(string), "Shodan") {
		t.Errorf("notes = %v, want one saying open ports weren't checked", got["notes"])
	}
}

func TestIPCIDR(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/ip", nil, nil)
	got := object(t, call(t, cs, "ip_cidr", map[string]any{"cidr": "10.0.0.1/8"}))
	if got["cidr"] != "10.0.0.0/8" || got["usable_hosts"] != "16777214" || got["attribution"] != nil {
		t.Errorf("cidr = %v, want 10.0.0.0/8 with 16777214 hosts and no attribution", got)
	}
	if res := call(t, cs, "ip_cidr", map[string]any{"cidr": "10.0.0.0/33"}); !res.IsError || !strings.Contains(text(t, res), "not valid CIDR") {
		t.Errorf("bad cidr = %q, want the REST message", text(t, res))
	}
}

// TestIPParity: an MCP result is the REST body plus its declared additions.
func TestIPParity(t *testing.T) {
	s := newStack(t, stackOpts{chk: fakeChecker{lk: iptools.BlockLookup{Sources: []string{"ipsum"}, MaxCount: 3}}})
	cs := s.client(t, "/mcp", nil, nil)
	cases := []struct {
		tool, arg, value, rest string
		added                  []string
	}{
		{"ip_lookup", "ip", "8.8.8.8", "/?ip=8.8.8.8", []string{"attribution"}},
		{"ip_cidr", "cidr", "2001:db8::/32", "/cidr?cidr=2001:db8::/32", nil},
	}
	for _, tc := range cases {
		mcpBody := object(t, call(t, cs, tc.tool, map[string]any{tc.arg: tc.value}))
		for _, k := range tc.added {
			delete(mcpBody, k)
		}
		rec := s.do(http.MethodGet, tc.rest, "", map[string]string{"Host": ipHost, "Accept": "application/json"})
		if rec.Code != http.StatusOK {
			t.Fatalf("REST %s = %d", tc.rest, rec.Code)
		}
		if diff := cmp.Diff(decode(t, rec.Body.Bytes()), mcpBody); diff != "" {
			t.Errorf("%s vs REST %s (-rest +mcp):\n%s", tc.tool, tc.rest, diff)
		}
	}
}

// TestUntrustedStringsThroughTheStack: what a third party chose reaches the
// model capped and with its invisible characters shown; lists stay whole, and
// a result over the hard cap is an error rather than a cut.
func TestUntrustedStringsThroughTheStack(t *testing.T) {
	r := richResult
	r.ASName = "Evil\u202eCorp\U000E0041" + strings.Repeat("x", 10<<10)
	r.Shodan = &iptools.ShodanInfo{Found: true, Hostnames: make([]string, 300)}
	for i := range r.Shodan.Hostnames {
		r.Shodan.Hostnames[i] = strings.Repeat("h", 90) + ".example"
	}
	cs := newStack(t, stackOpts{geo: &fakeGeo{res: r}}).client(t, "/mcp", nil, nil)
	got := object(t, call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"}))
	as := got["as_name"].(string)
	if !strings.HasPrefix(as, `Evil\u{202E}Corp\u{E0041}`) || !strings.HasSuffix(as, " bytes]") || len(as) > 2100 {
		t.Errorf("as_name = %.60q…(%d bytes), want visible escapes and a cap with its marker", as, len(as))
	}
	if n := len(got["shodan"].(map[string]any)["hostnames"].([]any)); n != 300 {
		t.Errorf("hostnames kept %d of 300; lists are never cut", n)
	}

	r.Shodan = &iptools.ShodanInfo{Found: true, Vulns: make([]string, 2000)}
	for i := range r.Shodan.Vulns {
		r.Shodan.Vulns[i] = strings.Repeat("v", 60)
	}
	cs = newStack(t, stackOpts{geo: &fakeGeo{res: r}}).client(t, "/mcp", nil, nil)
	res := call(t, cs, "ip_lookup", map[string]any{"ip": "8.8.8.8"})
	if !res.IsError || !strings.Contains(text(t, res), "Result too large") {
		t.Errorf("an oversized result = isError %v %.80q, want refused as too large", res.IsError, text(t, res))
	}
}

func TestStructuredContentIsAlwaysAnObject(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	for name, args := range map[string]map[string]any{
		"ip_lookup": {"ip": "8.8.8.8"},
		"ip_cidr":   {"cidr": "192.168.1.0/24"},
	} {
		res := call(t, cs, name, args)
		object(t, res)
		raw, _ := json.Marshal(res.StructuredContent)
		if raw[0] != '{' {
			t.Errorf("%s structuredContent = %s, want an object", name, raw)
		}
	}
}
