package tests

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestIPLookupSelf(t *testing.T) {
	s := newStack(t, stackOpts{})
	// The raw address, not its limiter key: for IPv6 that is a /64.
	const v6 = "2001:db8:1:2::7"
	got := object(t, call(t, s.client(t, "/mcp/ip", map[string]string{"CF-Connecting-IP": v6}), "ip_lookup", map[string]any{"ip": "self"}))
	if got["ip"] != v6 || got["self"] != true {
		t.Errorf("self = %v, want %s and self: true", got, v6)
	}
	if notes := got["notes"].([]any); len(notes) != 1 || !strings.Contains(notes[0].(string), "MCP client") {
		t.Errorf("notes = %v, want the note naming whose address this is", notes)
	}

	loop := s.client(t, "/mcp/ip", map[string]string{"CF-Connecting-IP": "127.0.0.1"})
	failsWith(t, call(t, loop, "ip_lookup", map[string]any{"ip": "SELF"}), "not a public address")
}

func TestIPLookupShodanSkipped(t *testing.T) {
	r := richResult
	r.Shodan = &iptools.ShodanInfo{Skipped: true}
	got := object(t, call(t, newStack(t, stackOpts{geo: &fakeGeo{res: r}}).client(t, "/mcp", nil), "ip_lookup", required["ip_lookup"]))
	if diff := cmp.Diff([]string{"IP2Location LITE", "The Spamhaus Project"}, sources(got)); diff != "" {
		t.Errorf("attribution (-want +got):\n%s", diff)
	}
	if notes, _ := got["notes"].([]any); len(notes) != 1 || !strings.Contains(notes[0].(string), "Shodan") {
		t.Errorf("notes = %v, want one saying open ports weren't checked", got["notes"])
	}
}
