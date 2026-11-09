package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestParseTorExitList(t *testing.T) {
	raw := `# Tor exit list generated at 2026-11-09
1.2.3.4
# comment line
invalid-ip
5.6.7.8
::ffff:9.10.11.12
2001:db8::1
`
	entries, err := iptools.ParseTorExitListForTest(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		"1.2.3.4":     true,
		"5.6.7.8":     true,
		"9.10.11.12":  true,
		"2001:db8::1": true,
	}

	if len(entries) != len(expected) {
		t.Fatalf("got %d entries, want %d", len(entries), len(expected))
	}

	for _, e := range entries {
		if !expected[e.IP] {
			t.Errorf("unexpected IP in entries: %s", e.IP)
		}
		if e.Source != iptools.BlocklistSourceTorExit {
			t.Errorf("got source %s, want %s", e.Source, iptools.BlocklistSourceTorExit)
		}
		if e.Reason != "tor exit node" {
			t.Errorf("got reason %s, want 'tor exit node'", e.Reason)
		}
	}
}
