package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestCheckBogon(t *testing.T) {
	cases := []struct {
		ip      string
		isBogon bool
		wantTag string
	}{
		{"127.0.0.1", true, "Loopback"},
		{"10.0.1.5", true, "Private-Use"},
		{"192.168.1.1", true, "Private-Use"},
		{"169.254.1.1", true, "Link Local"},
		{"::1", true, "Loopback"},
		{"fc00::1", true, "Unique Local"},
		{"8.8.8.8", false, ""},
		{"1.1.1.1", false, ""},
		{"2606:4700:4700::1111", false, ""},
		{"not-an-ip", false, ""},
	}

	for _, c := range cases {
		res := iptools.CheckBogon(c.ip)
		if res.IsBogon != c.isBogon {
			t.Errorf("CheckBogon(%q).IsBogon = %v, want %v", c.ip, res.IsBogon, c.isBogon)
		}
		if c.isBogon && c.wantTag != "" && !strings.Contains(res.Tag, c.wantTag) {
			t.Errorf("CheckBogon(%q).Tag = %q, want substring %q", c.ip, res.Tag, c.wantTag)
		}
	}
}

func TestUpdatePrefixTrieWithDROP(t *testing.T) {
	mockFeed := `{"cidr": "198.51.100.0/24", "sblid": "SBL123456"}
{"type": "metadata", "copyright": "Spamhaus"}
{"cidr": "203.0.113.0/28", "sblid": "SBL789012"}
`
	count := iptools.UpdatePrefixTrie(strings.NewReader(mockFeed))
	if count != 2 {
		t.Fatalf("UpdatePrefixTrie count = %d, want 2", count)
	}

	res := iptools.CheckBogon("203.0.113.5")
	if !res.IsBogon || !strings.Contains(res.Tag, "SBL789012") {
		t.Errorf("CheckBogon(203.0.113.5) = %+v, want Spamhaus DROP SBL789012", res)
	}
}
