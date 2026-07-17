package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/tools/iptools"
)

func TestParseSubnetIPv4(t *testing.T) {
	got, err := iptools.ParseSubnet("192.168.1.42/24") // host bits set → normalized
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := iptools.Subnet{
		CIDR: "192.168.1.0/24", Family: "IPv4", Prefix: 24,
		Network: "192.168.1.0", Broadcast: "192.168.1.255",
		Netmask: "255.255.255.0", Wildcard: "0.0.0.255",
		FirstHost: "192.168.1.1", LastHost: "192.168.1.254",
		Usable: "254", Total: "256",
	}
	if *got != want {
		t.Errorf("got  %+v\nwant %+v", *got, want)
	}
}

func TestParseSubnetIPv4Edges(t *testing.T) {
	// /31 — RFC 3021 point-to-point: 2 usable, no broadcast.
	if s, _ := iptools.ParseSubnet("10.0.0.0/31"); s.Usable != "2" || s.Broadcast != "" ||
		s.FirstHost != "10.0.0.0" || s.LastHost != "10.0.0.1" {
		t.Errorf("/31 wrong: %+v", s)
	}
	// /32 — single host.
	if s, _ := iptools.ParseSubnet("8.8.8.8/32"); s.Usable != "1" ||
		s.Netmask != "255.255.255.255" || s.FirstHost != "8.8.8.8" {
		t.Errorf("/32 wrong: %+v", s)
	}
	// bare IP → /32.
	if s, _ := iptools.ParseSubnet("1.1.1.1"); s.CIDR != "1.1.1.1/32" || s.Prefix != 32 {
		t.Errorf("bare IP not treated as /32: %+v", s)
	}
	// /0 — the shift-by-zero / full-range extreme: host mask is all ones, so netmask
	// is 0.0.0.0, wildcard 255.255.255.255, and the 2^32 count math must not overflow.
	if s, _ := iptools.ParseSubnet("0.0.0.0/0"); s.Netmask != "0.0.0.0" || s.Wildcard != "255.255.255.255" ||
		s.Broadcast != "255.255.255.255" || s.FirstHost != "0.0.0.1" || s.LastHost != "255.255.255.254" ||
		s.Total != "4294967296" || s.Usable != "4294967294" {
		t.Errorf("/0 wrong: %+v", s)
	}
}

func TestParseSubnetIPv6Edges(t *testing.T) {
	// /128 — single host: hostBits==0, so total 1 and first==last==network.
	if s, _ := iptools.ParseSubnet("2001:db8::1/128"); s.Total != "1" || s.Usable != "1" ||
		s.Network != "2001:db8::1" || s.FirstHost != "2001:db8::1" || s.LastHost != "2001:db8::1" ||
		s.Broadcast != "" || s.Netmask != "" {
		t.Errorf("/128 wrong: %+v", s)
	}
	// /127 — two addresses, both usable (IPv6 has no broadcast), last == network+1.
	if s, _ := iptools.ParseSubnet("2001:db8::/127"); s.Total != "2" || s.Usable != "2" ||
		s.FirstHost != "2001:db8::" || s.LastHost != "2001:db8::1" {
		t.Errorf("/127 wrong: %+v", s)
	}
}

func TestParseSubnetIPv6(t *testing.T) {
	got, err := iptools.ParseSubnet("2001:db8::/64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Family != "IPv6" || got.Network != "2001:db8::" || got.Broadcast != "" || got.Netmask != "" {
		t.Errorf("v6 basics wrong: %+v", got)
	}
	if got.LastHost != "2001:db8::ffff:ffff:ffff:ffff" {
		t.Errorf("v6 last host = %q", got.LastHost)
	}
	if got.Total != "18446744073709551616" || got.Usable != got.Total {
		t.Errorf("v6 count wrong: total=%q usable=%q", got.Total, got.Usable)
	}
}

func TestParseSubnetInvalid(t *testing.T) {
	for _, in := range []string{"", "nonsense", "192.168.1.0/33", "999.1.1.1/24"} {
		if _, err := iptools.ParseSubnet(in); err == nil {
			t.Errorf("ParseSubnet(%q) = nil error, want error", in)
		}
	}
}
