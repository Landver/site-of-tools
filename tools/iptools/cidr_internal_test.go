package iptools

import "testing"

// White-box: ipv4RangeBounds is unexported.

func TestIPv4RangeBounds(t *testing.T) {
	start, end, ok := ipv4RangeBounds("1.10.16.0/20")
	if !ok {
		t.Fatalf("1.10.16.0/20 should parse")
	}
	// Network through broadcast, the whole /20 (4096 addresses), not just usable hosts.
	if start != 0x010A1000 || end != 0x010A1FFF {
		t.Errorf("bounds = [%#08x, %#08x], want [0x010a1000, 0x010a1fff]", start, end)
	}

	if s, e, ok := ipv4RangeBounds("8.8.8.8/32"); !ok || s != e {
		t.Errorf("8.8.8.8/32 = (%d, %d, %v), want start==end", s, e, ok)
	}

	for _, in := range []string{"2001:db8::/32", "not-a-cidr", "", "300.1.1.1/24"} {
		if _, _, ok := ipv4RangeBounds(in); ok {
			t.Errorf("ipv4RangeBounds(%q) = ok, want ok=false", in)
		}
	}
}
