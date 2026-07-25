package iptools

import "testing"

// White-box (package iptools): ipv4RangeBounds unexported — same
// CLAUDE.md-sanctioned exception as ipsum_internal_test.go /
// spamhaus_internal_test.go.

// TestIPv4RangeBounds covers Spamhaus-DROP-style range math (blocklist.go
// stores these as BlockEntry.RangeStart/RangeEnd for whole netblock).
func TestIPv4RangeBounds(t *testing.T) {
	start, end, ok := ipv4RangeBounds("1.10.16.0/20")
	if !ok {
		t.Fatalf("1.10.16.0/20 should parse")
	}
	// 1.10.16.0 = 0x010A1000, 1.10.31.255 = 0x010A1FFF (network..broadcast,
	// whole block — RangeStart/RangeEnd cover it entirely, not just usable
	// hosts). This assertion also pins address count (0xFFF+1 = 4096 =
	// 2^12, a /20) — separate count check would only re-derive same fact.
	if start != 0x010A1000 || end != 0x010A1FFF {
		t.Errorf("bounds = [%#08x, %#08x], want [0x010a1000, 0x010a1fff]", start, end)
	}

	// /32 — single-address range, start == end.
	if s, e, ok := ipv4RangeBounds("8.8.8.8/32"); !ok || s != e {
		t.Errorf("8.8.8.8/32 = (%d, %d, %v), want start==end", s, e, ok)
	}

	// IPv6 & unparseable input: ok=false, no panic.
	for _, in := range []string{"2001:db8::/32", "not-a-cidr", "", "300.1.1.1/24"} {
		if _, _, ok := ipv4RangeBounds(in); ok {
			t.Errorf("ipv4RangeBounds(%q) = ok, want ok=false", in)
		}
	}
}
