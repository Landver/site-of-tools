package dnstools

import (
	"slices"
	"strings"
	"testing"
)

// The MX half of /email, driven from constructed rdata: which hosts the
// FCrDNS fan-out spends its five slots on, and what a null MX says.

func TestMXPreferenceDecidesWhichHostsAreChecked(t *testing.T) {
	t.Parallel()

	// A comcast.net-shaped set: more hosts than maxMailHosts, across two
	// priority levels, handed over in the order a rotating RRset produced.
	rotated := []Record{
		{Type: "MX", Value: "20 mx3.example.net."},
		{Type: "MX", Value: "10 mx1.example.net."},
		{Type: "MX", Value: "20 mx4.example.net."},
		{Type: "MX", Value: "20 mx5.example.net."},
		{Type: "MX", Value: "10 mx2.example.net."},
		{Type: "MX", Value: "30 last.example.net."},
	}

	sorted := slices.Clone(rotated)
	slices.SortStableFunc(sorted, func(a, b Record) int { return mxPref(a.Value) - mxPref(b.Value) })
	var order []string
	for _, rec := range sorted[:maxMailHosts] {
		order = append(order, mxHost(rec.Value))
	}
	want := []string{"mx1.example.net", "mx2.example.net", "mx3.example.net", "mx4.example.net", "mx5.example.net"}
	if !slices.Equal(order, want) {
		t.Errorf("hosts a sender tries first = %v, want %v", order, want)
	}
}

func TestMXRdataParsing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rdata    string
		wantHost string
		wantPref int
	}{
		{"10 mail.example.com.", "mail.example.com", 10},
		{"0 .", ".", 0},
		// Malformed rdata sorts last so it cannot displace a real host.
		{"mail.example.com.", "mail.example.com", maxMXPref},
		{"notanumber mail.example.com.", "mail.example.com", maxMXPref},
		{"", "", maxMXPref},
	}
	for _, c := range cases {
		if got := mxHost(c.rdata); got != c.wantHost {
			t.Errorf("mxHost(%q) = %q, want %q", c.rdata, got, c.wantHost)
		}
		if got := mxPref(c.rdata); got != c.wantPref {
			t.Errorf("mxPref(%q) = %d, want %d", c.rdata, got, c.wantPref)
		}
	}
}

// A null MX is the zone saying it receives no mail. HasMX stays true because a
// record is published, so the note is the only thing that stops the page
// asserting the opposite of what the zone says.
func TestNullMXIsReported(t *testing.T) {
	t.Parallel()

	e := &EmailAuth{Domain: "example.com", HasMX: true, MXCount: 1, NullMX: true}
	e.judge()

	var found bool
	for _, n := range e.Notes {
		if strings.Contains(n.Text, "null MX") {
			found = true
			if n.Level != "info" {
				t.Errorf("null MX note level = %q, want info", n.Level)
			}
		}
	}
	if !found {
		t.Errorf("no note mentions the null MX; got %+v", e.Notes)
	}
}
