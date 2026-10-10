package dnstools

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestMXPreferenceDecidesWhichHostsAreChecked(t *testing.T) {
	t.Parallel()

	// More hosts than maxMailHosts across two priorities, in a rotated RRset's order.
	rotated := []Record{
		{Type: "MX", Value: "20 mx3.example.net."},
		{Type: "MX", Value: "10 mx1.example.net."},
		{Type: "MX", Value: "20 mx4.example.net."},
		{Type: "MX", Value: "20 mx5.example.net."},
		{Type: "MX", Value: "10 mx2.example.net."},
		{Type: "MX", Value: "30 last.example.net."},
	}

	hosts, _, _ := mailHosts(rotated)
	var order []string
	for _, h := range hosts[:maxMailHosts] {
		order = append(order, h.host)
	}
	want := []string{"mx1.example.net", "mx2.example.net", "mx3.example.net", "mx4.example.net", "mx5.example.net"}
	if !slices.Equal(order, want) {
		t.Errorf("hosts a sender tries first = %v, want %v", order, want)
	}
}

// 13 records: past the 12 Go sorts by insertion sort, so an unstable sort would reorder ties.
func TestMailHostsKeepsRRsetOrderWithinAPreference(t *testing.T) {
	t.Parallel()

	var recs []Record
	var want10, want20 []string
	for i := range 13 {
		host := fmt.Sprintf("mx%02d.example.net", i)
		if i%3 == 0 {
			recs = append(recs, Record{Type: "MX", Value: "20 " + host + "."})
			want20 = append(want20, host)
		} else {
			recs = append(recs, Record{Type: "MX", Value: "10 " + host + "."})
			want10 = append(want10, host)
		}
	}
	hosts, _, _ := mailHosts(recs)
	var got []string
	for _, h := range hosts {
		got = append(got, h.host)
	}
	if want := append(want10, want20...); !slices.Equal(got, want) {
		t.Errorf("hosts = %v, want %v", got, want)
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

// HasMX stays true for a null MX, so only the note stops the page claiming the zone takes mail.
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

// A "v=DKIM1; p=" wildcard revokes every other selector, as recommended for a no-mail domain.
func TestRevokingDKIMWildcardIsNotAProblem(t *testing.T) {
	t.Parallel()

	revoking := &EmailAuth{Domain: "example.com", DKIMWildcard: true, DKIMRevoked: []string{"google", "selector1"}}
	revoking.judge()
	keyed := &EmailAuth{Domain: "example.com", DKIMWildcard: true, DKIM: []DKIMKey{{Selector: "google", Found: true}}}
	keyed.judge()

	level := func(e *EmailAuth) string {
		n, _ := noteWith(e.Notes, "wildcard")
		return n.Level
	}
	if got := level(revoking); got != "ok" {
		t.Errorf("revoking wildcard: level %q, want ok; notes %+v", got, revoking.Notes)
	}
	if got := level(keyed); got != "warn" {
		t.Errorf("wildcard with a real key: level %q, want warn; notes %+v", got, keyed.Notes)
	}
}

// Both cards take null MX from mailHosts, so one /email response can't contradict itself.
func TestNullMXMeansNoTargetButDot(t *testing.T) {
	t.Parallel()

	mx := func(vals ...string) (recs []Record) {
		for _, v := range vals {
			recs = append(recs, Record{Type: "MX", Value: v})
		}
		return recs
	}
	cases := []struct {
		name           string
		recs           []Record
		null, conflict bool
	}{
		{"single null MX", mx("0 ."), true, false},
		{"every target is dot", mx("0 .", "10 ."), true, false},
		{"dot beside a real host", mx("0 .", "10 mx1.example.net."), false, true},
		{"real hosts only", mx("10 mx1.example.net."), false, false},
		{"no records", nil, false, false},
	}
	for _, c := range cases {
		if _, null, conflict := mailHosts(c.recs); null != c.null || conflict != c.conflict {
			t.Errorf("%s: mailHosts null, conflict = %v, %v; want %v, %v", c.name, null, conflict, c.null, c.conflict)
		}
		if c.null {
			if _, null := newTestService().checkMailHosts(context.Background(), c.recs, ""); !null {
				t.Errorf("%s: email card NullMX = false, reputation card says true", c.name)
			}
		}
	}
}
