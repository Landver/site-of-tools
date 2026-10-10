package dnstools

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func answer(label string, serial uint32, values ...string) ServerAnswer {
	return ServerAnswer{Label: label, Addr: "192.0.2.1:53", Values: values, TTL: 300, Serial: serial}
}

func failed(label, why string) ServerAnswer {
	return ServerAnswer{Label: label, Error: why}
}

// The contract is grouping one operator's nameservers, not the key's shape.
func TestProviderKeyGroupsOneOperator(t *testing.T) {
	t.Parallel()

	sameOperator := []struct {
		name    string
		hosts   []string
		finding string
	}{
		{
			name:  "NS1's servers under one delegation",
			hosts: []string{"dns1.p08.nsone.net.", "dns2.p08.nsone.net.", "dns3.p08.nsone.net."},
		},
		{
			name:  "Cloudflare's pair",
			hosts: []string{"ns3.cloudflare.com.", "ns4.cloudflare.com."},
		},
		{
			// Route 53 spreads one zone across four TLDs; split buckets never compare serials.
			name: "Route 53's four cross-TLD servers",
			hosts: []string{
				"ns-520.awsdns-01.net.", "ns-1707.awsdns-21.co.uk.",
				"ns-421.awsdns-52.com.", "ns-1283.awsdns-32.org.",
			},
			finding: "providerkey-splits-one-operator",
		},
		{
			// Nominet runs all eight from one zone under a two-label suffix.
			name:    "Nominet's registry servers",
			hosts:   []string{"dns1.nic.uk.", "nsa.nic.uk.", "nsb.nic.uk."},
			finding: "providerkey-splits-one-operator",
		},
	}

	for _, tc := range sameOperator {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			first := providerKey(tc.hosts[0])
			for _, h := range tc.hosts[1:] {
				if got := providerKey(h); got != first {
					t.Errorf("providerKey(%q) = %q but providerKey(%q) = %q: one operator split across buckets"+regresses(tc.finding),
						tc.hosts[0], first, h, got)
				}
			}
		})
	}

	// Two operators must never share a bucket, or a real disagreement is compared away.
	distinct := []string{"dns1.p08.nsone.net.", "ns-520.awsdns-01.net.", "ns3.cloudflare.com.", "ns1.digitalocean.com."}
	for i, a := range distinct {
		for _, b := range distinct[i+1:] {
			if providerKey(a) == providerKey(b) {
				t.Errorf("providerKey(%q) == providerKey(%q) = %q: two operators in one bucket", a, b, providerKey(a))
			}
		}
	}
}

func TestSummariseAgreement(t *testing.T) {
	t.Parallel()

	sp := &Spread{
		Authoritative: []ServerAnswer{
			answer("ns1.example.com.", 100, "192.0.2.1"),
			answer("ns2.example.com.", 100, "192.0.2.1"),
		},
		Resolvers: []ServerAnswer{answer("Cloudflare (1.1.1.1)", 0, "192.0.2.1")},
	}
	sp.summarise()

	if !sp.Consistent {
		t.Error("every server returned the same answer but Consistent is false")
	}
	if !sp.AuthConsistent {
		t.Error("the zone's own servers agree but AuthConsistent is false")
	}
	if len(sp.Groups) != 1 {
		t.Errorf("built %d answer groups from one distinct answer", len(sp.Groups))
	}
	if sp.Answered != 3 || sp.Asked != 3 {
		t.Errorf("answered %d of %d, want 3 of 3", sp.Answered, sp.Asked)
	}
}

func TestSummariseDisagreement(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		answer("ns1.example.com.", 100, "192.0.2.1"),
		answer("ns2.example.com.", 100, "192.0.2.9"),
	}}
	sp.summarise()

	if sp.AuthConsistent {
		t.Error("the zone's own servers returned different answers but AuthConsistent is true")
	}
	if sp.Consistent {
		t.Error("two distinct answers but Consistent is true")
	}
	if len(sp.Groups) != 2 {
		t.Errorf("built %d groups from two distinct answers", len(sp.Groups))
	}
	for _, g := range sp.Groups {
		if len(g.Servers) == 0 {
			t.Errorf("group %v names no server", g.Values)
		}
	}
}

// The verdict must not read green beside a panel saying nothing came back.
func TestSummariseNothingAnswered(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		failed("ns1.example.com.", "timeout"),
		failed("ns2.example.com.", "timeout"),
	}}
	sp.summarise()

	if sp.Answered != 0 {
		t.Errorf("answered = %d when every server errored", sp.Answered)
	}
	if sp.Consistent {
		t.Error("Consistent is true when nothing answered")
	}
	if len(sp.Groups) != 0 {
		t.Errorf("built %d groups from no answers", len(sp.Groups))
	}
	if !hasNote(sp.Health, "fail", "None of the zone's") {
		t.Errorf("health notes %v do not report that nothing answered", sp.Health)
	}
}

// RFC 2182: one live nameserver is a single point of failure.
func TestSummariseSingleLiveNameserverIsAFinding(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		answer("ns1.example.com.", 100, "192.0.2.1"),
		failed("ns2.example.com.", "timeout"),
	}}
	sp.summarise()

	if !hasNote(sp.Health, "fail", "Only 1 of the zone's") {
		t.Errorf("health notes %v do not flag a single surviving nameserver", sp.Health)
	}
}

func TestSummariseSerialsWithinOneProvider(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		answer("dns1.p08.nsone.net.", 100, "192.0.2.1"),
		answer("dns2.p08.nsone.net.", 101, "192.0.2.1"),
	}}
	sp.summarise()

	if sp.SerialsAgree {
		t.Error("two servers of one provider on serials 100 and 101 but SerialsAgree is true")
	}
	if sp.MultiProvider {
		t.Error("one provider's servers reported as more than one provider")
	}
}

// Route 53's nameservers span four TLDs; pins providerkey-splits-one-operator.
func TestSummariseSerialsAcrossRoute53Suffixes(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		answer("ns-520.awsdns-01.net.", 200, "192.0.2.1"),
		answer("ns-1707.awsdns-21.co.uk.", 201, "192.0.2.1"),
	}}
	sp.summarise()

	if sp.SerialsAgree {
		t.Error("one Route 53 zone serving serials 200 and 201 but SerialsAgree is true")
	}
	if sp.MultiProvider {
		t.Error("a pure Route 53 zone reported as served by more than one DNS provider")
	}
}

// Rotation needs a witness in one provider; a cross-provider split may be a stale zone.
func TestRotationIsWitnessedInsideOneProvider(t *testing.T) {
	t.Parallel()

	across := &Spread{Authoritative: []ServerAnswer{
		answer("dns1.p08.nsone.net.", 100, "192.0.2.1"),
		answer("dns2.p08.nsone.net.", 100, "192.0.2.1"),
		answer("ns-520.awsdns-01.net.", 7, "192.0.2.2"),
		answer("ns-1707.awsdns-21.co.uk.", 7, "192.0.2.2"),
	}}
	across.summarise()
	if across.Rotation {
		t.Error("a split only between two providers was read as rotation")
	}
	if !across.MultiProvider || across.AuthConsistent {
		t.Errorf("MultiProvider = %v, AuthConsistent = %v; want a disagreeing two-provider zone", across.MultiProvider, across.AuthConsistent)
	}

	inside := &Spread{Authoritative: []ServerAnswer{
		answer("dns1.p08.nsone.net.", 100, "192.0.2.1"),
		answer("dns2.p08.nsone.net.", 100, "192.0.2.3"),
		answer("ns-520.awsdns-01.net.", 7, "192.0.2.2"),
	}}
	inside.summarise()
	if !inside.Rotation {
		t.Error("two servers of one provider on one serial with different sets is rotation")
	}
}

func TestUnanimousRcode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		codes []string
		want  string
	}{
		{[]string{"NOERROR", "NXDOMAIN"}, ""},
		{[]string{"", "NOERROR"}, "NOERROR"},
		{[]string{"NOERROR", "", "NOERROR"}, "NOERROR"},
		{[]string{"", ""}, ""},
		{nil, ""},
	} {
		if got := unanimousRcode(tc.codes, func(c string) string { return c }); got != tc.want {
			t.Errorf("unanimousRcode(%q) = %q, want %q", tc.codes, got, tc.want)
		}
	}
}

func TestAnswerGroupsAreLargestFirst(t *testing.T) {
	t.Parallel()

	got := answerGroups(
		[]string{"a", "b", "c", "d", "e"},
		[][]string{{"192.0.2.9"}, {"192.0.2.1"}, nil, {"192.0.2.1"}, {"192.0.2.1"}},
	)
	want := []AnswerGroup{
		{Values: []string{"192.0.2.1"}, Servers: []string{"b", "d", "e"}},
		{Values: []string{"192.0.2.9"}, Servers: []string{"a"}},
		{Values: nil, Servers: []string{"c"}},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("answerGroups (-want +got):\n%s", diff)
	}

	sp := &Spread{
		Authoritative: []ServerAnswer{answer("ns1.example.com.", 100, "192.0.2.9"), failed("ns2.example.com.", "timeout")},
		Resolvers:     []ServerAnswer{answer("Cloudflare (1.1.1.1)", 0, "192.0.2.1"), answer("Google (8.8.8.8)", 0, "192.0.2.1")},
	}
	sp.summarise()
	wantSpread := []AnswerGroup{
		{Values: []string{"192.0.2.1"}, Servers: []string{"Cloudflare (1.1.1.1)", "Google (8.8.8.8)"}},
		{Values: []string{"192.0.2.9"}, Servers: []string{"ns1.example.com."}},
	}
	if diff := cmp.Diff(wantSpread, sp.Groups); diff != "" {
		t.Errorf("Spread.Groups (-want +got):\n%s", diff)
	}
}
