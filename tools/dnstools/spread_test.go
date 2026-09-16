package dnstools

import (
	"strings"
	"testing"
)

// summarise() and providerKey() are the verdict layer of /consistency: every
// confident sentence that page prints comes out of them. Both are unexported
// and neither touches the network, so they are driven here from constructed
// server answers.

func answer(label string, serial uint32, values ...string) ServerAnswer {
	return ServerAnswer{Label: label, Addr: "192.0.2.1:53", Values: values, TTL: 300, Serial: serial}
}

func failed(label, why string) ServerAnswer {
	return ServerAnswer{Label: label, Error: why}
}

// providerKey exists to group one operator's own nameservers so their serials
// get compared. The contract is grouping, not the string itself, so that is
// what is pinned: a rewrite is free to change the key's shape.
func TestProviderKeyGroupsOneOperator(t *testing.T) {
	t.Parallel()

	sameOperator := []struct {
		name  string
		hosts []string
		// finding: non-empty when the bucketing is wrong today, naming the
		// review finding whose fix makes this case pass.
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
			// Route 53 deliberately spreads one zone's nameservers across four
			// TLDs. Four buckets means their serials are never compared, so
			// SerialsAgree cannot fail, and every single-provider AWS zone is
			// told it has more than one DNS provider.
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
					msg := "providerKey(%q) = %q but providerKey(%q) = %q: one operator split across buckets"
					if tc.finding != "" {
						msg += " [expected red until " + tc.finding + " is fixed]"
					}
					t.Errorf(msg, tc.hosts[0], first, h, got)
				}
			}
		})
	}

	// The other half of the contract: two operators must never share a bucket,
	// or a real disagreement is compared away.
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
	// Largest group first, and every group names who returned it.
	for _, g := range sp.Groups {
		if len(g.Servers) == 0 {
			t.Errorf("group %v names no server", g.Values)
		}
	}
}

// Nothing answered means nothing to be consistent about: the verdict must not
// read green beside a panel saying no records came back.
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
	if !hasNote(sp.Health, "fail", "None of the zone's nameservers answered") {
		t.Errorf("health notes %v do not report that nothing answered", sp.Health)
	}
}

// RFC 2182: a single nameserver is a single point of failure for the whole
// domain, so one live server is a finding rather than a pass.
func TestSummariseSingleLiveNameserverIsAFinding(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		answer("ns1.example.com.", 100, "192.0.2.1"),
		failed("ns2.example.com.", "timeout"),
	}}
	sp.summarise()

	if !hasNote(sp.Health, "fail", "Only one nameserver answered") {
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

// The same test on Route 53, whose four nameservers sit under four different
// TLDs. Serial drift there is invisible today and every single-provider AWS
// zone is told it has several providers.
//
// Pins providerkey-splits-one-operator; expected red until it is fixed.
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

func hasNote(notes []Note, level, substr string) bool {
	for _, n := range notes {
		if n.Level == level && strings.Contains(n.Text, substr) {
			return true
		}
	}
	return false
}
