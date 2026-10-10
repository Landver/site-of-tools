package dnstools

import (
	"strings"
	"testing"
)

// A timeout and a refusal are different claims; only a refusal earns the word "refused".
func TestTCPFindingSaysWhatWasSeen(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		refused bool
		want    string
	}{
		{"timed out", false, "did not complete a TCP/53 query"},
		{"refused", true, "refused TCP/53"},
	}
	for _, c := range cases {
		sp := &Spread{Authoritative: []ServerAnswer{
			{Label: "ns1.example.com", Addr: "192.0.2.1:53", TCPFail: true, TCPRefused: c.refused},
			{Label: "ns2.example.com", Addr: "192.0.2.2:53"},
		}}
		sp.health()
		if _, ok := noteWith(sp.Health, c.want); !ok {
			t.Errorf("%s: no finding says %q; got %+v", c.name, c.want, sp.Health)
		}
	}
}

// One vantage point cannot see who else the server would recurse for.
func TestOpenResolverFindingClaimsOnlyWhatOneVantagePointSaw(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		{Label: "ns1.example.com", Addr: "192.0.2.1:53", OpenResolver: true},
		{Label: "ns2.example.com", Addr: "192.0.2.2:53"},
	}}
	sp.health()

	n, ok := noteWith(sp.Health, "recursive query")
	if !ok {
		t.Fatalf("no open-recursion finding; got %+v", sp.Health)
	}
	if strings.Contains(n.Text, "by anyone on the internet") {
		t.Errorf("finding claims a scope one vantage point cannot see: %q", n.Text)
	}
}

// Bracketed IPv6 addresses reach the ASN lookup unbracketed, and the /24 check leaves them out.
func TestDelegationHealthReadsIPv6Addresses(t *testing.T) {
	t.Parallel()

	var asked []string
	asnOf := func(ip string) string {
		asked = append(asked, ip)
		return ""
	}
	sp := &Spread{Authoritative: []ServerAnswer{
		{Label: "ns1.example.com", Addr: "[2001:db8::1]:53"},
		{Label: "ns2.example.com", Addr: "192.0.2.1:53"},
	}}
	sp.addDelegationHealth(asnOf, nil)

	if len(asked) != 2 || asked[0] != "2001:db8::1" || asked[1] != "192.0.2.1" {
		t.Errorf("addresses handed to the ASN lookup = %v, want the two unbracketed addresses", asked)
	}
	if n, ok := noteWith(sp.Health, "same /24"); ok {
		t.Errorf("a mixed v4/v6 pair produced a /24 finding: %q", n.Text)
	}
}

func TestDelegationHealthFlagsOneSlashTwentyFour(t *testing.T) {
	t.Parallel()

	sp := &Spread{Authoritative: []ServerAnswer{
		{Label: "ns1.example.com", Addr: "192.0.2.1:53"},
		{Label: "ns2.example.com", Addr: "192.0.2.2:53"},
	}}
	sp.addDelegationHealth(func(string) string { return "" }, nil)

	if _, ok := noteWith(sp.Health, "same /24"); !ok {
		t.Errorf("no /24 finding for two addresses in one /24; got %+v", sp.Health)
	}
}
