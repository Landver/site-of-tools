package dnstools

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
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

// A failed NS lookup is not an empty delegation: "nothing serves it" needs an answer that says so.
func TestUnreadNSIsNotNoDelegation(t *testing.T) {
	t.Parallel()

	refuseNS := func(rcode int) func(*testing.T) string {
		return func(t *testing.T) string {
			_, addr := serveZoneWith(t, testZone{zoneKey("example.test", "NS"): {"example.test. 300 IN NS ns1.example.test."}},
				func(m *dns.Msg, q dns.Question) {
					if q.Qtype == dns.TypeNS {
						m.Answer, m.Rcode = nil, rcode
					}
				})
			return addr
		}
	}
	cases := map[string]func(*testing.T) string{
		"SERVFAIL": refuseNS(dns.RcodeServerFailure),
		"REFUSED":  refuseNS(dns.RcodeRefused),
		"timeout": func(t *testing.T) string {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0") // accepts and never replies
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			return pc.LocalAddr().String()
		},
	}
	for name, serve := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			names, _, _, err := NewService(300*time.Millisecond).zoneNameservers(context.Background(), "www.example.test.", serve(t))
			if len(names) != 0 || err == nil {
				t.Fatalf("names=%v err=%v, want none and the lookup's error", names, err)
			}
			sp := &Spread{nsErr: err}
			sp.health()
			if hasNote(sp.Health, "fail", "No nameservers are delegated") || !hasNote(sp.Health, "warn", "could not be read") {
				t.Errorf("health = %+v, want the unread-delegation warn and no fail", sp.Health)
			}
		})
	}

	// The resolver saying NXDOMAIN is evidence, so the fail stays.
	_, addr := serveZone(t, testZone{})
	names, _, _, err := newTestService().zoneNameservers(context.Background(), "example.test.", addr)
	sp := &Spread{nsErr: err}
	sp.health()
	if len(names) != 0 || !errors.Is(err, errNXDomain) || !hasNote(sp.Health, "fail", "No nameservers are delegated") {
		t.Errorf("NXDOMAIN zone: names=%v err=%v health=%+v, want the no-delegation fail", names, err, sp.Health)
	}
}

// A name served by a zone above its registrable domain (github.io's users, a public suffix) is not undelegated.
func TestNoZoneCutIsNotNoDelegation(t *testing.T) {
	t.Parallel()
	_, addr := serveZone(t, testZone{zoneKey("octocat.github.io", "A"): {"octocat.github.io. 300 IN A 192.0.2.1"}})

	for _, name := range []string{"octocat.github.io.", "github.io.", "com."} {
		names, _, _, err := newTestService().zoneNameservers(context.Background(), name, addr)
		sp := &Spread{nsErr: err}
		sp.health()
		if len(names) != 0 || hasNote(sp.Health, "fail", "No nameservers are delegated") || !hasNote(sp.Health, "warn", "No zone cut was found") {
			t.Errorf("%s: names=%v err=%v health=%+v, want the no-zone-cut warn and no fail", name, names, err, sp.Health)
		}
	}
}
