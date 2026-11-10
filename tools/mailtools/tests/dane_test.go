package tests

import (
	"context"
	"net"
	"testing"

	"github.com/Landver/site-of-tools/tools/mailtools"
	"github.com/miekg/dns"
)

func TestMatchMXWithMTASTS(t *testing.T) {
	cases := []struct {
		mx       string
		patterns []string
		want     bool
	}{
		{"aspmx.l.google.com", []string{"aspmx.l.google.com"}, true},
		{"mail.corpberry.com", []string{"*.corpberry.com"}, true},
		{"sub.mail.corpberry.com", []string{"*.corpberry.com"}, false}, // wildcard only matches 1 label
		{"other.org", []string{"*.corpberry.com"}, false},
		{"", []string{"*.corpberry.com"}, false},
		{"mail.corpberry.com", nil, false},
	}

	for _, c := range cases {
		got := mailtools.MatchMXWithMTASTS(c.mx, c.patterns)
		if got != c.want {
			t.Errorf("MatchMXWithMTASTS(%q, %v) = %v, want %v", c.mx, c.patterns, got, c.want)
		}
	}
}

func TestCheckDANEMock(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer pc.Close()

	server := &dns.Server{PacketConn: pc}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = true
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTLSA {
			tlsa := &dns.TLSA{
				Hdr:          dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 300},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "abcdef1234567890",
			}
			m.Answer = append(m.Answer, tlsa)
		}
		_ = w.WriteMsg(m)
	})
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()

	// Direct check with empty or non-existent host
	res := mailtools.CheckDANE(context.Background(), "")
	if res.Configured {
		t.Errorf("CheckDANE(\"\") configured = true, want false")
	}
}
