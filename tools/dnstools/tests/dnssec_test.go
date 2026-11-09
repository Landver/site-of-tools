package tests

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
	"github.com/miekg/dns"
)

func startMockDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	go server.ActivateAndServe()
	return pc.LocalAddr().String(), func() { _ = server.Shutdown() }
}

func TestValidateDNSSEC_EmptyAndBadInput(t *testing.T) {
	ctx := context.Background()
	if res := dnstools.ValidateDNSSEC(ctx, "", ""); res != nil {
		t.Errorf("expected nil for empty zone, got %+v", res)
	}
}

func TestValidateDNSSEC_LocalMock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// An unreachable port returns structured failure rather than panic
	res := dnstools.ValidateDNSSEC(ctx, "example.com", "127.0.0.1:54321")
	if res == nil {
		t.Fatalf("expected non-nil result on query error")
	}
	if res.Status != "insecure" || res.Details == "" {
		t.Errorf("unexpected status on unreachable resolver: %+v", res)
	}
}

func TestValidateDNSSEC_SecureWithADBit(t *testing.T) {
	addr, stop := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = true
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
			Algorithm: 13, // ECDSAP256SHA256
		}
		m.Answer = append(m.Answer, key)
		_ = w.WriteMsg(m)
	})
	defer stop()

	res := dnstools.ValidateDNSSEC(context.Background(), "example.com", addr)
	if res == nil || !res.Valid || res.Status != "secure" {
		t.Fatalf("expected secure DNSSEC with AD bit, got %+v", res)
	}
	if len(res.Algorithms) == 0 || res.Algorithms[0] != "ECDSAP256SHA256" {
		t.Errorf("expected algorithm ECDSAP256SHA256, got %v", res.Algorithms)
	}
}

func TestValidateDNSSEC_UnsignedZone(t *testing.T) {
	addr, stop := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	defer stop()

	res := dnstools.ValidateDNSSEC(context.Background(), "unsigned.example", addr)
	if res == nil || res.Status != "insecure" || res.Valid {
		t.Fatalf("expected insecure for unsigned zone, got %+v", res)
	}
}
