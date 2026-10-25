package dnstools

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// A caller-chosen zone names these: a probe would be a port-53 packet into our network.
func TestNameserverProbeRefusesNonPublicAddresses(t *testing.T) {
	t.Parallel()
	_, via := serveZone(t, testZone{
		zoneKey("loop.ns.test", "A"):      {"loop.ns.test. 300 IN A 127.0.0.1"},
		zoneKey("lan.ns.test", "A"):       {"lan.ns.test. 300 IN A 10.1.2.3"},
		zoneKey("cgnat.ns.test", "A"):     {"cgnat.ns.test. 300 IN A 100.64.1.1"},
		zoneKey("multicast.ns.test", "A"): {"multicast.ns.test. 300 IN A 224.0.0.1"},
		zoneKey("v6loop.ns.test", "AAAA"): {"v6loop.ns.test. 300 IN AAAA ::1"},
		zoneKey("nat64.ns.test", "AAAA"):  {"nat64.ns.test. 300 IN AAAA 64:ff9b::a00:1"},
		zoneKey("mixed.ns.test", "A"):     {"mixed.ns.test. 300 IN A 100.64.1.1"},
		zoneKey("mixed.ns.test", "AAAA"):  {"mixed.ns.test. 300 IN AAAA 2001:500:2::c"},
		zoneKey("public.ns.test", "A"):    {"public.ns.test. 300 IN A 198.41.0.4"},
	})
	svc := newTestService()
	ctx := context.Background()

	for _, ns := range []string{"loop.ns.test", "lan.ns.test", "cgnat.ns.test", "multicast.ns.test", "v6loop.ns.test", "nat64.ns.test"} {
		a := svc.askAuthoritative(ctx, "example.test.", "A", ns, via)
		if a.Addr != "" || !strings.Contains(a.Error, "non-public address") {
			t.Errorf("%s: probed %q (error %q), want it refused unprobed", ns, a.Addr, a.Error)
		}
	}

	for ns, want := range map[string]string{"mixed.ns.test": "2001:500:2::c", "public.ns.test": "198.41.0.4"} {
		if ip, found := svc.nameserverAddress(ctx, ns, via); ip != want || !found {
			t.Errorf("%s: nameserverAddress = %q, %v; want %q, true", ns, ip, found, want)
		}
	}
}

// This host's public addresses come from config, so only the guard refuses them.
func TestNameserverProbeRefusesOwnAddresses(t *testing.T) {
	t.Parallel()
	_, via := serveZone(t, testZone{
		zoneKey("own.ns.test", "A"):       {"own.ns.test. 300 IN A 93.184.216.34"},
		zoneKey("dual.ns.test", "A"):      {"dual.ns.test. 300 IN A 93.184.216.34"},
		zoneKey("dual.ns.test", "AAAA"):   {"dual.ns.test. 300 IN AAAA 2001:500:2::c"},
		zoneKey("own6.ns.test", "AAAA"):   {"own6.ns.test. 300 IN AAAA 2a01:4f8:c0c:1234::53"},
		zoneKey("other.ns.test", "A"):     {"other.ns.test. 300 IN A 198.41.0.4"},
		zoneKey("other6.ns.test", "AAAA"): {"other6.ns.test. 300 IN AAAA 2a01:4f8:c0c:1235::53"},
	})
	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34", "2a01:4f8:c0c:1234::/64"})
	svc := newTestService().WithEgressGuard(own)
	ctx := context.Background()

	for _, ns := range []string{"own.ns.test", "own6.ns.test"} {
		a := svc.askAuthoritative(ctx, "example.test.", "A", ns, via)
		if a.Addr != "" || !strings.Contains(a.Error, "non-public address") {
			t.Errorf("%s: probed %q (error %q), want our own address refused unprobed", ns, a.Addr, a.Error)
		}
	}
	for ns, want := range map[string]string{"dual.ns.test": "2001:500:2::c", "other.ns.test": "198.41.0.4", "other6.ns.test": "2a01:4f8:c0c:1235::53"} {
		if ip, found := svc.nameserverAddress(ctx, ns, via); ip != want || !found {
			t.Errorf("%s: nameserverAddress = %q, %v; want %q, true", ns, ip, found, want)
		}
	}
	if got := (traceServer{Name: "own.ns.test.", IP: "93.184.216.34"}).addr(svc); got != "" {
		t.Errorf("trace would send to our own address: %q", got)
	}
	if ip, _ := newTestService().nameserverAddress(ctx, "own.ns.test", via); ip != "93.184.216.34" {
		t.Errorf("without a guard the address is merely public, got %q", ip)
	}
}

// Only the configured RDAP and CT hosts are dialled directly; redirects go through the guard.
func TestDomainClientGuardsEveryOtherHost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	base := ln.Addr().String()

	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"})
	dc := NewDomainClient("http://"+base, "", time.Second, own)
	dial := dc.client.Transport.(*http.Transport).DialContext

	conn, err := dial(t.Context(), "tcp", base)
	if err != nil {
		t.Fatalf("the configured host must stay dialable: %v", err)
	}
	conn.Close()

	for _, c := range []struct {
		addr string
		want error
	}{
		{"127.0.0.1:443", platform.ErrBlockedAddress},
		{"10.0.0.1:443", platform.ErrBlockedAddress},
		{"100.64.0.1:443", platform.ErrBlockedAddress},
		{"[::1]:443", platform.ErrBlockedAddress},
		{"93.184.216.34:443", platform.ErrBlockedAddress},
		{"93.184.216.35:8443", platform.ErrBlockedPort},
	} {
		if _, err := dial(t.Context(), "tcp", c.addr); !errors.Is(err, c.want) {
			t.Errorf("dial %s = %v, want %v", c.addr, err, c.want)
		}
	}
}
