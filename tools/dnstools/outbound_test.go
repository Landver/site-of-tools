package dnstools

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// A zone the caller chose names these addresses, and a probe of one would be a
// port-53 packet into our own network.
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

// This host's public addresses come from config, not from a range rule, so
// only the guard knows to refuse them.
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

// A hostile policy server picks its Content-Type, and the error quoting it
// becomes a note on the page.
func TestMTASTSContentTypeIsBounded(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := "text/html"
		if r.URL.Path == "/huge" {
			ct += "; " + strings.Repeat("\u202ex", 20_000)
		}
		w.Header().Set("Content-Type", ct)
		_, _ = io.WriteString(w, "version: STSv1\n")
	}))
	t.Cleanup(srv.Close)
	svc := newTestService()
	svc.http = srv.Client()

	_, err := svc.fetchPolicy(t.Context(), srv.URL+"/normal")
	if want := "policy file is served as text/html, and RFC 8461 requires text/plain"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
	_, err = svc.fetchPolicy(t.Context(), srv.URL+"/huge")
	if err == nil {
		t.Fatal("a text/html policy was accepted")
	}
	if msg := err.Error(); len(msg) > 160 || !strings.HasPrefix(msg, "policy file is served as text/html; ") ||
		!strings.HasSuffix(msg, "…, and RFC 8461 requires text/plain") {
		t.Errorf("err is %d bytes, want the header clipped: %.300s", len(msg), msg)
	}
}

// The configured RDAP and CT hosts are the only ones dialled directly; a
// redirect anywhere else goes through the guard, judged on the address.
func TestDomainClientGuardsEveryOtherHost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	base := ln.Addr().String()

	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"})
	dc := NewDomainClient("http://"+base, "", time.Second).WithEgressGuard(own)
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

func TestMTASTSFetchIsGuarded(t *testing.T) {
	t.Parallel()
	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"})
	cases := []struct {
		addr string
		want error
	}{
		{"10.0.0.1:443", platform.ErrBlockedAddress},
		{"100.64.0.1:443", platform.ErrBlockedAddress},
		{"127.0.0.1:443", platform.ErrBlockedAddress},
		{"[::1]:443", platform.ErrBlockedAddress},
		{"169.254.169.254:443", platform.ErrBlockedAddress},
		{"93.184.216.35:80", platform.ErrBlockedPort},
		{"93.184.216.35:8443", platform.ErrBlockedPort},
	}
	for name, svc := range map[string]*Service{
		"default":    NewService(time.Second),
		"configured": NewService(time.Second).WithEgressGuard(own),
	} {
		client := svc.policyClient()
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s: transport is %T", name, client.Transport)
		}
		if tr.Proxy != nil || !tr.DisableKeepAlives {
			t.Errorf("%s: a proxy or a pooled connection would bypass the guard", name)
		}
		if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
			t.Errorf("%s: CheckRedirect = %v; RFC 8461 forbids following a redirect", name, err)
		}
		for _, c := range cases {
			if _, err := tr.DialContext(t.Context(), "tcp", c.addr); !errors.Is(err, c.want) {
				t.Errorf("%s: dial %s = %v, want %v", name, c.addr, err, c.want)
			}
		}
		if name == "configured" {
			if _, err := tr.DialContext(t.Context(), "tcp", "93.184.216.34:443"); !errors.Is(err, platform.ErrBlockedAddress) {
				t.Errorf("dial to our own address = %v, want ErrBlockedAddress", err)
			}
		}
	}
}
