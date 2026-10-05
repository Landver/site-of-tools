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

func TestNameserverProbeRefusesNonPublicAndOwnAddresses(t *testing.T) {
	t.Parallel()
	_, via := serveZone(t, testZone{
		zoneKey("lan.ns.test", "A"):      {"lan.ns.test. 300 IN A 10.1.2.3"},
		zoneKey("mixed.ns.test", "A"):    {"mixed.ns.test. 300 IN A 100.64.1.1"},
		zoneKey("mixed.ns.test", "AAAA"): {"mixed.ns.test. 300 IN AAAA 2001:500:2::c"},
		zoneKey("own.ns.test", "A"):      {"own.ns.test. 300 IN A 93.184.216.34"},
	})
	plain := newTestService()
	guarded := newTestService().WithEgressGuard(platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"}))
	ctx := context.Background()

	for _, tc := range []struct {
		svc *Service
		ns  string
	}{{plain, "lan.ns.test"}, {guarded, "own.ns.test"}} {
		if a := tc.svc.askAuthoritative(ctx, "example.test.", "A", tc.ns, via); a.Addr != "" || !strings.Contains(a.Error, "non-public address") {
			t.Errorf("%s: probed %q (error %q), want it refused unprobed", tc.ns, a.Addr, a.Error)
		}
	}
	for ns, want := range map[string]string{"mixed.ns.test": "2001:500:2::c", "own.ns.test": "93.184.216.34"} {
		if ip, found := plain.nameserverAddress(ctx, ns, via); ip != want || !found {
			t.Errorf("%s: nameserverAddress = %q, %v; want %q, true", ns, ip, found, want)
		}
	}
	if got := (traceServer{Name: "own.ns.test.", IP: "93.184.216.34"}).addr(guarded); got != "" {
		t.Errorf("trace would send to our own address: %q", got)
	}
}

func TestMTASTSContentTypeIsBounded(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; "+strings.Repeat("\u202ex", 20_000))
		_, _ = io.WriteString(w, "version: STSv1\n")
	}))
	t.Cleanup(srv.Close)
	svc := newTestService()
	svc.http = srv.Client()

	_, err := svc.fetchPolicy(t.Context(), srv.URL)
	if err == nil {
		t.Fatal("a text/html policy was accepted")
	}
	if msg := err.Error(); len(msg) > 160 || !strings.HasPrefix(msg, "policy file is served as text/html; ") ||
		!strings.HasSuffix(msg, "…, and RFC 8461 requires text/plain") {
		t.Errorf("err is %d bytes, want the header clipped: %.300s", len(msg), msg)
	}
}

func TestDomainClientGuardsEveryOtherHost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"})
	dc := NewDomainClient("http://"+ln.Addr().String(), "", time.Second).WithEgressGuard(own)
	dial := dc.client.Transport.(*http.Transport).DialContext

	conn, err := dial(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the configured host must stay dialable: %v", err)
	}
	conn.Close()
	for addr, want := range map[string]error{
		"127.0.0.1:443":      platform.ErrBlockedAddress,
		"93.184.216.34:443":  platform.ErrBlockedAddress,
		"93.184.216.35:8443": platform.ErrBlockedPort,
	} {
		if _, err := dial(t.Context(), "tcp", addr); !errors.Is(err, want) {
			t.Errorf("dial %s = %v, want %v", addr, err, want)
		}
	}
}

func TestMTASTSFetchIsGuarded(t *testing.T) {
	t.Parallel()
	own := platform.NewEgressGuard([]string{"443"}, []string{"93.184.216.34"})
	for name, tc := range map[string]struct {
		svc     *Service
		refused string
	}{
		"default":    {NewService(time.Second), "10.0.0.1:443"},
		"configured": {NewService(time.Second).WithEgressGuard(own), "93.184.216.34:443"},
	} {
		tr := tc.svc.http.Transport.(*http.Transport)
		if tr.Proxy != nil || !tr.DisableKeepAlives {
			t.Errorf("%s: a proxy or a pooled connection would bypass the guard", name)
		}
		if err := tc.svc.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
			t.Errorf("%s: CheckRedirect = %v; RFC 8461 forbids following a redirect", name, err)
		}
		for addr, want := range map[string]error{tc.refused: platform.ErrBlockedAddress, "93.184.216.35:80": platform.ErrBlockedPort} {
			if _, err := tr.DialContext(t.Context(), "tcp", addr); !errors.Is(err, want) {
				t.Errorf("%s: dial %s = %v, want %v", name, addr, err, want)
			}
		}
	}
}
