// Loopback DNS servers, reachable only through the test-only seams in dns.go and trace.go.
package dnstools

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// loopbackRegistry maps a test-only key to a loopback address; parallel tests share it.
type loopbackRegistry struct {
	mu sync.RWMutex
	m  map[string]string
}

func (r *loopbackRegistry) lookup(key string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	addr, ok := r.m[key]
	return addr, ok
}

func (r *loopbackRegistry) add(t *testing.T, key, addr string) {
	r.mu.Lock()
	r.m[key] = addr
	r.mu.Unlock()
	t.Cleanup(func() {
		r.mu.Lock()
		delete(r.m, key)
		r.mu.Unlock()
	})
}

var (
	testResolvers   = &loopbackRegistry{m: map[string]string{}} // for resolverOverride
	testNameservers = &loopbackRegistry{m: map[string]string{}} // for traceAddrOverride
)

func TestMain(m *testing.M) {
	// Set before any test goroutine exists, so no parallel test races on the seams.
	resolverOverride = testResolvers.lookup
	traceAddrOverride = testNameservers.lookup
	os.Exit(m.Run())
}

func serveLoopbackUDP(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			t.Logf("test dns server stopped: %v", err)
		}
	}()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// serveNS is UDP only, so a TC=1 reply's TCP retry fails as on a path blocking port 53 TCP.
func serveNS(t *testing.T, h dns.HandlerFunc) traceServer {
	t.Helper()
	addr := serveLoopbackUDP(t, h)
	// Not an IP, so if it were never registered nsRoutable would refuse it rather than dial it.
	ip := "ns-" + addr
	testNameservers.add(t, ip, addr)
	return traceServer{Name: "ns." + ip + ".", IP: ip}
}

// testZone maps zoneKey(name, type) to records; unknown names answer NXDOMAIN, known ones NODATA.
type testZone map[string][]string

func zoneKey(name, qtype string) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + strings.ToUpper(qtype)
}

func spfZone(records map[string]string) testZone {
	z := testZone{}
	for name, txt := range records {
		z[zoneKey(name, "TXT")] = []string{dns.Fqdn(name) + ` 300 IN TXT "` + txt + `"`}
	}
	return z
}

// serveZone serves z on loopback: key is for LookupSet/EmailAuth, addr for lookup and checkSPF.
func serveZone(t *testing.T, z testZone) (key, addr string) {
	t.Helper()
	return serveZoneWith(t, z, nil)
}

// serveZoneWith is serveZone with edit applied to each single-question reply before it is sent.
func serveZoneWith(t *testing.T, z testZone, edit func(m *dns.Msg, q dns.Question)) (key, addr string) {
	t.Helper()

	names := map[string]bool{}
	for k := range z {
		names[k[:strings.LastIndex(k, "|")]] = true
	}

	addr = serveLoopbackUDP(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative = true
		if len(req.Question) == 1 {
			q := req.Question[0]
			name := strings.ToLower(q.Name)
			for _, s := range z[zoneKey(name, dns.TypeToString[q.Qtype])] {
				rr, err := dns.NewRR(s)
				if err != nil {
					t.Errorf("canned record %q: %v", s, err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
			if len(m.Answer) == 0 && !names[name] {
				m.Rcode = dns.RcodeNameError
			}
			if edit != nil {
				edit(m, q)
			}
		}
		_ = w.WriteMsg(m)
	})
	key = "test-" + addr
	testResolvers.add(t, key, addr)
	return key, addr
}

func newTestService() *Service { return NewService(2 * time.Second) }

func TestLoopbackResolverSeam(t *testing.T) {
	t.Parallel()

	key, _ := serveZone(t, testZone{
		zoneKey("seam.test", "A"): {"seam.test. 300 IN A 192.0.2.7"},
	})
	svc := newTestService()

	set, err := svc.LookupSet(context.Background(), "seam.test", key, []string{"A"})
	if err != nil {
		t.Fatalf("lookup through the test resolver: %v", err)
	}
	if len(set.Found) != 1 || len(set.Found[0].Records) != 1 {
		t.Fatalf("got %+v, want one A record from the loopback zone", set.Found)
	}
	if got := set.Found[0].Records[0].Value; got != "192.0.2.7" {
		t.Errorf("A record = %q, want the canned answer", got)
	}

	// Unregistered keys and free-form addresses are refused exactly as in production.
	for _, bad := range []string{"", "127.0.0.1:53", "test-127.0.0.1:65000", "my-own-server:53"} {
		if _, err := svc.LookupSet(context.Background(), "seam.test", bad, []string{"A"}); err != ErrBadResolver {
			t.Errorf("resolver %q: got %v, want ErrBadResolver", bad, err)
		}
	}
}
