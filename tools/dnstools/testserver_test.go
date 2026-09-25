// White-box test scaffolding for the dnstools domain layer.
//
// The package's whole point is that it only ever talks to three pinned public
// resolvers, so until now nothing in it could be tested without egress: every
// domain-layer test asked the real internet and skipped when it could not.
// This file supplies the missing seam — a DNS server on loopback, registered
// under a resolver key that only a test can create (resolverOverride in
// dns.go) — so the decoders, the cache, the SPF counter and the verdict
// builders can be driven over canned answers.
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

// testResolvers holds the loopback servers tests have registered. Guarded,
// because tests run in parallel and each one registers its own server.
var testResolvers = struct {
	mu sync.RWMutex
	m  map[string]string
}{m: map[string]string{}}

// testNameservers holds the loopback authoritative servers a trace test has
// registered, keyed by the fake "IP" its traceServer carries. Same shape and
// same guarding as testResolvers above; a separate map because it feeds a
// different seam (traceAddrOverride, which returns a host:port rather than
// resolving an allowlist key).
var testNameservers = struct {
	mu sync.RWMutex
	m  map[string]string
}{m: map[string]string{}}

func TestMain(m *testing.M) {
	// Assigned once here, before any test goroutine exists, so no parallel
	// test can read the seam while another writes it.
	resolverOverride = func(key string) (string, bool) {
		testResolvers.mu.RLock()
		defer testResolvers.mu.RUnlock()
		addr, ok := testResolvers.m[key]
		return addr, ok
	}
	traceAddrOverride = func(ip string) (string, bool) {
		testNameservers.mu.RLock()
		defer testNameservers.mu.RUnlock()
		addr, ok := testNameservers.m[ip]
		return addr, ok
	}
	os.Exit(m.Run())
}

// serveNS starts a UDP-only DNS server on loopback answering with h, and
// returns a traceServer the walk will actually send packets to.
//
// UDP only, deliberately: ask() retries a truncated answer over TCP, and a
// server with no TCP listener is exactly the shape of the failure this whole
// guard exists for — a TC=1 reply whose retry cannot complete, which is what
// the root's oversized DNSKEY set produces on a path that blocks port 53 TCP.
func serveNS(t *testing.T, h dns.HandlerFunc) traceServer {
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
			t.Logf("test nameserver stopped: %v", err)
		}
	}()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := pc.LocalAddr().String()
	// Not an IP on purpose: traceRoutable would reject it, so a test that
	// forgot to register it reaches nothing rather than some real host.
	ip := "ns-" + addr
	testNameservers.mu.Lock()
	testNameservers.m[ip] = addr
	testNameservers.mu.Unlock()
	t.Cleanup(func() {
		testNameservers.mu.Lock()
		delete(testNameservers.m, ip)
		testNameservers.mu.Unlock()
	})
	return traceServer{Name: "ns." + ip + ".", IP: ip}
}

// testZone: canned answers in presentation format, keyed by owner name and
// type. A name absent from every key answers NXDOMAIN; a name present under
// another type answers NODATA — the three-way split the package partitions on.
type testZone map[string][]string

func zoneKey(name, qtype string) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + strings.ToUpper(qtype)
}

// spfZone builds a zone of TXT records from domain -> record text, which is
// what every SPF case needs and nothing else.
func spfZone(records map[string]string) testZone {
	z := testZone{}
	for name, txt := range records {
		z[zoneKey(name, "TXT")] = []string{dns.Fqdn(name) + ` 300 IN TXT "` + txt + `"`}
	}
	return z
}

// serveZone starts a DNS server on loopback serving z, registers it under a
// resolver key unique to this test, and returns the key and the address. The
// key goes through LookupSet/EmailAuth; the address goes to the internals that
// take one directly (lookup, checkSPF).
func serveZone(t *testing.T, z testZone) (key, addr string) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Names present under any type, so the handler can tell NODATA from
	// NXDOMAIN without the caller spelling out empty RRsets.
	names := map[string]bool{}
	for k := range z {
		names[k[:strings.LastIndex(k, "|")]] = true
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
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
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			// Shutdown closes the socket, which surfaces here; the test is
			// already over by then, so only log.
			t.Logf("test dns server stopped: %v", err)
		}
	}()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr = pc.LocalAddr().String()
	key = "test-" + addr
	testResolvers.mu.Lock()
	testResolvers.m[key] = addr
	testResolvers.mu.Unlock()
	t.Cleanup(func() {
		testResolvers.mu.Lock()
		delete(testResolvers.m, key)
		testResolvers.mu.Unlock()
	})
	return key, addr
}

// newTestService is a Service whose queries can only reach the loopback zone.
func newTestService() *Service { return NewService(2 * time.Second) }

// The seam itself: a test resolver key reaches the loopback zone, and every
// key a request could carry still reaches nothing but the allowlist.
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

	// Registration is per test and per address: an unregistered key, and any
	// free-form address, are refused exactly as they are in production.
	for _, bad := range []string{"", "127.0.0.1:53", "test-127.0.0.1:65000", "my-own-server:53"} {
		if _, err := svc.LookupSet(context.Background(), "seam.test", bad, []string{"A"}); err != ErrBadResolver {
			t.Errorf("resolver %q: got %v, want ErrBadResolver", bad, err)
		}
	}
}
