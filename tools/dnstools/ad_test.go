package dnstools

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// serveADZone is serveZone with one more knob: which query types the server
// marks AD. A signed name aliased into an unsigned zone is exactly this shape
// on the wire, its CNAME validated and its addresses not.
func serveADZone(t *testing.T, z testZone, ad map[string]bool) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		if len(req.Question) == 1 {
			q := req.Question[0]
			qtype := dns.TypeToString[q.Qtype]
			for _, s := range z[zoneKey(q.Name, qtype)] {
				rr, err := dns.NewRR(s)
				if err != nil {
					t.Errorf("canned record %q: %v", s, err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
			m.AuthenticatedData = ad[qtype]
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })

	addr := pc.LocalAddr().String()
	key := "test-" + addr
	testResolvers.mu.Lock()
	testResolvers.m[key] = addr
	testResolvers.mu.Unlock()
	t.Cleanup(func() {
		testResolvers.mu.Lock()
		delete(testResolvers.m, key)
		testResolvers.mu.Unlock()
	})
	return key
}

// One AD bit used to mark the whole set "Validated". Validated now means every
// answer was, and a partial set names the types that weren't.
func TestAuthenticatedMeansEveryAnswer(t *testing.T) {
	t.Parallel()

	z := testZone{
		zoneKey("alias.test", "CNAME"): {"alias.test. 300 IN CNAME edge.test."},
		zoneKey("alias.test", "A"):     {"alias.test. 300 IN CNAME edge.test.", "edge.test. 60 IN A 192.0.2.9"},
	}
	types := []string{"CNAME", "A"}

	partly := serveADZone(t, z, map[string]bool{"CNAME": true})
	set, err := newTestService().LookupSet(context.Background(), "alias.test", partly, types)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if set.Authenticated {
		t.Error("Authenticated = true with the A answer unvalidated")
	}
	if !slices.Equal(set.Unvalidated, []string{"A"}) {
		t.Errorf("Unvalidated = %v, want [A]", set.Unvalidated)
	}

	all := serveADZone(t, z, map[string]bool{"CNAME": true, "A": true})
	set, err = newTestService().LookupSet(context.Background(), "alias.test", all, types)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !set.Authenticated || len(set.Unvalidated) != 0 {
		t.Errorf("every answer validated: Authenticated = %v, Unvalidated = %v", set.Authenticated, set.Unvalidated)
	}

	// No AD anywhere is "not validated", which Signed/unsigned already says;
	// listing every type as unvalidated would add nothing.
	none := serveADZone(t, z, nil)
	set, err = newTestService().LookupSet(context.Background(), "alias.test", none, types)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if set.Authenticated || set.Unvalidated != nil {
		t.Errorf("nothing validated: Authenticated = %v, Unvalidated = %v", set.Authenticated, set.Unvalidated)
	}
}

// Problems first: a findings list read top to bottom answers "what is wrong"
// before "what is fine", and within a level the checks keep their own order.
func TestSortNotesPutsProblemsFirst(t *testing.T) {
	t.Parallel()

	notes := []Note{
		{"ok", "spf ok"}, {"info", "context"}, {"warn", "dmarc weak"},
		{"ok", "mta-sts ok"}, {"fail", "no dkim"}, {"warn", "sp=none"},
	}
	sortNotes(notes)
	var got []string
	for _, n := range notes {
		got = append(got, n.Text)
	}
	want := []string{"no dkim", "dmarc weak", "sp=none", "context", "spf ok", "mta-sts ok"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("order = %v, want %v", got, want)
	}
}
