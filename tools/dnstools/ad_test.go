package dnstools

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// startLoopbackDNS serves h over UDP on loopback until the test ends and returns its address.
func startLoopbackDNS(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// zoneReply answers req from z the way serveZone does: records, NODATA or NXDOMAIN.
func zoneReply(t *testing.T, z testZone, req *dns.Msg) *dns.Msg {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative = true
	if len(req.Question) != 1 {
		return m
	}
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
	exists := false
	for k := range z {
		exists = exists || strings.HasPrefix(k, name+"|")
	}
	if len(m.Answer) == 0 && !exists {
		m.Rcode = dns.RcodeNameError
	}
	return m
}

// serveADZone is serveZone that also sets AD on the given query types.
func serveADZone(t *testing.T, z testZone, ad map[string]bool) string {
	t.Helper()

	addr := startLoopbackDNS(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := zoneReply(t, z, req)
		if len(req.Question) == 1 {
			m.AuthenticatedData = ad[dns.TypeToString[req.Question[0].Qtype]]
		}
		_ = w.WriteMsg(m)
	})
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

// Validated means every answer carried AD; a partial set names the rest.
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

	none := serveADZone(t, z, nil)
	set, err = newTestService().LookupSet(context.Background(), "alias.test", none, types)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if set.Authenticated || set.Unvalidated != nil {
		t.Errorf("nothing validated: Authenticated = %v, Unvalidated = %v", set.Authenticated, set.Unvalidated)
	}
}

// Problems first; stable within a level.
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

// Target is the named host without the root dot; the root names nothing.
func TestRecordTargetNamesTheHost(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ rr, want string }{
		{"example.com. 300 IN MX 10 Mail.Example.net.", "mail.example.net"},
		{"example.com. 300 IN NS ns1.example.net.", "ns1.example.net"},
		{"www.example.com. 300 IN CNAME example.com.", "example.com"},
		{"4.3.2.1.in-addr.arpa. 300 IN PTR host.example.com.", "host.example.com"},
		{"example.com. 300 IN MX 0 .", ""},
		{"example.com. 300 IN A 192.0.2.1", ""},
	} {
		rr, err := dns.NewRR(tc.rr)
		if err != nil {
			t.Fatalf("%s: %v", tc.rr, err)
		}
		if got := toRecord(rr).Target; got != tc.want {
			t.Errorf("%s: Target = %q, want %q", tc.rr, got, tc.want)
		}
	}
}

func TestFailureGroupsFoldIdenticalFailures(t *testing.T) {
	t.Parallel()

	bogus := &EDE{Code: 6, Text: "DNSSEC Bogus"}
	set := &ResultSet{Failed: []TypeFailure{
		{Type: "A", Rcode: "SERVFAIL", EDE: bogus, Bogus: true},
		{Type: "AAAA", Rcode: "SERVFAIL", EDE: bogus, Bogus: true},
		{Type: "TXT", Error: "i/o timeout"},
		{Type: "MX", Rcode: "SERVFAIL", EDE: bogus, Bogus: true},
	}}
	groups := set.FailureGroups()
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2: %+v", len(groups), groups)
	}
	if got := strings.Join(groups[0].Types, ","); got != "A,AAAA,MX" {
		t.Errorf("first group types = %s, want A,AAAA,MX", got)
	}
	if !groups[0].Bogus || groups[1].Error != "i/o timeout" {
		t.Errorf("groups lost their failure detail: %+v", groups)
	}
}

// SPF first, then labelled TXT records, then the rest.
func TestTXTRankPutsSPFFirst(t *testing.T) {
	t.Parallel()

	recs := []Record{
		{Value: `"opaque-token"`},
		{Value: `"google-site-verification=x"`, Label: "Google"},
		{Value: `"v=spf1 -all"`, Label: "SPF"},
	}
	slices.SortStableFunc(recs, func(a, b Record) int { return txtRank(a) - txtRank(b) })
	if recs[0].Value != `"v=spf1 -all"` || recs[2].Value != `"opaque-token"` {
		t.Errorf("order = %v", recs)
	}
}
