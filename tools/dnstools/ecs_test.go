package dnstools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// White-box, and deliberately so: the whole feature is a verdict derived from
// the SCOPE an authoritative server reports, and no public resolver can be
// asked to report a chosen scope on demand. The verdict table therefore has to
// be driven over a server we control.
//
// testserver_test.go's serveZone is the right shape but has no client-subnet
// knob — it neither reads the option out of the request nor puts one in the
// response — and that option is the entire subject here. The server below adds
// the one thing it lacks and is reached through ecsRun's address parameter
// rather than through the resolver allowlist. Everything that CAN be tested
// through the exported API is, in tools/dnstools/tests/ecs_test.go.
//
// The listen/start/cleanup half is a near copy of serveZone's, and the tidy
// end state is one `startDNS(t, dns.Handler)` in testserver_test.go that both
// build on (or a client-subnet knob on serveZone, deleting this entirely).
// Left alone here only because this change's scope is the files the ECS
// feature added; testserver_test.go is not one of them. No rule forbids
// editing it — recorded as wiring, not as a constraint of the codebase.

// ecsServer is a DNS server on loopback that answers according to the client
// subnet the query carried. Zero value plus reply is the common case; the
// other fields exist for the two responses that are well-formed but wrong.
type ecsServer struct {
	// reply is given the subnet as "a.b.c.d/len" (empty when the query
	// carried none) and returns the A values to answer with, the scope to
	// report, and whether to echo a client-subnet option at all. "Whether" is
	// a separate return value because a missing option and a scope of 0 are
	// the two facts this feature must never conflate.
	reply func(subnet string) (vals []string, scope uint8, echo bool)
	// echoSubnet: echo the option for THIS prefix, whatever the query sent.
	// A resolver serving a cached ECS answer keyed to another network.
	echoSubnet string
	// echoNetmask: the source prefix length to echo, defaulting to the one
	// the query carried. A length other than the query's is the other way an
	// echo can describe something we did not ask.
	echoNetmask uint8
	// rcode: the response code, NOERROR when zero.
	rcode int
}

// ecsTestServer is the common case: a server with nothing wrong with it.
func ecsTestServer(t *testing.T, reply func(subnet string) (vals []string, scope uint8, echo bool)) string {
	t.Helper()
	return ecsServer{reply: reply}.start(t)
}

// start brings the server up and returns its address.
func (s ecsServer) start(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetReply(req)
		m.Authoritative = true
		m.Rcode = s.rcode

		var subnet string
		var addr net.IP
		var mask uint8
		if o := req.IsEdns0(); o != nil {
			for _, x := range o.Option {
				if e, ok := x.(*dns.EDNS0_SUBNET); ok {
					subnet = fmt.Sprintf("%s/%d", e.Address, e.SourceNetmask)
					addr, mask = e.Address, e.SourceNetmask
				}
			}
		}

		vals, scope, echo := s.reply(subnet)
		if len(req.Question) == 1 && m.Rcode == dns.RcodeSuccess {
			q := req.Question[0]
			for _, v := range vals {
				rr, err := dns.NewRR(q.Name + " 60 IN A " + v)
				if err != nil {
					t.Errorf("canned record %q: %v", v, err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		}
		if s.echoSubnet != "" {
			ip, n, err := net.ParseCIDR(s.echoSubnet)
			if err != nil {
				t.Errorf("echoSubnet %q: %v", s.echoSubnet, err)
			} else {
				ones, _ := n.Mask.Size()
				addr, mask = ip.To4(), uint8(ones)
			}
		}
		if s.echoNetmask != 0 {
			mask = s.echoNetmask
		}
		m.SetEdns0(1232, false)
		if echo && addr != nil {
			opt := m.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1,
				SourceNetmask: mask,
				SourceScope:   scope,
				Address:       addr,
			})
		}
		_ = w.WriteMsg(m)
	})}

	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			t.Logf("ecs test dns server stopped: %v", err)
		}
	}()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// ecsPerSubnet gives each vantage point its own address, which is the shape of
// a genuinely steered zone.
func ecsPerSubnet(subnet string) []string {
	for i, v := range ecsVantages {
		if v.subnet == subnet {
			return []string{fmt.Sprintf("192.0.2.%d", i+1)}
		}
	}
	return []string{"192.0.2.99"}
}

// The load-bearing case: different answers AND a non-zero scope is the only
// combination that earns "answers-differ". The server here reports /17 for the
// /24 we sent, so the scope is one it chose rather than a copy of ours and
// ScopeDistinct must be set — that flag is what separates this from the
// Cloudflare shape where an echoed /24 accompanies a rotating pool.
func TestECSSteeredNeedsBothDifferentAnswersAndScope(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		return ecsPerSubnet(subnet), 17, true
	})
	got, err := newTestService().ecsRun(context.Background(), "steered.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictDiffers {
		t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictDiffers)
	}
	if got.MaxScope != 17 {
		t.Errorf("MaxScope = %d, want the scope the server reported (17)", got.MaxScope)
	}
	if got.Rotation {
		t.Error("Rotation set although no scope was 0: Rotation is the scope-0 shape")
	}
	if !got.ScopeDistinct {
		t.Error("ScopeDistinct not set although the server reported /17 for a /24 source: an echo and a chosen scope must not read alike")
	}
	for _, v := range got.Vantages {
		if v.SourceNetmask != ecsSourceNetmask {
			t.Errorf("%s: SourceNetmask = %d, want the %d it sent", v.Place, v.SourceNetmask, ecsSourceNetmask)
		}
	}
	if len(got.Groups) != len(ecsVantages) {
		t.Errorf("%d answer groups, want one per vantage point (%d)", len(got.Groups), len(ecsVantages))
	}
	if got.Answered != got.Asked || got.Asked != len(ecsVantages) {
		t.Errorf("answered %d of %d, want all %d vantage points", got.Answered, got.Asked, len(ecsVantages))
	}
	for _, g := range got.Groups {
		if len(g.Vantages) == 0 {
			t.Error("an answer group with no vantage points in it")
		}
	}
}

// The false verdict this feature exists to avoid: a zone rotating a pool
// returns different answers per query, and calling that geo steering is wrong.
// Scope 0 is the discriminator, so scope 0 must win over differing answers.
func TestECSRotationIsNotSteering(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		return ecsPerSubnet(subnet), 0, true
	})
	got, err := newTestService().ecsRun(context.Background(), "rotating.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictUntailored {
		t.Errorf("verdict = %q, want %q: every response said scope 0", got.Verdict, ECSVerdictUntailored)
	}
	if !got.Rotation {
		t.Error("Rotation not set: the answers differed while no answer was tailored")
	}
	if len(got.Groups) < 2 {
		t.Errorf("%d answer groups, want the differing answers to still be shown", len(got.Groups))
	}
}

// Scope 0 everywhere with one answer is the one case we can say "not steered"
// about with confidence, and it must not be confused with rotation.
func TestECSNotSteeredWhenNothingIsTailored(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, 0, true
	})
	got, err := newTestService().ecsRun(context.Background(), "flat.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictUntailored {
		t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictUntailored)
	}
	if got.Rotation {
		t.Error("Rotation set although every vantage point got the same answer")
	}
	if len(got.Groups) != 1 {
		t.Errorf("%d answer groups, want 1", len(got.Groups))
	}
}

// A non-zero scope with one answer everywhere is neither tailoring nor proof
// of its absence. The scope here EQUALS the prefix we sent, which is what a
// server that echoes the option unchanged returns, so ScopeDistinct must stay
// clear: the card may say "one answer set", never "the zone read the network".
func TestECSAwareWhenScopeIsReadButTheAnswerIsFlat(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, ecsSourceNetmask, true
	})
	got, err := newTestService().ecsRun(context.Background(), "aware.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictMatches {
		t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictMatches)
	}
	if got.MaxScope != ecsSourceNetmask {
		t.Errorf("MaxScope = %d, want %d", got.MaxScope, ecsSourceNetmask)
	}
	if got.ScopeDistinct {
		t.Error("ScopeDistinct set on a scope that merely repeats the length we sent")
	}
}

// The option stripped on the way back is "we could not tell", never "not
// steered" — the distinction the docs' design value turns on.
func TestECSUnsupportedWhenNoOptionComesBack(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, 0, false
	})
	got, err := newTestService().ecsRun(context.Background(), "stripped.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictUnsupported {
		t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictUnsupported)
	}
	if got.Echoed != 0 {
		t.Errorf("Echoed = %d, want 0: no response carried the option", got.Echoed)
	}
	for _, v := range got.Vantages {
		if v.Echoed {
			t.Errorf("%s reported an echoed option the server never sent", v.Place)
		}
	}
}

// Every vantage point in the table must actually reach the wire, as a /24, at
// the documented address. A silently dropped subnet would make the whole page
// six copies of one measurement.
func TestECSSendsEveryVantageSubnetAsA24(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	seen := map[string]bool{}
	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		mu.Lock()
		seen[subnet] = true
		mu.Unlock()
		return []string{"192.0.2.10"}, 0, true
	})
	if _, err := newTestService().ecsRun(context.Background(), "probe.test", "A", addr, "test"); err != nil {
		t.Fatalf("ecs run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, v := range ecsVantages {
		if !seen[v.subnet] {
			t.Errorf("vantage %s (%s) never reached the server; saw %v", v.place, v.subnet, seen)
		}
		if !strings.HasSuffix(v.subnet, fmt.Sprintf("/%d", ecsSourceNetmask)) {
			t.Errorf("vantage %s is %s, want a /%d", v.place, v.subnet, ecsSourceNetmask)
		}
	}
}

// A cancelled request must stop asking, and must say so per vantage point
// rather than leaving a blank row that summarise would count as an answer.
func TestECSStopsWhenTheRequestIsCancelled(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, 0, true
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := newTestService().ecsRun(ctx, "cancelled.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Answered != 0 {
		t.Errorf("Answered = %d on a cancelled request, want 0", got.Answered)
	}
	if got.Verdict != ECSVerdictInconclusive {
		t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictInconclusive)
	}
	for _, v := range got.Vantages {
		if v.Error == "" {
			t.Errorf("%s has no error although it was never asked", v.Place)
		}
	}
}

// The JSON a caller gets: snake_case keys, and slices that marshal as [] so a
// client can iterate without a null check. Checked on the worst case — a run
// where every vantage point was given nothing — because that is where a nil
// slice hides, and because that run must also reach the no-records verdict.
func TestECSMarshalsEmptySlicesAsArrays(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return nil, 0, true
	})
	got, err := newTestService().ecsRun(context.Background(), "empty.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	for _, want := range []string{
		`"groups":[{"values":[]`, // the empty answer set is a group, not a gap
		`"vantages":[`, `"max_scope"`, `"ecs_echoed"`, `"query_ms"`, `"resolver_addr"`,
		`"with_records":0`, `"verdict":"no-records"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("JSON is missing %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "null") {
		t.Errorf("JSON carries a null slice:\n%s", body)
	}
}

// The resolver is fixed and is NOT the package default, because the package
// default silently breaks this measurement. Guarding the key keeps a later
// "tidy-up" from pointing it back at Cloudflare, and keeps it a key rather
// than a second copy of a row of Resolvers.
func TestECSDoesNotUseTheCloudflareDefault(t *testing.T) {
	t.Parallel()

	if ecsResolverKey == DefaultResolver {
		t.Fatalf("the ECS resolver is the package default (%s), which never forwards client subnet", ecsResolverKey)
	}
	addr, ok := resolverAddr(ecsResolverKey)
	if !ok {
		t.Fatalf("ecsResolverKey %q is not in the Resolvers table, so ECS() cannot resolve an address", ecsResolverKey)
	}
	if addr != "8.8.8.8:53" {
		t.Errorf("%s resolves to %q, want a resolver documented to honour ECS", ecsResolverKey, addr)
	}
	if name := ResolverName(ecsResolverKey); name == ecsResolverKey {
		t.Errorf("ResolverName(%q) fell through to the key itself, so the card would name no resolver", ecsResolverKey)
	}
}

// The false NEGATIVE the empty-set skip used to produce: a name served in some
// regions and NODATA in others is textbook geo steering, and it must not be
// reported as "same answer everywhere". This is the case the card exists for.
func TestECSTreatsNoRecordsAsAnAnswerThatCanDiffer(t *testing.T) {
	t.Parallel()

	// The first three vantage points get a record, the last three get none.
	served := map[string]bool{}
	for _, v := range ecsVantages[:3] {
		served[v.subnet] = true
	}
	addr := ecsServer{reply: func(subnet string) ([]string, uint8, bool) {
		if served[subnet] {
			return []string{"192.0.2.10"}, ecsSourceNetmask, true
		}
		return nil, ecsSourceNetmask, true
	}}.start(t)

	got, err := newTestService().ecsRun(context.Background(), "regional.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictDiffers {
		t.Errorf("verdict = %q, want %q: three networks were given a record and three were given none, under a non-zero scope",
			got.Verdict, ECSVerdictDiffers)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("%d answer groups, want 2 (the record, and no record)", len(got.Groups))
	}
	var empty, full int
	for _, g := range got.Groups {
		if len(g.Values) == 0 {
			empty = len(g.Vantages)
		} else {
			full = len(g.Vantages)
		}
	}
	if empty != 3 || full != 3 {
		t.Errorf("groups split %d with records / %d without, want 3 and 3", full, empty)
	}
	if got.WithRecords != 3 {
		t.Errorf("WithRecords = %d, want 3", got.WithRecords)
	}
	// And the split is stated in words, not left for the reader to spot in
	// the table.
	if !hasNote(got.Notes, "warn", "were given no A record at all") {
		t.Errorf("no note about the networks that got nothing: %+v", got.Notes)
	}
}

// Same split, scope 0 everywhere. Scope still wins — the zone says its answer
// is not tailored — but the difference must still register as a difference.
func TestECSPartialRecordsStillDifferUnderScopeZero(t *testing.T) {
	t.Parallel()

	first := ecsVantages[0].subnet
	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		if subnet == first {
			return []string{"192.0.2.10"}, 0, true
		}
		return nil, 0, true
	})
	got, err := newTestService().ecsRun(context.Background(), "partial-flat.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictUntailored {
		t.Errorf("verdict = %q, want %q: every response reported scope 0", got.Verdict, ECSVerdictUntailored)
	}
	if !got.Rotation {
		t.Error("Rotation not set although one network got a record and the rest got none")
	}
	if len(got.Groups) != 2 {
		t.Errorf("%d answer groups, want 2", len(got.Groups))
	}
}

// Nothing anywhere is its own verdict. "Not steered / everyone gets the same
// records" is a sentence about records, and there are none.
func TestECSNoRecordsAnywhereIsNotAVerdictAboutRecords(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		why   string
		rcode int
		want  string
	}{
		{"NODATA: the name exists, this type does not", dns.RcodeSuccess, "NOERROR"},
		{"NXDOMAIN: the name does not exist at all", dns.RcodeNameError, "NXDOMAIN"},
	} {
		t.Run(c.why, func(t *testing.T) {
			t.Parallel()

			addr := ecsServer{rcode: c.rcode, reply: func(string) ([]string, uint8, bool) {
				return nil, 0, true
			}}.start(t)
			got, err := newTestService().ecsRun(context.Background(), "nothing.test", "A", addr, "test")
			if err != nil {
				t.Fatalf("ecs run: %v", err)
			}
			if got.Verdict != ECSVerdictNoRecords {
				t.Errorf("verdict = %q, want %q", got.Verdict, ECSVerdictNoRecords)
			}
			if got.Rcode != c.want {
				t.Errorf("Rcode = %q, want the unanimous %q so the card can say which kind of nothing", got.Rcode, c.want)
			}
			if got.WithRecords != 0 {
				t.Errorf("WithRecords = %d, want 0", got.WithRecords)
			}
			if got.Rotation {
				t.Error("Rotation set although no vantage point was given a record")
			}
			for _, n := range got.Notes {
				if strings.Contains(n.Text, "same records") {
					t.Errorf("a note claims something about records that do not exist: %q", n.Text)
				}
			}
		})
	}
}

// A scope for somebody else's prefix describes somebody else's traffic. It is
// shown, and it is kept out of the numbers the verdict is read from.
func TestECSIgnoresAScopeForAPrefixWeNeverSent(t *testing.T) {
	t.Parallel()

	addr := ecsServer{
		echoSubnet: "203.0.113.0/24",
		reply: func(string) ([]string, uint8, bool) {
			return []string{"192.0.2.10"}, 20, true
		},
	}.start(t)
	got, err := newTestService().ecsRun(context.Background(), "wrongprefix.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Verdict != ECSVerdictUnsupported {
		t.Errorf("verdict = %q, want %q: not one scope described a network we asked about", got.Verdict, ECSVerdictUnsupported)
	}
	if got.Echoed != 0 || got.MaxScope != 0 {
		t.Errorf("Echoed = %d, MaxScope = %d, want 0 and 0: every echo was for 203.0.113.0/24", got.Echoed, got.MaxScope)
	}
	if got.Mismatched != len(ecsVantages) {
		t.Errorf("Mismatched = %d, want all %d", got.Mismatched, len(ecsVantages))
	}
	for _, v := range got.Vantages {
		if !v.Mismatch {
			t.Errorf("%s: mismatch not flagged although the echo was %q, not %q", v.Place, v.EchoedSubnet, v.Subnet)
		}
		if v.EchoedSubnet != "203.0.113.0/24" {
			t.Errorf("%s: EchoedSubnet = %q, want the prefix the server actually echoed", v.Place, v.EchoedSubnet)
		}
	}
	if !hasNote(got.Notes, "warn", "a prefix we never sent") {
		t.Errorf("no note about the mismatched echoes: %+v", got.Notes)
	}
}

// The other shape of the same problem: our address, a length we did not send.
func TestECSIgnoresAScopeAtALengthWeNeverSent(t *testing.T) {
	t.Parallel()

	addr := ecsServer{
		echoNetmask: 16,
		reply: func(string) ([]string, uint8, bool) {
			return []string{"192.0.2.10"}, 16, true
		},
	}.start(t)
	got, err := newTestService().ecsRun(context.Background(), "wronglength.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Echoed != 0 || got.Mismatched != len(ecsVantages) {
		t.Errorf("Echoed = %d, Mismatched = %d: a /16 echo answers for 256 networks, only one of which we sent",
			got.Echoed, got.Mismatched)
	}
}

// An honest echo must NOT be flagged, or the verdict never fires in
// production. This is the guard on the two checks above.
func TestECSAcceptsTheEchoItActuallySent(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, ecsSourceNetmask, true
	})
	got, err := newTestService().ecsRun(context.Background(), "honest.test", "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	if got.Mismatched != 0 {
		t.Errorf("Mismatched = %d on a server echoing exactly what it was sent", got.Mismatched)
	}
	if got.Echoed != len(ecsVantages) {
		t.Errorf("Echoed = %d, want all %d", got.Echoed, len(ecsVantages))
	}
	for _, v := range got.Vantages {
		if v.EchoedSubnet != v.Subnet {
			t.Errorf("%s echoed %q, want %q", v.Place, v.EchoedSubnet, v.Subnet)
		}
	}
}

// notes() must not restate the verdict. Two copies of one sentence in two
// layers (here and templates/ecs.html) drift the first time either is edited,
// and the card renders both.
func TestECSNotesDoNotRestateTheVerdict(t *testing.T) {
	t.Parallel()

	// Phrases that belong to the template's verdict paragraph alone.
	banned := []string{
		"Everyone gets the same records",
		"the same records",
		"not tailored to the client",
		"rotating pool",
		"Fewer than two vantage points",
		"dropped between here and the zone",
	}
	for _, c := range []struct {
		why   string
		scope uint8
		echo  bool
		vals  func(string) []string
	}{
		{"answers-differ", ecsSourceNetmask, true, ecsPerSubnet},
		{"answers-match", ecsSourceNetmask, true, func(string) []string { return []string{"192.0.2.10"} }},
		{"untailored", 0, true, func(string) []string { return []string{"192.0.2.10"} }},
		{"rotation", 0, true, ecsPerSubnet},
		{"unsupported", 0, false, func(string) []string { return []string{"192.0.2.10"} }},
		{"no-records", 0, true, func(string) []string { return nil }},
	} {
		t.Run(c.why, func(t *testing.T) {
			t.Parallel()

			addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
				return c.vals(subnet), c.scope, c.echo
			})
			got, err := newTestService().ecsRun(context.Background(), "notes.test", "A", addr, "test")
			if err != nil {
				t.Fatalf("ecs run: %v", err)
			}
			for _, n := range got.Notes {
				for _, b := range banned {
					if strings.Contains(n.Text, b) {
						t.Errorf("verdict %q: a note repeats the template's verdict prose (%q): %q", got.Verdict, b, n.Text)
					}
				}
			}
		})
	}
}

// The whole table goes out in ONE wave. Sized below it, a resolver that
// accepts packets and never answers costs two ecsQueryTimeouts — 6s of a page
// that cannot render until this card is done — which is twice what the
// feature's own caveat promises.
func TestECSFansOutInASingleWave(t *testing.T) {
	t.Parallel()

	if ecsConcurrency < maxECSVantages || ecsConcurrency < len(ecsVantages) {
		t.Fatalf("ecsConcurrency = %d, want at least %d: a narrower limit multiplies the worst case by the number of waves",
			ecsConcurrency, max(maxECSVantages, len(ecsVantages)))
	}

	// Measured, not merely asserted: a socket that accepts and never replies.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	start := time.Now()
	got, err := NewService(30*time.Second).ecsRun(context.Background(), "blackhole.test", "A", pc.LocalAddr().String(), "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	elapsed := time.Since(start)
	// One timeout plus slack, and comfortably under two.
	if limit := ecsQueryTimeout + ecsQueryTimeout/2; elapsed > limit {
		t.Errorf("a dead resolver held the card for %v, want under %v (one ecsQueryTimeout)", elapsed, limit)
	}
	if got.Verdict != ECSVerdictInconclusive {
		t.Errorf("verdict = %q, want %q when nothing answered", got.Verdict, ECSVerdictInconclusive)
	}
	t.Logf("dead resolver: elapsed=%v query_ms=%d answered=%d verdict=%s", elapsed, got.QueryMS, got.Answered, got.Verdict)
}

// answerGroups is the grouping both this card and Spread's do. The property
// that matters, and that the inline copies did not have: an empty answer set
// is a group, and it comes back as an empty slice rather than [""].
func TestAnswerGroupsKeepsEmptySetsAsTheirOwnGroup(t *testing.T) {
	t.Parallel()

	values, members := answerGroups(
		[]string{"a", "b", "c", "d"},
		[][]string{{"1.2.3.4"}, {}, {"1.2.3.4"}, nil},
	)
	if len(values) != 2 {
		t.Fatalf("%d groups, want 2 (the record, and no record): %v", len(values), values)
	}
	if len(values[0]) != 1 || values[0][0] != "1.2.3.4" {
		t.Errorf("first group = %v, want the record set", values[0])
	}
	if len(values[1]) != 0 {
		t.Errorf("second group = %#v, want an empty set, not a one-element set of the empty string", values[1])
	}
	if strings.Join(members[0], ",") != "a,c" || strings.Join(members[1], ",") != "b,d" {
		t.Errorf("members = %v, want [a c] and [b d]", members)
	}
}
