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

// ecsServer answers by the client subnet the query carried; the other fields fake wrong echoes.
type ecsServer struct {
	// reply gets the query's "a.b.c.d/len" or ""; a missing echo must never read as scope 0.
	reply func(subnet string) (vals []string, scope uint8, echo bool)
	// echoSubnet is echoed whatever the query sent, like a cached answer for another network.
	echoSubnet string
	// echoNetmask overrides the echoed source length (default: the query's).
	echoNetmask uint8
	rcode       int
}

func ecsTestServer(t *testing.T, reply func(subnet string) (vals []string, scope uint8, echo bool)) string {
	t.Helper()
	return ecsServer{reply: reply}.start(t)
}

func (s ecsServer) start(t *testing.T) string {
	t.Helper()
	return startLoopbackDNS(t, func(w dns.ResponseWriter, req *dns.Msg) {
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
	})
}

// runECS runs the ECS card for an A query against the server at addr.
func runECS(t *testing.T, name, addr string) *ECS {
	t.Helper()
	got, err := newTestService().ecsRun(context.Background(), name, "A", addr, "test")
	if err != nil {
		t.Fatalf("ecs run: %v", err)
	}
	return got
}

// ecsPerSubnet gives each vantage point its own address, like a genuinely steered zone.
func ecsPerSubnet(subnet string) []string {
	for i, v := range ecsVantages {
		if v.subnet == subnet {
			return []string{fmt.Sprintf("192.0.2.%d", i+1)}
		}
	}
	return []string{"192.0.2.99"}
}

// /17 for our /24 is a scope the server chose, not an echo, so ScopeDistinct must be set.
func TestECSSteeredNeedsBothDifferentAnswersAndScope(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		return ecsPerSubnet(subnet), 17, true
	})
	got := runECS(t, "steered.test", addr)
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

// A rotating pool differs per query, so scope 0 must win over differing answers.
func TestECSRotationIsNotSteering(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		return ecsPerSubnet(subnet), 0, true
	})
	got := runECS(t, "rotating.test", addr)
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

func TestECSNotSteeredWhenNothingIsTailored(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, 0, true
	})
	got := runECS(t, "flat.test", addr)
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

// A scope equal to the prefix we sent is an unchanged echo, so ScopeDistinct must stay clear.
func TestECSAwareWhenScopeIsReadButTheAnswerIsFlat(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, ecsSourceNetmask, true
	})
	got := runECS(t, "aware.test", addr)
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

// A stripped option means "could not tell", never "not steered".
func TestECSUnsupportedWhenNoOptionComesBack(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, 0, false
	})
	got := runECS(t, "stripped.test", addr)
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
	runECS(t, "probe.test", addr)

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

// Each vantage must carry an error, or summarise would count a blank row as an answer.
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

// An all-empty run is where a nil slice would hide, and it must also reach no-records.
func TestECSMarshalsEmptySlicesAsArrays(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return nil, 0, true
	})
	got := runECS(t, "empty.test", addr)
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

// A record in some regions and NODATA in others is textbook geo steering.
func TestECSTreatsNoRecordsAsAnAnswerThatCanDiffer(t *testing.T) {
	t.Parallel()

	served := map[string]bool{}
	for _, v := range ecsVantages[:3] {
		served[v.subnet] = true
	}
	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		if served[subnet] {
			return []string{"192.0.2.10"}, ecsSourceNetmask, true
		}
		return nil, ecsSourceNetmask, true
	})

	got := runECS(t, "regional.test", addr)
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
	if !hasNote(got.Notes, "warn", "were given no A record at all") {
		t.Errorf("no note about the networks that got nothing: %+v", got.Notes)
	}
}

// Scope 0 still wins, but a record for one network and none for the rest is still a difference.
func TestECSPartialRecordsStillDifferUnderScopeZero(t *testing.T) {
	t.Parallel()

	first := ecsVantages[0].subnet
	addr := ecsTestServer(t, func(subnet string) ([]string, uint8, bool) {
		if subnet == first {
			return []string{"192.0.2.10"}, 0, true
		}
		return nil, 0, true
	})
	got := runECS(t, "partial-flat.test", addr)
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
			got := runECS(t, "nothing.test", addr)
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

// An echo for somebody else's prefix is shown but kept out of the verdict's numbers.
func TestECSIgnoresAScopeForAPrefixWeNeverSent(t *testing.T) {
	t.Parallel()

	addr := ecsServer{
		echoSubnet: "203.0.113.0/24",
		reply: func(string) ([]string, uint8, bool) {
			return []string{"192.0.2.10"}, 20, true
		},
	}.start(t)
	got := runECS(t, "wrongprefix.test", addr)
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

// Our address, but a length we did not send.
func TestECSIgnoresAScopeAtALengthWeNeverSent(t *testing.T) {
	t.Parallel()

	addr := ecsServer{
		echoNetmask: 16,
		reply: func(string) ([]string, uint8, bool) {
			return []string{"192.0.2.10"}, 16, true
		},
	}.start(t)
	got := runECS(t, "wronglength.test", addr)
	if got.Echoed != 0 || got.Mismatched != len(ecsVantages) {
		t.Errorf("Echoed = %d, Mismatched = %d: a /16 echo answers for 256 networks, only one of which we sent",
			got.Echoed, got.Mismatched)
	}
}

// Guards the two checks above: an honest echo must not be flagged.
func TestECSAcceptsTheEchoItActuallySent(t *testing.T) {
	t.Parallel()

	addr := ecsTestServer(t, func(string) ([]string, uint8, bool) {
		return []string{"192.0.2.10"}, ecsSourceNetmask, true
	})
	got := runECS(t, "honest.test", addr)
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

// The verdict sentence lives in templates/ecs.html; a copy in notes() would drift.
func TestECSNotesDoNotRestateTheVerdict(t *testing.T) {
	t.Parallel()

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
			got := runECS(t, "notes.test", addr)
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

// Each extra wave adds a full timeout when the resolver never answers.
func TestECSFansOutInASingleWave(t *testing.T) {
	t.Parallel()

	if ecsConcurrency < maxECSVantages || ecsConcurrency < len(ecsVantages) {
		t.Fatalf("ecsConcurrency = %d, want at least %d: a narrower limit multiplies the worst case by the number of waves",
			ecsConcurrency, max(maxECSVantages, len(ecsVantages)))
	}

	// A socket that accepts and never replies.
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
	if limit := ecsQueryTimeout + ecsQueryTimeout/2; elapsed > limit {
		t.Errorf("a dead resolver held the card for %v, want under %v (one ecsQueryTimeout)", elapsed, limit)
	}
	if got.Verdict != ECSVerdictInconclusive {
		t.Errorf("verdict = %q, want %q when nothing answered", got.Verdict, ECSVerdictInconclusive)
	}
	t.Logf("dead resolver: elapsed=%v query_ms=%d answered=%d verdict=%s", elapsed, got.QueryMS, got.Answered, got.Verdict)
}

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
