package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// uncheckedLinks names the zones whose link the walk could not establish
// either way, with the reason it gives.
//
// This is the shape upstream trouble takes here. A lost DNSKEY packet used to
// surface as "bogus", which failed these tests loudly and told visitors their
// domain was broken; it is now "indeterminate", which is honest and is also
// nothing to assert against. A test that read a chain in that state would
// fail on the network's bad days, and the push gate runs these.
func uncheckedLinks(tr *dnstools.Trace) []string {
	var out []string
	for _, l := range tr.Chain {
		if l.Status == "indeterminate" {
			out = append(out, l.Zone+": "+l.Detail)
		}
	}
	return out
}

// uncheckedAbove is the same thing for a test whose whole subject is the
// verdict on ONE zone: it reports the links the walk could not read on the way
// down, and says nothing about the zone under test.
//
// The distinction matters because a skip is also how a regression hides. A
// validator that answered "could not tell" to everything would walk straight
// through every uncheckedLinks() skip in this file and out the other side with
// a green run — including the one test that proves the verification is real at
// all. So the zones above are allowed to be unreadable (the root and most TLD
// DNSKEY sets are large enough that a blocked TCP retry is routine); the zone
// being judged is not.
func uncheckedAbove(tr *dnstools.Trace, zone string) []string {
	var out []string
	for _, l := range tr.Chain {
		if l.Status == "indeterminate" && !strings.EqualFold(l.Zone, zone) {
			out = append(out, l.Zone+": "+l.Detail)
		}
	}
	return out
}

// Live tests here deliberately do NOT call t.Parallel(). The whole suite
// queries the same handful of public servers, and running these concurrently
// got the box rate-limited into random timeouts — a flaky deploy gate caused
// by our own test concurrency rather than by the code (commit 40c39db).
// These walk root and TLD servers, which are even less forgiving.

// The walk has to actually start at the root and descend, one zone cut at a
// time, ending on a server that sets the authoritative bit. That is the whole
// feature: anything that quietly asks a resolver instead would still return
// records and would still look right.
func TestTraceWalksFromTheRootToTheAuthoritativeZone(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if len(tr.Hops) == 0 {
		t.Fatal("the walk produced no hops at all")
	}
	if tr.Hops[0].Zone != "." {
		t.Errorf("first hop asked %q, want the root — a walk that starts anywhere else is not a trace", tr.Hops[0].Zone)
	}
	if tr.RootServer == "" || !strings.HasSuffix(tr.RootServer, "root-servers.net") {
		t.Errorf("RootServer = %q, want a named root server", tr.RootServer)
	}
	last := tr.Hops[len(tr.Hops)-1]
	if last.Error != "" {
		t.Skipf("the walk did not complete (%s) — upstream trouble, not a code failure", last.Error)
	}
	if !last.Authoritative {
		t.Errorf("the walk ended on a non-authoritative answer from %q; it should stop only on AA=1", last.Server)
	}
	if tr.AnswerZone != "cloudflare.com." {
		t.Errorf("AnswerZone = %q, want cloudflare.com.", tr.AnswerZone)
	}
	if len(tr.Answer) == 0 {
		t.Error("the authoritative zone returned no A records")
	}

	// Every hop is accounted for: the zone cut, who was asked, and how long it
	// took. A blank row would mean the ladder is lying about what it measured.
	for i, h := range tr.Hops {
		if h.Zone == "" {
			t.Errorf("hop %d has no zone", i)
		}
		if h.Error == "" && h.Server == "" {
			t.Errorf("hop %d (%s) reports neither a server nor an error", i, h.Zone)
		}
		if h.Error == "" && h.ServerIP == "" {
			t.Errorf("hop %d (%s) named a server but not its address", i, h.Zone)
		}
	}
	// The referral chain has to be a chain: each hop's referral is the next
	// hop's zone.
	for i := 0; i+1 < len(tr.Hops); i++ {
		if tr.Hops[i].Referral != tr.Hops[i+1].Zone {
			t.Errorf("hop %d delegated %q but hop %d asked %q", i, tr.Hops[i].Referral, i+1, tr.Hops[i+1].Zone)
		}
	}
}

// The headline claim: the chain of trust is checked HERE, from the hardcoded
// root anchors down, not read off a resolver's AD bit. cloudflare.com is
// signed, so every link must come back secure and the records themselves must
// verify.
func TestTraceVerifiesASignedChainItself(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if tr.Truncated || tr.AnswerZone == "" {
		t.Skip("the walk did not finish — upstream trouble, not a code failure")
	}
	if bad := uncheckedLinks(tr); len(bad) > 0 {
		t.Skipf("a link of the chain could not be checked from here (%s) — upstream trouble, not a code failure", strings.Join(bad, "; "))
	}
	if tr.DNSSEC != "secure" {
		t.Fatalf("DNSSEC = %q for a signed zone, want secure. Chain: %+v", tr.DNSSEC, tr.Chain)
	}
	if len(tr.Chain) < 3 {
		t.Fatalf("chain has %d links, want one each for the root, com. and the zone", len(tr.Chain))
	}
	if tr.Chain[0].Zone != "." {
		t.Errorf("first link is for %q, want the root", tr.Chain[0].Zone)
	}
	for _, l := range tr.Chain {
		if l.Status != "secure" {
			t.Errorf("link %s (parent %s) = %s: %s", l.Zone, l.Parent, l.Status, l.Detail)
			continue
		}
		if l.MatchedTag == 0 {
			t.Errorf("link %s is secure but names no key, so nothing says what it rests on", l.Zone)
		}
		if l.Algorithm == "" {
			t.Errorf("link %s is secure but names no algorithm", l.Zone)
		}
		if len(l.DSKeyTags) == 0 || len(l.KeyTags) == 0 {
			t.Errorf("link %s is secure with DS %v and DNSKEY %v; both must be non-empty", l.Zone, l.DSKeyTags, l.KeyTags)
		}
	}
	if !tr.AnswerSigned {
		t.Error("a signed zone's answer arrived without an RRSIG")
	}
	if !tr.AnswerVerified {
		t.Error("the answer's signature did not verify, so the chain was proved and the data was not")
	}
}

// dnssec-failed.org exists for exactly this: the parent publishes a DS and the
// zone's keys do not match it. A validator that only ever sees healthy zones
// would pass every other test in this file while being a no-op, so this is the
// one that proves the verification is real.
func TestTraceCallsABrokenChainBogus(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "dnssec-failed.org", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if tr.Truncated || tr.AnswerZone == "" {
		t.Skip("the walk did not finish — upstream trouble, not a code failure")
	}
	// Above the zone only. dnssec-failed.org.'s own link is the subject: if
	// THAT came back unreadable there is nothing upstream to blame — its key
	// set is two RSA keys and arrives in one packet — and turning it into a
	// skip would let the one test that proves this verifier is not a no-op
	// pass by never running.
	if bad := uncheckedAbove(tr, "dnssec-failed.org."); len(bad) > 0 {
		t.Skipf("a link above the zone could not be checked from here (%s) — upstream trouble, not a code failure", strings.Join(bad, "; "))
	}
	if tr.DNSSEC != "bogus" {
		t.Fatalf("DNSSEC = %q for a deliberately-broken zone, want bogus. Chain: %+v", tr.DNSSEC, tr.Chain)
	}

	// The break has to be reported at the zone that broke, not smeared over
	// the whole walk: the root and the TLD above it are fine.
	var broken []string
	for _, l := range tr.Chain {
		if l.Status == "bogus" {
			broken = append(broken, l.Zone)
		}
	}
	if len(broken) != 1 || broken[0] != "dnssec-failed.org." {
		t.Errorf("bogus links = %v, want only dnssec-failed.org.", broken)
	}
	if tr.Chain[0].Status != "secure" {
		t.Errorf("the root link is %q; one broken zone must not discredit the anchor above it", tr.Chain[0].Status)
	}
	// And it has to be a failure in the verdict, not a footnote. The verdict
	// is written once, in Verdict, and the page renders that; a "fail" note
	// somewhere further down the page is not the same thing.
	if tr.Verdict.Level != "fail" {
		t.Errorf("a broken chain gave a %q-level verdict: %q", tr.Verdict.Level, tr.Verdict.Text)
	}
}

// The walk must not stop at the first AA=1 without asking WHICH zone answered.
// A parent and its child sharing nameservers is ordinary — every registry
// operator that runs zones under its own TLD does it — and then the parent's
// server answers the child's name directly. Validating the child's records
// under the parent's keys cannot succeed, and the walk used to print "bogus"
// plus "validating resolvers will treat this name as bogus and answer
// SERVFAIL" for www.nic.cz, which validates correctly everywhere.
func TestTraceCrossesAZoneCutTheDelegationNeverAnnounced(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "www.nic.cz", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if tr.Truncated || tr.AnswerZone == "" {
		t.Skip("the walk did not finish — upstream trouble, not a code failure")
	}
	if tr.DNSSEC == "bogus" {
		t.Fatalf("a correctly signed name was reported bogus: %q. Chain: %+v", tr.Verdict.Text, tr.Chain)
	}
	if bad := uncheckedLinks(tr); len(bad) > 0 {
		t.Skipf("a link of the chain could not be checked from here (%s) — upstream trouble, not a code failure", strings.Join(bad, "; "))
	}
	if tr.DNSSEC != "secure" {
		t.Fatalf("DNSSEC = %q, want secure. Chain: %+v", tr.DNSSEC, tr.Chain)
	}
	// cz.'s servers answer for nic.cz too, so the ladder stops at cz. while
	// the answer belongs to nic.cz. Both facts have to be on the page.
	if tr.AnswerZone != "nic.cz." {
		t.Errorf("AnswerZone = %q, want nic.cz. — the zone that actually owns the answer", tr.AnswerZone)
	}
	last := tr.Hops[len(tr.Hops)-1]
	if last.ZoneCut != "nic.cz." {
		t.Errorf("the answering rung asked %q and reports ZoneCut %q, want nic.cz. named", last.Zone, last.ZoneCut)
	}
	// The chain has to gain the link for the zone it crossed into, or the
	// answer was verified under keys nothing vouched for.
	if l := tr.Chain[len(tr.Chain)-1]; l.Zone != "nic.cz." || l.Status != "secure" {
		t.Errorf("last chain link = %s (%s), want a secure link for nic.cz.", l.Zone, l.Status)
	}
	if !tr.AnswerVerified {
		t.Error("the answer's own signature did not verify under the zone that made it")
	}
}

// An empty answer is not a proved absence. NXDOMAIN and NODATA are proved by
// NSEC or NSEC3 records this walk does not read, so a green "the chain checks
// out" over them is a cryptographic claim with no cryptography behind it.
func TestTraceWillNotCallAnUnprovenAbsenceSecure(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	for _, name := range []string{"nosuchname-zzz.example", "ns.nic.cz"} {
		tr, err := svc.Trace(context.Background(), name, "A")
		if err != nil {
			t.Fatalf("trace %s: %v", name, err)
		}
		if tr.Truncated || tr.AnswerZone == "" {
			t.Skipf("%s: the walk did not finish — upstream trouble, not a code failure", name)
		}
		if len(tr.Answer) != 0 || tr.CNAME != "" {
			t.Skipf("%s now has records, so there is no absence here to check", name)
		}
		// This holds however the walk went: an absence this walk never proved
		// must never come back as "secure".
		if tr.DNSSEC == "secure" {
			t.Errorf("%s: DNSSEC = secure on zero denial-of-existence evidence", name)
		}
		if tr.Verdict.Level == "ok" {
			t.Errorf("%s: the verdict is level ok, which the page paints green: %q", name, tr.Verdict.Text)
		}
		// The NSEC caveat is the verdict for a walk whose chain DID verify.
		// When a link could not be checked the verdict is about that link
		// instead, which is the right answer to a different question — and
		// happens for real when a root or TLD server declines to answer.
		if !chainAllSecure(tr) {
			t.Logf("%s: a chain link was not secure, so the verdict is about the chain: %q", name, tr.Verdict.Text)
			continue
		}
		if !strings.Contains(tr.Verdict.Text, "NSEC") {
			t.Errorf("%s: the verdict does not carry the caveat: %q", name, tr.Verdict.Text)
		}
	}
}

// Most names are unsigned, and an unsigned name must read as ordinary. This is
// the tone requirement, and it is as load-bearing as the crypto: reporting the
// normal state of the internet as a failure trains people to ignore the page.
func TestTraceTreatsAnUnsignedZoneAsNormalRatherThanBroken(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	// github.com publishes no DS today. If that changes this test has nothing
	// to say, so it skips rather than failing on somebody else's zone change.
	tr, err := svc.Trace(context.Background(), "github.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if tr.Truncated || tr.AnswerZone == "" {
		t.Skip("the walk did not finish — upstream trouble, not a code failure")
	}
	if bad := uncheckedLinks(tr); len(bad) > 0 {
		t.Skipf("a link of the chain could not be checked from here (%s) — upstream trouble, not a code failure", strings.Join(bad, "; "))
	}
	if tr.DNSSEC != "insecure" {
		t.Skipf("github.com now reports %q, so there is no unsigned zone here to check the tone of", tr.DNSSEC)
	}

	if tr.Verdict.Level != "info" {
		t.Errorf("an unsigned name got a %q-level verdict; unsigned is normal, not a fault: %q", tr.Verdict.Level, tr.Verdict.Text)
	}
	if tr.Verdict.Text == "" {
		t.Error("an unsigned name produced no explanation at all")
	}
	if hasNote(tr, "fail") {
		t.Errorf("an unsigned name produced a fail-level finding: %+v", tr.Notes)
	}
	// The unsigned cut is the zone's own, and everything above it still
	// verified. Reporting the root or the TLD as unsigned would be wrong.
	if tr.Chain[0].Status != "secure" {
		t.Errorf("the root link is %q even though the root is signed", tr.Chain[0].Status)
	}
	last := tr.Chain[len(tr.Chain)-1]
	if last.Status != "insecure" {
		t.Errorf("the last link is %q, want the unsigned cut to be the one reported", last.Status)
	}
	if !strings.Contains(strings.ToLower(last.Detail), "most names are") {
		t.Errorf("the unsigned link reads %q; it should say plainly that this is the common case", last.Detail)
	}
}

// This is a public endpoint and every hop is a packet at somebody else's
// nameserver, so one request has a hard ceiling on what it can cost.
func TestTraceStaysInsideItsQueryBudget(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	// A deliberately deep name: the walk pays per zone cut, so this is the
	// shape that would run away without a ceiling.
	tr, err := svc.Trace(context.Background(), "a.b.c.d.e.example.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	if tr.Queries == 0 {
		t.Error("the walk reports no queries at all")
	}
	if tr.Queries > 48 {
		t.Errorf("one walk sent %d queries; the documented ceiling is 48", tr.Queries)
	}
	if len(tr.Hops) > 12 {
		t.Errorf("the walk took %d hops, past its depth ceiling of 12", len(tr.Hops))
	}
}

// A visitor who navigates away must not leave a walk running against the root
// servers, and the half-finished result must not be dressed up as a verdict.
func TestTraceStopsWhenTheRequestIsCancelled(t *testing.T) {
	svc := dnstools.NewService(6 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	tr, err := svc.Trace(ctx, "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("a cancelled walk should still return what it has, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a cancelled walk took %s to give up", elapsed)
	}
	if !tr.Truncated {
		t.Error("a cancelled walk is not marked truncated, so the page would present it as complete")
	}
	if tr.DNSSEC == "secure" {
		t.Error("a cancelled walk reported a secure chain it never checked")
	}
	if tr.Verdict.Level != "warn" || !strings.Contains(tr.Verdict.Text, "did not finish") {
		t.Errorf("a cancelled walk should say it did not finish, got [%s] %q", tr.Verdict.Level, tr.Verdict.Text)
	}
}

// One walk cannot hold a goroutine indefinitely. The query budget bounds how
// many questions it asks; only a clock bounds how long the slowest answer to
// each of them may take, and 48 queries at 5s each — doubled by the TCP retry
// a truncated DNSKEY set forces — is minutes per HTTP request with nothing
// else in the stack to stop it.
func TestTraceHasItsOwnDeadline(t *testing.T) {
	requireEgress(t)
	// A per-query timeout far larger than the walk's own ceiling: without a
	// walk-level deadline this would run for as long as the upstreams want.
	svc := dnstools.NewService(90 * time.Second)

	start := time.Now()
	tr, err := svc.Trace(context.Background(), "a.b.c.d.e.example.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	// 20s ceiling plus room for the in-flight query to unwind and for a slow
	// CI box; the point is "bounded", not "bounded to the millisecond".
	if elapsed := time.Since(start); elapsed > 40*time.Second {
		t.Errorf("one walk took %s; it must stop at its own deadline", elapsed)
	}
	if tr.QueryMS > 40_000 {
		t.Errorf("the walk reports %d ms, past any deadline it claims to keep", tr.QueryMS)
	}
}

// Same contract as every other route here: the domain struct is the JSON body,
// and a slice with nothing in it marshals as [] rather than null, so a client
// can iterate without a nil check.
func TestTraceMarshalsEmptySlicesAsArrays(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tr, err := svc.Trace(ctx, "example.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"hops":[]`, `"chain":[]`, `"answer":[]`, `"verdict":{`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON is missing %s — an empty slice must not marshal as null:\n%s", want, b)
		}
	}
}

func TestTraceRejectsBadInput(t *testing.T) {
	t.Parallel()
	svc := dnstools.NewService(2 * time.Second)
	ctx := context.Background()

	if _, err := svc.Trace(ctx, "", "A"); err != dnstools.ErrEmptyName {
		t.Errorf("empty name: got %v, want ErrEmptyName", err)
	}
	if _, err := svc.Trace(ctx, "   ", "A"); err != dnstools.ErrEmptyName {
		t.Errorf("blank name: got %v, want ErrEmptyName", err)
	}
	// ANY and AXFR parse but must never leave this box at a third party's
	// nameserver, which is what the walk aims at.
	for _, bad := range []string{"NOTATYPE", "ANY", "AXFR"} {
		if _, err := svc.Trace(ctx, "example.com", bad); err == nil {
			t.Errorf("type %q was accepted", bad)
		}
	}
	// An IP has a delegation, but not the one this page explains.
	if _, err := svc.Trace(ctx, "1.1.1.1", "A"); err == nil {
		t.Error("an IP literal should be refused")
	}
	if _, err := svc.Trace(ctx, "not a domain!", "A"); err == nil {
		t.Error("a malformed name should be refused before it costs a query")
	}
	// A blank type is the A default, not an error. Asked on a dead context so
	// this stays what it claims to be: validation only. With a live context
	// this line walked the root servers — inside a t.Parallel() test, which is
	// the concurrency this file's header says caused commit 40c39db's flake —
	// and its `err != nil &&` guard made the assertion vacuous besides.
	dead, stop := context.WithCancel(context.Background())
	stop()
	if _, err := svc.Trace(dead, "example.com", ""); err != nil {
		t.Errorf("a blank type should default to A, got %v", err)
	}
}

// chainAllSecure reports whether every link of the chain verified. Live tests
// that want to assert something about the ANSWER have to know the chain got
// that far: a root or TLD server that declines one query turns the verdict
// into a statement about that link instead, correctly.
func chainAllSecure(tr *dnstools.Trace) bool {
	if len(tr.Chain) == 0 {
		return false
	}
	for _, l := range tr.Chain {
		if l.Status != "secure" {
			return false
		}
	}
	return true
}

// hasNote reports whether the trace produced a finding at this severity.
func hasNote(tr *dnstools.Trace, level string) bool {
	for _, n := range tr.Notes {
		if n.Level == level {
			return true
		}
	}
	return false
}

// The guard on every skip in this file.
//
// Each live test above steps aside when a link of its chain came back
// unreadable, which is right on its own terms: the root and TLD DNSKEY sets
// are large, a blocked TCP retry is routine, and a lost packet must not read
// as a blocked deploy. Taken together those skips are also a blind spot. A
// verifier that regressed into answering "could not tell" to everything — the
// opposite failure from the one this file's last fix was about, and just as
// useless — would satisfy every one of them and finish the run green.
//
// So this test asserts the property those skips cannot: the walk still reaches
// "secure" SOMEWHERE. Five names, five separate sets of nameservers, five
// registries. Upstream trouble takes one of them out at a time; nothing short
// of a broken verifier takes out all five at once.
func TestTraceStillProvesASignedNameSecure(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	// Signed, and long-lived enough to pin a test to: the registry that runs
	// the root zone's own TLD, IANA, two DNS operators and the IETF.
	signed := []string{"cloudflare.com", "iana.org", "verisign.com", "nlnetlabs.nl", "ietf.org"}

	var why []string
	for _, name := range signed {
		tr, err := svc.Trace(context.Background(), name, "A")
		switch {
		case err != nil:
			why = append(why, name+": "+err.Error())
			continue
		case tr.DNSSEC == "secure":
			// One is enough. The verifier is demonstrably still capable of a
			// positive verdict, so the skips above are skips and not cover.
			return
		case tr.DNSSEC == "bogus":
			// Not a flake in any direction: these names validate everywhere.
			t.Fatalf("%s was reported bogus: %q. Chain: %+v", name, tr.Verdict.Text, tr.Chain)
		}
		why = append(why, name+": "+tr.DNSSEC+" ("+strings.Join(uncheckedLinks(tr), "; ")+")")
	}
	t.Fatalf("not one of these %d signed names verified end to end: %s. A lost packet does that to one name at a time, not to all of them at once — and this is exactly the state in which every other live trace test in this file skips rather than fails.",
		len(signed), strings.Join(why, " | "))
}
