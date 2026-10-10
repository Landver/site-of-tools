package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// uncheckedLinks lists the links the walk could not establish either way, other than except's.
func uncheckedLinks(tr *dnstools.Trace, except string) []string {
	var out []string
	for _, l := range tr.Chain {
		if l.Status == "indeterminate" && (except == "" || !strings.EqualFold(l.Zone, except)) {
			out = append(out, l.Zone+": "+l.Detail)
		}
	}
	return out
}

func skipIfUnfinished(t *testing.T, tr *dnstools.Trace) {
	t.Helper()
	if tr.Truncated || tr.AnswerZone == "" {
		t.Skip("the walk did not finish — upstream trouble, not a code failure")
	}
}

// skipIfUnchecked skips on an unreadable link: a lost DNSKEY packet is "indeterminate", not a bug.
func skipIfUnchecked(t *testing.T, tr *dnstools.Trace, except string) {
	t.Helper()
	if bad := uncheckedLinks(tr, except); len(bad) > 0 {
		t.Skipf("a link of the chain could not be checked from here (%s) — upstream trouble, not a code failure", strings.Join(bad, "; "))
	}
}

// Live tests here never call t.Parallel(): concurrent walks got the box rate-limited into timeouts.

// The walk starts at the root and descends one zone cut at a time to a server setting AA=1.
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

	// A blank row would mean the ladder is lying about what it measured.
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
	// Each hop's referral is the next hop's zone.
	for i := 0; i+1 < len(tr.Hops); i++ {
		if tr.Hops[i].Referral != tr.Hops[i+1].Zone {
			t.Errorf("hop %d delegated %q but hop %d asked %q", i, tr.Hops[i].Referral, i+1, tr.Hops[i+1].Zone)
		}
	}
}

// The chain of trust is checked here from the root anchors down, not read off a resolver's AD bit.
func TestTraceVerifiesASignedChainItself(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "cloudflare.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	skipIfUnfinished(t, tr)
	skipIfUnchecked(t, tr, "")
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

// dnssec-failed.org's keys don't match its DS: the one test proving the verifier is not a no-op.
func TestTraceCallsABrokenChainBogus(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "dnssec-failed.org", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	skipIfUnfinished(t, tr)
	// Its own link fits in one packet, so only the links above it may excuse a skip.
	skipIfUnchecked(t, tr, "dnssec-failed.org.")
	if tr.DNSSEC != "bogus" {
		t.Fatalf("DNSSEC = %q for a deliberately-broken zone, want bogus. Chain: %+v", tr.DNSSEC, tr.Chain)
	}

	// The break is reported at the zone that broke, not smeared over the root and TLD.
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
	// A failure in the verdict the page renders, not a fail note further down.
	if tr.Verdict.Level != "fail" {
		t.Errorf("a broken chain gave a %q-level verdict: %q", tr.Verdict.Level, tr.Verdict.Text)
	}
}

// A parent sharing nameservers with its child answers the child's name directly, so the
// walk must ask which zone answered: www.nic.cz validates everywhere.
func TestTraceCrossesAZoneCutTheDelegationNeverAnnounced(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	tr, err := svc.Trace(context.Background(), "www.nic.cz", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	skipIfUnfinished(t, tr)
	if tr.DNSSEC == "bogus" {
		t.Fatalf("a correctly signed name was reported bogus: %q. Chain: %+v", tr.Verdict.Text, tr.Chain)
	}
	skipIfUnchecked(t, tr, "")
	if tr.DNSSEC != "secure" {
		t.Fatalf("DNSSEC = %q, want secure. Chain: %+v", tr.DNSSEC, tr.Chain)
	}
	// cz.'s servers answer for nic.cz too: the ladder stops at cz., the answer is nic.cz.'s.
	if tr.AnswerZone != "nic.cz." {
		t.Errorf("AnswerZone = %q, want nic.cz. — the zone that actually owns the answer", tr.AnswerZone)
	}
	last := tr.Hops[len(tr.Hops)-1]
	if last.ZoneCut != "nic.cz." {
		t.Errorf("the answering rung asked %q and reports ZoneCut %q, want nic.cz. named", last.Zone, last.ZoneCut)
	}
	// Without a link for the zone crossed into, the answer rests on keys nothing vouched for.
	if l := tr.Chain[len(tr.Chain)-1]; l.Zone != "nic.cz." || l.Status != "secure" {
		t.Errorf("last chain link = %s (%s), want a secure link for nic.cz.", l.Zone, l.Status)
	}
	if !tr.AnswerVerified {
		t.Error("the answer's own signature did not verify under the zone that made it")
	}
}

// NXDOMAIN and NODATA are proved by NSEC(3), which this walk doesn't read: never "secure".
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
		if tr.DNSSEC == "secure" {
			t.Errorf("%s: DNSSEC = secure on zero denial-of-existence evidence", name)
		}
		if tr.Verdict.Level == "ok" {
			t.Errorf("%s: the verdict is level ok, which the page paints green: %q", name, tr.Verdict.Text)
		}
		// The NSEC caveat needs a verified chain; otherwise the verdict is about the bad link.
		if !chainAllSecure(tr) {
			t.Logf("%s: a chain link was not secure, so the verdict is about the chain: %q", name, tr.Verdict.Text)
			continue
		}
		if !strings.Contains(tr.Verdict.Text, "NSEC") {
			t.Errorf("%s: the verdict does not carry the caveat: %q", name, tr.Verdict.Text)
		}
	}
}

// Most names are unsigned, so unsigned must read as ordinary, not as a failure.
func TestTraceTreatsAnUnsignedZoneAsNormalRatherThanBroken(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	// github.com publishes no DS today; if that changes, this skips.
	tr, err := svc.Trace(context.Background(), "github.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	skipIfUnfinished(t, tr)
	skipIfUnchecked(t, tr, "")
	if tr.DNSSEC != "insecure" {
		t.Skipf("github.com now reports %q, so there is no unsigned zone here to check the tone of", tr.DNSSEC)
	}

	if tr.Verdict.Level != "info" {
		t.Errorf("an unsigned name got a %q-level verdict; unsigned is normal, not a fault: %q", tr.Verdict.Level, tr.Verdict.Text)
	}
	if tr.Verdict.Text == "" {
		t.Error("an unsigned name produced no explanation at all")
	}
	if len(notesAt(tr.Notes, "fail")) > 0 {
		t.Errorf("an unsigned name produced a fail-level finding: %+v", tr.Notes)
	}
	// The unsigned cut is the zone's own; the root and TLD above it still verified.
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

// Every hop is a packet at somebody else's nameserver, so one request has a hard ceiling.
func TestTraceStaysInsideItsQueryBudget(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	// Deep on purpose: the walk pays per zone cut.
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

// A cancelled walk stops, and its half result is not dressed up as a verdict.
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

// Only a clock bounds slow answers: 48 queries at 5s, doubled by TCP retries, is minutes.
func TestTraceHasItsOwnDeadline(t *testing.T) {
	requireEgress(t)
	// A per-query timeout far past the walk's own ceiling.
	svc := dnstools.NewService(90 * time.Second)

	start := time.Now()
	tr, err := svc.Trace(context.Background(), "a.b.c.d.e.example.com", "A")
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	// The 20s ceiling plus room to unwind on a slow CI box.
	if elapsed := time.Since(start); elapsed > 40*time.Second {
		t.Errorf("one walk took %s; it must stop at its own deadline", elapsed)
	}
	if tr.QueryMS > 40_000 {
		t.Errorf("the walk reports %d ms, past any deadline it claims to keep", tr.QueryMS)
	}
}

// An empty slice marshals as [], not null, so a client can iterate without a nil check.
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
	// ANY and AXFR parse, but must never be aimed at a third party's nameserver.
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
	// A blank type defaults to A; the dead context keeps this validation-only.
	dead, stop := context.WithCancel(context.Background())
	stop()
	if _, err := svc.Trace(dead, "example.com", ""); err != nil {
		t.Errorf("a blank type should default to A, got %v", err)
	}
}

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

// Guards every skip above: a verifier answering "could not tell" to everything would pass them all.
// Packet loss takes out one of five separate registries at a time, never all five.
func TestTraceStillProvesASignedNameSecure(t *testing.T) {
	requireEgress(t)
	svc := dnstools.NewService(6 * time.Second)

	signed := []string{"cloudflare.com", "iana.org", "verisign.com", "nlnetlabs.nl", "ietf.org"}

	var why []string
	for _, name := range signed {
		tr, err := svc.Trace(context.Background(), name, "A")
		switch {
		case err != nil:
			why = append(why, name+": "+err.Error())
			continue
		case tr.DNSSEC == "secure":
			return // one is enough: the verifier can still reach a positive verdict
		case tr.DNSSEC == "bogus":
			// Not a flake in any direction: these names validate everywhere.
			t.Fatalf("%s was reported bogus: %q. Chain: %+v", name, tr.Verdict.Text, tr.Chain)
		}
		why = append(why, name+": "+tr.DNSSEC+" ("+strings.Join(uncheckedLinks(tr, ""), "; ")+")")
	}
	t.Fatalf("not one of these %d signed names verified end to end: %s. A lost packet does that to one name at a time, not to all of them at once — and this is exactly the state in which every other live trace test in this file skips rather than fails.",
		len(signed), strings.Join(why, " | "))
}

// "The zone says it has no record" is the headline only when no record or alias is printed below it.
func TestTraceHeadlineDoesNotDenyRecordsItPrints(t *testing.T) {
	t.Parallel()
	const absent = "The zone says it has no A record."
	for _, tc := range []struct {
		name   string
		tr     dnstools.Trace
		denies bool
	}{
		{"records", dnstools.Trace{Answer: []string{"192.0.2.1"}}, false},
		{"alias", dnstools.Trace{CNAME: "target.example.com."}, false},
		{"nothing", dnstools.Trace{}, true},
	} {
		tr := tc.tr
		tr.Type, tr.DNSSEC, tr.AnswerRcode = "A", "indeterminate", "NOERROR"
		out := renderCard(t, "dns/tracewalk", map[string]any{"Trace": &tr})
		if got := strings.Contains(out, absent); got != tc.denies {
			t.Errorf("%s: headline %q shown = %v, want %v:\n%s", tc.name, absent, got, tc.denies, out)
		}
	}
}
