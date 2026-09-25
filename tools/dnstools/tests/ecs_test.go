package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// *Service must satisfy the handler dependency, or the card silently never
// renders: the handler takes it by interface assertion, which fails quietly.
var _ dnstools.ECSer = dnstools.NewService(time.Second)

// Input is rejected before anything leaves the box, and each rejection is the
// error the handler maps to 400 rather than a 502.
func TestECSRejectsInputThatCannotBeMeasured(t *testing.T) {
	t.Parallel()

	svc := dnstools.NewService(time.Second)
	cases := []struct {
		why, name, qtype string
		want             error
	}{
		{"no name at all", "", "A", dnstools.ErrEmptyName},
		{"an IP literal has no zone to steer", "8.8.8.8", "A", dnstools.ErrBadType},
		{"MX is the same record everywhere", "example.com", "MX", dnstools.ErrBadType},
		{"TXT is not a steering target", "example.com", "TXT", dnstools.ErrBadType},
		{"PTR is a reverse question", "example.com", "PTR", dnstools.ErrBadType},
		{"not a domain name", "not a domain", "A", dnstools.ErrBadName},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			t.Parallel()
			got, err := svc.ECS(context.Background(), c.name, c.qtype)
			if !errors.Is(err, c.want) {
				t.Fatalf("ECS(%q, %q) error = %v, want %v", c.name, c.qtype, err, c.want)
			}
			if got != nil {
				t.Errorf("a rejected request still returned a report: %+v", got)
			}
		})
	}
}

// The default type is A: /consistency defaults its own selector to A, and the
// card must ask the same question the rest of the page is about.
func TestECSDefaultsToA(t *testing.T) {
	requireEgress(t)

	got, err := dnstools.NewService(5*time.Second).ECS(context.Background(), "example.com", "")
	if err != nil {
		t.Fatalf("ECS: %v", err)
	}
	if got.Type != "A" {
		t.Errorf("Type = %q, want A", got.Type)
	}
}

// The live shape: every vantage point in the table is accounted for, named,
// and carries the prefix that was actually sent.
//
// Not parallel, and none of the live tests here are: these queries all land on
// one public resolver and running them at once is what made this suite flaky.
func TestECSLiveReportsEveryVantagePoint(t *testing.T) {
	requireEgress(t)

	got, err := dnstools.NewService(5*time.Second).ECS(context.Background(), "www.wikipedia.org", "A")
	if err != nil {
		t.Fatalf("ECS: %v", err)
	}
	if got.Asked == 0 || len(got.Vantages) != got.Asked {
		t.Fatalf("Asked = %d but %d vantage points are listed", got.Asked, len(got.Vantages))
	}
	if got.Answered == 0 {
		t.Skipf("no vantage point answered out of %d — flaky network, not a code failure", got.Asked)
	}
	for _, v := range got.Vantages {
		if v.Region == "" || v.Place == "" || v.Subnet == "" {
			t.Errorf("an unnamed vantage point: %+v", v)
		}
		if !strings.Contains(v.Subnet, "/") {
			t.Errorf("vantage %s subnet %q is not a prefix", v.Place, v.Subnet)
		}
		if v.Error == "" && v.Values == nil {
			t.Errorf("vantage %s answered with a nil value set, which marshals as null", v.Place)
		}
	}
	if got.ResolverAddr == "" || got.Resolver == "" {
		t.Error("the report does not name the resolver it asked")
	}
	t.Logf("verdict=%s max_scope=%d echoed=%d groups=%d answered=%d/%d in %dms",
		got.Verdict, got.MaxScope, got.Echoed, len(got.Groups), got.Answered, got.Asked, got.QueryMS)
}

// The verdict must never contradict the fields it was derived from. Asserted
// against the live internet rather than a canned scope, because the point is
// that the resolver this feature pins actually returns a scope: pointed at one
// that does not, every name on earth would come back "unsupported".
func TestECSLiveVerdictAgreesWithTheEvidence(t *testing.T) {
	requireEgress(t)

	svc := dnstools.NewService(5 * time.Second)
	// A name known to steer and one known not to, so a bug that hard-codes
	// either answer fails on the other.
	scoped := false
	for _, name := range []string{"www.wikipedia.org", "www.netflix.com"} {
		got, err := svc.ECS(context.Background(), name, "A")
		if err != nil {
			t.Fatalf("ECS(%s): %v", name, err)
		}
		if got.Answered < 2 {
			t.Logf("%s: only %d of %d vantage points answered, skipping its assertions", name, got.Answered, got.Asked)
			continue
		}
		if got.Echoed > 0 {
			scoped = true
		}
		t.Logf("%s: verdict=%s max_scope=%d echoed=%d groups=%d",
			name, got.Verdict, got.MaxScope, got.Echoed, len(got.Groups))

		switch got.Verdict {
		case "answers-differ":
			if got.MaxScope == 0 || len(got.Groups) < 2 {
				t.Errorf("%s: answers-differ needs a non-zero scope AND differing answers, got scope %d over %d groups",
					name, got.MaxScope, len(got.Groups))
			}
			// The flag that separates a scope the zone chose from a copy of
			// the one we sent. It cannot be set without a non-zero scope to
			// have been chosen.
			if got.ScopeDistinct && got.MaxScope == 0 {
				t.Errorf("%s: ScopeDistinct set with no non-zero scope anywhere", name)
			}
		case "answers-match":
			if got.MaxScope == 0 || len(got.Groups) > 1 {
				t.Errorf("%s: answers-match needs a non-zero scope and one answer set, got scope %d over %d groups",
					name, got.MaxScope, len(got.Groups))
			}
		case "untailored":
			if got.MaxScope != 0 {
				t.Errorf("%s: untailored claimed while a response reported scope /%d", name, got.MaxScope)
			}
			if got.Rotation != (len(got.Groups) > 1) {
				t.Errorf("%s: Rotation = %v over %d answer groups", name, got.Rotation, len(got.Groups))
			}
		case "unsupported":
			if got.Echoed != 0 {
				t.Errorf("%s: unsupported claimed while %d responses carried the option", name, got.Echoed)
			}
		case "no-records":
			// Both names below publish A records, so this is a real failure
			// here rather than a shape to tolerate.
			t.Errorf("%s: no-records claimed while %d of %d vantage points were given records",
				name, got.WithRecords, got.Answered)
		case "inconclusive":
			t.Errorf("%s: inconclusive although %d vantage points answered", name, got.Answered)
		default:
			t.Errorf("%s: unknown verdict %q", name, got.Verdict)
		}
	}
	if !scoped {
		t.Skip("no client-subnet option came back from anywhere — this network strips ECS, so nothing here was measured")
	}
}

// Whatever else is true, "we could not tell" must never be rendered as a
// verdict about tailoring: they are separate values, and this is the design
// value the whole card rests on. "untailored" is itself the weaker of the two
// claims the card used to make here: it says no client-subnet tailoring
// happened on this resolver's path, not that the name answers the same
// everywhere.
func TestECSNeverCallsAnUnmeasuredNameNotSteered(t *testing.T) {
	requireEgress(t)

	got, err := dnstools.NewService(5*time.Second).ECS(context.Background(), "example.com", "A")
	if err != nil {
		t.Fatalf("ECS: %v", err)
	}
	if got.Verdict == "untailored" && got.Echoed == 0 {
		t.Error("reported untailored without a single client-subnet option to read it from")
	}
	if got.Verdict == "untailored" && got.MaxScope != 0 {
		t.Errorf("reported untailored with a scope of /%d", got.MaxScope)
	}
}

// ecsTemplates parses this tool's own templates. Only this package's, not the
// shared partials: the card is a fragment, the shared set needs the renderer's
// function map, and nothing here is testing the site chrome.
func ecsTemplates(t *testing.T) *template.Template {
	t.Helper()
	sub, err := fs.Sub(dnstools.Templates, "templates")
	if err != nil {
		t.Fatalf("sub FS: %v", err)
	}
	tmpl, err := template.ParseFS(sub, "*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	return tmpl
}

// The card renders, states its verdict, and carries the two classes the
// consistency page's CSS multi-column flow needs. Without them the card is
// split down the middle mid-render, which no Go test would otherwise catch.
func TestECSCardRendersIntoTheConsistencyColumns(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := ecsTemplates(t).ExecuteTemplate(&buf, "dns/ecs", map[string]any{
		"ECS": &dnstools.ECS{
			Name: "www.wikipedia.org", Type: "A",
			Resolver: "Google (8.8.8.8)", Verdict: "answers-differ",
			MaxScope: 17, Echoed: 2, Answered: 2, Asked: 2, ScopeDistinct: true,
			Vantages: []dnstools.ECSAnswer{
				{Region: "Europe", Place: "Amsterdam, NL", Subnet: "192.87.0.0/24",
					Values: []string{"185.15.59.224"}, Echoed: true, Scope: 16, SourceNetmask: 24, RTTMS: 68},
				{Region: "Asia", Place: "Tokyo, JP", Subnet: "133.11.0.0/24",
					Values: []string{}, Error: "no response"},
				// Answered, with nothing to say. Reaches the branch that has to
				// climb back to the root dot for the record type.
				{Region: "Oceania", Place: "Melbourne, AU", Subnet: "130.194.0.0/24",
					Values: []string{}, Rcode: "NOERROR", Echoed: true, Scope: 0, RTTMS: 91},
			},
			Groups: []dnstools.ECSGroup{{Values: []string{"185.15.59.224"}, Vantages: []string{"Amsterdam, NL"}}},
			Notes:  []dnstools.Note{{Level: "ok", Text: "a finding"}},
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		// One card in one of the consistency page's two stacking columns, at
		// the same width as the public resolvers card it deliberately mirrors.
		// This assertion has now outlived two layouts (a CSS multi-column flow
		// wanted "mb-4 break-inside-avoid", a full-width row wanted
		// "sm:col-span-2"), so it pins the width the card claims and nothing
		// about the page around it.
		`class="card"`,
		"answers by client network",
		"This answer depends on the network that asks",
		// A scope the zone chose has to read differently from one that merely
		// repeats the length we sent, or the card is back to presenting an
		// echo as evidence.
		"scope /16, the zone's own block",
		"Amsterdam, NL", "192.87.0.0/24", "185.15.59.224", "scope /16",
		"Tokyo, JP", "no response",
		"Melbourne, AU", "no A record (NOERROR)", "scope 0, not tailored",
		"a finding", // the shared notes partial was reached
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered card is missing %q:\n%s", want, out)
		}
	}
}

// No ECS in the view model (unsupported record type, or the dependency off)
// must render nothing at all, not an empty card explaining its own absence.
func TestECSCardRendersNothingWithoutAResult(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := ecsTemplates(t).ExecuteTemplate(&buf, "dns/ecs", map[string]any{"Query": "example.com"}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Errorf("rendered %q, want nothing", buf.String())
	}
}

// The envelope is the /consistency JSON contract: every key that endpoint
// already returns stays at the top level, and "ecs" joins them. A nested
// shape would break published callers.
func TestECSEnvelopeKeepsSpreadAtTheTopLevel(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(&dnstools.ECSEnvelope{
		Spread: &dnstools.Spread{Name: "example.com", Type: "A", Consistent: true},
		ECS:    &dnstools.ECS{Name: "example.com", Verdict: "untailored"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"name", "type", "consistent", "auth_consistent", "ecs"} {
		if _, ok := out[key]; !ok {
			t.Errorf("the envelope lost top-level key %q: %s", key, body)
		}
	}
	if _, ok := out["spread"]; ok {
		t.Errorf("the envelope nested the spread instead of inlining it: %s", body)
	}
}

// The degenerate envelope, and why it needs a constructor: encoding/json does
// not fail on a nil embedded pointer, it silently skips every field it would
// have promoted. Built by hand, the endpoint answers 200 with a body that has
// quietly dropped the whole published contract.
func TestECSEnvelopeRefusesToBeBuiltWithoutASpread(t *testing.T) {
	t.Parallel()

	// The failure the constructor exists to make impossible, demonstrated so
	// nobody "simplifies" the guard away.
	body, err := json.Marshal(&dnstools.ECSEnvelope{ECS: &dnstools.ECS{Name: "x", Verdict: "answers-match"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var degenerate map[string]json.RawMessage
	if err := json.Unmarshal(body, &degenerate); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(degenerate) != 1 {
		t.Fatalf("a nil embedded Spread unexpectedly promoted its fields: %s", body)
	}

	if _, err := dnstools.NewECSEnvelope(nil, &dnstools.ECS{Verdict: "answers-match"}); !errors.Is(err, dnstools.ErrNoSpread) {
		t.Errorf("NewECSEnvelope(nil, ecs) error = %v, want ErrNoSpread rather than an ecs-only body", err)
	}

	// A nil ECS is fine: the card did not run, and "ecs" is simply absent.
	env, err := dnstools.NewECSEnvelope(&dnstools.Spread{Name: "example.com", Type: "A"}, nil)
	if err != nil {
		t.Fatalf("NewECSEnvelope with no card: %v", err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"name":"example.com"`) || strings.Contains(string(b), `"ecs"`) {
		t.Errorf("want the spread at the top level and no ecs key, got: %s", b)
	}
}

// The card must never print a sentence about records when no vantage point
// was given one. "Everyone gets the same records" is the wrong sentence for
// a name that published nothing anywhere.
func TestECSCardSaysNoRecordsRatherThanSameRecords(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := ecsTemplates(t).ExecuteTemplate(&buf, "dns/ecs", map[string]any{
		"ECS": &dnstools.ECS{
			Name: "nodata.example", Type: "A", Verdict: "no-records",
			Rcode: "NOERROR", Echoed: 6, Answered: 6, Asked: 6, WithRecords: 0,
			Vantages: []dnstools.ECSAnswer{
				{Place: "Tokyo, JP", Subnet: "133.11.0.0/24", Values: []string{},
					Rcode: "NOERROR", Echoed: true, Scope: 24},
			},
			Groups: []dnstools.ECSGroup{{Values: []string{}, Vantages: []string{"Tokyo, JP"}}},
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No A record anywhere") {
		t.Errorf("the card does not say the name published nothing:\n%s", out)
	}
	// The eyebrow is the card's title and always reads "answers by location";
	// what must not appear is a verdict sentence claiming records exist.
	for _, banned := range []string{"same records", "answers the same everywhere", "This name answers by location"} {
		if strings.Contains(out, banned) {
			t.Errorf("the card claims %q about a name with no records:\n%s", banned, out)
		}
	}
}

// A scope echoed for a prefix we never sent is rendered as such. The struct
// has always carried EchoedSubnet; a card that never printed it left the
// stated mitigation existing only in a comment.
func TestECSCardShowsAnEchoForTheWrongPrefix(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	err := ecsTemplates(t).ExecuteTemplate(&buf, "dns/ecs", map[string]any{
		"ECS": &dnstools.ECS{
			Name: "cached.example", Type: "A", Verdict: "unsupported",
			Answered: 1, Asked: 1, Mismatched: 1,
			Vantages: []dnstools.ECSAnswer{
				{Place: "New York, US", Subnet: "128.59.0.0/24", Values: []string{"192.0.2.10"},
					Echoed: true, Scope: 20, EchoedSubnet: "203.0.113.0/24", Mismatch: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"203.0.113.0/24", "not the network we sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("the card is missing %q, so a scope for another network reads as ours:\n%s", want, out)
		}
	}
	if strings.Contains(out, "scope /20, the zone's own block") || strings.Contains(out, "scope /20, the length we sent") {
		t.Errorf("the card presents somebody else's scope as this row's:\n%s", out)
	}
}

// The verdict paragraph must quantify over the responses it was derived from.
// A card that warns "only 1 of 6 carried a scope" and then asserts "every
// response carried a scope of /24" contradicts itself, and the assertion is
// the sentence a reader quotes.
func TestECSCardDoesNotSayEveryResponseWhenOnlySomeWereMeasured(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		verdict, want string
		scope         uint8
	}{
		{"answers-match", "on the 1 of 6 responses that carried one", 24},
		{"untailored", "The 1 of 6 responses that carried a scope reported scope 0", 0},
	} {
		t.Run(c.verdict, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			err := ecsTemplates(t).ExecuteTemplate(&buf, "dns/ecs", map[string]any{
				"ECS": &dnstools.ECS{
					Name: "partial.example", Type: "A", Verdict: c.verdict,
					MaxScope: c.scope, Echoed: 1, Answered: 6, Asked: 6, WithRecords: 6,
				},
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			out := buf.String()
			if !strings.Contains(out, c.want) {
				t.Errorf("want the measured subset named (%q):\n%s", c.want, out)
			}
			if strings.Contains(out, "Every response") || strings.Contains(out, "the responses carried") {
				t.Errorf("the card universally quantifies over responses that carried no scope:\n%s", out)
			}
		})
	}
}
