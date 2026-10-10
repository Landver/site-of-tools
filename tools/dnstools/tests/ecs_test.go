package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/dnstools"
)

// The handler finds ECSer by type assertion, which fails quietly: *Service must satisfy it.
var _ dnstools.ECSer = dnstools.NewService(time.Second)

// Rejected input never leaves the box, and each rejection maps to 400, not 502.
func TestECSRejectsInputThatCannotBeMeasured(t *testing.T) {
	t.Parallel()

	svc := dnstools.NewService(time.Second)
	cases := []struct {
		why, name, qtype string
		want             error
	}{
		{"no name at all", "", "A", dnstools.ErrEmptyName},
		{"an IP literal has no zone to steer", "8.8.8.8", "A", dnstools.ErrNeedDomain},
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

// /consistency defaults to A, so the card must ask the same question by default.
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

// Every vantage point is accounted for, named, and carries the prefix actually sent.
// Not parallel, like every live test here: they all land on one public resolver.
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

// The verdict never contradicts its evidence; live, since the pinned resolver must return a scope.
func TestECSLiveVerdictAgreesWithTheEvidence(t *testing.T) {
	requireEgress(t)

	svc := dnstools.NewService(5 * time.Second)
	// One name that steers and one that doesn't, so a hard-coded answer fails one.
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
			// ScopeDistinct marks a scope the zone chose, so it needs a non-zero one.
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
			// Both names publish A records: upstream trouble, e.g. a rate-limited runner IP.
			t.Logf("%s: no vantage point was given a record (rcode %q), skipping its assertions",
				name, got.Rcode)
			continue
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

// "We could not tell" must never render as "untailored", which needs an echoed scope of 0.
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

// renderCard executes one of this tool's templates without the site chrome; toolURL is stubbed.
func renderCard(t *testing.T, name string, data any) string {
	t.Helper()
	tmpl, err := template.New("dns").Funcs(template.FuncMap{
		"toolURL": func(sub string) string { return "https://" + sub + ".example" },
	}).ParseFS(dnstools.Templates, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return buf.String()
}

// One card in one consistency column: the page's CSS columns split anything wider mid-render.
func TestECSCardRendersIntoTheConsistencyColumns(t *testing.T) {
	t.Parallel()

	out := renderCard(t, "dns/ecs", map[string]any{
		"ECS": &dnstools.ECS{
			Name: "www.wikipedia.org", Type: "A",
			Resolver: "Google (8.8.8.8)", Verdict: "answers-differ",
			MaxScope: 17, Echoed: 2, Answered: 2, Asked: 2, ScopeDistinct: true,
			Vantages: []dnstools.ECSAnswer{
				{Region: "Europe", Place: "Amsterdam, NL", Subnet: "192.87.0.0/24",
					Values: []string{"185.15.59.224"}, Echoed: true, Scope: 16, SourceNetmask: 24, RTTMS: 68},
				{Region: "Asia", Place: "Tokyo, JP", Subnet: "133.11.0.0/24",
					Values: []string{}, Error: "no response"},
				// Answered with nothing: the branch that climbs back to the root dot for the type.
				{Region: "Oceania", Place: "Melbourne, AU", Subnet: "130.194.0.0/24",
					Values: []string{}, Rcode: "NOERROR", Echoed: true, Scope: 0, RTTMS: 91},
			},
			Groups: []dnstools.ECSGroup{{Values: []string{"185.15.59.224"}, Vantages: []string{"Amsterdam, NL"}}},
			Notes:  []dnstools.Note{{Level: "ok", Text: "a finding"}},
		},
	})
	for _, want := range []string{
		`class="card"`,
		"answers by client network",
		"This answer depends on the network that asks",
		// A scope the zone chose must read differently from an echo of the length we sent.
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
	if strings.Contains(out, "col-span-2") {
		t.Errorf("the card claims the full width; it belongs in one column:\n%s", out)
	}
}

// No ECS in the view model renders nothing, not an empty card explaining its absence.
func TestECSCardRendersNothingWithoutAResult(t *testing.T) {
	t.Parallel()

	if out := renderCard(t, "dns/ecs", map[string]any{"Query": "example.com"}); strings.TrimSpace(out) != "" {
		t.Errorf("rendered %q, want nothing", out)
	}
}

// The /consistency JSON keeps the spread's keys at the top level; nesting would break callers.
func TestECSEnvelopeKeepsSpreadAtTheTopLevel(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(&dnstools.ECSEnvelope{
		Spread: &dnstools.Spread{Name: "example.com", Type: "A", Consistent: true},
		ECS:    &dnstools.ECS{Name: "example.com", Verdict: "untailored"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys := jsonKeys(t, body)
	for _, key := range []string{"name", "type", "consistent", "auth_consistent", "ecs"} {
		if !slices.Contains(keys, key) {
			t.Errorf("the envelope lost top-level key %q: %s", key, body)
		}
	}
	if slices.Contains(keys, "spread") {
		t.Errorf("the envelope nested the spread instead of inlining it: %s", body)
	}
}

// encoding/json silently drops every field a nil embedded pointer promotes, hence the constructor.
func TestECSEnvelopeRefusesToBeBuiltWithoutASpread(t *testing.T) {
	t.Parallel()

	// Demonstrated so nobody "simplifies" the guard away.
	body, err := json.Marshal(&dnstools.ECSEnvelope{ECS: &dnstools.ECS{Name: "x", Verdict: "answers-match"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(jsonKeys(t, body)) != 1 {
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

// No records anywhere must not read as "everyone gets the same records".
func TestECSCardSaysNoRecordsRatherThanSameRecords(t *testing.T) {
	t.Parallel()

	out := renderCard(t, "dns/ecs", map[string]any{
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
	if !strings.Contains(out, "No A record for any of the 6 networks") {
		t.Errorf("the card does not say the name published nothing:\n%s", out)
	}
	// The title always reads "answers by location"; a verdict claiming records must not.
	for _, banned := range []string{"same records", "answers the same everywhere", "This name answers by location"} {
		if strings.Contains(out, banned) {
			t.Errorf("the card claims %q about a name with no records:\n%s", banned, out)
		}
	}
}

// A scope echoed for a prefix we never sent is rendered as such.
func TestECSCardShowsAnEchoForTheWrongPrefix(t *testing.T) {
	t.Parallel()

	out := renderCard(t, "dns/ecs", map[string]any{
		"ECS": &dnstools.ECS{
			Name: "cached.example", Type: "A", Verdict: "unsupported",
			Answered: 1, Asked: 1, Mismatched: 1,
			Vantages: []dnstools.ECSAnswer{
				{Place: "New York, US", Subnet: "128.59.0.0/24", Values: []string{"192.0.2.10"},
					Echoed: true, Scope: 20, EchoedSubnet: "203.0.113.0/24", Mismatch: true},
			},
		},
	})
	for _, want := range []string{"203.0.113.0/24", "not the network we sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("the card is missing %q, so a scope for another network reads as ours:\n%s", want, out)
		}
	}
	if strings.Contains(out, "scope /20, the zone's own block") || strings.Contains(out, "scope /20, the length we sent") {
		t.Errorf("the card presents somebody else's scope as this row's:\n%s", out)
	}
}

// The verdict quantifies over the responses that carried a scope, never "every response".
func TestECSCardDoesNotSayEveryResponseWhenOnlySomeWereMeasured(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		verdict, want string
		scope         uint8
	}{
		{"answers-match", "the 1 of 6 responses that carried one", 24},
		{"untailored", "the 1 of 6 responses that carried one", 0},
	} {
		t.Run(c.verdict, func(t *testing.T) {
			t.Parallel()

			out := renderCard(t, "dns/ecs", map[string]any{
				"ECS": &dnstools.ECS{
					Name: "partial.example", Type: "A", Verdict: c.verdict,
					MaxScope: c.scope, Echoed: 1, Answered: 6, Asked: 6, WithRecords: 6,
				},
			})
			if !strings.Contains(out, c.want) {
				t.Errorf("want the measured subset named (%q):\n%s", c.want, out)
			}
			if strings.Contains(out, "Every response") || strings.Contains(out, "the responses carried") {
				t.Errorf("the card universally quantifies over responses that carried no scope:\n%s", out)
			}
		})
	}
}
