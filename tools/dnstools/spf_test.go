package dnstools

import (
	"context"
	"testing"
)

// The SPF lookup counter, over synthetic records served from loopback.
//
// Every number in the table is the RFC 7208 §4.6.4 cost of *evaluating* the
// record: one per include, a, mx, ptr, exists and redirect term evaluated,
// counted again each time a term is evaluated again. Cases that the counter
// gets wrong today are marked with the finding they pin and are expected to
// fail until that finding is fixed — the point of the table is that the fix
// turns them green rather than being taken on trust.
func TestSPFLookupCount(t *testing.T) {
	t.Parallel()

	// zeroCost: a record that publishes addresses only, so an include of it
	// costs the include term and nothing more.
	const zeroCost = "v=spf1 ip4:192.0.2.0/24 -all"

	cases := []struct {
		name    string
		records map[string]string
		want    int
		wantAll string
		// finding: non-empty when today's counter disagrees with the RFC, and
		// names the review finding whose fix makes this case pass.
		finding string
	}{
		{
			name:    "a and mx with a CIDR suffix each cost one",
			records: map[string]string{"t.test": "v=spf1 a/24 mx/24 -all"},
			want:    2,
			wantAll: "-all",
		},
		{
			name:    "a alone with a CIDR suffix",
			records: map[string]string{"t.test": "v=spf1 a/24 ~all"},
			want:    1,
			wantAll: "~all",
		},
		{
			name:    "bare ptr costs one",
			records: map[string]string{"t.test": "v=spf1 ptr -all"},
			want:    1,
			wantAll: "-all",
		},
		{
			name:    "a: and mx: with targets",
			records: map[string]string{"t.test": "v=spf1 a:foo.test mx:bar.test -all"},
			want:    2,
			wantAll: "-all",
		},
		{
			name:    "ip4, ip6 and exp cost nothing",
			records: map[string]string{"t.test": "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 exp=why.test -all"},
			want:    0,
			wantAll: "-all",
		},
		{
			name:    "exists costs one",
			records: map[string]string{"t.test": "v=spf1 exists:%{ir}.dnswl.test -all"},
			want:    1,
			wantAll: "-all",
		},
		{
			// A bare `all` carries an implicit "+", i.e. anyone may send.
			name:    "bare all reads as +all",
			records: map[string]string{"t.test": "v=spf1 a all"},
			want:    1,
			wantAll: "+all",
		},
		{
			name:    "+ALL is +all whatever its case",
			records: map[string]string{"t.test": "v=spf1 +ALL"},
			want:    0,
			wantAll: "+all",
		},
		{
			name:    "?all is neutral and still recorded",
			records: map[string]string{"t.test": "v=spf1 ip4:192.0.2.1 ?all"},
			want:    0,
			wantAll: "?all",
		},
		{
			name:    "a record with no all mechanism",
			records: map[string]string{"t.test": "v=spf1 a:mail.test"},
			want:    1,
			wantAll: "",
		},
		{
			// RFC 7208 §4.6.1: mechanism and modifier names are
			// case-insensitive, so this record costs exactly as much as its
			// lowercase twin.
			name: "mechanism names are case-insensitive",
			records: map[string]string{
				"t.test":   "v=spf1 Include:inc.test MX A PTR Redirect=r.test",
				"inc.test": zeroCost,
				"r.test":   zeroCost,
			},
			want:    5,
			finding: "spf-mechanism-case-sensitive",
		},
		{
			// RFC 7208 §6.1: a redirect modifier MUST be ignored when the
			// record contains an all mechanism, so neither it nor the record
			// it points at costs anything.
			name: "redirect is ignored when the record has an all mechanism",
			records: map[string]string{
				"t.test":   "v=spf1 include:inc.test redirect=big.test -all",
				"inc.test": zeroCost,
				"big.test": "v=spf1 include:b1.test include:b2.test include:b3.test include:b4.test include:b5.test include:b6.test include:b7.test include:b8.test -all",
				"b1.test":  zeroCost, "b2.test": zeroCost, "b3.test": zeroCost, "b4.test": zeroCost,
				"b5.test": zeroCost, "b6.test": zeroCost, "b7.test": zeroCost, "b8.test": zeroCost,
			},
			want:    1,
			wantAll: "-all",
			finding: "spf-redirect-counted-despite-all",
		},
		{
			// The limit is per evaluation, not per distinct name: the same
			// include listed twice is evaluated twice and costs twice.
			name: "the same include twice costs twice",
			records: map[string]string{
				"t.test":  "v=spf1 include:p.test include:p.test -all",
				"p.test":  "v=spf1 include:x1.test include:x2.test include:x3.test -all",
				"x1.test": zeroCost, "x2.test": zeroCost, "x3.test": zeroCost,
			},
			want:    8,
			wantAll: "-all",
			finding: "spf-shared-include-undercount",
		},
		{
			// Same rule reached down two branches: shared.test's sub-tree is
			// paid for once per branch that includes it.
			name: "an include reached from two branches costs twice",
			records: map[string]string{
				"t.test":      "v=spf1 include:a.test include:b.test -all",
				"a.test":      "v=spf1 include:shared.test -all",
				"b.test":      "v=spf1 include:shared.test -all",
				"shared.test": "v=spf1 include:s1.test include:s2.test include:s3.test include:s4.test -all",
				"s1.test":     zeroCost, "s2.test": zeroCost, "s3.test": zeroCost, "s4.test": zeroCost,
			},
			want:    12,
			wantAll: "-all",
			finding: "spf-shared-include-undercount",
		},
		{
			// A record that includes itself must stop at the repeat rather
			// than recursing: the top term plus the term that closes the loop.
			name: "a self-referencing include terminates",
			records: map[string]string{
				"t.test":    "v=spf1 include:loop.test -all",
				"loop.test": "v=spf1 include:loop.test -all",
			},
			want:    2,
			wantAll: "-all",
		},
		{
			name: "a record over the ten-lookup limit is counted past it",
			records: map[string]string{
				"t.test": "v=spf1 a mx ptr include:c1.test include:c2.test include:c3.test include:c4.test " +
					"include:c5.test include:c6.test include:c7.test include:c8.test -all",
				"c1.test": zeroCost, "c2.test": zeroCost, "c3.test": zeroCost, "c4.test": zeroCost,
				"c5.test": zeroCost, "c6.test": zeroCost, "c7.test": zeroCost, "c8.test": zeroCost,
			},
			want:    11,
			wantAll: "-all",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, addr := serveZone(t, spfZone(tc.records))
			svc := newTestService()

			r := svc.checkSPF(context.Background(), "t.test", addr)
			if r == nil {
				t.Fatal("no SPF result for a domain that publishes one")
			}
			if r.Lookups != tc.want {
				msg := "lookups = %d, RFC 7208 cost is %d (chain %v)"
				if tc.finding != "" {
					msg += " [expected red until " + tc.finding + " is fixed]"
				}
				t.Errorf(msg, r.Lookups, tc.want, r.Chain)
			}
			if r.All != tc.wantAll {
				t.Errorf("all = %q, want %q", r.All, tc.wantAll)
			}
			if r.Limit != 10 {
				t.Errorf("limit = %d, want the RFC 7208 value of 10", r.Limit)
			}
		})
	}
}

// A domain with no SPF record gets no SPF result, rather than an empty one the
// verdict layer would then grade.
func TestSPFAbsentRecord(t *testing.T) {
	t.Parallel()
	_, addr := serveZone(t, spfZone(map[string]string{"other.test": "v=spf1 -all"}))

	if r := newTestService().checkSPF(context.Background(), "t.test", addr); r != nil {
		t.Errorf("checkSPF on a domain with no SPF returned %+v, want nil", r)
	}
}

// The include budget stops the walk and says so out loud, rather than turning
// one page view into unbounded upstream traffic.
func TestSPFIncludeBudgetIsEnforced(t *testing.T) {
	t.Parallel()

	records := map[string]string{}
	rec := "v=spf1"
	for i := range 20 {
		name := chainName(i)
		records[name] = "v=spf1 ip4:192.0.2.0/24 -all"
		rec += " include:" + name
	}
	records["t.test"] = rec + " -all"

	_, addr := serveZone(t, spfZone(records))
	r := newTestService().checkSPF(context.Background(), "t.test", addr)
	if r == nil {
		t.Fatal("no SPF result")
	}
	if len(r.Chain) > maxSPFIncludes {
		t.Errorf("followed %d includes, budget is %d", len(r.Chain), maxSPFIncludes)
	}
	if !r.Truncated {
		t.Errorf("a 20-include record should report Truncated, chain length %d", len(r.Chain))
	}
	// The verdict does not depend on the untaken half: the record is already
	// past the limit either way.
	if r.Lookups <= r.Limit {
		t.Errorf("lookups = %d, a 20-include record is over the limit of %d", r.Lookups, r.Limit)
	}
}

func chainName(i int) string { return "inc" + string(rune('a'+i%26)) + ".test" }
