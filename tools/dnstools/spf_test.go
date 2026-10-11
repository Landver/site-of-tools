package dnstools

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// Each want is the RFC 7208 §4.6.4 evaluation cost: a term evaluated twice costs twice.
func TestSPFLookupCount(t *testing.T) {
	t.Parallel()

	// zeroCost publishes addresses only, so including it costs just the include term.
	const zeroCost = "v=spf1 ip4:192.0.2.0/24 -all"

	cases := []struct {
		name    string
		records map[string]string
		want    int
		wantAll string
		finding string
		loop    bool
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
			// A bare `all` carries an implicit "+": anyone may send.
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
			// RFC 7208 §4.6.1: mechanism and modifier names are case-insensitive.
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
			// RFC 7208 §6.1: redirect is ignored beside an all, so its target costs nothing.
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
			// The limit counts evaluations, not distinct names.
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
			// Stops at the repeat: the top term plus the one that closes the loop.
			name: "a self-referencing include terminates",
			records: map[string]string{
				"t.test":    "v=spf1 include:loop.test -all",
				"loop.test": "v=spf1 include:loop.test -all",
			},
			want:    2,
			wantAll: "-all",
			loop:    true,
		},
		{
			name:    "a record including itself is a loop",
			records: map[string]string{"t.test": "v=spf1 include:t.test -all"},
			want:    1,
			wantAll: "-all",
			loop:    true,
		},
		{
			name: "two records including each other are a loop",
			records: map[string]string{
				"t.test": "v=spf1 include:a.test -all",
				"a.test": "v=spf1 include:b.test -all",
				"b.test": "v=spf1 include:a.test -all",
			},
			want:    3,
			wantAll: "-all",
			loop:    true,
		},
		{
			name: "a redirect back to the start is a loop",
			records: map[string]string{
				"t.test": "v=spf1 redirect=r.test",
				"r.test": "v=spf1 redirect=t.test",
			},
			want: 2,
			loop: true,
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

			r, _ := svc.checkSPF(context.Background(), "t.test", addr)
			if r == nil {
				t.Fatal("no SPF result for a domain that publishes one")
			}
			if r.Lookups != tc.want {
				t.Errorf("lookups = %d, RFC 7208 cost is %d (chain %v)"+regresses(tc.finding), r.Lookups, tc.want, r.Chain)
			}
			if r.All != tc.wantAll {
				t.Errorf("all = %q, want %q", r.All, tc.wantAll)
			}
			if r.Limit != 10 {
				t.Errorf("limit = %d, want the RFC 7208 value of 10", r.Limit)
			}
			// A shared include is not a loop; a loop permerrors however few lookups it took.
			if r.Loop != tc.loop {
				t.Errorf("loop = %v, want %v (chain %v)", r.Loop, tc.loop, r.Chain)
			}
			e := &EmailAuth{SPF: r}
			e.judge()
			if tc.loop && (!hasNote(e.Notes, "fail", "in a loop") || hasNote(e.Notes, "ok", "SPF")) {
				t.Errorf("a looping SPF is not failed, or is still graded ok: %+v", e.Notes)
			}
		})
	}
}

// No SPF record gives nil, not an empty result the verdict layer would grade.
func TestSPFAbsentRecord(t *testing.T) {
	t.Parallel()
	_, addr := serveZone(t, spfZone(map[string]string{"other.test": "v=spf1 -all"}))

	if r, _ := newTestService().checkSPF(context.Background(), "t.test", addr); r != nil {
		t.Errorf("checkSPF on a domain with no SPF returned %+v, want nil", r)
	}
}

// A SERVFAIL on the SPF or DMARC TXT lookup is "couldn't find out", never "no record".
func TestTXTLookupFailureIsNotAbsence(t *testing.T) {
	t.Parallel()
	_, addr := serveZoneWith(t, testZone{
		zoneKey("t.test", "MX"):         {"t.test. 300 IN MX 10 mx1.t.test."},
		zoneKey("mx1.t.test", "A"):      {"mx1.t.test. 300 IN A 192.0.2.25"},
		zoneKey("t.test", "TXT"):        {`t.test. 300 IN TXT "v=spf1 -all"`},
		zoneKey("_dmarc.t.test", "TXT"): {`_dmarc.t.test. 300 IN TXT "v=DMARC1; p=reject"`},
	}, func(m *dns.Msg, q dns.Question) {
		if q.Qtype == dns.TypeTXT && (q.Name == "t.test." || q.Name == "_dmarc.t.test.") {
			m.Answer, m.Rcode = nil, dns.RcodeServerFailure
		}
	})

	e := newTestService().emailRun(context.Background(), "t.test", addr)
	if !e.HasMX {
		t.Fatalf("the MX lookup should have answered: %+v", e)
	}
	for _, check := range []string{"SPF", "DMARC"} {
		if hasNote(e.Notes, "fail", "No "+check+" record") {
			t.Errorf("a failed %s lookup is reported as no record: %+v", check, e.Notes)
		}
		if !hasNote(e.Notes, "warn", "The "+check+" record could not be read") {
			t.Errorf("no note says the %s lookup failed: %+v", check, e.Notes)
		}
	}
}

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
	r, _ := newTestService().checkSPF(context.Background(), "t.test", addr)
	if r == nil {
		t.Fatal("no SPF result")
	}
	if len(r.Chain) > maxSPFIncludes {
		t.Errorf("followed %d includes, budget is %d", len(r.Chain), maxSPFIncludes)
	}
	if !r.Truncated {
		t.Errorf("a 20-include record should report Truncated, chain length %d", len(r.Chain))
	}
	// Past the limit either way, so the untaken half cannot change the verdict.
	if r.Lookups <= r.Limit {
		t.Errorf("lookups = %d, a 20-include record is over the limit of %d", r.Lookups, r.Limit)
	}
}

func chainName(i int) string { return "inc" + string(rune('a'+i%26)) + ".test" }
