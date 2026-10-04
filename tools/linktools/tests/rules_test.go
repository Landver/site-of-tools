package tests

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/linktools"
)

func TestRuleMatchesNamesEveryCandidate(t *testing.T) {
	t.Parallel()
	cat := linktools.Rules()

	ref := cat.Matches(" REF ")
	if ref.Param != "ref" || !slices.ContainsFunc(ref.Tracking, func(r linktools.Rule) bool { return slices.Contains(r.Hosts, "amazon.") }) ||
		!slices.ContainsFunc(ref.NeverStrip, func(d linktools.Deny) bool { return slices.Contains(d.Hosts, "github.com") }) {
		t.Errorf("ref = %+v, want Amazon's rule and the git forges' never-strip entry, hosts included", ref)
	}
	utm := cat.Matches("utm_source")
	if !slices.ContainsFunc(utm.Tracking, func(r linktools.Rule) bool { return r.Prefix && r.Param == "utm_" }) {
		t.Errorf("utm_source = %+v, want the utm_ prefix rule", utm)
	}
	state := cat.Matches("state")
	if len(state.Tracking) != 0 || len(state.NeverStrip) != 1 || state.NeverStrip[0].Hosts != nil {
		t.Errorf("state = %+v, want one global never-strip entry", state)
	}
	if none := cat.Matches("color"); none.Tracking == nil || none.NeverStrip == nil || len(none.Tracking)+len(none.NeverStrip) != 0 {
		t.Errorf("color = %+v, want empty lists, not nil", none)
	}
}

func verdicts(t *testing.T, raw string) (*linktools.URLVerdict, map[string]string) {
	t.Helper()
	v, err := linktools.Rules().Verdict(raw)
	if err != nil {
		t.Fatalf("Verdict(%q): %v", raw, err)
	}
	got := map[string]string{}
	for _, p := range v.Params {
		switch {
		case p.Strip:
			got[p.Key] = "strip"
		case p.Affiliate:
			got[p.Key] = "affiliate"
		case p.NeverStrip:
			got[p.Key] = "never strip"
		default:
			got[p.Key] = "keep"
		}
	}
	return v, got
}

func TestRuleVerdictIsWhatCleanDoes(t *testing.T) {
	t.Parallel()
	amazon := "https://www.amazon.com/dp/X?tag=aff-20&ref=nav&th=1&utm_source=x&state=s"
	_, got := verdicts(t, amazon)
	want := map[string]string{"tag": "affiliate", "ref": "strip", "th": "keep", "utm_source": "strip", "state": "never strip"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("amazon (-want +got):\n%s", diff)
	}
	var removed []string
	for _, r := range clean(t, amazon, linktools.CleanOptions{}).Removed {
		removed = append(removed, r.Key)
	}
	if diff := cmp.Diff([]string{"ref", "utm_source"}, removed); diff != "" {
		t.Errorf("Clean disagrees with the verdict (-want +got):\n%s", diff)
	}

	if _, got := verdicts(t, "https://github.com/o/r?ref=main&utm_source=x"); got["ref"] != "never strip" || got["utm_source"] != "strip" {
		t.Errorf("github = %v, want ref protected there", got)
	}
	v, got := verdicts(t, "https://b.s3.amazonaws.com/k?X-Amz-Signature=a&utm_source=x")
	if v.Signed == "" || got["utm_source"] != "keep" || v.Params[1].Rule == "" {
		t.Errorf("presigned = %+v, want the signature named, the rule shown and nothing stripped", v)
	}
	for _, bad := range []string{"", "http://[::1"} {
		if _, err := linktools.Rules().Verdict(bad); err == nil {
			t.Errorf("Verdict(%q) gave no error", bad)
		}
	}
}

func TestRuleSummaryCountsTheTables(t *testing.T) {
	t.Parallel()
	cat := linktools.Rules()
	want := linktools.RuleSummary{Version: linktools.RulesVersion, Scope: cat.Scope,
		Tracking: len(cat.Tracking), NeverStrip: len(cat.NeverStrip), Wrappers: len(cat.Wrappers)}
	if diff := cmp.Diff(want, cat.Summary()); diff != "" || want.Tracking == 0 {
		t.Errorf("summary (-want +got):\n%s", diff)
	}
}
