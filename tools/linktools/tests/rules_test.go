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

// TestCleanAppliesHostScopedRules: ref is Amazon's tracker but a git forge's branch.
func TestCleanAppliesHostScopedRules(t *testing.T) {
	t.Parallel()
	var removed []string
	for _, r := range clean(t, "https://www.amazon.com/dp/X?tag=aff-20&ref=nav&th=1&utm_source=x&state=s", linktools.CleanOptions{}).Removed {
		removed = append(removed, r.Key)
	}
	if diff := cmp.Diff([]string{"ref", "utm_source"}, removed); diff != "" {
		t.Errorf("amazon removed (-want +got):\n%s", diff)
	}
	if got := clean(t, "https://github.com/o/r?ref=main&utm_source=x", linktools.CleanOptions{}).Output; got != "https://github.com/o/r?ref=main" {
		t.Errorf("github = %s, want ref kept and utm_source gone", got)
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
