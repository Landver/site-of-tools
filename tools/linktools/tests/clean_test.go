package tests

import (
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/linktools"
)

func clean(t *testing.T, raw string, opt linktools.CleanOptions) *linktools.CleanResult {
	t.Helper()
	res, err := linktools.NewService().Clean(raw, opt)
	if err != nil {
		t.Fatalf("Clean(%q) returned an error: %v", raw, err)
	}
	return res
}

// TestStripsTheHeadOfTheDistribution. The four the research corpus found missing
// from ClearURLs entirely are the point of hand-writing the table.
func TestStripsTheHeadOfTheDistribution(t *testing.T) {
	for _, key := range []string{
		"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
		"gclid", "gbraid", "wbraid", "gclsrc", "dclid", "srsltid",
		"fbclid", "msclkid", "ttclid", "twclid", "yclid", "igshid",
		"mc_cid", "mc_eid", "mkt_tok", "_openstat",
	} {
		res := clean(t, "https://example.com/p?"+key+"=VALUE&keep=1", linktools.CleanOptions{})
		if strings.Contains(res.Output, key) {
			t.Errorf("%s survived cleaning: %s", key, res.Output)
		}
		if !strings.Contains(res.Output, "keep=1") {
			t.Errorf("%s: cleaning also removed an unrelated parameter: %s", key, res.Output)
		}
	}
}

// TestNeverStripList. Stripping an OAuth parameter breaks a login; stripping a
// presigned URL's signature turns it into a 403. This test is the guard.
func TestNeverStripList(t *testing.T) {
	for _, key := range []string{
		"q", "id", "page", "token", "code", "state", "redirect_uri",
		"session", "sig", "signature", "v", "search",
	} {
		res := clean(t, "https://example.com/p?"+key+"=VALUE", linktools.CleanOptions{})
		if !strings.Contains(res.Output, key+"=VALUE") {
			t.Errorf("%s was stripped; it is on the never-strip list: %s", key, res.Output)
		}
	}
}

// TestPresignedURLUntouched. The canonical query of a presigned URL covers every
// other parameter, so removing any of them invalidates the signature.
func TestPresignedURLUntouched(t *testing.T) {
	const presigned = "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F20260925%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260925T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=abc123&utm_source=email"
	res := clean(t, presigned, linktools.CleanOptions{})
	if len(res.Removed) != 0 {
		t.Errorf("removed %d parameters from a presigned URL; the signature covers the whole query", len(res.Removed))
	}
	if res.Output != res.Input {
		t.Errorf("presigned URL was modified:\n in: %s\nout: %s", res.Input, res.Output)
	}
}

// TestCleaningNeverChangesTheHost is the invariant the short-link create path
// depends on: it validates a target and THEN cleans it, so a clean step able to
// move the host would void that validation (docs/04-short-links.md §9).
func TestCleaningNeverChangesTheHost(t *testing.T) {
	cases := []string{
		"https://example.com/a/b?utm_source=x",
		"https://user@example.com:8443/a?fbclid=1#frag",
		"https://example.com/?url=https%3A%2F%2Fevil.tld&utm_source=x",
		"https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.tld%2F&utm_source=x",
	}
	for _, raw := range cases {
		before := parse(t, raw)
		res := clean(t, raw, linktools.CleanOptions{}) // Unwrap deliberately off
		after := parse(t, res.Output)
		if before.Host != after.Host {
			t.Errorf("host moved from %q to %q cleaning %s", before.Host, after.Host, raw)
		}
		if before.Scheme != after.Scheme || before.Path != after.Path || before.Port != after.Port {
			t.Errorf("cleaning changed a non-query component of %s:\n  %s://%s%s\n  %s://%s%s",
				raw, before.Scheme, before.Host, before.Path, after.Scheme, after.Host, after.Path)
		}
	}
}

// TestNothingRemovedMeansByteIdentical: the cheapest possible proof that
// cleaning is not quietly reformatting URLs.
func TestNothingRemovedMeansByteIdentical(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/a%2Fb/c?q=a+b&x=%2520&bad=%zz#frag",
		"https://example.com/?a=1;b=2",
		"https://example.com/",
	} {
		res := clean(t, raw, linktools.CleanOptions{})
		if len(res.Removed) == 0 && res.Output != res.Input {
			t.Errorf("nothing was removed but the URL changed:\n in: %s\nout: %s", res.Input, res.Output)
		}
	}
}

// TestEveryRemovalIsAttributed. Both the page and the API promise to name the
// rule; an unattributed removal is exactly the magic this tool exists not to be.
func TestEveryRemovalIsAttributed(t *testing.T) {
	res := clean(t, "https://example.com/?utm_source=a&fbclid=b&gclid=c", linktools.CleanOptions{})
	if len(res.Removed) != 3 {
		t.Fatalf("removed %d, want 3", len(res.Removed))
	}
	for _, r := range res.Removed {
		if r.Rule == "" {
			t.Errorf("removal of %q names no rule", r.Key)
		}
		if r.Why == "" {
			t.Errorf("removal of %q gives no reason", r.Key)
		}
	}
}

// TestSortIsOffByDefault. Reordering a query breaks every signed URL whose
// signature covers the literal string, so it can never be automatic.
func TestSortIsOffByDefault(t *testing.T) {
	const raw = "https://example.com/?z=1&a=2&m=3"
	if got := clean(t, raw, linktools.CleanOptions{}).Output; got != raw {
		t.Errorf("parameters reordered without being asked:\n in: %s\nout: %s", raw, got)
	}
}

// TestAffiliateOffByDefault. Stripping gclid costs an advertiser a data point;
// stripping an Associates tag takes money from whoever wrote the review.
func TestAffiliateOffByDefault(t *testing.T) {
	const raw = "https://www.amazon.com/dp/B000?tag=someblog-20"
	if got := clean(t, raw, linktools.CleanOptions{}).Output; !strings.Contains(got, "tag=someblog-20") {
		t.Errorf("affiliate tag stripped by default: %s", got)
	}
	got := clean(t, raw, linktools.CleanOptions{StripAffiliate: true}).Output
	if strings.Contains(got, "tag=someblog-20") {
		t.Errorf("affiliate tag survived when explicitly asked for: %s", got)
	}
}

// TestUnwrapIsOfflineAndDecodesExactlyOnce.
//
// The subtle one: a Safe Links target is encoded ONCE, so a second decode pass
// eats the target's own %20 and yields a different URL
// (docs/reports/wrapper-formats.md).
func TestUnwrapIsOfflineAndDecodesExactlyOnce(t *testing.T) {
	const wrapped = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fa%2520b%3Fq%3D1&data=x&sdata=y&reserved=0"
	res := clean(t, wrapped, linktools.CleanOptions{Unwrap: true})
	if res.Unwrapped != "https://example.com/a%20b?q=1" {
		t.Errorf("unwrapped = %q, want the target decoded exactly once (%%2520 -> %%20, not a space)", res.Unwrapped)
	}
	if res.Wrapper == "" {
		t.Error("wrapper not named")
	}
}

// TestOpaqueShortenersAreNotWrappers. t.co and friends hold no target in the
// string, so claiming to unwrap them would be a lie; they belong to the tracer.
func TestOpaqueShortenersAreNotWrappers(t *testing.T) {
	for _, raw := range []string{"https://t.co/abc123", "https://lnkd.in/abc123", "https://bit.ly/abc123"} {
		target, _, ok := linktools.NewService().Unwrap(raw)
		if ok && target != "" && target != raw {
			t.Errorf("%s reported as unwrapped to %q; it is opaque and needs a fetch", raw, target)
		}
	}
}

// TestCleanRejectsEmptyInput. A relative reference like "not a url" is a valid
// URL reference and cleaning it is meaningful, so only genuinely empty input is
// an error — but it must then come back untouched rather than reformatted.
func TestCleanRejectsEmptyInput(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		if _, err := linktools.NewService().Clean(raw, linktools.CleanOptions{}); err == nil {
			t.Errorf("Clean(%q) returned no error", raw)
		}
	}
	res := clean(t, "not a url", linktools.CleanOptions{})
	if res.Output != "not a url" {
		t.Errorf("a relative reference with nothing to strip was rewritten: %q", res.Output)
	}
}

// TestRuleTableInvariants: properties of the data, so the table can grow
// without the test rotting.
func TestRuleTableInvariants(t *testing.T) {
	cat := linktools.Rules()
	if cat.Version == "" {
		t.Error("catalog has no version; the extension caches on it")
	}
	if cat.Scope == "" {
		t.Error("catalog states no scope; the page promises to say the table is curated, not exhaustive")
	}
	if len(cat.Tracking) < 50 {
		t.Errorf("only %d rules; the table should cover the head of the distribution", len(cat.Tracking))
	}
	seen := map[string]bool{}
	for _, r := range cat.Tracking {
		key := strings.ToLower(r.Param)
		if key == "" {
			t.Error("a rule has an empty parameter name")
		}
		if seen[key] {
			t.Errorf("duplicate rule for %q", key)
		}
		seen[key] = true
		if r.Origin == "" && r.Note == "" {
			t.Errorf("rule %q explains nothing; every removal must be attributable", r.Param)
		}
	}
	// The deny set and the GLOBAL rule table must not intersect: one says
	// "never remove this", the other says "remove this". Host-scoped rules are
	// exempt — "ref" on one specific host is precisely the two-tier design.
	global := map[string]bool{}
	for _, r := range cat.Tracking {
		if len(r.Hosts) == 0 {
			global[strings.ToLower(r.Param)] = true
		}
	}
	for _, d := range cat.NeverStrip {
		if global[strings.ToLower(d.Param)] {
			t.Errorf("%q is in BOTH the global rule table and the never-strip list", d.Param)
		}
	}
	if len(cat.Wrappers) == 0 {
		t.Error("no wrapper rules; A16 is the feature a non-developer uses daily")
	}
}
