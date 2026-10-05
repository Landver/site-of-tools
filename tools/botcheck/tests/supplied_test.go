package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

var (
	headerRules = []string{
		"bot_user_agent", "ua_header_mismatch", "ch_platform_mismatch", "embedded_runtime", "lang_mismatch",
		"ch_brands_mismatch", "sec_fetch_missing", "accept_encoding_missing", "accept_language_missing", "accept_nav_mismatch",
	}
	ipRules = []string{"tz_mismatch", "datacenter_ip", "proxy_ip", "ip_blocklisted", "webrtc_ip_mismatch"}
)

func withoutHeaders(s botcheck.Signals) botcheck.Signals {
	s.HeadersSupplied = false
	s.HTTPUserAgent, s.HTTPAccept, s.HTTPAcceptEncoding, s.AcceptLanguage = "", "", "", ""
	s.SecCHUA, s.SecCHUAPlatform, s.SecFetchMode, s.HTTPUpgradeInsecureRequests = "", "", "", ""
	return s
}

func withoutIP(s botcheck.Signals) botcheck.Signals {
	s.IPSupplied = false
	s.EgressIP, s.IPTimezone, s.ASN = "", "", ""
	s.IsDatacenter, s.IsProxy, s.IsVPN, s.IsTor = false, false, false, false
	s.IPBlocklistSources, s.IPBlocklistCount, s.IPBlocklistDeliberate = nil, 0, false
	return s
}

func TestUnsuppliedHalvesSkipNotFail(t *testing.T) {
	cases := []struct {
		name string
		s    botcheck.Signals
		want []string
	}{
		{"no headers", withoutHeaders(cleanChrome()), headerRules},
		{"no IP", withoutIP(cleanChrome()), ipRules},
		{"fingerprint only", withoutIP(withoutHeaders(cleanChrome())), append(append([]string{}, headerRules...), ipRules...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := botcheck.Evaluate(tc.s)
			var skipped []string
			for _, c := range r.Checks {
				if c.Skipped {
					skipped = append(skipped, c.ID)
				}
			}
			if diff := cmp.Diff(tc.want, skipped, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("skipped (-want +got):\n%s", diff)
			}
			if r.Score != 100 || r.Verdict != "human" {
				t.Errorf("score=%d verdict=%q, want 100/human (fired: %v)", r.Score, r.Verdict, triggeredIDs(r))
			}
		})
	}
}

func TestCoverageCounts(t *testing.T) {
	tier := func(evaluated, skipped, fired int) botcheck.TierCoverage {
		return botcheck.TierCoverage{Evaluated: evaluated, Skipped: skipped, Fired: fired}
	}
	stealth := cleanChrome()
	stealth.Webdriver, stealth.IsVPN, stealth.Plugins = true, true, 0
	cases := []struct {
		name string
		s    botcheck.Signals
		want botcheck.Coverage
	}{
		{"everything supplied", cleanChrome(), botcheck.Coverage{Hard: tier(8, 0, 0), Consistency: tier(31, 0, 0), Soft: tier(29, 0, 0)}},
		{"fired", stealth, botcheck.Coverage{Hard: tier(8, 0, 1), Consistency: tier(31, 0, 1), Soft: tier(29, 0, 1)}},
		{"fingerprint only", withoutIP(withoutHeaders(cleanChrome())), botcheck.Coverage{Hard: tier(7, 1, 0), Consistency: tier(21, 10, 0), Soft: tier(25, 4, 0)}},
		{"nothing supplied", botcheck.Signals{}, botcheck.Coverage{Hard: tier(0, 8, 0), Consistency: tier(0, 31, 0), Soft: tier(0, 29, 0)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, botcheck.Evaluate(tc.s).Coverage); diff != "" {
				t.Errorf("coverage (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAddHTTPSignals(t *testing.T) {
	var s botcheck.Signals
	botcheck.AddHTTPSignals(&s, botcheck.HTTPSignals{
		UserAgent: "ua", Accept: "acc", AcceptLanguage: "lang", AcceptEncoding: "enc",
		SecCHUA: "chua", SecCHUAPlatform: "plat", SecFetchMode: "mode", UpgradeInsecureRequests: "1",
	})
	want := botcheck.Signals{
		HeadersSupplied: true,
		HTTPUserAgent:   "ua", HTTPAccept: "acc", AcceptLanguage: "lang", HTTPAcceptEncoding: "enc",
		SecCHUA: "chua", SecCHUAPlatform: "plat", SecFetchMode: "mode", HTTPUpgradeInsecureRequests: "1",
	}
	if diff := cmp.Diff(want, s); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}

func TestAddIPSignals(t *testing.T) {
	const ip = "203.0.113.9"
	geo := &iptools.Result{IP: ip, Timezone: "-", ASN: "-", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "TOR"}}
	cases := []struct {
		name    string
		svc     botcheck.Looker
		chk     iptools.Checker
		want    botcheck.Signals
		wantRes *iptools.Result
	}{
		{
			name: "ipsum only is not deliberate; placeholders cleaned",
			svc:  fakeLooker{res: geo}, chk: listedBy(4, "ipsum"),
			want: botcheck.Signals{
				IPSupplied: true, EgressIP: ip, IsProxy: true, IsTor: true,
				IPBlocklistSources: []string{"ipsum"}, IPBlocklistCount: 4,
			},
			wantRes: geo,
		},
		{
			name: "any other source is deliberate, read even without geo",
			svc:  fakeLooker{err: iptools.ErrUnavailable}, chk: listedBy(0, "ipsum", "spamhaus-drop"),
			want: botcheck.Signals{
				IPSupplied: true, EgressIP: ip,
				IPBlocklistSources: []string{"ipsum", "spamhaus-drop"}, IPBlocklistDeliberate: true,
			},
		},
		{
			name: "datacenter, failed blocklist read",
			svc:  fakeLooker{res: &iptools.Result{Timezone: "+09:00", ASN: "16509", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH"}}},
			chk:  fakeChecker{err: errors.New("mongo down")},
			want: botcheck.Signals{IPSupplied: true, EgressIP: ip, IPTimezone: "+09:00", ASN: "16509", IsProxy: true, IsDatacenter: true},
		},
		{
			name: "no checker, no looker",
			want: botcheck.Signals{IPSupplied: true, EgressIP: ip},
		},
		{
			name: "vpn",
			svc:  fakeLooker{res: &iptools.Result{Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN"}}},
			want: botcheck.Signals{IPSupplied: true, EgressIP: ip, IsProxy: true, IsVPN: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s botcheck.Signals
			res := botcheck.AddIPSignals(context.Background(), &s, ip, tc.svc, tc.chk)
			if diff := cmp.Diff(tc.want, s); diff != "" {
				t.Errorf("signals (-want +got):\n%s", diff)
			}
			if tc.wantRes != nil && res != tc.wantRes {
				t.Errorf("returned %p, want the lookup %p", res, tc.wantRes)
			}
		})
	}
}
