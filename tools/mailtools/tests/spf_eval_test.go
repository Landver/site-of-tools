package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func TestEvaluateSPF_MechanismsAndVerdicts(t *testing.T) {
	record := "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.1 ip6:2001:db8::/32 -all"

	tests := []struct {
		ip      string
		sender  string
		want    mailtools.SPFVerdict
		matchOn string
	}{
		{"192.0.2.45", "user@example.com", mailtools.SPFPass, "ip4:192.0.2.0/24"},
		{"198.51.100.1", "user@example.com", mailtools.SPFPass, "ip4:198.51.100.1"},
		{"2001:db8::1234", "user@example.com", mailtools.SPFPass, "ip6:2001:db8::/32"},
		{"203.0.113.5", "user@example.com", mailtools.SPFFail, "-all"},
		{"invalid-ip", "user@example.com", mailtools.SPFPermError, ""},
	}

	for _, tt := range tests {
		res := mailtools.EvaluateSPF(tt.ip, tt.sender, record)
		if res.Verdict != tt.want {
			t.Errorf("EvaluateSPF(%s) = %s, want %s", tt.ip, res.Verdict, tt.want)
		}
		if tt.matchOn != "" && res.MatchedOn != tt.matchOn {
			t.Errorf("EvaluateSPF(%s) matched on %q, want %q", tt.ip, res.MatchedOn, tt.matchOn)
		}
	}
}

func TestEvaluateSPF_SoftfailAndNeutral(t *testing.T) {
	softfailRec := "v=spf1 ip4:1.2.3.4 ~all"
	res := mailtools.EvaluateSPF("5.6.7.8", "test@corpberry.com", softfailRec)
	if res.Verdict != mailtools.SPFSoftfail {
		t.Errorf("expected softfail, got %s", res.Verdict)
	}

	neutralRec := "v=spf1 ip4:1.2.3.4 ?all"
	res2 := mailtools.EvaluateSPF("5.6.7.8", "test@corpberry.com", neutralRec)
	if res2.Verdict != mailtools.SPFNeutral {
		t.Errorf("expected neutral, got %s", res2.Verdict)
	}
}

func TestEvaluateSPF_EdgeCasesAndFallbacks(t *testing.T) {
	cases := []struct {
		name   string
		ip     string
		sender string
		record string
		want   mailtools.SPFVerdict
	}{
		{"empty record returns None", "1.2.3.4", "user@test.com", "", mailtools.SPFNone},
		{"not an spf record returns None", "1.2.3.4", "user@test.com", "v=something_else", mailtools.SPFNone},
		{"no all mechanism falls back to neutral", "1.2.3.4", "user@test.com", "v=spf1 ip4:5.6.7.8", mailtools.SPFNeutral},
		{"explicit +all yields pass", "1.2.3.4", "user@test.com", "v=spf1 +all", mailtools.SPFPass},
		{"empty sender handled cleanly", "1.2.3.4", "", "v=spf1 ip4:1.2.3.4 -all", mailtools.SPFPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mailtools.EvaluateSPF(tc.ip, tc.sender, tc.record)
			if res.Verdict != tc.want {
				t.Errorf("got %s, want %s (reason: %s)", res.Verdict, tc.want, res.Reason)
			}
		})
	}
}
