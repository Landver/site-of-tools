package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func TestAuditEmailAuthLiveOrOffline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Testing with a reputable domain
	res := newService(nil).AuditEmailAuth(ctx, "google.com")
	if res == nil {
		t.Fatal("AuditEmailAuth returned nil for google.com")
	}

	if !res.HasSPF {
		t.Log("Note: Live DNS lookup for google.com SPF was empty or timed out")
	} else {
		if res.SPF == nil || res.SPF.Record == "" {
			t.Error("HasSPF is true but res.SPF is empty")
		}
		if res.SPF.Lookups <= 0 {
			t.Errorf("expected SPF lookups > 0, got %d", res.SPF.Lookups)
		}
	}

	if !res.HasDMARC {
		t.Log("Note: Live DNS lookup for google.com DMARC was empty or timed out")
	} else {
		if res.DMARC == nil || res.DMARCPolicy == "" {
			t.Error("HasDMARC is true but res.DMARC is empty")
		}
	}
}

func TestAuditDomainHealthEnriched(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := newService(nil).AuditDomainHealth(ctx, "stripe.com")
	if err != nil {
		t.Fatalf("AuditDomainHealth failed: %v", err)
	}

	if report.Domain != "stripe.com" {
		t.Errorf("domain = %q, want stripe.com", report.Domain)
	}
	if report.Auth == nil {
		t.Fatal("report.Auth is nil")
	}

	// Verify that recommendations and scoring handle auth
	if report.OverallScore < 0 || report.OverallScore > 100 {
		t.Errorf("invalid score: %d", report.OverallScore)
	}
}

func TestMTASTSPolicyParsing(t *testing.T) {
	rawPolicy := "version: STSv1\nmode: ENFORCE\nmx: mail.example.com\nmx: *.example.com\nmax_age: 604800\n"
	var res mailtools.MTASTSAnalysis
	mailtools.ParseMTASTSPolicy(rawPolicy, &res)

	if res.Mode != "enforce" {
		t.Errorf("Mode: want enforce, got %q", res.Mode)
	}
	if res.MaxAge != 604800 {
		t.Errorf("MaxAge: want 604800, got %d", res.MaxAge)
	}
	if len(res.MXPatterns) != 2 || res.MXPatterns[0] != "mail.example.com" || res.MXPatterns[1] != "*.example.com" {
		t.Errorf("MXPatterns unexpected: %+v", res.MXPatterns)
	}
}
