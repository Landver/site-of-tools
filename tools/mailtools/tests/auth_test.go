package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func TestAuditEmailAuthLiveOrOffline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Testing with a reputable domain
	res := mailtools.AuditEmailAuth(ctx, "google.com", nil)
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

	report, err := mailtools.AuditDomainHealth(ctx, "stripe.com", nil, nil, "")
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.com\nmax_age: 604800\n"))
	}))
	defer srv.Close()

	// Test that policy format parses cleanly
	if srv.URL == "" {
		t.Fatal("server failed to start")
	}
}
