package tests

import (
	"context"
	"net"
	"testing"
	"time"

)

func TestLiveDomainMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live domain matrix test in short mode")
	}

	// Verify outbound DNS is available in the test environment (e.g. CI environments with restricted network)
	if _, err := net.LookupMX("google.com"); err != nil {
		t.Skipf("Skipping live domain matrix: outbound DNS unavailable (%v)", err)
	}

	domains := []struct {
		domain      string
		expectScore int // minimum expected score
		expectDisp  bool
	}{
		{"github.com", 90, false},
		{"google.com", 95, false},
		{"microsoft.com", 90, false},
		{"stripe.com", 95, false},
		{"apple.com", 90, false},
		{"cloudflare.com", 90, false},
		{"mailinator.com", 0, true},
	}

	for _, tt := range domains {
		t.Run(tt.domain, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()

			rep, err := newService(nil).AuditDomainHealth(ctx, tt.domain)
			if err != nil {
				t.Fatalf("AuditDomainHealth(%q) failed: %v", tt.domain, err)
			}

			t.Logf("Domain: %s -> Score: %d/100, Type: %s, Disposable: %v, Vendor: %s, MX Redundancy: %v, DNSBL Listed: %d, DNSBL Warnings: %d",
				rep.Domain, rep.OverallScore, rep.Classification.Type, rep.Classification.IsDisposable,
				rep.Gateway.Vendor, rep.Gateway.HasRedundancy, rep.DNSBL.ListedCount, rep.DNSBL.WarningCount)

			if rep.DNSBL != nil {
				for _, r := range rep.DNSBL.Results {
					t.Logf("  DNSBL [%s]: Listed=%v, Warning=%v, Code=%s, Category=%s",
						r.Name, r.Listed, r.IsWarning, r.ReturnCode, r.Category)
				}
			}

			if rep.Classification.IsDisposable != tt.expectDisp {
				t.Errorf("%s: IsDisposable = %v, want %v", tt.domain, rep.Classification.IsDisposable, tt.expectDisp)
			}

			// Major corporate domains must NEVER have listed blacklists due to public resolver notices!
			if !tt.expectDisp && rep.DNSBL != nil && rep.DNSBL.ListedCount > 0 {
				t.Errorf("%s: DNSBL.ListedCount = %d, expected 0 false positives! Listings: %+v",
					tt.domain, rep.DNSBL.ListedCount, rep.DNSBL.Results)
			}

			if rep.OverallScore < tt.expectScore {
				t.Errorf("%s: OverallScore = %d, want >= %d. Recommendations: %v",
					tt.domain, rep.OverallScore, tt.expectScore, rep.Recommendations)
			}
		})
	}
}
