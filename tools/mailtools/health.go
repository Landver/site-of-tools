package mailtools

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// EmailAuthSummary holds published DMARC and SPF policies.
type EmailAuthSummary struct {
	HasSPF      bool   `json:"has_spf"`
	SPFRecord   string `json:"spf_record,omitempty"`
	HasDMARC    bool   `json:"has_dmarc"`
	DMARCRecord string `json:"dmarc_record,omitempty"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"` // reject, quarantine, none, missing
}

// DomainHealthReport is the aggregated audit of an email domain's infrastructure and reputation.
type DomainHealthReport struct {
	Domain          string               `json:"domain"`
	Classification  DomainClassification `json:"classification"`
	Gateway         *GatewayAudit        `json:"gateway,omitempty"`
	Auth            *EmailAuthSummary    `json:"auth,omitempty"`
	BIMI            *BIMIAudit           `json:"bimi,omitempty"`
	DNSBL           *DNSBLReport         `json:"dnsbl,omitempty"`
	OverallScore    int                  `json:"overall_score"`
	Recommendations []string             `json:"recommendations"`
	DurationMS      int64                `json:"duration_ms"`
}

// AuditDomainHealth runs a comprehensive audit across domain categorization, MX/SEG, BIMI/VMC, and DNSBL.
func AuditDomainHealth(ctx context.Context, input string, guard *platform.EgressGuard, store *Store, dqsKey string) (*DomainHealthReport, error) {
	start := time.Now()
	domain := ExtractDomain(input)
	if domain == "" {
		return nil, errors.New("please provide a valid domain name or email address")
	}

	report := &DomainHealthReport{
		Domain: domain,
	}

	// 1. Classification (In-Memory, instantaneous)
	classifier := ActiveClassifier()
	report.Classification = classifier.Classify(domain)

	// 2. Parallel Audits for Network & DNS Operations
	var wg sync.WaitGroup
	var gwAudit *GatewayAudit
	var bimiAudit *BIMIAudit
	var dnsblReport *DNSBLReport
	var authSummary EmailAuthSummary

	wg.Add(4)

	// Gateway Audit
	go func() {
		defer wg.Done()
		gw, err := DetectGateway(ctx, domain)
		if err == nil {
			gwAudit = gw
		}
	}()

	// BIMI / VMC Audit
	go func() {
		defer wg.Done()
		bimi, _ := AuditBIMI(ctx, domain, guard)
		bimiAudit = bimi
	}()

	// DNSBL Audit (cached)
	go func() {
		defer wg.Done()
		dnsblReport, _ = CachedDNSBLAudit(ctx, store, domain, dqsKey)
	}()

	// SPF & DMARC Audit
	go func() {
		defer wg.Done()
		r := &net.Resolver{}
		// Check DMARC
		if txts, err := r.LookupTXT(ctx, "_dmarc."+domain); err == nil {
			for _, txt := range txts {
				trimmed := strings.TrimSpace(txt)
				if strings.HasPrefix(trimmed, "v=DMARC1") {
					authSummary.HasDMARC = true
					authSummary.DMARCRecord = trimmed
					for _, part := range strings.Split(trimmed, ";") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(part, "p=") {
							authSummary.DMARCPolicy = strings.ToLower(strings.TrimPrefix(part, "p="))
						}
					}
					break
				}
			}
		}
		// Check SPF
		if txts, err := r.LookupTXT(ctx, domain); err == nil {
			for _, txt := range txts {
				trimmed := strings.TrimSpace(txt)
				if strings.HasPrefix(trimmed, "v=spf1") {
					authSummary.HasSPF = true
					authSummary.SPFRecord = trimmed
					break
				}
			}
		}
	}()

	wg.Wait()

	report.Gateway = gwAudit
	report.BIMI = bimiAudit
	report.DNSBL = dnsblReport
	report.Auth = &authSummary

	// Calculate overall health score (0-100)
	score := 100

	if report.Classification.IsDisposable {
		score -= 60
		report.Recommendations = append(report.Recommendations, "High risk: Domain is a known disposable/burner email address service.")
	}

	if report.Gateway == nil || len(report.Gateway.MXRecords) == 0 {
		score -= 40
		report.Recommendations = append(report.Recommendations, "No functional MX records found: domain cannot receive inbound emails.")
	} else {
		if report.Gateway.IsNullMX {
			score -= 50
			report.Recommendations = append(report.Recommendations, "Null MX (RFC 7505) is active: this domain explicitly refuses all inbound mail.")
		} else if !report.Gateway.HasRedundancy {
			score -= 10
			report.Recommendations = append(report.Recommendations, "Add at least one backup MX record to prevent email delivery loss during provider maintenance.")
		}
		if report.Gateway.HasDirectMXRisk {
			score -= 15
			report.Recommendations = append(report.Recommendations, report.Gateway.DirectMXWarning)
		}
	}

	if report.Auth != nil {
		if !report.Auth.HasDMARC {
			score -= 15
			report.Recommendations = append(report.Recommendations, "No DMARC record found at _dmarc."+domain+": publish a DMARC policy to protect your domain from brand spoofing.")
		} else if report.Auth.DMARCPolicy == "none" {
			score -= 5
			report.Recommendations = append(report.Recommendations, "DMARC policy is currently set to p=none (monitoring only). Upgrade to p=quarantine or p=reject to actively block unauthorized mail.")
		}
		if !report.Auth.HasSPF {
			score -= 10
			report.Recommendations = append(report.Recommendations, "No SPF record found on domain: publish v=spf1 to authorize sending IP addresses.")
		}
	}

	if report.BIMI != nil {
		if !report.BIMI.RecordFound {
			report.Recommendations = append(report.Recommendations, "Publish a default._bimi TXT record to display verified corporate brand logos in recipient inboxes.")
		} else if !report.BIMI.HasVMC {
			report.Recommendations = append(report.Recommendations, "Acquire a Verified Mark Certificate (VMC) from DigiCert, GlobalSign, or SSL.com for Gmail and Apple Mail support.")
		}
	}

	if report.DNSBL != nil && report.DNSBL.ListedCount > 0 {
		score -= (report.DNSBL.ListedCount * 20)
		report.Recommendations = append(report.Recommendations, "Remediate domain or mail IP listings on active spam/reputation blacklists.")
	}

	if score < 0 {
		score = 0
	}
	report.OverallScore = score
	report.DurationMS = time.Since(start).Milliseconds()

	return report, nil
}
