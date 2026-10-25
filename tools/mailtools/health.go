package mailtools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

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
	var authSummary *EmailAuthSummary

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

	// Deep Email Authentication (SPF, DMARC, DKIM, MTA-STS)
	go func() {
		defer wg.Done()
		authSummary = AuditEmailAuth(ctx, domain, guard)
	}()

	wg.Wait()

	report.Gateway = gwAudit
	report.BIMI = bimiAudit
	report.DNSBL = dnsblReport
	report.Auth = authSummary

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
		} else if report.Auth.DMARC != nil && len(report.Auth.DMARC.Extra) > 0 {
			score -= 20
			report.Recommendations = append(report.Recommendations, "Multiple DMARC records found: RFC 7489 specifies that receivers must ignore all records, leaving your domain completely unprotected.")
		}

		if !report.Auth.HasSPF {
			score -= 10
			report.Recommendations = append(report.Recommendations, "No SPF record found on domain: publish v=spf1 to authorize sending IP addresses.")
		} else if report.Auth.SPF != nil {
			if report.Auth.SPF.Lookups > 10 {
				score -= 25
				report.Recommendations = append(report.Recommendations, fmt.Sprintf("SPF Permerror: Record requires %d DNS lookups, exceeding the RFC 7208 limit of 10. Major mail receivers will reject your emails.", report.Auth.SPF.Lookups))
			} else if report.Auth.SPF.Lookups >= 8 {
				report.Recommendations = append(report.Recommendations, fmt.Sprintf("SPF Warning: Record requires %d of 10 allowed DNS lookups. Future includes risk causing SPF permerrors.", report.Auth.SPF.Lookups))
			}
			if len(report.Auth.SPF.Extra) > 0 {
				score -= 20
				report.Recommendations = append(report.Recommendations, "Multiple SPF records found: RFC 7208 forbids multiple v=spf1 records and causes an immediate SPF Permerror.")
			}
			if report.Auth.SPF.Loop {
				score -= 20
				report.Recommendations = append(report.Recommendations, "SPF Include Loop detected: recursive includes circle back to an already visited domain, causing authentication failure.")
			}
			if report.Auth.SPF.All == "+all" {
				score -= 15
				report.Recommendations = append(report.Recommendations, "SPF uses dangerous '+all' mechanism: authorizes anyone on the internet to send email on behalf of your domain.")
			}
		}

		if report.Auth.MTASTS != nil && report.Auth.MTASTS.RecordFound && report.Auth.MTASTS.Mode == "enforce" {
			// Good hygiene
		} else {
			report.Recommendations = append(report.Recommendations, "Consider configuring MTA-STS (RFC 8461) to prevent SMTP downgrade and man-in-the-middle attacks.")
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
