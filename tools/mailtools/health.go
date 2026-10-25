package mailtools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

const fetchTimeout = 4 * time.Second

// Service runs the mail checks that reach the network. Build one and share it between REST and MCP.
type Service struct {
	guard  *platform.EgressGuard
	store  *Store // nil: nothing is cached
	dqsKey string
	http   *http.Client
}

// NewService needs the egress guard: every fetch a caller's domain points at goes through it.
func NewService(guard *platform.EgressGuard, store *Store, dqsKey string) *Service {
	if guard == nil {
		panic("mailtools.NewService: guard is nil")
	}
	return &Service{guard: guard, store: store, dqsKey: dqsKey, http: &http.Client{
		Timeout:   fetchTimeout,
		Transport: guard.Transport(fetchTimeout),
		// MTA-STS (RFC 8461 §3.3) and BIMI both forbid following redirects.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// fetch GETs u through the guard and returns at most limit bytes of a 200 body.
func (s *Service) fetch(ctx context.Context, u *url.URL, limit int64) ([]byte, error) {
	if err := s.guard.AllowHost(u.Hostname()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Corpberry-MailIntelligence/1.0")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d KB", limit/1024)
	}
	return body, nil
}

// DomainHealthReport is the aggregated audit of an email domain's infrastructure and reputation.
type DomainHealthReport struct {
	Domain          string               `json:"domain"`
	Classification  DomainClassification `json:"classification"`
	Gateway         *GatewayAudit        `json:"gateway"`
	Auth            *EmailAuthSummary    `json:"auth"`
	BIMI            *BIMIAudit           `json:"bimi"`
	DNSBL           *DNSBLReport         `json:"dnsbl,omitempty"`
	OverallScore    int                  `json:"overall_score"`
	Recommendations []string             `json:"recommendations"`
	DurationMS      int64                `json:"duration_ms"`
}

// AuditDomainHealth runs a comprehensive audit across domain categorization, MX/SEG, BIMI/VMC, and DNSBL.
func (s *Service) AuditDomainHealth(ctx context.Context, input string) (*DomainHealthReport, error) {
	start := time.Now()
	domain := ExtractDomain(input)
	if domain == "" {
		return nil, errors.New("please provide a valid domain name or email address")
	}
	report := &DomainHealthReport{Domain: domain, Classification: ActiveClassifier().Classify(domain)}

	var wg sync.WaitGroup
	wg.Go(func() { report.Auth = s.AuditEmailAuth(ctx, domain) })
	wg.Go(func() { report.BIMI = s.auditBIMI(ctx, domain) })
	mx, _ := lookupMX(ctx, domain)
	report.Gateway = gatewayAudit(domain, mx)
	report.DNSBL, _ = s.dnsbl(ctx, domain, func(string) []MXRecord { return mx })
	wg.Wait()

	// Calculate overall health score (0-100)
	score := 100

	if report.Classification.IsDisposable {
		score -= 60
		report.Recommendations = append(report.Recommendations, "High risk: Domain is a known disposable/burner email address service.")
	}

	if len(report.Gateway.MXRecords) == 0 {
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

	if report.Auth.MTASTS == nil || !report.Auth.MTASTS.RecordFound || report.Auth.MTASTS.Mode != "enforce" {
		report.Recommendations = append(report.Recommendations, "Consider configuring MTA-STS (RFC 8461) to prevent SMTP downgrade and man-in-the-middle attacks.")
	}

	if !report.BIMI.RecordFound {
		report.Recommendations = append(report.Recommendations, "Publish a default._bimi TXT record to display verified corporate brand logos in recipient inboxes.")
	} else if !report.BIMI.HasVMC {
		report.Recommendations = append(report.Recommendations, "Acquire a Verified Mark Certificate (VMC) from DigiCert, GlobalSign, or SSL.com for Gmail and Apple Mail support.")
	}

	if report.DNSBL != nil && report.DNSBL.ListedCount > 0 {
		score -= (report.DNSBL.ListedCount * 20)
		report.Recommendations = append(report.Recommendations, "Remediate domain or mail IP listings on active spam/reputation blacklists.")
	}

	report.OverallScore = max(score, 0)
	report.DurationMS = time.Since(start).Milliseconds()
	return report, nil
}
