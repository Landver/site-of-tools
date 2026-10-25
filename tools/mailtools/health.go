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

// NewService fetches what a caller's domain points at through guard; a nil guard refuses every fetch.
func NewService(guard *platform.EgressGuard, store *Store, dqsKey string) *Service {
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

	report.OverallScore, report.Recommendations = grade(report)
	report.DurationMS = time.Since(start).Milliseconds()
	return report, nil
}

// authPenalties is what each auth check's status costs; a status listed here also recommends that check's message.
var authPenalties = map[string]map[string]int{
	"spf":     {"fail": 20, "warn": 5},
	"dmarc":   {"fail": 20, "warn": 5},
	"dkim":    {"warn": 0},
	"mta-sts": {"warn": 0, "info": 0},
}

// grade scores the report out of 100 and collects the advice behind every finding.
func grade(r *DomainHealthReport) (int, []string) {
	score := 100
	var advice []string
	find := func(penalty int, msg string) {
		score -= penalty
		advice = append(advice, msg)
	}

	if r.Classification.IsDisposable {
		find(60, "High risk: Domain is a known disposable/burner email address service.")
	}
	switch g := r.Gateway; {
	case len(g.MXRecords) == 0:
		find(40, "No functional MX records found: domain cannot receive inbound emails.")
	case g.IsNullMX:
		find(50, "Null MX (RFC 7505) is active: this domain explicitly refuses all inbound mail.")
	case !g.HasRedundancy:
		find(10, "Add at least one backup MX record to prevent email delivery loss during provider maintenance.")
	}
	if r.Gateway.HasDirectMXRisk {
		find(15, r.Gateway.DirectMXWarning)
	}

	a := r.Auth
	for _, c := range []struct{ check, status, msg string }{
		{"spf", a.SPF.Status, a.SPF.StatusMsg},
		{"dmarc", a.DMARC.Status, a.DMARC.StatusMsg},
		{"dkim", a.DKIM.Status, a.DKIM.StatusMsg},
		{"mta-sts", a.MTASTS.Status, a.MTASTS.StatusMsg},
	} {
		if penalty, ok := authPenalties[c.check][c.status]; ok {
			find(penalty, c.msg)
		}
	}

	switch {
	case !r.BIMI.RecordFound:
		find(0, "Publish a default._bimi TXT record to display verified corporate brand logos in recipient inboxes.")
	case !r.BIMI.HasVMC:
		find(0, "Acquire a Verified Mark Certificate (VMC) from DigiCert, GlobalSign, or SSL.com for Gmail and Apple Mail support.")
	}
	if r.DNSBL != nil && r.DNSBL.ListedCount > 0 {
		find(20*r.DNSBL.ListedCount, "Remediate domain or mail IP listings on active spam/reputation blacklists.")
	}
	return max(score, 0), advice
}
