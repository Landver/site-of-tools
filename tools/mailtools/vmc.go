package mailtools

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// BIMIAudit contains the validation and cryptographic audit of a domain's BIMI & VMC setup.
type BIMIAudit struct {
	Domain          string    `json:"domain"`
	Selector        string    `json:"selector"`
	RecordFound     bool      `json:"record_found"`
	RawRecord       string    `json:"raw_record,omitempty"`
	LogoURL         string    `json:"logo_url,omitempty"`
	VMCURL          string    `json:"vmc_url,omitempty"`
	HasVMC          bool      `json:"has_vmc"`
	VMCValid        bool      `json:"vmc_valid"`
	VMCIssuer       string    `json:"vmc_issuer,omitempty"`
	VMCSubjectOrg   string    `json:"vmc_subject_org,omitempty"`
	VMCExpiresAt    time.Time `json:"vmc_expires_at,omitempty"`
	VMCDaysLeft     int       `json:"vmc_days_left,omitempty"`
	SANMatch        bool      `json:"san_match"`
	HasLogotypeExt  bool      `json:"has_logotype_ext"`
	Errors          []string  `json:"errors,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
}

// Approved MVAs based on BIMI Group Directory
var approvedMVAPatterns = []string{
	"digicert",
	"globalsign",
	"ssl.com",
}

// RFC 3709 id-pe-logotype OID: 1.3.6.1.5.5.7.1.12
var oidLogotype = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}

// AuditBIMI queries DNS for default._bimi.<domain> and cryptographically audits the VMC certificate.
func AuditBIMI(ctx context.Context, domain string, guard *platform.EgressGuard) (*BIMIAudit, error) {
	domain = ExtractDomain(domain)
	audit := &BIMIAudit{
		Domain:   domain,
		Selector: "default",
	}

	bimiDomain := fmt.Sprintf("default._bimi.%s", domain)
	r := &net.Resolver{}
	txts, err := r.LookupTXT(ctx, bimiDomain)
	if err != nil {
		audit.Errors = append(audit.Errors, fmt.Sprintf("No BIMI record found at %s: %v", bimiDomain, err))
		return audit, nil
	}

	for _, txt := range txts {
		if strings.HasPrefix(strings.TrimSpace(txt), "v=BIMI1") {
			audit.RecordFound = true
			audit.RawRecord = txt
			break
		}
	}

	if !audit.RecordFound {
		audit.Errors = append(audit.Errors, "DNS TXT record exists at default._bimi, but missing v=BIMI1 header tag")
		return audit, nil
	}

	// Parse tags: v=BIMI1; l=https://...; a=https://...
	tags := parseBIMITags(audit.RawRecord)
	audit.LogoURL = tags["l"]
	audit.VMCURL = tags["a"]

	if audit.LogoURL == "" {
		audit.Warnings = append(audit.Warnings, "BIMI record does not specify a logo URL (l= tag)")
	} else if !strings.HasPrefix(audit.LogoURL, "https://") {
		audit.Errors = append(audit.Errors, "BIMI logo URL (l=) MUST use secure HTTPS scheme")
	}

	if audit.VMCURL == "" {
		audit.Warnings = append(audit.Warnings, "No Verified Mark Certificate (a= tag) specified. Major mailbox providers (Gmail, Apple Mail) require a VMC/CMC to display logos.")
		return audit, nil
	}

	audit.HasVMC = true
	vmcURL, err := url.Parse(audit.VMCURL)
	if err != nil || vmcURL.Scheme != "https" || vmcURL.Hostname() == "" || vmcURL.User != nil {
		audit.Errors = append(audit.Errors, "BIMI certificate authority URL (a=) MUST be a valid absolute HTTPS URL without user credentials")
		return audit, nil
	}
	if guard != nil {
		if err := guard.AllowHost(vmcURL.Hostname()); err != nil {
			audit.Errors = append(audit.Errors, fmt.Sprintf("VMC host rejected by egress policy: %v", err))
			return audit, nil
		}
	}

	// Fetch and validate VMC certificate
	validateVMCChain(ctx, audit, guard)
	return audit, nil
}

func parseBIMITags(raw string) map[string]string {
	return parseAuthTags(raw)
}

// vmcHTTPClient is an internal seam for testing without network.
var vmcHTTPClient *http.Client

func validateVMCChain(ctx context.Context, audit *BIMIAudit, guard *platform.EgressGuard) {
	if !strings.HasPrefix(strings.ToLower(audit.VMCURL), "https://") {
		audit.Errors = append(audit.Errors, "VMC certificate URL must use HTTPS scheme")
		return
	}

	var client *http.Client
	if vmcHTTPClient != nil {
		client = vmcHTTPClient
	} else {
		if guard == nil {
			guard = platform.NewEgressGuard([]string{"443"}, nil)
		}
		tr := guard.Transport(4 * time.Second)
		tr.TLSHandshakeTimeout = 3 * time.Second
		tr.ResponseHeaderTimeout = 3 * time.Second

		client = &http.Client{
			Timeout:   4 * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // BIMI strictly forbids redirects
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", audit.VMCURL, nil)
	if err != nil {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Failed to construct VMC download request: %v", err))
		return
	}
	req.Header.Set("User-Agent", "Corpberry-MailIntelligence/1.0")

	resp, err := client.Do(req)
	if err != nil {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Failed to fetch VMC certificate: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		audit.Errors = append(audit.Errors, fmt.Sprintf("VMC endpoint returned HTTP %d", resp.StatusCode))
		return
	}

	// Limit PEM certificate chain download to 256 KB
	const maxVMCBytes = 256 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVMCBytes+1))
	if err != nil {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Failed to read VMC payload: %v", err))
		return
	}
	if len(body) > maxVMCBytes {
		audit.Errors = append(audit.Errors, "VMC certificate payload exceeds maximum permitted size (256 KB)")
		return
	}

	// Parse PEM blocks
	var certs []*x509.Certificate
	data := body
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				audit.Errors = append(audit.Errors, fmt.Sprintf("Malformed X.509 certificate in PEM chain: %v", err))
			} else {
				certs = append(certs, cert)
			}
		}
		data = rest
	}

	if len(certs) == 0 {
		audit.Errors = append(audit.Errors, "Payload at a= tag does not contain valid PEM X.509 certificates")
		return
	}

	leaf := certs[0]
	audit.VMCIssuer = leaf.Issuer.CommonName
	if len(leaf.Subject.Organization) > 0 {
		audit.VMCSubjectOrg = leaf.Subject.Organization[0]
	} else {
		audit.VMCSubjectOrg = leaf.Subject.CommonName
	}
	audit.VMCExpiresAt = leaf.NotAfter
	audit.VMCDaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)

	// Expiry check
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		audit.Errors = append(audit.Errors, fmt.Sprintf("VMC is not valid yet (NotBefore: %s)", leaf.NotBefore.Format("2006-01-02")))
	} else if now.After(leaf.NotAfter) {
		audit.Errors = append(audit.Errors, fmt.Sprintf("VMC certificate EXPIRED on %s", leaf.NotAfter.Format("2006-01-02")))
	} else if audit.VMCDaysLeft < 30 {
		audit.Warnings = append(audit.Warnings, fmt.Sprintf("VMC certificate expires in %d days", audit.VMCDaysLeft))
	}

	// Issuer check against approved MVAs
	issuerLower := strings.ToLower(leaf.Issuer.CommonName + " " + strings.Join(leaf.Issuer.Organization, " "))
	isApprovedMVA := false
	for _, app := range approvedMVAPatterns {
		if strings.Contains(issuerLower, app) {
			isApprovedMVA = true
			break
		}
	}
	if !isApprovedMVA {
		audit.Warnings = append(audit.Warnings, fmt.Sprintf("Issuer '%s' is not recognized as a BIMI Group accredited Mark Verifying Authority (DigiCert, GlobalSign, SSL.com)", leaf.Issuer.CommonName))
	}

	// SAN check: does certificate match the domain using RFC-compliant verification?
	if err := leaf.VerifyHostname(audit.Domain); err == nil {
		audit.SANMatch = true
	} else {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Domain '%s' does not match Subject Alternative Names in VMC (%s): %v", audit.Domain, strings.Join(leaf.DNSNames, ", "), err))
	}

	// Check RFC 3709 logotype extension
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidLogotype) {
			audit.HasLogotypeExt = true
			break
		}
	}
	if !audit.HasLogotypeExt {
		audit.Warnings = append(audit.Warnings, "Certificate is missing RFC 3709 embedded logotype extension (id-pe-logotype)")
	}

	if len(audit.Errors) == 0 {
		audit.VMCValid = true
	}
}
