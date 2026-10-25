package mailtools

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// BIMIAudit contains the validation and cryptographic audit of a domain's BIMI & VMC setup.
type BIMIAudit struct {
	Domain         string    `json:"domain"`
	Selector       string    `json:"selector"`
	RecordFound    bool      `json:"record_found"`
	RawRecord      string    `json:"raw_record,omitempty"`
	LogoURL        string    `json:"logo_url,omitempty"`
	VMCURL         string    `json:"vmc_url,omitempty"`
	HasVMC         bool      `json:"has_vmc"`
	VMCValid       bool      `json:"vmc_valid"`
	VMCIssuer      string    `json:"vmc_issuer,omitempty"`
	VMCSubjectOrg  string    `json:"vmc_subject_org,omitempty"`
	VMCExpiresAt   time.Time `json:"vmc_expires_at,omitempty"`
	VMCDaysLeft    int       `json:"vmc_days_left,omitempty"`
	SANMatch       bool      `json:"san_match"`
	HasLogotypeExt bool      `json:"has_logotype_ext"`
	Errors         []string  `json:"errors,omitempty"`
	Warnings       []string  `json:"warnings,omitempty"`
}

// Approved MVAs based on BIMI Group Directory
var approvedMVAPatterns = []string{
	"digicert",
	"globalsign",
	"ssl.com",
}

// RFC 3709 id-pe-logotype OID: 1.3.6.1.5.5.7.1.12
var oidLogotype = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}

// auditBIMI reads default._bimi.<domain> and, when it names one, fetches and audits the VMC.
func (s *Service) auditBIMI(ctx context.Context, domain string) *BIMIAudit {
	audit := &BIMIAudit{Domain: domain, Selector: "default"}
	bimiDomain := "default._bimi." + domain
	recs := lookupTXTWithPrefix(ctx, bimiDomain, "v=BIMI1")
	if len(recs) == 0 {
		audit.Errors = append(audit.Errors, "No v=BIMI1 record found at "+bimiDomain)
		return audit
	}
	audit.RecordFound, audit.RawRecord = true, recs[0]

	tags := parseTXTTags(audit.RawRecord)
	audit.LogoURL = tags["l"]
	audit.VMCURL = tags["a"]

	if audit.LogoURL == "" {
		audit.Warnings = append(audit.Warnings, "BIMI record does not specify a logo URL (l= tag)")
	} else if !strings.HasPrefix(audit.LogoURL, "https://") {
		audit.Errors = append(audit.Errors, "BIMI logo URL (l=) MUST use secure HTTPS scheme")
	}

	if audit.VMCURL == "" {
		audit.Warnings = append(audit.Warnings, "No Verified Mark Certificate (a= tag) specified. Major mailbox providers (Gmail, Apple Mail) require a VMC/CMC to display logos.")
		return audit
	}

	audit.HasVMC = true
	vmcURL, err := url.Parse(audit.VMCURL)
	if err != nil || vmcURL.Scheme != "https" || vmcURL.Hostname() == "" || vmcURL.User != nil {
		audit.Errors = append(audit.Errors, "BIMI certificate authority URL (a=) MUST be a valid absolute HTTPS URL without user credentials")
		return audit
	}
	s.validateVMC(ctx, audit, vmcURL)
	return audit
}

func (s *Service) validateVMC(ctx context.Context, audit *BIMIAudit, vmcURL *url.URL) {
	body, err := s.fetch(ctx, vmcURL, 256*1024)
	if err != nil {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Failed to fetch VMC certificate: %v", err))
		return
	}

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

	now := time.Now()
	if now.Before(leaf.NotBefore) {
		audit.Errors = append(audit.Errors, fmt.Sprintf("VMC is not valid yet (NotBefore: %s)", leaf.NotBefore.Format("2006-01-02")))
	} else if now.After(leaf.NotAfter) {
		audit.Errors = append(audit.Errors, fmt.Sprintf("VMC certificate EXPIRED on %s", leaf.NotAfter.Format("2006-01-02")))
	} else if audit.VMCDaysLeft < 30 {
		audit.Warnings = append(audit.Warnings, fmt.Sprintf("VMC certificate expires in %d days", audit.VMCDaysLeft))
	}

	issuer := strings.ToLower(leaf.Issuer.CommonName + " " + strings.Join(leaf.Issuer.Organization, " "))
	if !slices.ContainsFunc(approvedMVAPatterns, func(p string) bool { return strings.Contains(issuer, p) }) {
		audit.Warnings = append(audit.Warnings, fmt.Sprintf("Issuer '%s' is not recognized as a BIMI Group accredited Mark Verifying Authority (DigiCert, GlobalSign, SSL.com)", leaf.Issuer.CommonName))
	}

	if err := leaf.VerifyHostname(audit.Domain); err == nil {
		audit.SANMatch = true
	} else {
		audit.Errors = append(audit.Errors, fmt.Sprintf("Domain '%s' does not match Subject Alternative Names in VMC (%s): %v", audit.Domain, strings.Join(leaf.DNSNames, ", "), err))
	}

	audit.HasLogotypeExt = slices.ContainsFunc(leaf.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oidLogotype) })
	if !audit.HasLogotypeExt {
		audit.Warnings = append(audit.Warnings, "Certificate is missing RFC 3709 embedded logotype extension (id-pe-logotype)")
	}

	audit.VMCValid = len(audit.Errors) == 0
}
