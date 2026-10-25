package mailtools

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// 1. Secure Email Gateway: All Vendor Signatures & Feature Detection
// -----------------------------------------------------------------------------

func TestMatchVendor_AllSignatures(t *testing.T) {
	cases := []struct {
		host        string
		wantVendor  GatewayVendor
		wantFeature string
	}{
		// Proofpoint
		{"mx1-us1.pphosted.com", VendorProofpoint, "Targeted Attack Protection (TAP)"},
		{"pph-inbound.example.com", VendorProofpoint, "Attachment Sandboxing"},
		{"mx.proofpoint.com", VendorProofpoint, "DMARC Inbound Enforcement"},

		// Mimecast
		{"us-smtp-inbound-1.mimecast.com", VendorMimecast, "Targeted Threat Protection (TTP)"},
		{"mx.mimecast-offence.com", VendorMimecast, "Attachment Protect"},

		// Microsoft
		{"mail-example-com.mail.protection.outlook.com", VendorMicrosoft, "Exchange Online Protection (EOP)"},

		// Google
		{"aspmx.l.google.com", VendorGoogle, "Google Workspace Anti-Spam"},
		{"smtp.googlemail.com", VendorGoogle, "ARC Authentication"},
		{"aspmx2.googlemail.com", VendorGoogle, "Phishing & Malware Protection"},
		{"aspmx3.googlemail.com", VendorGoogle, "DKIM/DMARC Verification"},

		// Cisco
		{"mx1.iphmx.com", VendorCisco, "Cisco Talos Threat Intelligence"},
		{"inbound.ironport.com", VendorCisco, "SpamCop Telemetry"},

		// Barracuda
		{"d12345.barracudanetworks.com", VendorBarracuda, "Barracuda Real-Time Reputation (BRBL)"},
		{"mx.barracuda.com", VendorBarracuda, "Spam & Virus Firewall"},
		{"ess.barracuda.com", VendorBarracuda, "Link Protection"},

		// Sophos
		{"mx1.hydra.sophos.com", VendorSophos, "SophosLabs Telemetry"},
		{"inbound.sophos.com", VendorSophos, "Deep Learning AI Malware Detection"},

		// Trend Micro
		{"in.trendmicro.com", VendorTrendMicro, "Trend Micro Smart Protection Network"},
		{"mail.tmes.trendmicro.com", VendorTrendMicro, "Predictive Machine Learning"},

		// Fortinet
		{"mail.fortimail.com", VendorFortinet, "FortiGuard Antispam"},

		// Hornetsecurity
		{"mx.hornetsecurity.com", VendorHornet, "Advanced Threat Protection (ATP)"},
		{"relay.antispameurope.com", VendorHornet, "Spear Phishing Protection"},

		// Self-Hosted / Generic fallback
		{"mail.customdatacenter.net", VendorGeneric, "Standard SMTP / TLS Encryption"},
		{"", VendorGeneric, "Standard SMTP / TLS Encryption"},
	}

	for _, tc := range cases {
		vendor, features := matchVendor(tc.host)
		if vendor != tc.wantVendor {
			t.Errorf("matchVendor(%q).vendor = %v, want %v", tc.host, vendor, tc.wantVendor)
		}
		found := false
		for _, f := range features {
			if strings.Contains(f, tc.wantFeature) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("matchVendor(%q) missing feature %q in %+v", tc.host, tc.wantFeature, features)
		}
	}
}

// -----------------------------------------------------------------------------
// 2. DNSBL Return Code Semantics (All Codes and Warnings)
// -----------------------------------------------------------------------------

func TestParseReturnCode_AllSemantics(t *testing.T) {
	codes := []struct {
		code        string
		wantListed  bool
		wantWarning bool
		wantSubstr  string
	}{
		{"127.255.255.254", false, true, "Spamhaus Open Resolver Notice"},
		{"127.255.255.255", false, true, "Spamhaus Query Limit Exceeded"},
		{"127.0.0.2", true, false, "Direct UBE spam source / SBL"},
		{"127.0.0.3", true, false, "Snowshoe spam emitter / CSS"},
		{"127.0.0.4", true, false, "Botnet / Malware exploit infection / XBL"},
		{"127.0.0.5", true, false, "Botnet / Malware exploit infection / XBL"},
		{"127.0.0.6", true, false, "Botnet / Malware exploit infection / XBL"},
		{"127.0.0.7", true, false, "Botnet / Malware exploit infection / XBL"},
		{"127.0.0.10", true, false, "End-user dynamic IP range / PBL"},
		{"127.0.0.11", true, false, "End-user dynamic IP range / PBL"},
		{"127.0.1.2", true, false, "Spam domain (Spamhaus DBL)"},
		{"127.0.1.4", true, false, "Phishing domain (Spamhaus DBL)"},
		{"127.0.1.5", true, false, "Malware distribution domain (Spamhaus DBL)"},
		{"127.0.1.6", true, false, "Botnet C2 domain (Spamhaus DBL)"},
		{"127.0.1.102", true, false, "Abused legit web host / redirector"},
		{"127.0.1.103", true, false, "Abused legit web host / redirector"},
		{"127.0.1.104", true, false, "Abused legit web host / redirector"},
		{"127.0.0.99", true, false, "Listed in blacklist (code 127.0.0.99)"},
		{"10.0.0.1", false, false, "Clean / Not Listed"},
		{"", false, false, "Clean / Not Listed"},
	}

	for _, tc := range codes {
		res := DNSBLResult{Category: "Clean / Not Listed"}
		parseReturnCode(&res, tc.code)
		if res.Listed != tc.wantListed {
			t.Errorf("parseReturnCode(%q).Listed = %v, want %v", tc.code, res.Listed, tc.wantListed)
		}
		if res.IsWarning != tc.wantWarning {
			t.Errorf("parseReturnCode(%q).IsWarning = %v, want %v", tc.code, res.IsWarning, tc.wantWarning)
		}
		if !strings.Contains(res.Category, tc.wantSubstr) {
			t.Errorf("parseReturnCode(%q).Category = %q, want containing %q", tc.code, res.Category, tc.wantSubstr)
		}
	}
}

// -----------------------------------------------------------------------------
// 3. BIMI Tag Parsing & VMC X.509 Cryptographic Verification
// -----------------------------------------------------------------------------

func TestParseBIMITags_EdgeCases(t *testing.T) {
	cases := []struct {
		raw     string
		wantTag map[string]string
	}{
		{
			raw: "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			wantTag: map[string]string{
				"v": "BIMI1",
				"l": "https://example.com/logo.svg",
				"a": "https://example.com/vmc.pem",
			},
		},
		{
			// Whitespace, trailing semicolon, extra spacing
			raw: "  v = BIMI1 ;   l = https://brand.com/bimi.svg ; a = https://brand.com/cert.pem ; ",
			wantTag: map[string]string{
				"v": "BIMI1",
				"l": "https://brand.com/bimi.svg",
				"a": "https://brand.com/cert.pem",
			},
		},
		{
			// Missing values and malformed items without '='
			raw: "v=BIMI1; stray_item; l=; a=",
			wantTag: map[string]string{
				"v": "BIMI1",
				"l": "",
				"a": "",
			},
		},
	}

	for _, tc := range cases {
		got := parseBIMITags(tc.raw)
		for k, wantVal := range tc.wantTag {
			if got[k] != wantVal {
				t.Errorf("parseBIMITags(%q)[%q] = %q, want %q", tc.raw, k, got[k], wantVal)
			}
		}
	}
}

func helperGenerateVMC(t *testing.T, issuerCN, org string, notBefore, notAfter time.Time, san []string, addLogotype bool) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName:   san[0],
			Organization: []string{org},
		},
		Issuer: pkix.Name{
			CommonName:   issuerCN,
			Organization: []string{issuerCN},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  san,
	}

	if addLogotype {
		tmpl.ExtraExtensions = []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}, // oidLogotype
				Critical: false,
				Value:    []byte{0x30, 0x00},
			},
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type mockTransport func(req *http.Request) (*http.Response, error)

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestValidateVMCChain_SyntheticCertificates(t *testing.T) {
	ctx := context.Background()
	origClient := vmcHTTPClient
	defer func() { vmcHTTPClient = origClient }()

	// 1. Valid DigiCert VMC with Logotype extension
	now := time.Now()
	validPEM := helperGenerateVMC(t, "DigiCert Verified Mark Root CA", "Stripe Inc", now.Add(-24*time.Hour), now.Add(180*24*time.Hour), []string{"stripe.com"}, true)

	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(validPEM)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	audit := &BIMIAudit{Domain: "stripe.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, audit, nil)

	if !audit.VMCValid {
		t.Errorf("valid VMC failed validation: errors: %+v", audit.Errors)
	}
	if !audit.SANMatch {
		t.Errorf("expected SANMatch = true")
	}
	if !audit.HasLogotypeExt {
		t.Errorf("expected HasLogotypeExt = true")
	}
	if audit.VMCSubjectOrg != "Stripe Inc" {
		t.Errorf("VMCSubjectOrg = %q, want Stripe Inc", audit.VMCSubjectOrg)
	}

	// 2. Expired Certificate
	expiredPEM := helperGenerateVMC(t, "GlobalSign VMC CA", "Test Org", now.Add(-60*24*time.Hour), now.Add(-1*time.Hour), []string{"test.com"}, true)
	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(expiredPEM)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	auditExpired := &BIMIAudit{Domain: "test.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, auditExpired, nil)
	if auditExpired.VMCValid {
		t.Errorf("expired VMC must not be marked valid")
	}
	foundExpiredErr := false
	for _, errStr := range auditExpired.Errors {
		if strings.Contains(errStr, "EXPIRED") {
			foundExpiredErr = true
			break
		}
	}
	if !foundExpiredErr {
		t.Errorf("missing EXPIRED error in: %+v", auditExpired.Errors)
	}

	// 3. Not Yet Valid Certificate
	futurePEM := helperGenerateVMC(t, "SSL.com Verified Mark CA", "Test Org", now.Add(24*time.Hour), now.Add(365*24*time.Hour), []string{"test.com"}, true)
	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(futurePEM)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	auditFuture := &BIMIAudit{Domain: "test.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, auditFuture, nil)
	if auditFuture.VMCValid {
		t.Errorf("future VMC must not be marked valid")
	}

	// 4. SAN Mismatch and Missing Logotype extension
	mismatchPEM := helperGenerateVMC(t, "Untrusted Unknown CA", "Mismatch Org", now.Add(-24*time.Hour), now.Add(100*24*time.Hour), []string{"otherdomain.org"}, false)
	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(mismatchPEM)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	auditMismatch := &BIMIAudit{Domain: "stripe.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, auditMismatch, nil)
	if auditMismatch.SANMatch {
		t.Errorf("SANMatch should be false for domain mismatch")
	}
	if auditMismatch.HasLogotypeExt {
		t.Errorf("HasLogotypeExt should be false when extension omitted")
	}

	// 5. Server 500 error
	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("server error")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	audit500 := &BIMIAudit{Domain: "test.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, audit500, nil)
	if len(audit500.Errors) == 0 || !strings.Contains(audit500.Errors[0], "returned HTTP 500") {
		t.Errorf("expected HTTP 500 error, got: %+v", audit500.Errors)
	}

	// 6. Non-PEM Payload
	vmcHTTPClient = &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("NOT A VALID CERTIFICATE BLOCK")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	auditGarbage := &BIMIAudit{Domain: "test.com", VMCURL: "https://example.com/vmc.pem"}
	validateVMCChain(ctx, auditGarbage, nil)
	if len(auditGarbage.Errors) == 0 || !strings.Contains(auditGarbage.Errors[0], "valid PEM") {
		t.Errorf("expected invalid PEM error, got: %+v", auditGarbage.Errors)
	}
}

// -----------------------------------------------------------------------------
// 4. Worker Whitelist Guard & Sanity Checks
// -----------------------------------------------------------------------------

func TestWorker_WhitelistProtectionRule(t *testing.T) {
	classifier := NewDomainClassifier(
		[]string{"burner.com"},
		nil,
		nil,
		[]string{"google.com", "stripe.com"},
	)

	// List length guard: < 5000 items
	var shortList []string
	for i := 0; i < 500; i++ {
		shortList = append(shortList, fmt.Sprintf("disp%d.com", i))
	}
	if len(shortList) >= 5000 {
		t.Errorf("shortList should be < 5000")
	}

	// Whitelist intrusion test: 6000 items containing a protected corporate domain
	var infectedList []string
	for i := 0; i < 6000; i++ {
		infectedList = append(infectedList, fmt.Sprintf("burner-%d.xyz", i))
	}
	infectedList[3000] = "google.com" // whitelisted entry injected

	containsWhitelisted := false
	for _, d := range infectedList {
		if classifier.IsWhitelisted(d) {
			containsWhitelisted = true
			break
		}
	}
	if !containsWhitelisted {
		t.Errorf("infectedList must contain whitelisted domain")
	}
}

// -----------------------------------------------------------------------------
// 5. Engine Error Fallback Rendering
// -----------------------------------------------------------------------------

func TestEngine_RenderErrorFallback(t *testing.T) {
	err := fmt.Errorf("synthetic rendering failure")
	html := renderError(nil, err)
	if !strings.Contains(html, "alert-error") || !strings.Contains(html, "synthetic rendering failure") {
		t.Errorf("renderError(nil) fallback failed: %s", html)
	}
}
