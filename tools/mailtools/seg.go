package mailtools

import (
	"cmp"
	"context"
	"net"
	"slices"
	"strings"
)

// GatewayVendor represents an enterprise secure email gateway or cloud mail provider.
type GatewayVendor string

const (
	VendorProofpoint GatewayVendor = "Proofpoint Enterprise TAP"
	VendorMimecast   GatewayVendor = "Mimecast Secure Email Gateway"
	VendorMicrosoft  GatewayVendor = "Microsoft 365 Defender / EOP"
	VendorGoogle     GatewayVendor = "Google Workspace Inbound Gateway"
	VendorCisco      GatewayVendor = "Cisco Secure Email (IronPort)"
	VendorBarracuda  GatewayVendor = "Barracuda Email Security Gateway"
	VendorSophos     GatewayVendor = "Sophos Email Protection"
	VendorTrendMicro GatewayVendor = "Trend Micro Email Security"
	VendorFortinet   GatewayVendor = "Fortinet FortiMail"
	VendorHornet     GatewayVendor = "Hornetsecurity"
	VendorGeneric    GatewayVendor = "Self-Hosted / Direct MTA"
	VendorNullMX     GatewayVendor = "Null MX (RFC 7505 - Rejects All Mail)"
)

// MXRecord represents an analyzed MX record.
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// GatewayAudit contains the fingerprint and routing security analysis for a domain's MX records.
type GatewayAudit struct {
	Domain           string        `json:"domain"`
	Vendor           GatewayVendor `json:"vendor"`
	Confidence       string        `json:"confidence"` // High, Medium, Low
	MXRecords        []MXRecord    `json:"mx_records"`
	HasRedundancy    bool          `json:"has_redundancy"`
	HasDirectMXRisk  bool          `json:"has_direct_mx_risk"`
	DirectMXWarning  string        `json:"direct_mx_warning,omitempty"`
	IsNullMX         bool          `json:"is_null_mx"`
	SecurityFeatures []string      `json:"security_features,omitempty"`
}

type vendorSignature struct {
	vendor   GatewayVendor
	patterns []string
	features []string
	// distributed: one MX name fronts a fleet, so a single record is still redundant.
	distributed bool
}

var vendorSignatures = []vendorSignature{
	{
		vendor:      VendorProofpoint,
		patterns:    []string{"pphosted.com", "pph-", "proofpoint.com"},
		features:    []string{"Targeted Attack Protection (TAP)", "Attachment Sandboxing", "URL Defense", "DMARC Inbound Enforcement"},
		distributed: true,
	},
	{
		vendor:      VendorMimecast,
		patterns:    []string{"mimecast.com", "mimecast-offence.com"},
		features:    []string{"Targeted Threat Protection (TTP)", "Attachment Protect", "URL Protect", "Impersonation Protect"},
		distributed: true,
	},
	{
		vendor:      VendorMicrosoft,
		patterns:    []string{"mail.protection.outlook.com"},
		features:    []string{"Exchange Online Protection (EOP)", "Defender for Office 365", "Safe Links", "Safe Attachments", "Anti-Phishing"},
		distributed: true,
	},
	{
		vendor:      VendorGoogle,
		patterns:    []string{"smtp.google.com", "aspmx.l.google.com", "googlemail.com", "aspmx2.googlemail.com", "aspmx3.googlemail.com", ".google.com"},
		features:    []string{"Google Workspace Anti-Spam", "DKIM/DMARC Verification", "Phishing & Malware Protection", "ARC Authentication"},
		distributed: true,
	},
	{
		vendor:   VendorCisco,
		patterns: []string{"iphmx.com", "ironport.com"},
		features: []string{"Cisco Talos Threat Intelligence", "Outbreak Filters", "Advanced Malware Protection (AMP)", "SpamCop Telemetry"},
	},
	{
		vendor:   VendorBarracuda,
		patterns: []string{"barracudanetworks.com", "barracuda.com", "ess.barracuda.com"},
		features: []string{"Barracuda Real-Time Reputation (BRBL)", "Spam & Virus Firewall", "Email Threat Scanner", "Link Protection"},
	},
	{
		vendor:   VendorSophos,
		patterns: []string{"hydra.sophos.com", "sophos.com"},
		features: []string{"SophosLabs Telemetry", "Deep Learning AI Malware Detection", "Time-of-Click URL Protection"},
	},
	{
		vendor:   VendorTrendMicro,
		patterns: []string{"trendmicro.com", "tmes.trendmicro.com"},
		features: []string{"Trend Micro Smart Protection Network", "Pre-execution Machine Learning", "Predictive Machine Learning"},
	},
	{
		vendor:   VendorFortinet,
		patterns: []string{"fortimail.com"},
		features: []string{"FortiGuard Antispam", "FortiSandbox Integration", "Outbreak Prevention"},
	},
	{
		vendor:   VendorHornet,
		patterns: []string{"hornetsecurity.com", "antispameurope.com"},
		features: []string{"Advanced Threat Protection (ATP)", "Spear Phishing Protection", "Spam & Malware Filter"},
	},
}

// DetectGateway resolves and audits the Secure Email Gateway for a domain.
func DetectGateway(ctx context.Context, domain string) (*GatewayAudit, error) {
	domain = ExtractDomain(domain)
	mx, err := lookupMX(ctx, domain)
	return gatewayAudit(domain, mx), err
}

// lookupMX returns a domain's MX records by preference, then host, lowercased and without the root dot.
func lookupMX(ctx context.Context, domain string) ([]MXRecord, error) {
	found, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	mx := make([]MXRecord, len(found))
	for i, m := range found {
		mx[i] = MXRecord{Host: strings.TrimSuffix(strings.ToLower(m.Host), "."), Pref: m.Pref}
	}
	slices.SortFunc(mx, func(a, b MXRecord) int {
		return cmp.Or(cmp.Compare(a.Pref, b.Pref), strings.Compare(a.Host, b.Host))
	})
	return mx, nil
}

func gatewayAudit(domain string, mx []MXRecord) *GatewayAudit {
	audit := &GatewayAudit{Domain: domain, Vendor: VendorGeneric, Confidence: "Low", MXRecords: mx}
	if len(mx) == 0 {
		return audit
	}
	// RFC 7505 null MX: the single record "0 .", whose host is empty once the root dot is gone.
	if len(mx) == 1 && mx[0].Host == "" && mx[0].Pref == 0 {
		audit.Vendor, audit.Confidence, audit.IsNullMX = VendorNullMX, "High", true
		return audit
	}

	primary := matchVendor(mx[0].Host)
	audit.HasRedundancy = len(mx) > 1 || primary.distributed
	if primary.vendor == VendorGeneric {
		return audit
	}
	audit.Vendor, audit.Confidence, audit.SecurityFeatures = primary.vendor, "High", slices.Clone(primary.features)
	// A backup MX on another provider lets mail reach the domain without passing the primary gateway.
	if slices.ContainsFunc(mx[1:], func(m MXRecord) bool { return matchVendor(m.Host).vendor != primary.vendor }) {
		audit.HasDirectMXRisk = true
		audit.DirectMXWarning = "Mixed MX providers detected: backup MX may allow attackers to bypass primary security gateway (" + string(primary.vendor) + ") via direct-to-MX routing."
	}
	return audit
}

func matchVendor(host string) vendorSignature {
	for _, sig := range vendorSignatures {
		for _, pat := range sig.patterns {
			if strings.Contains(host, pat) {
				return sig
			}
		}
	}
	return vendorSignature{vendor: VendorGeneric}
}
