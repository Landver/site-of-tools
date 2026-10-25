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
	Domain             string        `json:"domain"`
	Vendor             GatewayVendor `json:"vendor"`
	Confidence         string        `json:"confidence"` // High, Medium, Low
	MXRecords          []MXRecord    `json:"mx_records"`
	HasRedundancy      bool          `json:"has_redundancy"`
	HasDirectMXRisk    bool          `json:"has_direct_mx_risk"`
	DirectMXWarning    string        `json:"direct_mx_warning,omitempty"`
	IsNullMX           bool          `json:"is_null_mx"`
	SecurityFeatures   []string      `json:"security_features,omitempty"`
}

type vendorSignature struct {
	vendor   GatewayVendor
	patterns []string
	features []string
}

var vendorSignatures = []vendorSignature{
	{
		vendor: VendorProofpoint,
		patterns: []string{"pphosted.com", "pph-", "proofpoint.com"},
		features: []string{"Targeted Attack Protection (TAP)", "Attachment Sandboxing", "URL Defense", "DMARC Inbound Enforcement"},
	},
	{
		vendor: VendorMimecast,
		patterns: []string{"mimecast.com", "mimecast-offence.com"},
		features: []string{"Targeted Threat Protection (TTP)", "Attachment Protect", "URL Protect", "Impersonation Protect"},
	},
	{
		vendor: VendorMicrosoft,
		patterns: []string{"mail.protection.outlook.com"},
		features: []string{"Exchange Online Protection (EOP)", "Defender for Office 365", "Safe Links", "Safe Attachments", "Anti-Phishing"},
	},
	{
		vendor: VendorGoogle,
		patterns: []string{"smtp.google.com", "aspmx.l.google.com", "googlemail.com", "aspmx2.googlemail.com", "aspmx3.googlemail.com", ".google.com"},
		features: []string{"Google Workspace Anti-Spam", "DKIM/DMARC Verification", "Phishing & Malware Protection", "ARC Authentication"},
	},
	{
		vendor: VendorCisco,
		patterns: []string{"iphmx.com", "ironport.com"},
		features: []string{"Cisco Talos Threat Intelligence", "Outbreak Filters", "Advanced Malware Protection (AMP)", "SpamCop Telemetry"},
	},
	{
		vendor: VendorBarracuda,
		patterns: []string{"barracudanetworks.com", "barracuda.com", "ess.barracuda.com"},
		features: []string{"Barracuda Real-Time Reputation (BRBL)", "Spam & Virus Firewall", "Email Threat Scanner", "Link Protection"},
	},
	{
		vendor: VendorSophos,
		patterns: []string{"hydra.sophos.com", "sophos.com"},
		features: []string{"SophosLabs Telemetry", "Deep Learning AI Malware Detection", "Time-of-Click URL Protection"},
	},
	{
		vendor: VendorTrendMicro,
		patterns: []string{"trendmicro.com", "tmes.trendmicro.com"},
		features: []string{"Trend Micro Smart Protection Network", "Pre-execution Machine Learning", "Predictive Machine Learning"},
	},
	{
		vendor: VendorFortinet,
		patterns: []string{"fortimail.com"},
		features: []string{"FortiGuard Antispam", "FortiSandbox Integration", "Outbreak Prevention"},
	},
	{
		vendor: VendorHornet,
		patterns: []string{"hornetsecurity.com", "antispameurope.com"},
		features: []string{"Advanced Threat Protection (ATP)", "Spear Phishing Protection", "Spam & Malware Filter"},
	},
}

// DetectGateway resolves and audits the Secure Email Gateway for a domain.
func DetectGateway(ctx context.Context, domain string) (*GatewayAudit, error) {
	domain = ExtractDomain(domain)
	audit := &GatewayAudit{
		Domain: domain,
		Vendor: VendorGeneric,
		Confidence: "Low",
	}

	r := &net.Resolver{}
	netMXs, err := r.LookupMX(ctx, domain)
	if err != nil {
		// If domain has no MX, check if fallback to A record exists or error out
		return audit, err
	}

	if len(netMXs) == 0 {
		return audit, nil
	}

	// Sort MX by preference (lowest preference number = highest priority)
	slices.SortFunc(netMXs, func(a, b *net.MX) int {
		return cmp.Compare(a.Pref, b.Pref)
	})

	for _, m := range netMXs {
		host := strings.TrimSuffix(strings.ToLower(m.Host), ".")
		audit.MXRecords = append(audit.MXRecords, MXRecord{
			Host: host,
			Pref: m.Pref,
		})
	}

	// RFC 7505 Null MX Check: "0 ."
	if len(audit.MXRecords) == 1 && (audit.MXRecords[0].Host == "" || audit.MXRecords[0].Host == ".") && audit.MXRecords[0].Pref == 0 {
		audit.Vendor = VendorNullMX
		audit.Confidence = "High"
		audit.IsNullMX = true
		return audit, nil
	}

	audit.HasRedundancy = len(audit.MXRecords) > 1

	// Fingerprint primary and backup gateways
	var primaryVendor GatewayVendor
	var backupVendors []GatewayVendor

	for i, mx := range audit.MXRecords {
		v, features := matchVendor(mx.Host)
		if i == 0 {
			primaryVendor = v
			if v != VendorGeneric {
				audit.Vendor = v
				audit.Confidence = "High"
				audit.SecurityFeatures = features
			}
		} else {
			backupVendors = append(backupVendors, v)
		}
	}

	// Direct-to-MX Bypass Vulnerability Detection:
	// If primary MX is protected by a commercial SEG (e.g. Proofpoint) but a backup/fallback MX
	// points directly to self-hosted server or a different unhardened provider.
	if primaryVendor != VendorGeneric && primaryVendor != VendorNullMX {
		for _, bv := range backupVendors {
			if bv != primaryVendor {
				audit.HasDirectMXRisk = true
				audit.DirectMXWarning = "Mixed MX providers detected: backup MX may allow attackers to bypass primary security gateway (" + string(primaryVendor) + ") via direct-to-MX routing."
				break
			}
		}
	}

	return audit, nil
}

func matchVendor(host string) (GatewayVendor, []string) {
	for _, sig := range vendorSignatures {
		for _, pat := range sig.patterns {
			if strings.Contains(host, pat) {
				return sig.vendor, append([]string(nil), sig.features...)
			}
		}
	}
	return VendorGeneric, []string{"Standard SMTP / TLS Encryption", "Basic MTA Protocol Compliance"}
}
