package mailtools

import (
	"net"
	"strings"
)

// ESPInfo identifies a known Email Service Provider or mailbox provider.
type ESPInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "mailbox", "esp", "cloud", "self-hosted"
	Icon     string `json:"icon"`     // Simple text badge or emoji
}

// IdentifyESP matches an IP or PTR hostname against common email senders.
func IdentifyESP(ipStr, ptr string) ESPInfo {
	h := strings.ToLower(ptr)

	// Google / Gmail / Workspace
	if strings.Contains(h, "google.com") || strings.Contains(h, "googlemail.com") || strings.Contains(h, "1e100.net") {
		return ESPInfo{Name: "Google Workspace / Gmail", Category: "mailbox", Icon: "Google"}
	}

	// Microsoft 365 / Outlook
	if strings.Contains(h, "outbound.protection.outlook.com") || strings.Contains(h, "microsoft.com") || strings.Contains(h, "hotmail.com") {
		return ESPInfo{Name: "Microsoft 365 / Outlook", Category: "mailbox", Icon: "Microsoft"}
	}

	// Amazon SES
	if strings.Contains(h, "amazonses.com") || strings.Contains(h, "aws.com") {
		return ESPInfo{Name: "Amazon SES", Category: "esp", Icon: "AWS"}
	}

	// SendGrid / Twilio
	if strings.Contains(h, "sendgrid.net") {
		return ESPInfo{Name: "SendGrid (Twilio)", Category: "esp", Icon: "SendGrid"}
	}

	// Mailgun
	if strings.Contains(h, "mailgun.org") || strings.Contains(h, "mailgun.net") {
		return ESPInfo{Name: "Mailgun (Sinch)", Category: "esp", Icon: "Mailgun"}
	}

	// Postmark
	if strings.Contains(h, "postmarkapp.com") {
		return ESPInfo{Name: "Postmark (ActiveCampaign)", Category: "esp", Icon: "Postmark"}
	}

	// Brevo / Sendinblue
	if strings.Contains(h, "sendinblue.com") || strings.Contains(h, "brevo.com") {
		return ESPInfo{Name: "Brevo", Category: "esp", Icon: "Brevo"}
	}

	// Mailchimp / Mandrill
	if strings.Contains(h, "mcsv.net") || strings.Contains(h, "mandrillapp.com") || strings.Contains(h, "mailchimp.com") {
		return ESPInfo{Name: "Mailchimp / Mandrill", Category: "esp", Icon: "Mailchimp"}
	}

	// ProtonMail
	if strings.Contains(h, "protonmail.ch") || strings.Contains(h, "proton.me") {
		return ESPInfo{Name: "Proton Mail", Category: "mailbox", Icon: "Proton"}
	}

	// Yahoo / AOL
	if strings.Contains(h, "yahoo.com") || strings.Contains(h, "yahoodns.net") || strings.Contains(h, "aol.com") {
		return ESPInfo{Name: "Yahoo / AOL", Category: "mailbox", Icon: "Yahoo"}
	}

	// Apple iCloud
	if strings.Contains(h, "apple.com") || strings.Contains(h, "icloud.com") {
		return ESPInfo{Name: "Apple iCloud Mail", Category: "mailbox", Icon: "Apple"}
	}

	// Fastmail
	if strings.Contains(h, "fastmail.com") || strings.Contains(h, "messagingengine.com") {
		return ESPInfo{Name: "Fastmail", Category: "mailbox", Icon: "Fastmail"}
	}

	// Zoho
	if strings.Contains(h, "zoho.com") || strings.Contains(h, "transmail.net") {
		return ESPInfo{Name: "Zoho Mail", Category: "mailbox", Icon: "Zoho"}
	}

	// Check if IP is private or loopback
	if parsed := net.ParseIP(ipStr); parsed != nil {
		if parsed.IsLoopback() || parsed.IsPrivate() {
			return ESPInfo{Name: "Internal / Private IP", Category: "self-hosted", Icon: "Private"}
		}
	}

	if ptr != "" {
		return ESPInfo{Name: ptr, Category: "self-hosted", Icon: "Server"}
	}
	return ESPInfo{Name: "Unknown Sender", Category: "self-hosted", Icon: "Unknown"}
}
