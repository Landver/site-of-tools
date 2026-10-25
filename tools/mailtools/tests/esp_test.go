package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func TestIdentifyESP(t *testing.T) {
	tests := []struct {
		ip       string
		wantName string
		wantCat  string
	}{
		{"209.85.220.41", "Google Workspace / Gmail", "mailbox"},
		{"74.125.82.49", "Google Workspace / Gmail", "mailbox"},
		{"2607:f8b0:4864:20::42f", "Google Workspace / Gmail", "mailbox"},
		{"::ffff:209.85.220.41", "Google Workspace / Gmail", "mailbox"},
		{"40.107.22.51", "Microsoft 365 / Outlook", "mailbox"},
		{"40.92.74.89", "Microsoft 365 / Outlook", "mailbox"},
		{"2a01:111:f403:c200::1", "Microsoft 365 / Outlook", "mailbox"},
		{"54.240.8.1", "Amazon SES", "esp"},
		{"23.251.224.10", "Amazon SES", "esp"},
		{"167.89.1.1", "SendGrid (Twilio)", "esp"},
		{"223.165.118.7", "SendGrid (Twilio)", "esp"},
		{"159.135.224.5", "Mailgun (Sinch)", "esp"},
		{"185.250.236.5", "Mailgun (Sinch)", "esp"},
		{"50.31.156.100", "Postmark (ActiveCampaign)", "esp"},
		{"198.2.132.10", "Mailchimp / Mandrill", "esp"},
		{"205.201.131.20", "Mailchimp / Mandrill", "esp"},
		{"198.2.180.5", "Mailchimp / Mandrill", "esp"},
		{"185.41.28.10", "Brevo", "esp"},
		{"77.32.150.1", "Brevo", "esp"},
		{"185.70.40.12", "Proton Mail", "mailbox"},
		{"85.9.206.169", "Proton Mail", "mailbox"},
		{"103.168.172.130", "Fastmail", "mailbox"},
		{"202.12.124.140", "Fastmail", "mailbox"},
		// Loopback and private ranges
		{"127.0.0.1", "Internal / Private IP", "self-hosted"},
		{"10.0.5.20", "Internal / Private IP", "self-hosted"},
		{"192.168.1.100", "Internal / Private IP", "self-hosted"},
		{"172.16.4.1", "Internal / Private IP", "self-hosted"},
		{"::1", "Internal / Private IP", "self-hosted"},
		{"fd00::1", "Internal / Private IP", "self-hosted"},
		// Outside every published range, or not an IP at all
		{"203.0.113.11", "Unknown Sender", "self-hosted"},
		{"209.85.127.255", "Unknown Sender", "self-hosted"},
		{"", "Unknown Sender", "self-hosted"},
		{"mail.corporategateway.corp", "Unknown Sender", "self-hosted"},
	}

	for _, tt := range tests {
		info := mailtools.IdentifyESP(tt.ip)
		if info.Name != tt.wantName || info.Category != tt.wantCat {
			t.Errorf("IdentifyESP(%q) = %+v, want Name=%q Category=%q", tt.ip, info, tt.wantName, tt.wantCat)
		}
	}
}
