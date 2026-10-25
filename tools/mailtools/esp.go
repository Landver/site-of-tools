package mailtools

import (
	"net/netip"
	"strings"
)

// ESPInfo identifies a known Email Service Provider or mailbox provider.
type ESPInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "mailbox", "esp", "self-hosted"
	Icon     string `json:"icon"`     // short text badge
}

type espRange struct {
	info     ESPInfo
	prefixes []netip.Prefix
}

// Ranges from each provider's published SPF record, read 2026-10-25 (host noted per row).
var espRanges = []espRange{
	{ESPInfo{"Google Workspace / Gmail", "mailbox", "Google"}, // _spf.google.com
		prefixes("74.125.0.0/16 209.85.128.0/17 2001:4860:4864::/56 2404:6800:4864::/56 2607:f8b0:4864::/56 2800:3f0:4864::/56 2a00:1450:4864::/56 2c0f:fb50:4864::/56")},
	{ESPInfo{"Microsoft 365 / Outlook", "mailbox", "Microsoft"}, // spf.protection.outlook.com
		prefixes("40.92.0.0/15 40.107.0.0/16 52.100.0.0/15 52.102.0.0/16 52.103.0.0/17 104.47.0.0/17 2a01:111:f400::/48 2a01:111:f403::/49 2a01:111:f403:8000::/51 2a01:111:f403:c000::/51 2a01:111:f403:f000::/52")},
	{ESPInfo{"Amazon SES", "esp", "AWS"}, // amazonses.com
		prefixes("199.255.192.0/22 199.127.232.0/22 54.240.0.0/18 69.169.224.0/20 23.249.208.0/20 23.251.224.0/19 76.223.176.0/20 54.240.64.0/18 76.223.128.0/19 216.221.160.0/19 206.55.144.0/20 24.110.64.0/18 98.77.0.0/16")},
	{ESPInfo{"SendGrid (Twilio)", "esp", "SendGrid"}, // sendgrid.net, ab.sendgrid.net
		prefixes("167.89.0.0/17 208.117.48.0/20 50.31.32.0/19 198.37.144.0/20 198.21.0.0/21 192.254.112.0/20 168.245.0.0/17 149.72.0.0/16 159.183.0.0/16 134.128.64.0/18 159.26.176.0/20 223.165.113.0/24 223.165.115.0/24 223.165.118.0/23 223.165.120.0/23")},
	{ESPInfo{"Mailgun (Sinch)", "esp", "Mailgun"}, // _spf1, _spf2 and _spf.eu.mailgun.org
		prefixes("159.135.224.0/20 69.72.32.0/20 204.220.90.0/23 204.220.92.0/22 161.38.192.0/20 143.55.224.0/21 143.55.232.0/22 159.112.240.0/20 198.244.48.0/20 204.220.168.0/21 204.220.176.0/20 141.193.32.0/23 159.135.140.80/29 159.135.132.128/25 161.38.204.0/22 87.253.232.0/21 185.189.236.0/22 185.211.120.0/22 185.250.236.0/22 143.55.236.0/22 198.244.60.0/22 204.220.160.0/20")},
	{ESPInfo{"Postmark (ActiveCampaign)", "esp", "Postmark"}, // spf.mtasv.net
		prefixes("50.31.156.96/27 104.245.209.192/26 50.31.205.0/24 147.160.158.0/24")},
	{ESPInfo{"Mailchimp / Mandrill", "esp", "Mailchimp"}, // spf.mandrillapp.com
		prefixes("198.2.128.0/24 198.2.132.0/22 198.2.136.0/23 198.2.145.0/24 198.2.186.0/23 205.201.131.0/24 205.201.134.128/25 205.201.136.0/23 205.201.139.0/24 198.2.177.0/24 198.2.178.0/23 198.2.180.0/24")},
	{ESPInfo{"Brevo", "esp", "Brevo"}, // spf.brevo.com
		prefixes("185.41.28.0/22 94.143.16.0/21 185.24.144.0/22 153.92.224.0/19 213.32.128.0/18 185.107.232.0/22 77.32.128.0/18 77.32.192.0/19 212.146.192.0/18 172.246.0.0/18")},
	{ESPInfo{"Proton Mail", "mailbox", "Proton"}, // _spf.protonmail.ch, _spf2.protonmail.ch
		prefixes("185.70.40.0/24 185.70.41.0/24 185.70.43.0/24 79.135.106.0/24 79.135.107.0/24 109.224.244.0/24 85.9.206.169/32 85.9.210.45/32 37.187.220.204/32 51.83.17.38/32 57.129.93.249/32")},
	{ESPInfo{"Fastmail", "mailbox", "Fastmail"}, // spf.messagingengine.com
		prefixes("103.168.172.128/27 202.12.124.128/27 204.75.18.128/27")},
}

func prefixes(list string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range strings.Fields(list) {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// IdentifyESP classifies a sending IP by the providers' published ranges.
func IdentifyESP(ip string) ESPInfo {
	// An unparsable IP is the zero Addr, which no prefix contains.
	addr, _ := netip.ParseAddr(ip)
	addr = addr.Unmap()
	for _, r := range espRanges {
		for _, p := range r.prefixes {
			if p.Contains(addr) {
				return r.info
			}
		}
	}
	if addr.IsLoopback() || addr.IsPrivate() {
		return ESPInfo{Name: "Internal / Private IP", Category: "self-hosted", Icon: "Private"}
	}
	return ESPInfo{Name: "Unknown Sender", Category: "self-hosted", Icon: "Unknown"}
}
