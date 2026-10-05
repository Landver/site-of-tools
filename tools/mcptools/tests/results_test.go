package tests

import (
	"encoding/json"
	"testing"
)

// required holds each tool's required arguments and nothing else, so every
// optional one is left to its default. A tool with none that still needs an
// input (one of several) gets the smallest one.
var required = map[string]map[string]any{
	"ip_lookup":           {"ip": "8.8.8.8"},
	"ip_cidr":             {"cidr": "192.168.1.0/24"},
	"dns_lookup":          {"name": "example.com"},
	"dns_consistency":     {"name": "example.com"},
	"dns_trace":           {"name": "example.com"},
	"dns_domain_info":     {"name": "example.com"},
	"dns_email_auth":      {"name": "example.com"},
	"link_inspect":        {"url": "https://example.com/?a=1"},
	"link_clean":          {"url": "https://example.com/?utm_source=x&a=1"},
	"link_tracking_rules": {},
	"link_diff":           {"url_a": "https://example.com/?a=1", "url_b": "https://example.com/?a=2"},
	"link_redirect_chain": {"url": "http://127.0.0.1/"},
	"link_curl_parse":     {"command": "curl https://example.com/"},
	"link_curl_build":     {"url": "https://example.com/"},
	"link_extract":        {"text": "see https://example.com/"},
	"link_utm":            {"url": "https://example.com/"},
	"link_percent_encode": {"value": "a b"},

	"cipher_jwt_decode":      {"token": jwtioToken},
	"cipher_jwt_sign":        {"key": signKey},
	"cipher_hash":            {},
	"cipher_hmac":            {},
	"cipher_password_hash":   {},
	"cipher_password_verify": {"hash": hunter2Hash},
	"cipher_encrypt":         {},
	"cipher_keys_generate":   {},
	"cipher_keys_inspect":    {"key": rfcEdKey},
	"cipher_cert":            {"cert": func() string { pem, _ := testCert(); return pem }()},
	"cipher_totp":            {"secret": "JBSWY3DPEHPK3PXP"},
	"cipher_random":          {},
	"cipher_encode":          {"text": "abc"},
	"cipher_basic_auth":      {"user": "aladdin"},
	"cipher_identify":        {"text": "abc"},
	"botcheck_score":         {"ip": "8.8.8.8"},
	"site_blog":              {},
}

// TestEveryToolAnswersAnObject: structuredContent is a JSON object for every
// public tool with its optional arguments omitted. link_short_resolve answers
// only from a store, so TestShortLinksLive covers it.
func TestEveryToolAnswersAnObject(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	for _, name := range toolNames(t, cs) {
		args, ok := required[name]
		if !ok {
			if name != "link_short_resolve" {
				t.Errorf("%s has no entry here", name)
			}
			continue
		}
		res := call(t, cs, name, args)
		object(t, res)
		if raw, _ := json.Marshal(res.StructuredContent); raw[0] != '{' {
			t.Errorf("%s structuredContent = %.60s, want an object", name, raw)
		}
	}
}
