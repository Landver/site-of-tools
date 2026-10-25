package tests

import "testing"

// required holds only required args, so optional ones default; a one-of input gets the smallest.
var required = map[string]map[string]any{
	"ip_lookup":           {"ip": "8.8.8.8"},
	"ip_cidr":             {"cidr": "192.168.1.0/24"},
	"dns_lookup":          {"name": "example.com"},
	"dns_consistency":     {"name": "example.com"},
	"dns_trace":           {"name": "example.com"},
	"dns_domain_info":     {"name": "example.com"},
	"link_inspect":        {"url": "https://example.com/?a=1"},
	"link_clean":          {"url": "https://example.com/?utm_source=x&a=1"},
	"link_tracking_rules": {},
	"link_diff":           {"url_a": "https://example.com/?a=1", "url_b": "https://example.com/?a=2"},
	"link_redirect_chain": {"url": "http://127.0.0.1/"},
	"link_curl_parse":     {"command": "curl https://example.com/"},
	"link_extract":        {"text": "see https://example.com/"},
	"link_utm":            {"url": "https://example.com/"},
	"link_percent_encode": {"value": "a b"},
	"link_headers_parse":  {"headers": "HTTP/1.1 200 OK\nCache-Control: public, max-age=3600"},

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
	"cipher_identify":        {"text": "abc"},
	"cipher_pkce_generate":   {},
	"cipher_pkce_verify":     {"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	"cipher_dpop_generate":   {"htm": "GET", "htu": "https://api.example.com/resource"},
	"cipher_dpop_verify":     {"token": testDPoPToken(), "htm": "GET", "htu": "https://api.example.com/resource"},

	"mail_dmarc_parse":     {"xml": "<feedback><report_metadata><org_name>test</org_name></report_metadata><policy_published><domain>test.com</domain></policy_published></feedback>"},
	"mail_bimi_validate":   {"svg": `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>`},
	"mail_classify_domain": {"domain": "test@gmail.com"},

	"botcheck_score": {"ip": "8.8.8.8"},
	"site_blog":      {},
}

// TestEveryToolAnswersAnObject; link_short_resolve needs a store and link_headers_inspect a reachable
// URL, so TestShortLinksLive and linktools' TestProbeHeadersLiveAndETag cover them.
func TestEveryToolAnswersAnObject(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	for _, name := range toolNames(t, cs) {
		args, ok := required[name]
		if !ok {
			if name != "link_short_resolve" && name != "link_headers_inspect" {
				t.Errorf("%s has no entry here", name)
			}
			continue
		}
		object(t, call(t, cs, name, args))
	}
}
