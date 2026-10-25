package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const dmarcReport = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>1001</report_id></report_metadata>
  <policy_published><domain>corpberry.com</domain><p>reject</p></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>corpberry.com</header_from></identifiers>
  </record>
</feedback>`

const (
	tinySVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title><circle cx="50" cy="50" r="40" fill="red"/>
</svg>`
	badSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" onload="alert(1)">
  <script>evil()</script><rect width="200" height="100"/>
</svg>`
	arcChain = `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=sig1
ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=sig2
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass`
	arcPassFirst = `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=pass; b=sig1
ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=sig2
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass`
)

func base64Of(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func gzipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestMailParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp/mail", nil, nil)
	q := url.QueryEscape
	cases := []struct {
		tool                 string
		args                 map[string]any
		method, target, form string
	}{
		{"mail_dmarc_parse", map[string]any{"xml": dmarcReport, "detailed": true}, http.MethodPost, "/dmarc/parse", "xml=" + q(dmarcReport)},
		{"mail_bimi_validate", map[string]any{"svg": tinySVG}, http.MethodPost, "/bimi", "svg=" + q(tinySVG)},
		{"mail_bimi_validate", map[string]any{"svg": badSVG}, http.MethodPost, "/bimi", "svg=" + q(badSVG)},
		{"mail_arc_analyze", map[string]any{"headers": arcChain}, http.MethodPost, "/arc/parse", "headers=" + q(arcChain)},
		{"mail_classify_domain", map[string]any{"domain": "someone@mailinator.com"}, http.MethodGet, "/disposable?domain=" + q("someone@mailinator.com"), ""},
		{"mail_classify_domain", map[string]any{"domain": "alex@gmail.com"}, http.MethodGet, "/classifier?domain=" + q("alex@gmail.com"), ""},
	}
	for _, tc := range cases {
		got := object(t, call(t, cs, tc.tool, tc.args))
		want := s.rest(t, mailHost, tc.method, tc.target, tc.form)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s %.60v vs REST %s (-rest +mcp):\n%s", tc.tool, tc.args, tc.target, diff)
		}
	}
}

func TestMailResults(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)
	cases := []struct {
		name, tool string
		args       map[string]any
		want       map[string]string
	}{
		{"dmarc as xml", "mail_dmarc_parse", map[string]any{"xml": dmarcReport}, map[string]string{"org_name": "google.com", "total_messages": "10"}},
		{"dmarc xml bytes as base64", "mail_dmarc_parse", map[string]any{"base64": base64Of([]byte(dmarcReport))}, map[string]string{"domain": "corpberry.com"}},
		{"dmarc gzip as base64", "mail_dmarc_parse", map[string]any{"base64": base64Of(gzipped(dmarcReport))}, map[string]string{"org_name": "google.com"}},
		{"bimi compliant", "mail_bimi_validate", map[string]any{"svg": tinySVG}, map[string]string{"compliant": "true"}},
		{"bimi not compliant", "mail_bimi_validate", map[string]any{"svg": badSVG}, map[string]string{"compliant": "false"}},
		{"arc intact", "mail_arc_analyze", map[string]any{"headers": arcChain}, map[string]string{"chain_valid": "true", "final_chain_validation": "none"}},
		{"arc cv=pass on the first hop", "mail_arc_analyze", map[string]any{"headers": arcPassFirst}, map[string]string{"chain_valid": "false"}},
		{"disposable", "mail_classify_domain", map[string]any{"domain": "test@mailinator.com"}, map[string]string{"is_disposable": "true", "type": "disposable"}},
		{"corporate", "mail_classify_domain", map[string]any{"domain": "stripe.com"}, map[string]string{"is_disposable": "false", "type": "corporate"}},
		{"free webmail", "mail_classify_domain", map[string]any{"domain": "alex@gmail.com"}, map[string]string{"is_freemail": "true", "type": "freemail"}},
	}
	for _, tc := range cases {
		got := object(t, call(t, cs, tc.tool, tc.args))
		for k, want := range tc.want {
			if fmt.Sprint(got[k]) != want {
				t.Errorf("%s: %s = %v, want %s", tc.name, k, got[k], want)
			}
		}
	}

	failsWith(t, call(t, cs, "mail_dmarc_parse", map[string]any{}), "provide either xml or base64")
	failsWith(t, call(t, cs, "mail_dmarc_parse", map[string]any{"xml": base64Of([]byte(dmarcReport))}), "XML")

	fixed := object(t, call(t, cs, "mail_bimi_validate", map[string]any{"svg": badSVG}))["auto_fixed_svg"].(string)
	if !strings.Contains(fixed, `baseProfile="tiny-ps"`) || !strings.Contains(fixed, `viewBox="0 -50 200 200"`) {
		t.Errorf("auto_fixed_svg doesn't fix the root:\n%s", fixed)
	}
}

func TestDMARCIsConciseByDefault(t *testing.T) {
	var rows strings.Builder
	for i := range 40 {
		fmt.Fprintf(&rows, `<record><row><source_ip>198.51.100.%d</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>corpberry.com</header_from></identifiers></record>`, i)
	}
	report := strings.Replace(dmarcReport, "</feedback>", rows.String()+"</feedback>", 1)
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)

	concise := object(t, call(t, cs, "mail_dmarc_parse", map[string]any{"xml": report}))
	if _, ok := concise["records"]; ok || len(concise["sources"].([]any)) != 30 || concise["sources_truncated"] != true {
		t.Errorf("concise: records present %v, %d sources, truncated %v; want no records, 30 sources, truncated",
			concise["records"] != nil, len(concise["sources"].([]any)), concise["sources_truncated"])
	}
	detailed := object(t, call(t, cs, "mail_dmarc_parse", map[string]any{"xml": report, "detailed": true}))
	if len(detailed["records"].([]any)) != 41 || len(detailed["sources"].([]any)) != 41 {
		t.Errorf("detailed: %d records, %d sources, want 41 of each", len(detailed["records"].([]any)), len(detailed["sources"].([]any)))
	}
}

// TestMailNetworkToolsLive: these two query public DNS, so they need the network and skip without it.
func TestMailNetworkToolsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("live DNS")
	}
	if _, err := net.LookupMX("google.com"); err != nil {
		t.Skipf("outbound DNS unavailable: %v", err)
	}
	cs := newStack(t, stackOpts{mail: mailService()}).client(t, "/mcp", nil, nil)
	if health := object(t, call(t, cs, "mail_domain_health", map[string]any{"domain": "google.com"})); health["domain"] != "google.com" {
		t.Errorf("mail_domain_health domain = %v", health["domain"])
	}
	if list := object(t, call(t, cs, "mail_check_dnsbl", map[string]any{"target": "127.0.0.2"})); list["target"] != "127.0.0.2" {
		t.Errorf("mail_check_dnsbl target = %v", list["target"])
	}
}
