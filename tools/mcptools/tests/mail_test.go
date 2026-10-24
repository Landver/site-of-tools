package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestMCP_MailDMARCParse(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)

	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
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

	// 1. Raw XML parameter
	resRaw := object(t, call(t, cs, "mail_dmarc_parse", map[string]any{"xml": xmlContent}))
	if resRaw["org_name"] != "google.com" || fmt.Sprint(resRaw["total_messages"]) != "10" {
		t.Errorf("mail_dmarc_parse raw XML result mismatch: %+v", resRaw)
	}

	// 2. Base64 encoded XML string inside xml argument
	b64XML := base64.StdEncoding.EncodeToString([]byte(xmlContent))
	resB64 := object(t, call(t, cs, "mail_dmarc_parse", map[string]any{"xml": b64XML}))
	if resB64["domain"] != "corpberry.com" {
		t.Errorf("mail_dmarc_parse b64 XML mismatch: %+v", resB64)
	}

	// 3. Base64-encoded gzip archive (.xml.gz) via base64 parameter
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write([]byte(xmlContent))
	gw.Close()
	b64Gz := base64.StdEncoding.EncodeToString(gzBuf.Bytes())

	resGz := object(t, call(t, cs, "mail_dmarc_parse", map[string]any{"base64": b64Gz}))
	if resGz["org_name"] != "google.com" {
		t.Errorf("mail_dmarc_parse gzip mismatch: %+v", resGz)
	}

	// 4. Missing both arguments fails
	failsWith(t, call(t, cs, "mail_dmarc_parse", map[string]any{}), "provide either xml or base64")
}

func TestMCP_MailBIMIValidateAndAutoFix(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)

	validSVG := `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <title>Logo</title><circle cx="50" cy="50" r="40" fill="red"/>
</svg>`

	badSVG := `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" onload="alert(1)">
  <script>evil()</script><rect width="200" height="100"/>
</svg>`

	// 1. Validate Compliant
	resVal := object(t, call(t, cs, "mail_bimi_validate", map[string]any{"svg": validSVG}))
	if resVal["compliant"] != true {
		t.Errorf("expected compliant: true, got: %+v", resVal)
	}

	// 2. Validate Non-Compliant
	resBad := object(t, call(t, cs, "mail_bimi_validate", map[string]any{"svg": badSVG}))
	if resBad["compliant"] == true {
		t.Errorf("expected compliant: false for bad SVG")
	}

	// 3. Auto-Fix
	resFix := object(t, call(t, cs, "mail_bimi_autofix", map[string]any{"svg": badSVG}))
	fixedSVG, ok := resFix["svg"].(string)
	if !ok || len(fixedSVG) == 0 {
		t.Fatalf("expected fixed svg string in result, got: %+v", resFix)
	}
	if !strings.Contains(fixedSVG, `baseProfile="tiny-ps"`) || strings.Contains(fixedSVG, "<script>") {
		t.Errorf("auto-fixed SVG did not remediate issues:\n%s", fixedSVG)
	}
}

func TestMCP_MailARCAnalyze(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp", nil, nil)

	validARC := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=sig1
ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=sig2
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass`

	res := object(t, call(t, cs, "mail_arc_analyze", map[string]any{"headers": validARC}))
	if res["chain_valid"] != true || res["final_chain_validation"] != "none" {
		t.Errorf("expected valid ARC chain, got: %+v", res)
	}

	// Broken ARC (cv=pass on initial hop)
	brokenARC := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=pass; b=sig1
ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=sig2
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass`

	resBroken := object(t, call(t, cs, "mail_arc_analyze", map[string]any{"headers": brokenARC}))
	if resBroken["chain_valid"] == true {
		t.Errorf("expected broken chain to be marked invalid")
	}
}
