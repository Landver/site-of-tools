package tests

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

const benchDMARCXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>987654321</report_id>
    <date_range><begin>1672531200</begin><end>1672617600</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><pct>100</pct></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>10</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>20230601</selector></dkim>
      <spf><domain>example.com</domain><result>pass</result><scope>mfrom</scope></spf>
    </auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.99</source_ip><count>2</count><policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>spoofed.net</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`

const benchBIMIValid = `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="45" fill="#b83266"/>
  <path d="M 30 50 L 45 65 L 70 35" stroke="#ffffff" stroke-width="6" fill="none"/>
</svg>`

const benchBIMINeedsFix = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="100" onload="alert(1)">
  <script>console.log("bad");</script>
  <rect width="200" height="100" fill="#3b82f6"/>
</svg>`

const benchARCHeaders = `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=abcd1234
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=origin.example; s=arc; bh=hash123; h=from:to; b=sig123
ARC-Authentication-Results: i=1; mx.origin.example; dkim=pass header.i=@origin.example; spf=pass (203.0.113.1)
ARC-Seal: i=2; a=rsa-sha256; d=list.example; s=arc; cv=pass; b=efgh5678
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=list.example; s=arc; bh=hash456; h=from:to; b=sig456
ARC-Authentication-Results: i=2; mx.list.example; arc=pass (as.1.origin.example=pass); dkim=pass header.i=@origin.example; spf=pass`

func BenchmarkParseDMARCReport_XML(b *testing.B) {
	data := []byte(benchDMARCXML)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mailtools.ParseDMARCReport(bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDMARCReport_Gzip(b *testing.B) {
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write([]byte(benchDMARCXML))
	gw.Close()
	gzData := gzBuf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mailtools.ParseDMARCReport(bytes.NewReader(gzData))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDMARCReport_RecordLimit(b *testing.B) {
	data := []byte(dmarcReportXML(5000))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := mailtools.ParseDMARCReport(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDMARCReport_GzipBomb(b *testing.B) {
	data := gzipped(b, dmarcReportXML(28000))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := mailtools.ParseDMARCReport(bytes.NewReader(data)); err == nil {
			b.Fatal("oversized report parsed")
		}
	}
}

func BenchmarkValidateBIMI(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mailtools.ValidateBIMI(benchBIMIValid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAutoFixBIMI(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mailtools.AutoFixBIMI(benchBIMINeedsFix)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeARC(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mailtools.AnalyzeARC(benchARCHeaders)
		if err != nil {
			b.Fatal(err)
		}
	}
}
