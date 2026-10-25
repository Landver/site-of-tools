package tests

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/shared"
	"github.com/Landver/site-of-tools/tools/mailtools"
)

func newMailApp(t *testing.T) *echo.Echo {
	t.Helper()
	r := platform.NewRenderer(false, nil,
		platform.TemplateSource{Embed: shared.Templates, DevDir: "shared/templates"},
		platform.TemplateSource{Embed: mailtools.Templates, DevDir: "tools/mailtools/templates"},
	)
	e := platform.NewApp(r, fstest.MapFS{}, false, nil)
	mailtools.Register(e, "https://mail.example", nil, nil, "", nil)
	return e
}

func TestDMARCXMLParsingAndGzip(t *testing.T) {
	xmlSample := `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>987654321</report_id>
    <date_range>
      <begin>1672531200</begin>
      <end>1672617600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <result>pass</result>
        <selector>20230601</selector>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
        <scope>mfrom</scope>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.99</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>spoofed.net</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>`

	// 1. Test parsing plain XML
	rep, err := mailtools.ParseDMARCReport(strings.NewReader(xmlSample))
	if err != nil {
		t.Fatalf("ParseDMARCReport plain XML failed: %v", err)
	}
	if rep.OrgName != "google.com" {
		t.Errorf("OrgName: want google.com, got %q", rep.OrgName)
	}
	if rep.Domain != "example.com" {
		t.Errorf("Domain: want example.com, got %q", rep.Domain)
	}
	if rep.TotalMessages != 12 {
		t.Errorf("TotalMessages: want 12, got %d", rep.TotalMessages)
	}
	if rep.PassCount != 10 {
		t.Errorf("PassCount: want 10, got %d", rep.PassCount)
	}
	if rep.RejectCnt != 2 {
		t.Errorf("RejectCnt: want 2, got %d", rep.RejectCnt)
	}
	if len(rep.Sources) != 2 {
		t.Fatalf("Sources: want 2, got %d", len(rep.Sources))
	}

	// 2. Test parsing gzip compressed XML (.xml.gz)
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write([]byte(xmlSample)); err != nil {
		t.Fatalf("writing gzip: %v", err)
	}
	gw.Close()

	repGz, err := mailtools.ParseDMARCReport(&gzBuf)
	if err != nil {
		t.Fatalf("ParseDMARCReport gzip failed: %v", err)
	}
	if repGz.TotalMessages != 12 || repGz.PassCount != 10 {
		t.Errorf("gzip parsed report mismatch: %+v", repGz)
	}
}

func TestARCChainAnalysis(t *testing.T) {
	validARC := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none;
 b=abcd1234
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=origin.example; s=arc;
 bh=hash123; h=from:to:subject; b=sig123
ARC-Authentication-Results: i=1; mx.origin.example;
 dkim=pass header.i=@origin.example;
 spf=pass (mx.origin.example: domain of sender@origin.example designates 203.0.113.1 as permitted sender)
ARC-Seal: i=2; a=rsa-sha256; d=list.example; s=arc; cv=pass;
 b=efgh5678
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=list.example; s=arc;
 bh=hash456; h=from:to:subject; b=sig456
ARC-Authentication-Results: i=2; mx.list.example;
 arc=pass (as.1.origin.example=pass ams.1.origin.example=pass);
 dkim=pass header.i=@origin.example`

	arc, err := mailtools.AnalyzeARC(validARC)
	if err != nil {
		t.Fatalf("AnalyzeARC failed: %v", err)
	}
	if !arc.ChainValid {
		t.Errorf("expected valid chain, got: %+v", arc.Findings)
	}
	if arc.ChainLength != 2 {
		t.Errorf("chain length: want 2, got %d", arc.ChainLength)
	}
	if arc.FinalCV != "pass" {
		t.Errorf("final cv: want pass, got %s", arc.FinalCV)
	}

	// Broken ARC chain: i=1 with cv=pass (invalid)
	brokenARC := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=pass;
 b=abcd1234
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=origin.example; s=arc;
 bh=hash123; h=from:to:subject; b=sig123
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass`

	badArc, err := mailtools.AnalyzeARC(brokenARC)
	if err != nil {
		t.Fatalf("AnalyzeARC on brokenARC failed: %v", err)
	}
	if badArc.ChainValid {
		t.Errorf("expected broken chain for i=1 cv=pass, but marked valid")
	}
}

func TestMailToolsHTTPRoutes(t *testing.T) {
	e := newMailApp(t)

	// 1. GET / renders health audit dashboard
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Error("GET / browser response missing <!DOCTYPE html>")
	}

	// 2. GET /dmarc HTML
	req = httptest.NewRequest(http.MethodGet, "/dmarc", nil)
	req.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dmarc: want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Error("GET /dmarc browser response missing <!DOCTYPE html>")
	}

	// 3. GET /dmarc HTMX fragment
	req = httptest.NewRequest(http.MethodGet, "/dmarc", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /dmarc htmx: want 200, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Error("GET /dmarc htmx fragment should not contain <!DOCTYPE html>")
	}

	// 4. POST /bimi/fix
	form := url.Values{"svg": {`<svg width="100" height="100"><circle cx="50" cy="50" r="40"/></svg>`}}
	req = httptest.NewRequest(http.MethodPost, "/bimi/fix", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("POST /bimi/fix: want 200, got %d (body %s)", rec.Code, rec.Body)
	}
	var fixRes struct {
		SVG string `json:"svg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &fixRes); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if !strings.Contains(fixRes.SVG, `baseProfile="tiny-ps"`) {
		t.Errorf("fixed svg missing tiny-ps: %s", fixRes.SVG)
	}
}

func TestDMARC_CorruptArchivesAndAggregation(t *testing.T) {
	// 1. Truncated Gzip archive (starts with gzip magic 0x1f, 0x8b but corrupted payload)
	corruptGz := bytes.NewReader([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00})
	_, err := mailtools.ParseDMARCReport(corruptGz)
	if err == nil {
		t.Errorf("expected error for truncated gzip archive, got nil")
	}

	// 2. Empty XML feedback
	emptyXML := strings.NewReader(`<?xml version="1.0"?><feedback></feedback>`)
	repEmpty, err := mailtools.ParseDMARCReport(emptyXML)
	if err != nil {
		t.Fatalf("ParseDMARCReport on empty feedback failed: %v", err)
	}
	if repEmpty.TotalMessages != 0 || len(repEmpty.Sources) != 0 {
		t.Errorf("expected 0 messages and 0 sources, got: %+v", repEmpty)
	}

	// 3. Duplicate IP Aggregation: multiple <record> blocks with the same source_ip
	dupXML := `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata><org_name>test.org</org_name></report_metadata>
  <policy_published><domain>corpberry.com</domain><p>reject</p></policy_published>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>corpberry.com</header_from></identifiers>
  </record>
  <record>
    <row><source_ip>209.85.220.41</source_ip><count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>corpberry.com</header_from></identifiers>
  </record>
</feedback>`

	repDup, err := mailtools.ParseDMARCReport(strings.NewReader(dupXML))
	if err != nil {
		t.Fatalf("ParseDMARCReport failed: %v", err)
	}
	if repDup.TotalMessages != 15 {
		t.Errorf("TotalMessages: want 15, got %d", repDup.TotalMessages)
	}
	// The 2 records must be aggregated into exactly 1 source entry
	if len(repDup.Sources) != 1 {
		t.Fatalf("expected 1 aggregated source, got %d", len(repDup.Sources))
	}
	if repDup.Sources[0].Count != 15 || repDup.Sources[0].PassCount != 15 {
		t.Errorf("aggregated source count mismatch: %+v", repDup.Sources[0])
	}
}

func TestDMARC_PercentagePreservation(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantPct int
	}{
		{
			name: "omitted pct tag defaults to 100",
			xml: `<feedback>
  <report_metadata><org_name>test</org_name><email>a@b.com</email><report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>test.com</domain><p>reject</p></policy_published>
</feedback>`,
			wantPct: 100,
		},
		{
			name: "explicit pct=0 is preserved",
			xml: `<feedback>
  <report_metadata><org_name>test</org_name><email>a@b.com</email><report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>test.com</domain><p>quarantine</p><pct>0</pct></policy_published>
</feedback>`,
			wantPct: 0,
		},
		{
			name: "explicit pct=25 is preserved",
			xml: `<feedback>
  <report_metadata><org_name>test</org_name><email>a@b.com</email><report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>test.com</domain><p>reject</p><pct>25</pct></policy_published>
</feedback>`,
			wantPct: 25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := mailtools.ParseDMARCReport(strings.NewReader(tt.xml))
			if err != nil {
				t.Fatalf("ParseDMARCReport failed: %v", err)
			}
			if rep.Percentage != tt.wantPct {
				t.Errorf("Percentage = %d, want %d", rep.Percentage, tt.wantPct)
			}
		})
	}
}

func TestBIMI_SecurityAndBoundaryViolations(t *testing.T) {
	// 1. Strict 32 KB size boundary limit
	exactSizeSVG := `<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100">`
	padding := strings.Repeat("<!-- pad -->", (32768-len(exactSizeSVG)-6)/12)
	exactSizeSVG += padding + "</svg>"

	valExact, err := mailtools.ValidateBIMI(exactSizeSVG)
	if err != nil {
		t.Fatalf("ValidateBIMI failed: %v", err)
	}
	for _, f := range valExact.Findings {
		if strings.Contains(f.Rule, "File Size Limit") && f.Severity == "fail" {
			t.Errorf("expected 32KB SVG to pass size limit, but failed")
		}
	}

	// 32,769 bytes -> fails size rule
	oversizedSVG := exactSizeSVG[:len(exactSizeSVG)-6] + "x" + "</svg>"
	valOver, err := mailtools.ValidateBIMI(oversizedSVG)
	if err != nil {
		t.Fatalf("ValidateBIMI oversized failed: %v", err)
	}
	foundSizeFail := false
	for _, f := range valOver.Findings {
		if strings.Contains(f.Rule, "File Size Limit") && f.Severity == "fail" {
			foundSizeFail = true
			break
		}
	}
	if !foundSizeFail {
		t.Errorf("expected 32,769 byte SVG to fail size limit")
	}

	// 2. Forbidden elements: iframe, canvas, foreignObject
	forbiddenTags := []string{
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><iframe src="https://evil.com"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><canvas id="c"/></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><foreignObject>text</foreignObject></svg>`,
	}
	for _, raw := range forbiddenTags {
		v, err := mailtools.ValidateBIMI(raw)
		if err != nil {
			t.Fatalf("ValidateBIMI failed: %v", err)
		}
		if v.Compliant {
			t.Errorf("expected forbidden tag in SVG to be non-compliant: %s", raw)
		}
	}

	// 3. Non-XML content
	_, errNonXML := mailtools.ValidateBIMI("<html><body>Not an SVG</body></html>")
	if errNonXML == nil {
		t.Errorf("expected error for non-SVG XML root, got nil")
	}
}

func TestARC_SequenceGapsAndIncompleteHops(t *testing.T) {
	// 1. Missing intermediate hop (sequence gap: i=1, then i=3 missing i=2)
	brokenSeq := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=abc
ARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=abc
ARC-Authentication-Results: i=1; mx.origin.example; spf=pass
ARC-Seal: i=3; a=rsa-sha256; d=hop3.example; s=arc; cv=pass; b=def
ARC-Message-Signature: i=3; a=rsa-sha256; d=hop3.example; s=arc; b=def
ARC-Authentication-Results: i=3; mx.hop3.example; spf=pass`

	arcSeq, err := mailtools.AnalyzeARC(brokenSeq)
	if err != nil {
		t.Fatalf("AnalyzeARC failed: %v", err)
	}
	if arcSeq.ChainValid {
		t.Errorf("expected chain with missing hop i=2 to be invalid")
	}

	// 2. Incomplete hop (hop i=1 has ARC-Seal only, missing Message-Signature and Auth-Results)
	incompleteHop := `ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=abc`
	arcInc, err := mailtools.AnalyzeARC(incompleteHop)
	if err != nil {
		t.Fatalf("AnalyzeARC failed: %v", err)
	}
	if arcInc.ChainValid {
		t.Errorf("expected incomplete hop to be invalid")
	}
}

func TestWASMFragmentRendering(t *testing.T) {
	tmpl, err := mailtools.FragmentTemplates()
	if err != nil {
		t.Fatalf("FragmentTemplates() error: %v", err)
	}

	// 1. DMARC Render
	xml := `<feedback>
		<report_metadata><org_name>google.com</org_name><date_range><begin>1000</begin><end>2000</end></date_range></report_metadata>
		<policy_published><domain>test.com</domain><p>none</p></policy_published>
		<record>
			<row><source_ip>1.2.3.4</source_ip><count>5</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
			<identifiers><header_from>test.com</header_from></identifiers>
		</record>
	</feedback>`
	dmarcHTML, err := mailtools.RenderDMARC(tmpl, strings.NewReader(xml))
	if err != nil {
		t.Fatalf("RenderDMARC error: %v", err)
	}
	if !strings.Contains(dmarcHTML, "Total Messages") || !strings.Contains(dmarcHTML, "test.com") {
		t.Errorf("RenderDMARC missing expected tokens in HTML: %s", dmarcHTML)
	}

	// 2. BIMI Render
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>`
	bimiHTML, err := mailtools.RenderBIMI(tmpl, svg)
	if err != nil {
		t.Fatalf("RenderBIMI error: %v", err)
	}
	if !strings.Contains(bimiHTML, "BIMI Specification Checklist") {
		t.Errorf("RenderBIMI missing expected tokens in HTML: %s", bimiHTML)
	}

	// 3. ARC Render
	arcHeaders := `ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=arc; cv=none; b=abc
ARC-Message-Signature: i=1; a=rsa-sha256; d=example.com; s=arc; b=abc
ARC-Authentication-Results: i=1; mx.example.com; spf=pass`
	arcHTML, err := mailtools.RenderARC(tmpl, arcHeaders)
	if err != nil {
		t.Fatalf("RenderARC error: %v", err)
	}
	if !strings.Contains(arcHTML, "Chain Structure") || !strings.Contains(arcHTML, "INTACT") {
		t.Errorf("RenderARC missing expected tokens in HTML: %s", arcHTML)
	}
}
