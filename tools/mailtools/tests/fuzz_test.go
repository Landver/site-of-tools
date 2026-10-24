package tests

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func FuzzParseDMARCReport(f *testing.F) {
	validXML := `<?xml version="1.0"?><feedback><report_metadata><org_name>g</org_name></report_metadata><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`
	f.Add([]byte(validXML))
	f.Add([]byte{})
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte("not xml"))

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write([]byte(validXML))
	gw.Close()
	f.Add(gzBuf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		rep, err := mailtools.ParseDMARCReport(r)
		if err == nil && rep == nil {
			t.Fatal("nil report without error")
		}
	})
}

func FuzzValidateAndAutoFixBIMI(f *testing.F) {
	f.Add(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 100 100"><circle cx="50" cy="50" r="45"/></svg>`)
	f.Add(`<svg width="200" height="100" onload="alert(1)"><script>evil()</script></svg>`)
	f.Add(`<svg viewBox="0 0 -10 -10">`)
	f.Add(`<svg viewBox="0 0 NaN NaN">`)
	f.Add(`<svg attr=">">`)
	f.Add(`<!-- <svg> --> <svg viewBox="0 0 10 10"></svg>`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, raw string) {
		val, err := mailtools.ValidateBIMI(raw)
		if err == nil && val == nil {
			t.Fatal("nil validation without error")
		}
		fixed, errFix := mailtools.AutoFixBIMI(raw)
		if errFix == nil {
			_, _ = mailtools.ValidateBIMI(fixed)
		}
	})
}

func FuzzAnalyzeARC(f *testing.F) {
	f.Add("ARC-Seal: i=1; a=rsa-sha256; d=origin.example; s=arc; cv=none; b=abc\nARC-Message-Signature: i=1; a=rsa-sha256; d=origin.example; s=arc; b=abc\nARC-Authentication-Results: i=1; mx.origin.example; spf=pass")
	f.Add("ARC-Seal: i=999999999; cv=pass\nARC-Message-Signature: i=999999999\nARC-Authentication-Results: i=999999999")
	f.Add("garbage string without colons")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		summary, err := mailtools.AnalyzeARC(raw)
		if err == nil && summary == nil {
			t.Fatal("nil summary without error")
		}
	})
}
