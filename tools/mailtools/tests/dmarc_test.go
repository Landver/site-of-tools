package tests

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

const dmarcHead = `<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata><org_name>google.com</org_name></report_metadata><policy_published><domain>example.com</domain><p>reject</p></policy_published>`

// dmarcReportXML builds a report of n distinct-IP rows of about 380 bytes each.
func dmarcReportXML(n int) string {
	var b strings.Builder
	b.WriteString(dmarcHead)
	for i := range n {
		fmt.Fprintf(&b, `<record><row><source_ip>198.51.%d.%d</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>`, i/256, i%256)
	}
	b.WriteString(`</feedback>`)
	return b.String()
}

func gzipped(t testing.TB, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestParseDMARCReport_Bounds(t *testing.T) {
	const limit = 2 << 20
	padTo := func(n int) string {
		xml := dmarcReportXML(1)
		return strings.Replace(xml, "<feedback>", "<feedback>"+strings.Repeat(" ", n-len(xml)), 1)
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{"xml at the size limit", []byte(padTo(limit)), ""},
		{"xml one byte over", []byte(padTo(limit + 1)), "report exceeds 2 MB"},
		{"gzip inflating past the limit", gzipped(t, padTo(limit+1)), "decompressing gzip report: report exceeds 2 MB"},
		{"gzip inflating to the limit", gzipped(t, padTo(limit)), ""},
		{"rows at the record limit", []byte(dmarcReportXML(5000)), ""},
		{"one row over the record limit", []byte(dmarcReportXML(5001)), "report has more than 5000 records"},
		{"gzip with one row over the record limit", gzipped(t, dmarcReportXML(5001)), "report has more than 5000 records"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := mailtools.ParseDMARCReport(bytes.NewReader(tt.input))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if rep.TotalMessages == 0 {
					t.Error("parsed report has no messages")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseDMARCReport_ProviderRollup(t *testing.T) {
	row := func(ip string, count int, dkim, spf string) string {
		return fmt.Sprintf(`<record><row><source_ip>%s</source_ip><count>%d</count><policy_evaluated><disposition>none</disposition><dkim>%s</dkim><spf>%s</spf></policy_evaluated></row></record>`, ip, count, dkim, spf)
	}
	xml := dmarcHead +
		row("209.85.220.41", 40, "pass", "pass") +
		row("74.125.82.49", 20, "pass", "fail") +
		row(" 40.107.22.51 ", 30, "fail", "fail") +
		row("54.240.8.1", 5, "pass", "pass") +
		row("203.0.113.9", 5, "fail", "fail") +
		row("203.0.113.8", 5, "fail", "fail") +
		`</feedback>`

	rep, err := mailtools.ParseDMARCReport(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}

	google := mailtools.ESPInfo{Name: "Google Workspace / Gmail", Category: "mailbox", Icon: "Google"}
	microsoft := mailtools.ESPInfo{Name: "Microsoft 365 / Outlook", Category: "mailbox", Icon: "Microsoft"}
	ses := mailtools.ESPInfo{Name: "Amazon SES", Category: "esp", Icon: "AWS"}
	unknown := mailtools.ESPInfo{Name: "Unknown Sender", Category: "self-hosted", Icon: "Unknown"}

	wantProviders := []mailtools.DMARCProviderSummary{
		{ESP: google, Sources: 2, Count: 60, PassCount: 60},
		{ESP: microsoft, Sources: 1, Count: 30, FailCount: 30},
		{ESP: unknown, Sources: 2, Count: 10, FailCount: 10},
		{ESP: ses, Sources: 1, Count: 5, PassCount: 5},
	}
	if diff := cmp.Diff(wantProviders, rep.Providers); diff != "" {
		t.Errorf("Providers mismatch (-want +got):\n%s", diff)
	}

	var gotIPs []string
	for _, s := range rep.Sources {
		gotIPs = append(gotIPs, s.SourceIP)
	}
	wantIPs := []string{"209.85.220.41", "40.107.22.51", "74.125.82.49", "203.0.113.8", "203.0.113.9", "54.240.8.1"}
	if diff := cmp.Diff(wantIPs, gotIPs); diff != "" {
		t.Errorf("Sources order (-want +got):\n%s", diff)
	}
	if rep.Sources[1].ESP != microsoft {
		t.Errorf("trimmed source IP not classified: %+v", rep.Sources[1])
	}
	if rep.TotalMessages != 105 || rep.PassCount != 65 || rep.FailCount != 40 {
		t.Errorf("totals = %d/%d/%d, want 105/65/40", rep.TotalMessages, rep.PassCount, rep.FailCount)
	}
}
