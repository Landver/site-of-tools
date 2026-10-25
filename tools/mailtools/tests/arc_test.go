package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

// arcSet renders one complete ARC set; extra is appended to its ARC-Authentication-Results.
func arcSet(i int, d, cv, extra string) string {
	return fmt.Sprintf("ARC-Seal: i=%d; a=rsa-sha256; d=%s; s=arc; cv=%s; b=AAAA\n"+
		"ARC-Message-Signature: i=%d; a=rsa-sha256; d=%s; s=arc; bh=AAAA; b=AAAA\n"+
		"ARC-Authentication-Results: i=%d; mx.%s; spf=pass%s\n", i, d, cv, i, d, i, d, extra)
}

const arcNotVerified = "Signatures not verified"

func TestAnalyzeARC_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		headers string
		wantErr string
	}{
		{"input over 256 KB", arcSet(1, "a.example", "none", "") + strings.Repeat("X-Pad: y\n", 256<<10/9), "headers exceed 256 KB"},
		{"instance past the RFC limit", arcSet(51, "a.example", "pass", ""), "i=51, past the RFC 8617 limit of 50"},
		{"huge instance", "ARC-Seal: i=999999999; cv=pass\nARC-Message-Signature: i=999999999\nARC-Authentication-Results: i=999999999", "past the RFC 8617 limit"},
		{"whitespace only", " \n\t", "empty email headers"},
		{"no ARC headers", "From: a@b.example\nSubject: hi", "no ARC headers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mailtools.AnalyzeARC(tt.headers)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAnalyzeARC_StructureFindings(t *testing.T) {
	tests := []struct {
		name      string
		headers   string
		wantValid bool
		wantNotes []string // finding titles after the leading "not verified" note
	}{
		{
			name:      "forged but well-formed chain is only structurally intact",
			headers:   arcSet(1, "paypal.com", "none", "") + arcSet(2, "paypal.com", "pass", "; arc=pass"),
			wantValid: true,
			wantNotes: []string{"ARC Chain Structure Intact"},
		},
		{
			name:      "the full 50-set chain is allowed",
			headers:   arcChain(50),
			wantValid: true,
			wantNotes: []string{"ARC Chain Structure Intact"},
		},
		{
			name:      "receiver recorded arc=fail",
			headers:   arcSet(1, "origin.example", "none", "") + arcSet(2, "list.example", "pass", "; arc=fail (signature mismatch)"),
			wantNotes: []string{"Hop i=2 reported arc=fail"},
		},
		{
			name:      "duplicate i=1 set",
			headers:   arcSet(1, "origin.example", "none", "") + arcSet(1, "forger.example", "none", ""),
			wantNotes: []string{"Duplicate ARC Set i=1"},
		},
		{
			name:      "folded CRLF headers unfold into one hop",
			headers:   "ARC-Seal: i=1; a=rsa-sha256; d=origin.example;\r\n s=arc; cv=none; b=AAAA\r\nARC-Message-Signature: i=1; d=origin.example;\r\n\ts=arc; b=AAAA\r\nARC-Authentication-Results: i=1;\r\n mx.origin.example; spf=pass\r\n",
			wantValid: true,
			wantNotes: []string{"ARC Chain Structure Intact"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum, err := mailtools.AnalyzeARC(tt.headers)
			if err != nil {
				t.Fatal(err)
			}
			if sum.ChainValid != tt.wantValid {
				t.Errorf("ChainValid = %v, want %v", sum.ChainValid, tt.wantValid)
			}
			var titles []string
			for _, f := range sum.Findings {
				titles = append(titles, f.Title)
			}
			if diff := cmp.Diff(append([]string{arcNotVerified}, tt.wantNotes...), titles); diff != "" {
				t.Errorf("finding titles (-want +got):\n%s", diff)
			}
			for _, f := range sum.Findings {
				if strings.Contains(strings.ToLower(f.Title+f.Detail), "verified") && f.Title != arcNotVerified {
					t.Errorf("finding implies verification: %+v", f)
				}
			}
		})
	}
}

func TestAnalyzeARC_HopFields(t *testing.T) {
	sum, err := mailtools.AnalyzeARC(arcSet(1, "origin.example", "none", "; dkim=pass; dmarc=pass") + arcSet(2, "list.example", "fail", "; arc=fail"))
	if err != nil {
		t.Fatal(err)
	}
	want := []mailtools.ARCHop{
		{Index: 1, Domain: "origin.example", Selector: "arc", Algorithm: "rsa-sha256", CV: "none",
			AuthResults: "i=1; mx.origin.example; spf=pass; dkim=pass; dmarc=pass",
			SPFResult:   "pass", DKIMResult: "pass", DMARCResult: "pass",
			SealPresent: true, SigPresent: true, ResultsPresent: true},
		{Index: 2, Domain: "list.example", Selector: "arc", Algorithm: "rsa-sha256", CV: "fail",
			AuthResults: "i=2; mx.list.example; spf=pass; arc=fail",
			SPFResult:   "pass", ARCResult: "fail",
			SealPresent: true, SigPresent: true, ResultsPresent: true},
	}
	if diff := cmp.Diff(want, sum.Hops); diff != "" {
		t.Errorf("Hops (-want +got):\n%s", diff)
	}
	if sum.FinalCV != "fail" || sum.ChainLength != 2 {
		t.Errorf("FinalCV = %q, ChainLength = %d; want the last hop's self-reported cv=fail and 2", sum.FinalCV, sum.ChainLength)
	}
}

func arcChain(n int) string {
	var b strings.Builder
	b.WriteString(arcSet(1, "hop1.example", "none", ""))
	for i := 2; i <= n; i++ {
		b.WriteString(arcSet(i, fmt.Sprintf("hop%d.example", i), "pass", "; arc=pass"))
	}
	return b.String()
}
