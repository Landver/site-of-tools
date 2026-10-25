package mailtools

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const maxDMARCPayload = 10 << 20 // 10 MB limit against decompression bombs

// Raw XML structures matching RFC 7489 Appendix C
type dmarcFeedbackXML struct {
	XMLName        xml.Name              `xml:"feedback"`
	Metadata       dmarcReportMetaXML    `xml:"report_metadata"`
	Policy         dmarcPolicyPubXML     `xml:"policy_published"`
	Records        []dmarcRecordXML      `xml:"record"`
}

type dmarcReportMetaXML struct {
	OrgName   string            `xml:"org_name"`
	Email     string            `xml:"email"`
	ReportID  string            `xml:"report_id"`
	DateRange dmarcDateRangeXML `xml:"date_range"`
}

type dmarcDateRangeXML struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type dmarcPolicyPubXML struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
	Pct    *int   `xml:"pct"`
	Fo     string `xml:"fo"`
}

type dmarcRecordXML struct {
	Row         dmarcRowXML         `xml:"row"`
	Identifiers dmarcIdentifiersXML `xml:"identifiers"`
	AuthResults dmarcAuthResultsXML `xml:"auth_results"`
}

type dmarcRowXML struct {
	SourceIP        string              `xml:"source_ip"`
	Count           int                 `xml:"count"`
	PolicyEvaluated dmarcPolicyEvalXML  `xml:"policy_evaluated"`
}

type dmarcPolicyEvalXML struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type dmarcIdentifiersXML struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeTo   string `xml:"envelope_to"`
	EnvelopeFrom string `xml:"envelope_from"`
}

type dmarcAuthResultsXML struct {
	DKIM []dmarcDKIMAuthXML `xml:"dkim"`
	SPF  []dmarcSPFAuthXML  `xml:"spf"`
}

type dmarcDKIMAuthXML struct {
	Domain   string `xml:"domain"`
	Result   string `xml:"result"`
	Selector string `xml:"selector"`
}

type dmarcSPFAuthXML struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
	Scope  string `xml:"scope"`
}

// User-facing structured types for JSON API and HTML templates
type DMARCReport struct {
	OrgName        string               `json:"org_name"`
	Email          string               `json:"email"`
	ReportID       string               `json:"report_id"`
	BeginTime      string               `json:"begin_time"`
	EndTime        string               `json:"end_time"`
	Domain         string               `json:"domain"`
	Policy         string               `json:"policy"`
	SubdomainPol   string               `json:"subdomain_policy,omitempty"`
	Percentage     int                  `json:"percentage"`
	TotalMessages  int                  `json:"total_messages"`
	PassCount      int                  `json:"pass_count"`
	FailCount      int                  `json:"fail_count"`
	QuarantineCnt  int                  `json:"quarantine_count"`
	RejectCnt      int                  `json:"reject_count"`
	PassRatePct    float64              `json:"pass_rate_pct"`
	Sources        []DMARCSourceSummary `json:"sources"`
	Records        []DMARCRecord        `json:"records"`
}

type DMARCSourceSummary struct {
	SourceIP    string  `json:"source_ip"`
	ESP         ESPInfo `json:"esp"`
	Count       int     `json:"count"`
	PassCount   int     `json:"pass_count"`
	FailCount   int     `json:"fail_count"`
	Disposition string  `json:"disposition"`
	SPFPass     bool    `json:"spf_pass"`
	DKIMPass    bool    `json:"dkim_pass"`
}

type DMARCRecord struct {
	SourceIP     string   `json:"source_ip"`
	ESP          ESPInfo  `json:"esp"`
	Count        int      `json:"count"`
	Disposition  string   `json:"disposition"` // "none", "quarantine", "reject"
	DKIMResult   string   `json:"dkim_result"` // "pass", "fail"
	SPFResult    string   `json:"spf_result"`  // "pass", "fail"
	HeaderFrom   string   `json:"header_from"`
	EnvelopeFrom string   `json:"envelope_from,omitempty"`
	DKIMDomains  []string `json:"dkim_domains,omitempty"`
	SPFDomains   []string `json:"spf_domains,omitempty"`
}

// ParseDMARCReport decompresses (if gzip) and parses a DMARC aggregate XML report.
func ParseDMARCReport(r io.Reader) (*DMARCReport, error) {
	r = io.LimitReader(r, maxDMARCPayload)
	// Read header bytes to check for gzip magic: 0x1f, 0x8b
	headerBuf := make([]byte, 2)
	n, err := io.ReadFull(r, headerBuf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	var xmlReader io.Reader
	if n == 2 && headerBuf[0] == 0x1f && headerBuf[1] == 0x8b {
		// Gzip compressed payload
		combined := io.MultiReader(bytes.NewReader(headerBuf[:n]), r)
		gz, err := gzip.NewReader(combined)
		if err != nil {
			return nil, fmt.Errorf("decompressing gzip report: %w", err)
		}
		defer gz.Close()
		xmlReader = io.LimitReader(gz, maxDMARCPayload)
	} else {
		// Plain XML payload
		xmlReader = io.LimitReader(io.MultiReader(bytes.NewReader(headerBuf[:n]), r), maxDMARCPayload)
	}

	decoder := xml.NewDecoder(xmlReader)
	var raw dmarcFeedbackXML
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing DMARC XML report: %w", err)
	}

	rep := &DMARCReport{
		OrgName:    raw.Metadata.OrgName,
		Email:      raw.Metadata.Email,
		ReportID:   raw.Metadata.ReportID,
		Domain:     raw.Policy.Domain,
		Policy:       raw.Policy.P,
		SubdomainPol: raw.Policy.SP,
		Percentage:   100,
	}
	if raw.Policy.Pct != nil {
		rep.Percentage = *raw.Policy.Pct
	}

	if raw.Metadata.DateRange.Begin > 0 {
		rep.BeginTime = time.Unix(raw.Metadata.DateRange.Begin, 0).UTC().Format(time.RFC3339)
	}
	if raw.Metadata.DateRange.End > 0 {
		rep.EndTime = time.Unix(raw.Metadata.DateRange.End, 0).UTC().Format(time.RFC3339)
	}

	sourceMap := make(map[string]*DMARCSourceSummary)

	for _, rec := range raw.Records {
		cnt := rec.Row.Count
		if cnt <= 0 {
			cnt = 1
		}
		rep.TotalMessages += cnt

		disp := rec.Row.PolicyEvaluated.Disposition
		if disp == "" {
			disp = "none"
		}
		switch disp {
		case "quarantine":
			rep.QuarantineCnt += cnt
		case "reject":
			rep.RejectCnt += cnt
		}

		dkimPass := rec.Row.PolicyEvaluated.DKIM == "pass"
		spfPass := rec.Row.PolicyEvaluated.SPF == "pass"

		isAligned := dkimPass || spfPass
		if isAligned {
			rep.PassCount += cnt
		} else {
			rep.FailCount += cnt
		}

		ipStr := rec.Row.SourceIP
		esp := IdentifyESP(ipStr, "")

		// Aggregate source summary
		s, exists := sourceMap[ipStr]
		if !exists {
			s = &DMARCSourceSummary{
				SourceIP:    ipStr,
				ESP:         esp,
				Disposition: disp,
			}
			sourceMap[ipStr] = s
		}
		s.Count += cnt
		if isAligned {
			s.PassCount += cnt
		} else {
			s.FailCount += cnt
		}
		if spfPass {
			s.SPFPass = true
		}
		if dkimPass {
			s.DKIMPass = true
		}

		var dkimDoms, spfDoms []string
		for _, d := range rec.AuthResults.DKIM {
			if d.Domain != "" {
				dkimDoms = append(dkimDoms, fmt.Sprintf("%s (%s)", d.Domain, d.Result))
			}
		}
		for _, s := range rec.AuthResults.SPF {
			if s.Domain != "" {
				spfDoms = append(spfDoms, fmt.Sprintf("%s (%s)", s.Domain, s.Result))
			}
		}

		rep.Records = append(rep.Records, DMARCRecord{
			SourceIP:     ipStr,
			ESP:          esp,
			Count:        cnt,
			Disposition:  disp,
			DKIMResult:   rec.Row.PolicyEvaluated.DKIM,
			SPFResult:    rec.Row.PolicyEvaluated.SPF,
			HeaderFrom:   rec.Identifiers.HeaderFrom,
			EnvelopeFrom: rec.Identifiers.EnvelopeFrom,
			DKIMDomains:  dkimDoms,
			SPFDomains:   spfDoms,
		})
	}

	if rep.TotalMessages > 0 {
		rep.PassRatePct = float64(rep.PassCount) / float64(rep.TotalMessages) * 100.0
	}

	for _, s := range sourceMap {
		rep.Sources = append(rep.Sources, *s)
	}
	sort.Slice(rep.Sources, func(i, j int) bool {
		return rep.Sources[i].Count > rep.Sources[j].Count
	})

	return rep, nil
}
