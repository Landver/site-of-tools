package mailtools

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// A full report row is ~550 bytes of XML, so 2 MB holds ~3,600 of them, far past a
// typical daily report; the row cap bounds reports made of minimal rows.
const (
	maxDMARCPayload = 2 << 20
	maxDMARCRecords = 5000
)

// Raw XML structures matching RFC 7489 Appendix C
type dmarcFeedbackXML struct {
	XMLName  xml.Name           `xml:"feedback"`
	Metadata dmarcReportMetaXML `xml:"report_metadata"`
	Policy   dmarcPolicyPubXML  `xml:"policy_published"`
	Records  dmarcRecords       `xml:"record"`
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
	SourceIP        string             `xml:"source_ip"`
	Count           int                `xml:"count"`
	PolicyEvaluated dmarcPolicyEvalXML `xml:"policy_evaluated"`
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
	DKIM []dmarcAuthXML `xml:"dkim"`
	SPF  []dmarcAuthXML `xml:"spf"`
}

type dmarcAuthXML struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// DMARCReport is a parsed aggregate report. The fields through PassRatePct summarise the
// whole report, Providers and Sources roll the rows up by ESP and by IP, Records holds every row.
type DMARCReport struct {
	OrgName       string                 `json:"org_name"`
	Email         string                 `json:"email"`
	ReportID      string                 `json:"report_id"`
	BeginTime     string                 `json:"begin_time"`
	EndTime       string                 `json:"end_time"`
	Domain        string                 `json:"domain"`
	Policy        string                 `json:"policy"`
	SubdomainPol  string                 `json:"subdomain_policy,omitempty"`
	Percentage    int                    `json:"percentage"`
	TotalMessages int                    `json:"total_messages"`
	PassCount     int                    `json:"pass_count"`
	FailCount     int                    `json:"fail_count"`
	QuarantineCnt int                    `json:"quarantine_count"`
	RejectCnt     int                    `json:"reject_count"`
	PassRatePct   float64                `json:"pass_rate_pct"`
	Providers     []DMARCProviderSummary `json:"providers"`
	Sources       []DMARCSourceSummary   `json:"sources"`
	Records       []DMARCRecord          `json:"records"`
}

// DMARCProviderSummary totals the report's messages per ESP.
type DMARCProviderSummary struct {
	ESP       ESPInfo `json:"esp"`
	Sources   int     `json:"sources"`
	Count     int     `json:"count"`
	PassCount int     `json:"pass_count"`
	FailCount int     `json:"fail_count"`
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

// ParseDMARCReport decompresses (if gzip) and parses a DMARC aggregate XML report,
// refusing more than maxDMARCPayload bytes of input or XML and more than maxDMARCRecords rows.
func ParseDMARCReport(r io.Reader) (*DMARCReport, error) {
	data, err := readDMARC(r)
	if err != nil {
		return nil, fmt.Errorf("reading report: %w", err)
	}
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decompressing gzip report: %w", err)
		}
		if data, err = readDMARC(gz); err != nil {
			return nil, fmt.Errorf("decompressing gzip report: %w", err)
		}
	}

	var raw dmarcFeedbackXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing DMARC XML report: %w", err)
	}
	return raw.report(), nil
}

func readDMARC(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDMARCPayload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDMARCPayload {
		return nil, fmt.Errorf("report exceeds %d MB", maxDMARCPayload>>20)
	}
	return data, nil
}

// dmarcRecords converts each <record> as it is decoded and stops past maxDMARCRecords.
type dmarcRecords []DMARCRecord

func (rs *dmarcRecords) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if len(*rs) == maxDMARCRecords {
		return fmt.Errorf("report has more than %d records", maxDMARCRecords)
	}
	var raw dmarcRecordXML
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	*rs = append(*rs, raw.record())
	return nil
}

func (x dmarcRecordXML) record() DMARCRecord {
	ip := strings.TrimSpace(x.Row.SourceIP)
	return DMARCRecord{
		SourceIP:     ip,
		ESP:          IdentifyESP(ip),
		Count:        max(x.Row.Count, 1),
		Disposition:  cmp.Or(x.Row.PolicyEvaluated.Disposition, "none"),
		DKIMResult:   x.Row.PolicyEvaluated.DKIM,
		SPFResult:    x.Row.PolicyEvaluated.SPF,
		HeaderFrom:   x.Identifiers.HeaderFrom,
		EnvelopeFrom: x.Identifiers.EnvelopeFrom,
		DKIMDomains:  authDomains(x.AuthResults.DKIM),
		SPFDomains:   authDomains(x.AuthResults.SPF),
	}
}

func authDomains(results []dmarcAuthXML) []string {
	var out []string
	for _, a := range results {
		if a.Domain != "" {
			out = append(out, fmt.Sprintf("%s (%s)", a.Domain, a.Result))
		}
	}
	return out
}

func (raw *dmarcFeedbackXML) report() *DMARCReport {
	rep := &DMARCReport{
		OrgName:      raw.Metadata.OrgName,
		Email:        raw.Metadata.Email,
		ReportID:     raw.Metadata.ReportID,
		BeginTime:    unixTime(raw.Metadata.DateRange.Begin),
		EndTime:      unixTime(raw.Metadata.DateRange.End),
		Domain:       raw.Policy.Domain,
		Policy:       raw.Policy.P,
		SubdomainPol: raw.Policy.SP,
		Percentage:   100,
		Records:      raw.Records,
	}
	if raw.Policy.Pct != nil {
		rep.Percentage = *raw.Policy.Pct
	}

	sources := map[string]*DMARCSourceSummary{}
	providers := map[string]*DMARCProviderSummary{}
	for _, r := range rep.Records {
		s, seen := sources[r.SourceIP]
		if !seen {
			s = &DMARCSourceSummary{SourceIP: r.SourceIP, ESP: r.ESP, Disposition: r.Disposition}
			sources[r.SourceIP] = s
		}
		p := providers[r.ESP.Name]
		if p == nil {
			p = &DMARCProviderSummary{ESP: r.ESP}
			providers[r.ESP.Name] = p
		}
		if !seen {
			p.Sources++
		}

		pass := r.DKIMResult == "pass" || r.SPFResult == "pass"
		tally := func(count, passed, failed *int) {
			*count += r.Count
			if pass {
				*passed += r.Count
			} else {
				*failed += r.Count
			}
		}
		tally(&rep.TotalMessages, &rep.PassCount, &rep.FailCount)
		tally(&s.Count, &s.PassCount, &s.FailCount)
		tally(&p.Count, &p.PassCount, &p.FailCount)
		switch r.Disposition {
		case "quarantine":
			rep.QuarantineCnt += r.Count
		case "reject":
			rep.RejectCnt += r.Count
		}
		s.SPFPass = s.SPFPass || r.SPFResult == "pass"
		s.DKIMPass = s.DKIMPass || r.DKIMResult == "pass"
	}
	if rep.TotalMessages > 0 {
		rep.PassRatePct = float64(rep.PassCount) / float64(rep.TotalMessages) * 100
	}

	for _, s := range sources {
		rep.Sources = append(rep.Sources, *s)
	}
	slices.SortFunc(rep.Sources, func(a, b DMARCSourceSummary) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.SourceIP, b.SourceIP))
	})
	for _, p := range providers {
		rep.Providers = append(rep.Providers, *p)
	}
	slices.SortFunc(rep.Providers, func(a, b DMARCProviderSummary) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.ESP.Name, b.ESP.Name))
	})
	return rep
}

func unixTime(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
