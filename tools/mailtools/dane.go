package mailtools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DANE TLSA (RFC 6698 / RFC 7672) & MTA-STS Alignment validation.

type TLSARecord struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

type DANEAnalysis struct {
	Configured   bool         `json:"configured"`
	DNSSECValid  bool         `json:"dnssec_valid"`
	Records      []TLSARecord `json:"records,omitempty"`
	Status       string       `json:"status"` // pass, warn, info
	StatusMsg    string       `json:"status_msg"`
	RolloverSafe bool         `json:"rollover_safe"`
}

// CheckDANE queries TLSA records at _25._tcp.<mxHost> and checks DNSSEC Authenticated Data (AD).
func CheckDANE(ctx context.Context, mxHost string) *DANEAnalysis {
	res := &DANEAnalysis{Status: "info", StatusMsg: "No DANE TLSA records configured for MX"}
	mxHost = strings.TrimSuffix(strings.TrimSpace(mxHost), ".")
	if mxHost == "" {
		return res
	}

	tlsaName := fmt.Sprintf("_25._tcp.%s.", mxHost)
	m := new(dns.Msg)
	m.SetQuestion(tlsaName, dns.TypeTLSA)
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true

	c := &dns.Client{Timeout: 3 * time.Second}
	in, _, err := c.ExchangeContext(ctx, m, "1.1.1.1:53")
	if err != nil || in == nil {
		return res
	}

	for _, ans := range in.Answer {
		if tlsa, ok := ans.(*dns.TLSA); ok {
			res.Configured = true
			res.Records = append(res.Records, TLSARecord{
				Usage:        tlsa.Usage,
				Selector:     tlsa.Selector,
				MatchingType: tlsa.MatchingType,
				Certificate:  tlsa.Certificate,
			})
		}
	}

	if !res.Configured {
		return res
	}

	res.DNSSECValid = in.AuthenticatedData
	res.RolloverSafe = len(res.Records) >= 2

	if !res.DNSSECValid {
		res.Status = "warn"
		res.StatusMsg = "TLSA records found, but DNSSEC validation (AD bit) is missing — untrusted by sending MTAs (RFC 7672)"
		return res
	}

	res.Status = "pass"
	if res.RolloverSafe {
		res.StatusMsg = fmt.Sprintf("DANE TLSA validated with DNSSEC (%d records, rollover-ready)", len(res.Records))
	} else {
		res.StatusMsg = fmt.Sprintf("DANE TLSA validated with DNSSEC (%d record)", len(res.Records))
	}

	return res
}

// MatchMXWithMTASTS checks if an MX host matches published MTA-STS patterns (RFC 8461 §4.1).
func MatchMXWithMTASTS(mxHost string, patterns []string) bool {
	mxHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mxHost), "."))
	if mxHost == "" || len(patterns) == 0 {
		return false
	}

	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if p == mxHost {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // e.g. ".example.com"
			if strings.HasSuffix(mxHost, suffix) && len(mxHost) > len(suffix) {
				// Wildcard matches a single label on the left (RFC 8461)
				prefix := mxHost[:len(mxHost)-len(suffix)]
				if !strings.Contains(prefix, ".") {
					return true
				}
			}
		}
	}
	return false
}
