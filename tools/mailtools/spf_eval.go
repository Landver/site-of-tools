package mailtools

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// SPFVerdict represents the outcome of RFC 7208 SPF evaluation for a specific sender and client IP.
type SPFVerdict string

const (
	SPFPass      SPFVerdict = "pass"
	SPFFail      SPFVerdict = "fail"
	SPFSoftfail  SPFVerdict = "softfail"
	SPFNeutral   SPFVerdict = "neutral"
	SPFNone      SPFVerdict = "none"
	SPFTempError SPFVerdict = "temperror"
	SPFPermError SPFVerdict = "permerror"
)

// SPFEvalResult holds the result of evaluating an SPF record against a sender IP and domain.
type SPFEvalResult struct {
	Verdict   SPFVerdict `json:"verdict"`
	IP        string     `json:"ip"`
	Sender    string     `json:"sender"`
	Domain    string     `json:"domain"`
	MatchedOn string     `json:"matched_on,omitempty"`
	Reason    string     `json:"reason"`
}

// EvaluateSPF evaluates an SPF record string against a sending IP address per RFC 7208 without network calls for CIDR/IP mechanisms.
func EvaluateSPF(ipStr, sender string, spfRecord string) SPFEvalResult {
	res := SPFEvalResult{
		Verdict: SPFNone,
		IP:      ipStr,
		Sender:  sender,
		Domain:  ExtractDomain(sender),
	}

	clientAddr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		res.Verdict = SPFPermError
		res.Reason = fmt.Sprintf("invalid client IP address: %s", ipStr)
		return res
	}

	trimmedRecord := strings.TrimSpace(spfRecord)
	if trimmedRecord == "" || !strings.HasPrefix(strings.ToLower(trimmedRecord), "v=spf1") {
		res.Verdict = SPFNone
		res.Reason = "no SPF record published"
		return res
	}

	terms := parseSPF(trimmedRecord)
	for _, t := range terms {
		switch t.name {
		case "ip4":
			if clientAddr.Is4() {
				if matchIPMechanism(clientAddr, t.target) {
					res.Verdict = qualifierToVerdict(t.qualifier)
					res.MatchedOn = fmt.Sprintf("ip4:%s", t.target)
					res.Reason = fmt.Sprintf("matched ip4 directive with qualifier %c", t.qualifier)
					return res
				}
			}
		case "ip6":
			if clientAddr.Is6() {
				if matchIPMechanism(clientAddr, t.target) {
					res.Verdict = qualifierToVerdict(t.qualifier)
					res.MatchedOn = fmt.Sprintf("ip6:%s", t.target)
					res.Reason = fmt.Sprintf("matched ip6 directive with qualifier %c", t.qualifier)
					return res
				}
			}
		case "all":
			res.Verdict = qualifierToVerdict(t.qualifier)
			res.MatchedOn = fmt.Sprintf("%call", t.qualifier)
			res.Reason = fmt.Sprintf("matched default %call directive", t.qualifier)
			return res
		}
	}

	res.Verdict = SPFNeutral
	res.Reason = "no mechanism matched; default neutral"
	return res
}

func matchIPMechanism(addr netip.Addr, target string) bool {
	if strings.Contains(target, "/") {
		prefix, err := netip.ParsePrefix(target)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	} else {
		targetAddr, err := netip.ParseAddr(target)
		if err == nil && targetAddr == addr {
			return true
		}
	}
	return false
}

func qualifierToVerdict(q byte) SPFVerdict {
	switch q {
	case '+':
		return SPFPass
	case '-':
		return SPFFail
	case '~':
		return SPFSoftfail
	case '?':
		return SPFNeutral
	default:
		return SPFPass
	}
}

// EvaluateSPFOnline evaluates an email sender against domain SPF via DNS lookups.
func (s *Service) EvaluateSPFOnline(ctx context.Context, ipStr, sender string) SPFEvalResult {
	domain := ExtractDomain(sender)
	recs := lookupTXTWithPrefix(ctx, domain, "v=spf1")
	if len(recs) == 0 {
		return SPFEvalResult{
			Verdict: SPFNone,
			IP:      ipStr,
			Sender:  sender,
			Domain:  domain,
			Reason:  "domain publishes no v=spf1 record",
		}
	}
	return EvaluateSPF(ipStr, sender, recs[0])
}
