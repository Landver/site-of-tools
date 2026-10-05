package botcheck

import (
	"context"
	"slices"

	"github.com/Landver/site-of-tools/tools/iptools"
)

type Looker interface {
	Lookup(ip string) (*iptools.Result, error)
}

// HTTPSignals are the request headers the rules read, as an API caller names them.
type HTTPSignals struct {
	UserAgent       string `json:"user_agent,omitempty" jsonschema:"User-Agent"`
	Accept          string `json:"accept,omitempty" jsonschema:"Accept"`
	AcceptLanguage  string `json:"accept_language,omitempty" jsonschema:"Accept-Language"`
	AcceptEncoding  string `json:"accept_encoding,omitempty" jsonschema:"Accept-Encoding"`
	SecCHUA         string `json:"sec_ch_ua,omitempty" jsonschema:"Sec-CH-UA"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty" jsonschema:"Sec-CH-UA-Platform"`
	SecFetchMode    string `json:"sec_fetch_mode,omitempty" jsonschema:"Sec-Fetch-Mode"`
	// No rule reads it (Safari never sends it), so no caller is asked for it.
	UpgradeInsecureRequests string `json:"-"`
}

// AddHTTPSignals copies h into sig and counts the headers as supplied, so an
// empty one is evidence (a browser that didn't send it), not a skip.
func AddHTTPSignals(sig *Signals, h HTTPSignals) {
	sig.HeadersSupplied = true
	sig.HTTPUserAgent = h.UserAgent
	sig.HTTPAccept = h.Accept
	sig.AcceptLanguage = h.AcceptLanguage
	sig.HTTPAcceptEncoding = h.AcceptEncoding
	sig.SecCHUA = h.SecCHUA
	sig.SecCHUAPlatform = h.SecCHUAPlatform
	sig.SecFetchMode = h.SecFetchMode
	sig.HTTPUpgradeInsecureRequests = h.UpgradeInsecureRequests
}

// AddIPSignals fills the IP half of sig for ip and counts it as supplied; the
// caller still sets sig.Now (zero skips tz_mismatch). Returns the lookup, or nil.
func AddIPSignals(ctx context.Context, sig *Signals, ip string, svc Looker, chk iptools.Checker) *iptools.Result {
	sig.IPSupplied = true
	sig.EgressIP = ip
	// The blocklist is read even without geo BINs. Any source but the ipsum
	// feed is a deliberate ban, so the scorer needn't know iptools' sources.
	if chk != nil {
		if lk, err := chk.Check(ctx, ip); err == nil {
			sig.IPBlocklistSources = lk.Sources
			sig.IPBlocklistCount = lk.MaxCount
			sig.IPBlocklistDeliberate = slices.ContainsFunc(lk.Sources, func(s string) bool {
				return s != iptools.BlocklistSourceIPsum
			})
		}
	}
	if svc == nil {
		return nil
	}
	res, err := svc.Lookup(ip)
	if err != nil || res == nil {
		return nil
	}
	sig.IPTimezone = cleanPlaceholder(res.Timezone)
	sig.ASN = cleanPlaceholder(res.ASN)
	if p := res.Proxy; p != nil && p.IsProxy {
		sig.IsProxy = true
		switch p.ProxyType {
		case "DCH":
			sig.IsDatacenter = true
		case "VPN":
			sig.IsVPN = true
		case "TOR":
			sig.IsTor = true
		}
	}
	return res
}

// cleanPlaceholder: IP2Location's "-" is unknown, which must not trip the tz check.
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
