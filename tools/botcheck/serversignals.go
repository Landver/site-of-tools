package botcheck

import (
	"context"
	"slices"

	"github.com/Landver/site-of-tools/tools/iptools"
)

type HTTPSignals struct {
	UserAgent       string `json:"user_agent,omitempty" jsonschema:"User-Agent"`
	Accept          string `json:"accept,omitempty" jsonschema:"Accept"`
	AcceptLanguage  string `json:"accept_language,omitempty" jsonschema:"Accept-Language"`
	AcceptEncoding  string `json:"accept_encoding,omitempty" jsonschema:"Accept-Encoding"`
	SecCHUA         string `json:"sec_ch_ua,omitempty" jsonschema:"Sec-CH-UA"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty" jsonschema:"Sec-CH-UA-Platform"`
	SecFetchMode    string `json:"sec_fetch_mode,omitempty" jsonschema:"Sec-Fetch-Mode"`
}

// AddHTTPSignals marks the headers supplied, so an empty one is evidence, not a skip.
func AddHTTPSignals(sig *Signals, h HTTPSignals) {
	sig.HeadersSupplied = true
	sig.HTTPUserAgent = h.UserAgent
	sig.HTTPAccept = h.Accept
	sig.AcceptLanguage = h.AcceptLanguage
	sig.HTTPAcceptEncoding = h.AcceptEncoding
	sig.SecCHUA = h.SecCHUA
	sig.SecCHUAPlatform = h.SecCHUAPlatform
	sig.SecFetchMode = h.SecFetchMode
}

// AddIPSignals fills sig's IP half, returning the lookup or nil; zero sig.Now skips the tz checks.
func AddIPSignals(ctx context.Context, sig *Signals, ip string, svc iptools.Looker, chk iptools.Checker) *iptools.Result {
	sig.IPSupplied = true
	sig.EgressIP = ip
	// Every source but ipsum and the probe list is a deliberate ban; the scorer needn't know iptools' sources.
	if chk != nil {
		if lk, err := chk.Check(ctx, ip); err == nil {
			sig.IPBlocklistSources = lk.Sources
			sig.IPBlocklistCount = lk.MaxCount
			sig.IPBlocklistDeliberate = slices.ContainsFunc(lk.Sources, func(s string) bool {
				return s != iptools.BlocklistSourceIPsum && s != iptools.BlocklistSourceProbe
			})
			sig.IPProbed = lk.Probed()
		}
	}
	if svc == nil {
		return nil
	}
	res, err := svc.Lookup(ctx, ip)
	if err != nil || res == nil {
		return nil
	}
	sig.IPTimezone = res.Timezone
	sig.ASN = res.ASN
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
