package botcheck

import (
	"context"
	"slices"

	"github.com/Landver/site-of-tools/tools/iptools"
)

// Looker resolves an IP to geolocation and proxy facts. *iptools.Service
// satisfies it (a nil one answers ErrUnavailable); tests inject a fake.
type Looker interface {
	Lookup(ip string) (*iptools.Result, error)
}

// HTTPSignals are the request headers the rules read.
type HTTPSignals struct {
	UserAgent               string
	Accept                  string
	AcceptLanguage          string
	AcceptEncoding          string
	SecCHUA                 string
	SecCHUAPlatform         string
	SecFetchMode            string
	UpgradeInsecureRequests string
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

// AddIPSignals fills the IP half of sig for ip, the address the request came
// from, and counts the IP as supplied. The caller still sets sig.Now: a zero
// Now silently skips tz_mismatch. Returns the lookup (nil when there is none)
// so callers needn't repeat it.
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

// cleanPlaceholder maps IP2Location's "-" (unknown) to "", so an unknown
// timezone can't trip the timezone cross-check.
func cleanPlaceholder(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
