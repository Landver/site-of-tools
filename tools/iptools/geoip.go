// Package iptools is ip.corpberry.com: IP to geo and ASN, with optional proxy/VPN detection.
package iptools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	ip2location "github.com/ip2location/ip2location-go/v9"
	ip2proxy "github.com/ip2location/ip2proxy-go/v4"
)

type Result struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Timezone    string  `json:"timezone"`
	Latitude    float32 `json:"lat"`
	Longitude   float32 `json:"lon"`
	ASN         string  `json:"asn"`
	ASName      string  `json:"as_name"`
	Proxy       *Proxy  `json:"proxy,omitempty"`
	// Not set by Lookup; nil means not checked, which is different from clean.
	Blocklist *BlockLookup `json:"blocklist,omitempty"`
	// nil when not checked: Shodan disabled, a private IP, or the lookup failed.
	Shodan *ShodanInfo `json:"shodan,omitempty"`
}

func (r *Result) ShodanConsulted() bool { return r != nil && r.Shodan != nil && !r.Shodan.Skipped }

// Proxy is set only when the PX12 database is loaded and the lookup succeeds.
type Proxy struct {
	IsProxy    bool   `json:"is_proxy"`
	ProxyType  string `json:"proxy_type,omitempty"`
	UsageType  string `json:"usage_type,omitempty"`
	Threat     string `json:"threat,omitempty"`
	Provider   string `json:"provider,omitempty"`
	FraudScore string `json:"fraud_score,omitempty"`
	ISP        string `json:"isp,omitempty"`
	Domain     string `json:"domain,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

// Service's handles open once and are shared: BIN reads are positional (ReadAt), so goroutine-safe.
type Service struct {
	db4, db6   *ip2location.DB
	asn4, asn6 *ip2location.DB
	proxy      *ip2proxy.DB // optional; nil disables proxy section
	shodan     *Shodan      // optional; nil disables Shodan enrichment
}

// WithShodan is a copy of s that adds Shodan's open ports and proxy tags, sharing s's open databases. Nil-safe.
func (s *Service) WithShodan(sh *Shodan) *Service {
	if s == nil {
		return nil
	}
	c := *s
	c.shodan = sh
	return &c
}

var ErrUnavailable = errors.New("geolocation databases are not loaded")

// OpenService returns ErrUnavailable for a missing geo path so the server can still start.
func OpenService(db11v4, db11v6, asnv4, asnv6, px12 string) (*Service, error) {
	if slices.Contains([]string{db11v4, db11v6, asnv4, asnv6}, "") {
		return nil, ErrUnavailable
	}
	s := &Service{}
	// The caller runs on with the tool disabled, so a handle leaked here would stay open forever.
	ok := false
	defer func() {
		if !ok {
			s.closeAll()
		}
	}()

	var err error
	if s.db4, err = ip2location.OpenDB(db11v4); err != nil {
		return nil, err
	}
	if s.db6, err = ip2location.OpenDB(db11v6); err != nil {
		return nil, err
	}
	if s.asn4, err = ip2location.OpenDB(asnv4); err != nil {
		return nil, err
	}
	if s.asn6, err = ip2location.OpenDB(asnv6); err != nil {
		return nil, err
	}
	if px12 != "" {
		p, err := ip2proxy.OpenDB(px12)
		if err != nil {
			return nil, fmt.Errorf("open ip2proxy: %w", err)
		}
		s.proxy = p
	}
	ok = true
	return s, nil
}

func (s *Service) closeAll() {
	for _, db := range []*ip2location.DB{s.db4, s.db6, s.asn4, s.asn6} {
		if db != nil {
			db.Close()
		}
	}
	if s.proxy != nil {
		_ = s.proxy.Close()
	}
}

// Lookup's ctx bounds only the Shodan call; the BIN reads are local.
func (s *Service) Lookup(ctx context.Context, ipStr string) (*Result, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", ipStr)
	}

	geoDB, asnDB := s.db6, s.asn6 // v6 BINs answer v4 too, but native v4 goes to the v4 BINs
	if parsed.To4() != nil {
		geoDB, asnDB = s.db4, s.asn4
	}

	geo, err := geoDB.Get_all(ipStr)
	if err != nil {
		return nil, err
	}
	as, err := asnDB.Get_all(ipStr)
	if err != nil {
		return nil, err
	}

	res := &Result{
		IP:          ipStr,
		CountryCode: clean(geo.Country_short),
		Country:     clean(geo.Country_long),
		Region:      clean(geo.Region),
		City:        clean(geo.City),
		Zip:         clean(geo.Zipcode),
		Timezone:    clean(geo.Timezone),
		Latitude:    geo.Latitude,
		Longitude:   geo.Longitude,
		ASN:         clean(as.Asn),
		ASName:      clean(as.As),
		Proxy:       s.lookupProxy(ipStr),
	}
	if s.shodan != nil && Routable(ipStr) {
		if si, err := s.shodan.Lookup(ctx, ipStr); err == nil && si != nil {
			res.Shodan = si
			FuseShodanProxy(res)
		}
	}
	return res, nil
}

// LookupWithReputation adds chk's verdict; a failed read leaves Blocklist nil, never "clean".
func LookupWithReputation(ctx context.Context, svc Looker, chk Checker, ip string) (*Result, error) {
	if svc == nil {
		return nil, ErrUnavailable
	}
	res, err := svc.Lookup(ctx, ip)
	if err != nil || res == nil || chk == nil {
		return res, err
	}
	if lk, err := chk.Check(ctx, ip); err == nil {
		res.Blocklist = &lk
	}
	return res, nil
}

func Routable(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && !a.IsLoopback() && !a.IsPrivate() &&
		!a.IsLinkLocalUnicast() && !a.IsUnspecified()
}

// FuseShodanProxy maps Shodan tags to IP2Proxy types (VPN > TOR > PUB), never overriding a PX12 hit.
func FuseShodanProxy(res *Result) {
	if res == nil || res.Shodan == nil {
		return
	}
	var tagType string
	for _, tag := range res.Shodan.Tags {
		switch strings.ToLower(tag) {
		case "vpn":
			tagType = "VPN"
		case "tor":
			if tagType != "VPN" {
				tagType = "TOR"
			}
		case "proxy":
			if tagType == "" {
				tagType = "PUB"
			}
		}
	}
	if tagType != "" {
		if res.Proxy == nil {
			res.Proxy = &Proxy{IsProxy: true, ProxyType: tagType, Provider: "Shodan"}
		} else if !res.Proxy.IsProxy {
			res.Proxy.IsProxy = true
			res.Proxy.ProxyType = tagType
			res.Proxy.Provider = "Shodan"
		}
	}
}

// lookupProxy returns nil on any error (e.g. a family the BIN lacks) so it never breaks the geo result.
func (s *Service) lookupProxy(ipStr string) *Proxy {
	if s.proxy == nil {
		return nil
	}
	r, err := s.proxy.GetAll(ipStr)
	if err != nil {
		return nil
	}
	return &Proxy{
		IsProxy:    r.IsProxy > 0, // 0 = no, 1 = proxy, 2 = proxy (data center)
		ProxyType:  clean(r.ProxyType),
		UsageType:  clean(r.UsageType),
		Threat:     clean(r.Threat),
		Provider:   clean(r.Provider),
		FraudScore: clean(r.FraudScore),
		ISP:        clean(r.Isp),
		Domain:     clean(r.Domain),
		LastSeen:   clean(r.LastSeen),
	}
}

// IP2Location and IP2Proxy use "-" for no value (private ranges, no city); it must never reach output.
func clean(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
